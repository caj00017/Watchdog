from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import BinaryIO, Self
from urllib.parse import quote, urljoin, urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from watchdog.domain.repositories import GitHubRepository, ResolvedRepository
from watchdog.repository.errors import (
    MalformedRepositorySourceError,
    RepositoryLimitExceededError,
    RepositoryNotFoundError,
    RepositorySourceUnavailableError,
    UnsafeRepositoryArchiveError,
)
from watchdog.repository.source import ArchiveDownload
from watchdog.repository.validation import parse_github_repository_url

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_ALLOWED_REDIRECT_HOSTS = {"api.github.com", "codeload.github.com"}
_GITHUB_API_BASE_URL = "https://api.github.com"


class GitHubBoundaryModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class GitHubOwnerResponse(GitHubBoundaryModel):
    login: str


class GitHubRepositoryResponse(GitHubBoundaryModel):
    owner: GitHubOwnerResponse
    name: str
    full_name: str
    private: bool
    default_branch: str


class GitHubTreeResponse(GitHubBoundaryModel):
    sha: str


class GitHubCommitDetailsResponse(GitHubBoundaryModel):
    tree: GitHubTreeResponse


class GitHubCommitResponse(GitHubBoundaryModel):
    sha: str
    commit: GitHubCommitDetailsResponse

    @model_validator(mode="after")
    def validate_shas(self) -> Self:
        for value in (self.sha, self.commit.tree.sha):
            if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
                raise ValueError("commit and tree SHAs must be 40 lowercase hexadecimal characters")
        return self


class GitHubRepositorySource:
    """Resolve and download public GitHub snapshots without invoking Git."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        api_version: str = "2026-03-10",
        network_timeout_seconds: float = 30.0,
    ) -> None:
        self._client = client
        self._api_version = api_version
        self._network_timeout_seconds = network_timeout_seconds

    async def resolve(
        self,
        repository: GitHubRepository,
        requested_ref: str | None,
    ) -> ResolvedRepository:
        encoded_owner = quote(repository.owner, safe="")
        encoded_name = quote(repository.name, safe="")
        repository_url = f"{_GITHUB_API_BASE_URL}/repos/{encoded_owner}/{encoded_name}"
        payload = await self._get_json(repository_url)
        try:
            upstream = GitHubRepositoryResponse.model_validate(payload, strict=True)
            canonical = parse_github_repository_url(
                f"https://github.com/{upstream.owner.login}/{upstream.name}"
            )
        except (TypeError, ValueError, ValidationError) as exc:
            raise MalformedRepositorySourceError("invalid repository metadata") from exc

        if upstream.private:
            raise RepositoryNotFoundError
        if upstream.full_name.casefold() != f"{repository.owner}/{repository.name}".casefold():
            raise MalformedRepositorySourceError("repository identity did not match the request")

        resolved_ref = requested_ref or upstream.default_branch
        encoded_ref = quote(resolved_ref, safe="")
        commit_payload = await self._get_json(f"{repository_url}/commits/{encoded_ref}")
        try:
            commit = GitHubCommitResponse.model_validate(commit_payload, strict=True)
        except (TypeError, ValueError, ValidationError) as exc:
            raise MalformedRepositorySourceError("invalid commit metadata") from exc

        return ResolvedRepository(
            repository=canonical,
            requested_ref=requested_ref,
            resolved_ref=resolved_ref,
            commit_sha=commit.sha,
            tree_sha=commit.commit.tree.sha,
        )

    async def download_archive(
        self,
        resolved: ResolvedRepository,
        destination: Path,
        *,
        max_bytes: int,
    ) -> ArchiveDownload:
        owner = quote(resolved.repository.owner, safe="")
        name = quote(resolved.repository.name, safe="")
        sha = quote(resolved.commit_sha, safe="")
        url = f"{_GITHUB_API_BASE_URL}/repos/{owner}/{name}/tarball/{sha}"
        redirect_count = 0

        while True:
            try:
                stream = self._client.stream(
                    "GET",
                    url,
                    headers=self._headers(),
                    follow_redirects=False,
                    timeout=self._network_timeout_seconds,
                )
                async with stream as response:
                    if response.status_code in _REDIRECT_STATUSES:
                        location = response.headers.get("location")
                        if location is None:
                            raise MalformedRepositorySourceError(
                                "archive redirect omitted its destination"
                            )
                        redirect_count += 1
                        if redirect_count > 3:
                            raise UnsafeRepositoryArchiveError("too many archive redirects")
                        url = self._validated_redirect(urljoin(url, location))
                        continue

                    self._check_status(response)
                    content_length = self._content_length(response)
                    if content_length is not None and content_length > max_bytes:
                        raise RepositoryLimitExceededError(
                            "compressed archive size", max_bytes, content_length
                        )
                    return await self._write_archive(response, destination, max_bytes=max_bytes)
            except httpx.TimeoutException as exc:
                raise RepositorySourceUnavailableError("unavailable due to a timeout") from exc
            except httpx.RequestError as exc:
                raise RepositorySourceUnavailableError from exc

    async def _get_json(self, url: str) -> dict[str, object]:
        try:
            response = await self._client.get(
                url,
                headers=self._headers(),
                follow_redirects=False,
                timeout=self._network_timeout_seconds,
            )
        except httpx.TimeoutException as exc:
            raise RepositorySourceUnavailableError("unavailable due to a timeout") from exc
        except httpx.RequestError as exc:
            raise RepositorySourceUnavailableError from exc
        self._check_status(response)
        try:
            payload = response.json()
        except ValueError as exc:
            raise MalformedRepositorySourceError("response was not valid JSON") from exc
        if not isinstance(payload, dict):
            raise MalformedRepositorySourceError("response root was not an object")
        return payload

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self._api_version,
            "User-Agent": "Nexura-Watchdog/0.1",
        }

    def _check_status(self, response: httpx.Response) -> None:
        if response.status_code in {404, 422}:
            raise RepositoryNotFoundError
        if response.status_code in {401, 403, 429} or response.status_code >= 500:
            raise RepositorySourceUnavailableError(
                f"unavailable (upstream HTTP {response.status_code})"
            )
        if response.is_error:
            raise MalformedRepositorySourceError(f"unexpected upstream HTTP {response.status_code}")

    def _content_length(self, response: httpx.Response) -> int | None:
        value = response.headers.get("content-length")
        if value is None:
            return None
        try:
            parsed = int(value)
        except ValueError as exc:
            raise MalformedRepositorySourceError("invalid archive Content-Length") from exc
        if parsed < 0:
            raise MalformedRepositorySourceError("negative archive Content-Length")
        return parsed

    def _validated_redirect(self, raw_url: str) -> str:
        try:
            parsed = urlsplit(raw_url)
            port = parsed.port
        except ValueError as exc:
            raise UnsafeRepositoryArchiveError("malformed archive redirect") from exc
        if (
            parsed.scheme != "https"
            or parsed.hostname not in _ALLOWED_REDIRECT_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or port not in {None, 443}
            or parsed.fragment
        ):
            raise UnsafeRepositoryArchiveError("archive redirect left the GitHub allowlist")
        return raw_url

    async def _write_archive(
        self,
        response: httpx.Response,
        destination: Path,
        *,
        max_bytes: int,
    ) -> ArchiveDownload:
        digest = hashlib.sha256()
        byte_count = 0
        archive_file: BinaryIO = await asyncio.to_thread(destination.open, "xb")
        try:
            await asyncio.to_thread(destination.chmod, 0o600)
            async for chunk in response.aiter_bytes(chunk_size=1024 * 1024):
                byte_count += len(chunk)
                if byte_count > max_bytes:
                    raise RepositoryLimitExceededError(
                        "compressed archive size", max_bytes, byte_count
                    )
                digest.update(chunk)
                await asyncio.to_thread(archive_file.write, chunk)
        finally:
            await asyncio.to_thread(archive_file.close)
        if byte_count == 0:
            raise MalformedRepositorySourceError("archive response was empty")
        return ArchiveDownload(byte_count=byte_count, sha256=digest.hexdigest())
