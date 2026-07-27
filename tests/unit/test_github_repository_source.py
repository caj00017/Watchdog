import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from tests.repository_fixtures import (
    COMMIT_SHA,
    TREE_SHA,
    resolved_repository,
    safe_repository_tar,
)
from watchdog.repository.errors import (
    MalformedRepositorySourceError,
    RepositoryLimitExceededError,
    RepositoryNotFoundError,
    RepositorySourceUnavailableError,
    UnsafeRepositoryArchiveError,
)
from watchdog.repository.github import GitHubRepositorySource
from watchdog.repository.validation import parse_github_repository_url


def repository_payload() -> dict[str, object]:
    return {
        "owner": {"login": "octocat"},
        "name": "Hello-World",
        "full_name": "octocat/Hello-World",
        "private": False,
        "default_branch": "main",
    }


def commit_payload() -> dict[str, object]:
    return {"sha": COMMIT_SHA, "commit": {"tree": {"sha": TREE_SHA}}}


class ChunkStream(httpx.AsyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


@pytest.mark.parametrize(
    ("requested_ref", "expected_ref"),
    [(None, "main"), ("feature/safe-intake", "feature/safe-intake")],
)
async def test_resolve_repository_and_exact_commit(
    requested_ref: str | None,
    expected_ref: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-github-api-version"] == "2026-03-10"
        assert request.headers["user-agent"] == "Nexura-Watchdog/0.1"
        if request.url.path == "/repos/octocat/Hello-World":
            return httpx.Response(200, json=repository_payload())
        assert request.url.raw_path.decode() == (
            f"/repos/octocat/Hello-World/commits/{expected_ref.replace('/', '%2F')}"
        )
        return httpx.Response(200, json=commit_payload())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        source = GitHubRepositorySource(client)
        result = await source.resolve(
            parse_github_repository_url("https://github.com/octocat/Hello-World"),
            requested_ref,
        )

    assert result.resolved_ref == expected_ref
    assert result.commit_sha == COMMIT_SHA
    assert result.tree_sha == TREE_SHA


async def test_download_archive_follows_only_github_redirect_and_hashes(tmp_path: Path) -> None:
    archive = safe_repository_tar()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com":
            assert request.url.path.endswith(f"/tarball/{COMMIT_SHA}")
            return httpx.Response(
                302,
                headers={"Location": f"https://codeload.github.com/octocat/archive/{COMMIT_SHA}"},
            )
        assert request.url.host == "codeload.github.com"
        return httpx.Response(200, content=archive)

    destination = tmp_path / "repository.tar.gz"
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await GitHubRepositorySource(client).download_archive(
            resolved_repository(),
            destination,
            max_bytes=len(archive) + 1,
        )

    assert result.byte_count == len(archive)
    assert len(result.sha256) == 64
    assert await asyncio.to_thread(destination.read_bytes) == archive


async def test_download_archive_rejects_redirect_outside_allowlist(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://example.com/archive.tar.gz"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(UnsafeRepositoryArchiveError):
            await GitHubRepositorySource(client).download_archive(
                resolved_repository(),
                tmp_path / "repository.tar.gz",
                max_bytes=100,
            )


async def test_download_archive_enforces_content_length_before_write(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Length": "101"}, content=b"short")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RepositoryLimitExceededError):
            await GitHubRepositorySource(client).download_archive(
                resolved_repository(),
                tmp_path / "repository.tar.gz",
                max_bytes=100,
            )


async def test_download_archive_enforces_streamed_size_without_header(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=ChunkStream(b"123", b"456"))

    destination = tmp_path / "repository.tar.gz"
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RepositoryLimitExceededError):
            await GitHubRepositorySource(client).download_archive(
                resolved_repository(),
                destination,
                max_bytes=5,
            )

    assert (await asyncio.to_thread(destination.stat)).st_size <= 5


async def test_download_archive_rejects_empty_response(tmp_path: Path) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=ChunkStream())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(MalformedRepositorySourceError, match="empty"):
            await GitHubRepositorySource(client).download_archive(
                resolved_repository(),
                tmp_path / "repository.tar.gz",
                max_bytes=100,
            )


@pytest.mark.parametrize(
    ("status", "error_type"),
    [
        (404, RepositoryNotFoundError),
        (422, RepositoryNotFoundError),
        (403, RepositorySourceUnavailableError),
        (429, RepositorySourceUnavailableError),
        (503, RepositorySourceUnavailableError),
    ],
)
async def test_resolve_maps_github_statuses(
    status: int,
    error_type: type[Exception],
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(error_type):
            await GitHubRepositorySource(client).resolve(
                parse_github_repository_url("https://github.com/octocat/Hello-World"),
                None,
            )


async def test_resolve_rejects_malformed_commit_sha() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/octocat/Hello-World":
            return httpx.Response(200, json=repository_payload())
        return httpx.Response(
            200,
            json={"sha": "not-a-sha", "commit": {"tree": {"sha": TREE_SHA}}},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(MalformedRepositorySourceError):
            await GitHubRepositorySource(client).resolve(
                parse_github_repository_url("https://github.com/octocat/Hello-World"),
                None,
            )
