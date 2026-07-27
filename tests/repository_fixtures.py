from __future__ import annotations

import asyncio
import hashlib
import io
import tarfile
from dataclasses import dataclass
from pathlib import Path

from watchdog.domain.repositories import GitHubRepository, ResolvedRepository
from watchdog.repository.source import ArchiveDownload

COMMIT_SHA = "a" * 40
TREE_SHA = "b" * 40


@dataclass(frozen=True, slots=True)
class TarEntry:
    name: str
    kind: str = "file"
    content: bytes = b""
    linkname: str = ""


def build_tar(entries: list[TarEntry]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for entry in entries:
            info = tarfile.TarInfo(entry.name)
            if entry.kind == "file":
                info.size = len(entry.content)
                info.mode = 0o755
                archive.addfile(info, io.BytesIO(entry.content))
            elif entry.kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            elif entry.kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = entry.linkname
                archive.addfile(info)
            elif entry.kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = entry.linkname
                archive.addfile(info)
            elif entry.kind == "fifo":
                info.type = tarfile.FIFOTYPE
                archive.addfile(info)
            else:
                raise ValueError(f"unsupported test entry kind: {entry.kind}")
    return buffer.getvalue()


def safe_repository_tar() -> bytes:
    return build_tar(
        [
            TarEntry("owner-repo-sha/", kind="dir"),
            TarEntry("owner-repo-sha/README.md", content=b"repository data\n"),
            TarEntry("owner-repo-sha/docs/", kind="dir"),
            TarEntry("owner-repo-sha/docs/readme-link", kind="symlink", linkname="../README.md"),
        ]
    )


def resolved_repository(ref: str | None = None) -> ResolvedRepository:
    return ResolvedRepository(
        repository=GitHubRepository(
            owner="octocat",
            name="Hello-World",
            canonical_url="https://github.com/octocat/Hello-World",
        ),
        requested_ref=ref,
        resolved_ref=ref or "main",
        commit_sha=COMMIT_SHA,
        tree_sha=TREE_SHA,
    )


class FakeRepositorySource:
    def __init__(self, archive: bytes | None = None, *, delay: float = 0) -> None:
        self.archive = archive or safe_repository_tar()
        self.delay = delay
        self.started = asyncio.Event()
        self.active = 0
        self.max_active = 0
        self.destinations: list[Path] = []

    async def resolve(
        self,
        _repository: GitHubRepository,
        requested_ref: str | None,
    ) -> ResolvedRepository:
        self.started.set()
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            return resolved_repository(requested_ref)
        finally:
            self.active -= 1

    async def download_archive(
        self,
        _resolved: ResolvedRepository,
        destination: Path,
        *,
        max_bytes: int,
    ) -> ArchiveDownload:
        if len(self.archive) > max_bytes:
            raise AssertionError("test archive unexpectedly exceeds configured limit")
        self.destinations.append(destination)
        await asyncio.to_thread(destination.write_bytes, self.archive)
        return ArchiveDownload(
            byte_count=len(self.archive),
            sha256=hashlib.sha256(self.archive).hexdigest(),
        )
