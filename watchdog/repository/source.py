from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from watchdog.domain.repositories import GitHubRepository, ResolvedRepository


@dataclass(frozen=True, slots=True)
class ArchiveDownload:
    byte_count: int
    sha256: str


class RepositorySource(Protocol):
    async def resolve(
        self,
        repository: GitHubRepository,
        requested_ref: str | None,
    ) -> ResolvedRepository: ...

    async def download_archive(
        self,
        resolved: ResolvedRepository,
        destination: Path,
        *,
        max_bytes: int,
    ) -> ArchiveDownload: ...
