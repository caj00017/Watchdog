from __future__ import annotations

import asyncio
import os
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType

from watchdog.domain.repositories import (
    AcquiredRepository,
    CleanupResult,
    GitHubRepository,
    RepositoryRequest,
    RepositorySnapshot,
)
from watchdog.repository.cleanup import WorkspaceCleaner
from watchdog.repository.errors import RepositoryCleanupError, RepositoryIntakeTimeoutError
from watchdog.repository.limits import RepositoryLimits
from watchdog.repository.source import RepositorySource
from watchdog.repository.validation import parse_github_repository_url
from watchdog.repository.workspace import SafeTarExtractor


class RepositoryIntakeService:
    """Create one-use repository leases bounded by shared local concurrency."""

    def __init__(
        self,
        source: RepositorySource,
        limits: RepositoryLimits,
        *,
        extractor: SafeTarExtractor | None = None,
        cleaner: WorkspaceCleaner | None = None,
    ) -> None:
        self._source = source
        self._limits = limits
        self._extractor = extractor or SafeTarExtractor()
        self._cleaner = cleaner or WorkspaceCleaner()
        self._semaphore = asyncio.Semaphore(limits.max_concurrent_intakes)

    def acquire(self, request: RepositoryRequest) -> RepositoryLease:
        repository = parse_github_repository_url(request.repository_url)
        return RepositoryLease(
            source=self._source,
            limits=self._limits,
            extractor=self._extractor,
            cleaner=self._cleaner,
            semaphore=self._semaphore,
            repository=repository,
            request=request,
        )


class RepositoryLease:
    """An async context manager that owns acquisition through verified deletion."""

    def __init__(
        self,
        *,
        source: RepositorySource,
        limits: RepositoryLimits,
        extractor: SafeTarExtractor,
        cleaner: WorkspaceCleaner,
        semaphore: asyncio.Semaphore,
        repository: GitHubRepository,
        request: RepositoryRequest,
    ) -> None:
        self._source = source
        self._limits = limits
        self._extractor = extractor
        self._cleaner = cleaner
        self._semaphore = semaphore
        self._repository = repository
        self._request = request
        self._workspace: Path | None = None
        self._archive: Path | None = None
        self._slot_acquired = False
        self._entered = False
        self._cleanup_result: CleanupResult | None = None

    @property
    def cleanup_result(self) -> CleanupResult:
        if self._cleanup_result is None:
            raise RuntimeError("cleanup has not completed")
        return self._cleanup_result

    async def __aenter__(self) -> AcquiredRepository:
        if self._entered:
            raise RuntimeError("repository leases are single-use")
        self._entered = True
        deadline = time.monotonic() + self._limits.max_duration_seconds

        try:
            async with asyncio.timeout(self._limits.max_duration_seconds):
                await self._semaphore.acquire()
                self._slot_acquired = True
                self._workspace = await asyncio.to_thread(self._create_workspace)
                self._archive = self._workspace / "repository.tar.gz"
                source_root = self._workspace / "source"

                resolved = await self._source.resolve(self._repository, self._request.ref)
                download = await self._source.download_archive(
                    resolved,
                    self._archive,
                    max_bytes=self._limits.max_archive_bytes,
                )
                extracted = await self._extractor.extract(
                    self._archive,
                    source_root,
                    self._limits,
                    deadline=deadline,
                )
                await asyncio.to_thread(self._archive.unlink)
                if await asyncio.to_thread(os.path.lexists, self._archive):
                    raise RepositoryCleanupError(self._failed_pre_yield_cleanup_result())

                snapshot = RepositorySnapshot(
                    repository=resolved.repository,
                    requested_ref=resolved.requested_ref,
                    resolved_ref=resolved.resolved_ref,
                    commit_sha=resolved.commit_sha,
                    tree_sha=resolved.tree_sha,
                    retrieved_at=datetime.now(UTC),
                    archive_sha256=download.sha256,
                    archive_bytes=download.byte_count,
                    extracted_bytes=extracted.extracted_bytes,
                    file_count=extracted.file_count,
                    symlink_count=extracted.symlink_count,
                )
                return AcquiredRepository(root=source_root, snapshot=snapshot)
        except TimeoutError as exc:
            error = RepositoryIntakeTimeoutError()
            await self._cleanup_after_failed_entry(error)
            raise error from exc
        except BaseException as exc:
            await self._cleanup_after_failed_entry(exc)
            raise

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        del exc_type, traceback
        try:
            await self._run_cleanup()
        except RepositoryCleanupError as cleanup_error:
            if exc is not None:
                raise cleanup_error from exc
            raise
        finally:
            self._release_slot()
        return False

    def _create_workspace(self) -> Path:
        base = self._limits.workspace_root
        if base is not None:
            base.mkdir(mode=0o700, parents=True, exist_ok=True)
            if base.is_symlink() or not base.is_dir():
                raise RuntimeError("configured workspace root is not a real directory")
        workspace = Path(
            tempfile.mkdtemp(prefix="nexura-watchdog-", dir=str(base) if base else None)
        )
        workspace.chmod(0o700)
        return workspace

    async def _cleanup_after_failed_entry(self, original: BaseException) -> None:
        try:
            await self._run_cleanup()
        except RepositoryCleanupError as cleanup_error:
            raise cleanup_error from original
        finally:
            self._release_slot()

    async def _run_cleanup(self) -> None:
        if self._workspace is None or self._archive is None:
            return
        try:
            self._cleanup_result = await self._cleaner.cleanup(self._workspace, self._archive)
        except RepositoryCleanupError as exc:
            self._cleanup_result = exc.result
            raise

    def _release_slot(self) -> None:
        if self._slot_acquired:
            self._semaphore.release()
            self._slot_acquired = False

    def _failed_pre_yield_cleanup_result(self) -> CleanupResult:
        now = datetime.now(UTC)
        return CleanupResult(
            status="failed",
            started_at=now,
            completed_at=now,
            archive_removed=False,
            workspace_removed=False,
            verified=False,
        )
