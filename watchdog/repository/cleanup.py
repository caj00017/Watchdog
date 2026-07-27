from __future__ import annotations

import asyncio
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path

from watchdog.domain.repositories import CleanupResult
from watchdog.repository.errors import RepositoryCleanupError


class WorkspaceCleaner:
    async def cleanup(self, workspace: Path, archive: Path) -> CleanupResult:
        started_at = datetime.now(UTC)
        task = asyncio.create_task(asyncio.to_thread(self._remove, workspace, archive))
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as cancelled:
            try:
                await task
            except (OSError, RuntimeError):
                result = self._result(started_at, workspace, archive, status="failed")
                raise RepositoryCleanupError(result) from cancelled
            raise
        except (OSError, RuntimeError) as exc:
            result = self._result(started_at, workspace, archive, status="failed")
            raise RepositoryCleanupError(result) from exc

        result = self._result(started_at, workspace, archive, status="verified")
        if not result.verified:
            failed = result.model_copy(update={"status": "failed"})
            raise RepositoryCleanupError(failed)
        return result

    def _remove(self, workspace: Path, archive: Path) -> None:
        if os.path.lexists(archive):
            if archive.is_dir() and not archive.is_symlink():
                raise RuntimeError("archive path unexpectedly became a directory")
            archive.unlink()
        if os.path.lexists(workspace):
            if workspace.is_symlink() or not workspace.is_dir():
                raise RuntimeError("workspace path is no longer a real directory")
            shutil.rmtree(workspace)

    def _result(
        self,
        started_at: datetime,
        workspace: Path,
        archive: Path,
        *,
        status: str,
    ) -> CleanupResult:
        archive_removed = not os.path.lexists(archive)
        workspace_removed = not os.path.lexists(workspace)
        verified = archive_removed and workspace_removed and status == "verified"
        return CleanupResult(
            status="verified" if verified else "failed",
            started_at=started_at,
            completed_at=datetime.now(UTC),
            archive_removed=archive_removed,
            workspace_removed=workspace_removed,
            verified=verified,
        )
