from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tests.repository_fixtures import COMMIT_SHA, FakeRepositorySource, TarEntry, build_tar
from watchdog.domain.repositories import RepositoryRequest
from watchdog.repository.errors import (
    RepositoryIntakeTimeoutError,
    UnsafeRepositoryArchiveError,
)
from watchdog.repository.intake import RepositoryIntakeService, RepositoryLease
from watchdog.repository.limits import RepositoryLimits


def limits(
    workspace_root: Path,
    *,
    max_duration_seconds: float = 10,
    max_concurrent_intakes: int = 1,
) -> RepositoryLimits:
    return RepositoryLimits(
        network_timeout_seconds=5,
        max_duration_seconds=max_duration_seconds,
        max_archive_bytes=1024 * 1024,
        max_extracted_bytes=1024 * 1024,
        max_files=100,
        max_path_length=256,
        max_concurrent_intakes=max_concurrent_intakes,
        workspace_root=workspace_root,
    )


def request() -> RepositoryRequest:
    return RepositoryRequest(
        repository_url="https://github.com/octocat/Hello-World",
        ref="main",
    )


async def directory_entries(path: Path) -> list[Path]:
    return await asyncio.to_thread(lambda: list(path.iterdir()))


async def test_acquires_exact_snapshot_and_verifies_cleanup(tmp_path: Path) -> None:
    source = FakeRepositorySource()
    service = RepositoryIntakeService(source, limits(tmp_path))
    lease = service.acquire(request())

    async with lease as acquired:
        workspace = acquired.root.parent
        assert await asyncio.to_thread(acquired.root.is_dir)
        assert not await asyncio.to_thread((workspace / "repository.tar.gz").exists)
        assert await asyncio.to_thread((acquired.root / "README.md").read_bytes) == (
            b"repository data\n"
        )
        assert acquired.snapshot.commit_sha == COMMIT_SHA
        assert acquired.snapshot.resolved_ref == "main"
        assert acquired.snapshot.file_count == 2
        assert acquired.snapshot.symlink_count == 1

    assert not await asyncio.to_thread(workspace.exists)
    assert lease.cleanup_result.verified
    assert lease.cleanup_result.archive_removed
    assert lease.cleanup_result.workspace_removed


async def test_caller_exception_still_removes_workspace(tmp_path: Path) -> None:
    service = RepositoryIntakeService(FakeRepositorySource(), limits(tmp_path))
    lease = service.acquire(request())

    with pytest.raises(RuntimeError, match="consumer failed"):
        async with lease as acquired:
            workspace = acquired.root.parent
            raise RuntimeError("consumer failed")

    assert not await asyncio.to_thread(workspace.exists)
    assert lease.cleanup_result.verified


async def test_unsafe_archive_is_removed_before_error_returns(tmp_path: Path) -> None:
    source = FakeRepositorySource(build_tar([TarEntry("../outside", content=b"bad")]))
    lease = RepositoryIntakeService(source, limits(tmp_path)).acquire(request())

    with pytest.raises(UnsafeRepositoryArchiveError):
        async with lease:
            raise AssertionError("unsafe archive must not be yielded")

    workspace = source.destinations[0].parent
    assert not await asyncio.to_thread(workspace.exists)
    assert lease.cleanup_result.verified


async def test_duration_timeout_cleans_partial_workspace(tmp_path: Path) -> None:
    source = FakeRepositorySource(delay=0.1)
    lease = RepositoryIntakeService(
        source,
        limits(tmp_path, max_duration_seconds=0.01),
    ).acquire(request())

    with pytest.raises(RepositoryIntakeTimeoutError):
        async with lease:
            raise AssertionError("timed-out intake must not be yielded")

    assert lease.cleanup_result.verified
    assert await directory_entries(tmp_path) == []


async def test_cancellation_cleans_partial_workspace(tmp_path: Path) -> None:
    source = FakeRepositorySource(delay=1)
    lease = RepositoryIntakeService(source, limits(tmp_path)).acquire(request())

    async def acquire() -> None:
        async with lease:
            raise AssertionError("cancelled intake must not be yielded")

    task = asyncio.create_task(acquire())
    await source.started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert lease.cleanup_result.verified
    assert await directory_entries(tmp_path) == []


async def test_service_enforces_shared_concurrency_limit(tmp_path: Path) -> None:
    source = FakeRepositorySource(delay=0.05)
    service = RepositoryIntakeService(
        source,
        limits(tmp_path, max_concurrent_intakes=1),
    )

    async def acquire(lease: RepositoryLease) -> str:
        async with lease as acquired:
            return acquired.snapshot.commit_sha
        raise AssertionError("repository lease did not enter")

    commits = await asyncio.gather(
        acquire(service.acquire(request())),
        acquire(service.acquire(request())),
    )

    assert list(commits) == [COMMIT_SHA, COMMIT_SHA]
    assert source.max_active == 1
    assert await directory_entries(tmp_path) == []


async def test_lease_is_single_use(tmp_path: Path) -> None:
    lease = RepositoryIntakeService(FakeRepositorySource(), limits(tmp_path)).acquire(request())

    async with lease:
        pass
    with pytest.raises(RuntimeError, match="single-use"):
        async with lease:
            pass
