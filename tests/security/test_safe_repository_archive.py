from __future__ import annotations

import asyncio
import os
import stat
import time
from pathlib import Path

import pytest

from tests.repository_fixtures import TarEntry, build_tar, safe_repository_tar
from watchdog.repository.cleanup import WorkspaceCleaner
from watchdog.repository.errors import (
    EmptyRepositoryError,
    RepositoryCleanupError,
    RepositoryIntakeTimeoutError,
    RepositoryLimitExceededError,
    UnsafeRepositoryArchiveError,
)
from watchdog.repository.limits import RepositoryLimits
from watchdog.repository.workspace import ExtractionResult, SafeTarExtractor


def limits(**overrides: int | float | Path | None) -> RepositoryLimits:
    values: dict[str, int | float | Path | None] = {
        "network_timeout_seconds": 5,
        "max_duration_seconds": 30,
        "max_archive_bytes": 1024 * 1024,
        "max_extracted_bytes": 1024 * 1024,
        "max_files": 100,
        "max_path_length": 256,
        "max_concurrent_intakes": 1,
        "workspace_root": None,
    }
    values.update(overrides)
    return RepositoryLimits.model_validate(values)


async def write_archive(path: Path, content: bytes) -> None:
    await asyncio.to_thread(path.write_bytes, content)


async def extract(
    tmp_path: Path,
    archive_bytes: bytes,
    *,
    repository_limits: RepositoryLimits | None = None,
    deadline: float | None = None,
) -> tuple[Path, ExtractionResult]:
    archive = tmp_path / "repository.tar.gz"
    destination = tmp_path / "source"
    await write_archive(archive, archive_bytes)
    result = await SafeTarExtractor().extract(
        archive,
        destination,
        repository_limits or limits(),
        deadline=deadline or time.monotonic() + 10,
    )
    return destination, result


async def test_extracts_regular_files_and_contained_symlinks(tmp_path: Path) -> None:
    destination, result = await extract(tmp_path, safe_repository_tar())

    readme = destination / "README.md"
    link = destination / "docs" / "readme-link"
    assert await asyncio.to_thread(readme.read_bytes) == b"repository data\n"
    assert await asyncio.to_thread(os.readlink, link) == "../README.md"
    assert stat.S_IMODE((await asyncio.to_thread(readme.stat)).st_mode) == 0o600
    assert stat.S_IMODE((await asyncio.to_thread(destination.stat)).st_mode) == 0o700
    assert result.extracted_bytes == len(b"repository data\n")
    assert result.file_count == 2
    assert result.symlink_count == 1


@pytest.mark.parametrize(
    "entries",
    [
        [TarEntry("../outside", content=b"x")],
        [TarEntry("/absolute", content=b"x")],
        [TarEntry("root\\windows", content=b"x")],
        [TarEntry("root/control\nname", content=b"x")],
        [TarEntry("root/a", content=b"x"), TarEntry("other/b", content=b"x")],
        [TarEntry("root/File", content=b"x"), TarEntry("root/file", content=b"x")],
        [TarEntry("root/file", content=b"x"), TarEntry("root/file", content=b"y")],
        [TarEntry("root/link", kind="symlink", linkname="../../outside")],
        [TarEntry("root/link", kind="symlink", linkname="safe\nunsafe")],
        [
            TarEntry("root/link", kind="symlink", linkname="directory"),
            TarEntry("root/link/file", content=b"x"),
        ],
        [TarEntry("root/link", kind="hardlink", linkname="root/file")],
        [TarEntry("root/pipe", kind="fifo")],
    ],
    ids=[
        "traversal",
        "absolute",
        "backslash",
        "control-character",
        "multiple-roots",
        "case-collision",
        "duplicate",
        "escaping-symlink",
        "symlink-control-character",
        "symlink-parent",
        "hardlink",
        "fifo",
    ],
)
async def test_rejects_unsafe_archive_members(
    tmp_path: Path,
    entries: list[TarEntry],
) -> None:
    with pytest.raises(UnsafeRepositoryArchiveError):
        await extract(tmp_path, build_tar(entries))


@pytest.mark.parametrize(
    ("entries", "repository_limits"),
    [
        (
            [TarEntry("root/a", content=b"a"), TarEntry("root/b", content=b"b")],
            limits(max_files=1),
        ),
        (
            [TarEntry("root/a/", kind="dir"), TarEntry("root/b/", kind="dir")],
            limits(max_files=1),
        ),
        ([TarEntry("root/file", content=b"too large")], limits(max_extracted_bytes=2)),
        ([TarEntry("root/long-name", content=b"x")], limits(max_path_length=3)),
    ],
    ids=["file-count", "directory-count", "extracted-bytes", "path-length"],
)
async def test_enforces_extraction_limits(
    tmp_path: Path,
    entries: list[TarEntry],
    repository_limits: RepositoryLimits,
) -> None:
    with pytest.raises(RepositoryLimitExceededError):
        await extract(tmp_path, build_tar(entries), repository_limits=repository_limits)


@pytest.mark.parametrize("archive_bytes", [b"not a gzip archive", build_tar([])])
async def test_rejects_malformed_or_empty_archives(
    tmp_path: Path,
    archive_bytes: bytes,
) -> None:
    expected = (
        UnsafeRepositoryArchiveError if archive_bytes.startswith(b"not") else EmptyRepositoryError
    )
    with pytest.raises(expected):
        await extract(tmp_path, archive_bytes)


async def test_stops_when_the_deadline_has_passed(tmp_path: Path) -> None:
    with pytest.raises(RepositoryIntakeTimeoutError):
        await extract(tmp_path, safe_repository_tar(), deadline=time.monotonic() - 1)


async def test_cleanup_refuses_a_workspace_replaced_by_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    workspace = tmp_path / "workspace"
    await asyncio.to_thread(target.mkdir)
    await asyncio.to_thread(workspace.symlink_to, target, target_is_directory=True)

    with pytest.raises(RepositoryCleanupError) as caught:
        await WorkspaceCleaner().cleanup(workspace, workspace / "repository.tar.gz")

    assert not caught.value.result.verified
    assert await asyncio.to_thread(target.is_dir)
    assert await asyncio.to_thread(workspace.is_symlink)
