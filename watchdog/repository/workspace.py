from __future__ import annotations

import asyncio
import os
import tarfile
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from watchdog.repository.errors import (
    EmptyRepositoryError,
    RepositoryIntakeTimeoutError,
    RepositoryLimitExceededError,
    UnsafeRepositoryArchiveError,
)
from watchdog.repository.limits import RepositoryLimits

_COPY_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    extracted_bytes: int
    file_count: int
    symlink_count: int


class SafeTarExtractor:
    """Extract regular files and contained symlinks without trusting tar paths."""

    async def extract(
        self,
        archive: Path,
        destination: Path,
        limits: RepositoryLimits,
        *,
        deadline: float,
    ) -> ExtractionResult:
        cancel_event = threading.Event()
        task = asyncio.create_task(
            asyncio.to_thread(
                self._extract_sync,
                archive,
                destination,
                limits,
                deadline,
                cancel_event,
            )
        )
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            cancel_event.set()
            with suppress(Exception):
                await task
            raise

    def _extract_sync(
        self,
        archive_path: Path,
        destination: Path,
        limits: RepositoryLimits,
        deadline: float,
        cancel_event: threading.Event,
    ) -> ExtractionResult:
        destination.mkdir(mode=0o700)
        root_name: str | None = None
        seen_members: set[str] = set()
        materialized_paths: set[str] = set()
        case_paths: dict[str, str] = {}
        symlink_paths: set[PurePosixPath] = set()
        file_count = 0
        symlink_count = 0
        extracted_bytes = 0

        try:
            with tarfile.open(archive_path, mode="r:gz") as source:
                for member in source:
                    self._check_deadline(deadline, cancel_event)
                    root_name, relative = self._validated_member_path(
                        member.name,
                        root_name,
                        limits.max_path_length,
                    )
                    if relative is None:
                        if not member.isdir():
                            raise UnsafeRepositoryArchiveError(
                                "archive root entry was not a directory"
                            )
                        continue

                    key = relative.as_posix()
                    if key in seen_members:
                        raise UnsafeRepositoryArchiveError("archive contained duplicate paths")
                    seen_members.add(key)
                    self._register_case_paths(relative, case_paths)
                    self._register_materialized_paths(
                        relative,
                        materialized_paths,
                        limits.max_files,
                    )
                    self._reject_symlink_parent(relative, symlink_paths)
                    target = destination.joinpath(*relative.parts)

                    if member.isdir():
                        self._ensure_directory(destination, relative)
                        target.chmod(0o700)
                        continue

                    if not (member.isreg() or member.issym()):
                        raise UnsafeRepositoryArchiveError(
                            "archive contained a hardlink, device, FIFO, or unsupported member"
                        )
                    if getattr(member, "sparse", None):
                        raise UnsafeRepositoryArchiveError("archive contained a sparse file")

                    file_count += 1
                    if file_count > limits.max_files:
                        raise RepositoryLimitExceededError(
                            "file count", limits.max_files, file_count
                        )
                    self._ensure_directory(destination, PurePosixPath(*relative.parts[:-1]))
                    if os.path.lexists(target):
                        raise UnsafeRepositoryArchiveError("archive path collided with a directory")

                    if member.issym():
                        self._create_symlink(member.linkname, relative, target)
                        symlink_paths.add(relative)
                        symlink_count += 1
                        continue

                    if member.size < 0:
                        raise UnsafeRepositoryArchiveError("archive contained a negative file size")
                    projected_size = extracted_bytes + member.size
                    if projected_size > limits.max_extracted_bytes:
                        raise RepositoryLimitExceededError(
                            "extracted size", limits.max_extracted_bytes, projected_size
                        )
                    extracted_bytes += self._copy_file(
                        source,
                        member,
                        target,
                        deadline,
                        cancel_event,
                    )
        except RepositoryIntakeTimeoutError:
            raise
        except (EmptyRepositoryError, RepositoryLimitExceededError, UnsafeRepositoryArchiveError):
            raise
        except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
            raise UnsafeRepositoryArchiveError("archive was malformed or unreadable") from exc

        if file_count == 0:
            raise EmptyRepositoryError
        return ExtractionResult(
            extracted_bytes=extracted_bytes,
            file_count=file_count,
            symlink_count=symlink_count,
        )

    def _validated_member_path(
        self,
        raw_name: str,
        root_name: str | None,
        max_path_length: int,
    ) -> tuple[str, PurePosixPath | None]:
        if (
            not raw_name
            or "\\" in raw_name
            or raw_name.startswith("/")
            or self._contains_control_character(raw_name)
        ):
            raise UnsafeRepositoryArchiveError("archive contained an unsafe path")
        normalized = raw_name[:-1] if raw_name.endswith("/") else raw_name
        parts = normalized.split("/")
        if not normalized or any(part in {"", ".", ".."} for part in parts):
            raise UnsafeRepositoryArchiveError("archive contained path traversal or empty segments")
        if root_name is None:
            root_name = parts[0]
        elif parts[0] != root_name:
            raise UnsafeRepositoryArchiveError("archive contained multiple root directories")
        if len(parts) == 1:
            return root_name, None
        relative = PurePosixPath(*parts[1:])
        if len(relative.as_posix()) > max_path_length:
            raise RepositoryLimitExceededError(
                "relative path length", max_path_length, len(relative.as_posix())
            )
        return root_name, relative

    def _register_case_paths(self, relative: PurePosixPath, known: dict[str, str]) -> None:
        for index in range(1, len(relative.parts) + 1):
            path = PurePosixPath(*relative.parts[:index]).as_posix()
            key = path.casefold()
            previous = known.get(key)
            if previous is not None and previous != path:
                raise UnsafeRepositoryArchiveError("archive contained case-colliding paths")
            known[key] = path

    def _register_materialized_paths(
        self,
        relative: PurePosixPath,
        known: set[str],
        max_paths: int,
    ) -> None:
        for index in range(1, len(relative.parts) + 1):
            known.add(PurePosixPath(*relative.parts[:index]).as_posix())
            if len(known) > max_paths:
                raise RepositoryLimitExceededError("workspace entry count", max_paths, len(known))

    def _reject_symlink_parent(
        self,
        relative: PurePosixPath,
        symlinks: set[PurePosixPath],
    ) -> None:
        for index in range(1, len(relative.parts)):
            if PurePosixPath(*relative.parts[:index]) in symlinks:
                raise UnsafeRepositoryArchiveError("archive path traversed an earlier symlink")

    def _ensure_directory(self, root: Path, relative: PurePosixPath) -> None:
        current = root
        for part in relative.parts:
            current = current / part
            if os.path.lexists(current):
                if current.is_symlink() or not current.is_dir():
                    raise UnsafeRepositoryArchiveError(
                        "archive directory path collided with a non-directory"
                    )
            else:
                current.mkdir(mode=0o700)

    def _create_symlink(self, raw_target: str, relative: PurePosixPath, target: Path) -> None:
        if (
            not raw_target
            or "\\" in raw_target
            or raw_target.startswith("/")
            or self._contains_control_character(raw_target)
        ):
            raise UnsafeRepositoryArchiveError("archive contained an unsafe symlink")
        resolved_parts = list(relative.parts[:-1])
        for part in raw_target.split("/"):
            if part in {"", "."}:
                if part == "":
                    raise UnsafeRepositoryArchiveError("symlink contained an empty path segment")
                continue
            if part == "..":
                if not resolved_parts:
                    raise UnsafeRepositoryArchiveError("symlink escaped the workspace")
                resolved_parts.pop()
            else:
                resolved_parts.append(part)
        os.symlink(raw_target, target)

    def _contains_control_character(self, value: str) -> bool:
        return any(ord(character) < 32 or ord(character) == 127 for character in value)

    def _copy_file(
        self,
        archive: tarfile.TarFile,
        member: tarfile.TarInfo,
        target: Path,
        deadline: float,
        cancel_event: threading.Event,
    ) -> int:
        source_file = archive.extractfile(member)
        if source_file is None:
            raise UnsafeRepositoryArchiveError("regular file had no archive content")
        copied = 0
        with source_file, target.open("xb") as destination:
            target.chmod(0o600)
            while copied < member.size:
                self._check_deadline(deadline, cancel_event)
                chunk = source_file.read(min(_COPY_CHUNK_SIZE, member.size - copied))
                if not chunk:
                    raise UnsafeRepositoryArchiveError(
                        "regular file ended before its declared size"
                    )
                destination.write(chunk)
                copied += len(chunk)
        if copied != member.size:
            raise UnsafeRepositoryArchiveError("regular file size did not match its header")
        return copied

    def _check_deadline(self, deadline: float, cancel_event: threading.Event) -> None:
        if cancel_event.is_set() or time.monotonic() >= deadline:
            raise RepositoryIntakeTimeoutError
