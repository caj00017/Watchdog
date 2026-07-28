from __future__ import annotations

import errno
import hashlib
import os
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from watchdog.evidence.limits import EvidenceLimits

_CHUNK_SIZE = 1024 * 1024


class EvidenceWorkStopped(Exception):
    """Internal control flow with diagnostics that never contain repository bytes."""


class EvidenceDeadlineExceeded(EvidenceWorkStopped):
    pass


class EvidenceCancelled(EvidenceWorkStopped):
    pass


@dataclass(frozen=True, slots=True)
class ReadResult:
    data: bytes | None
    limitation_code: str | None
    bytes_read: int


def validate_repository_path(path: str) -> bool:
    return bool(path) and not (
        path.startswith("/")
        or "\\" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    )


class DescriptorRepositoryReader:
    """Read allowlisted relative paths without following any path component."""

    def __init__(
        self,
        root: Path,
        limits: EvidenceLimits,
        *,
        deadline: float,
        cancel_event: threading.Event,
    ) -> None:
        self._root = root
        self._limits = limits
        self._deadline = deadline
        self._cancel_event = cancel_event
        self._root_descriptor: int | None = None
        self._attempted_paths: set[str] = set()
        self.total_bytes_read = 0
        self.files_read = 0

    def __enter__(self) -> DescriptorRepositoryReader:
        self._check_active()
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(self._root, flags)
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(descriptor)
                raise OSError(errno.ENOTDIR, "repository root is not a directory")
        except OSError as exc:
            raise ValueError("acquired repository root is unavailable or unsafe") from exc
        self._root_descriptor = descriptor
        return self

    def __exit__(self, *_args: object) -> None:
        if self._root_descriptor is not None:
            os.close(self._root_descriptor)
            self._root_descriptor = None

    def read(self, path: str, expected_sha256: str) -> ReadResult:
        self._check_active()
        if not validate_repository_path(path):
            return ReadResult(None, "source_path_invalid", 0)
        if path not in self._attempted_paths:
            if len(self._attempted_paths) >= self._limits.max_source_files:
                return ReadResult(None, "source_file_limit_exceeded", 0)
            self._attempted_paths.add(path)
        descriptor, open_code = self._open_relative(path)
        if descriptor is None:
            return ReadResult(None, open_code, 0)
        bytes_read = 0
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                return ReadResult(None, "source_not_regular_file", 0)
            if before.st_size > self._limits.max_bytes_per_source_file:
                return ReadResult(None, "source_file_bytes_limit_exceeded", 0)
            if self.total_bytes_read + before.st_size > self._limits.max_total_source_bytes:
                return ReadResult(None, "source_total_bytes_limit_exceeded", 0)

            chunks: list[bytes] = []
            digest = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                self._check_active()
                try:
                    chunk = os.read(descriptor, min(_CHUNK_SIZE, remaining))
                except BlockingIOError:
                    return ReadResult(None, "source_unreadable", bytes_read)
                if not chunk:
                    break
                chunks.append(chunk)
                digest.update(chunk)
                bytes_read += len(chunk)
                self.total_bytes_read += len(chunk)
                remaining -= len(chunk)

            after = os.fstat(descriptor)
            if not self._same_file(before, after) or bytes_read != before.st_size:
                return ReadResult(None, "source_changed_during_read", bytes_read)
            if digest.hexdigest() != expected_sha256:
                return ReadResult(None, "source_digest_mismatch", bytes_read)
            self.files_read += 1
            return ReadResult(b"".join(chunks), None, bytes_read)
        except OSError:
            return ReadResult(None, "source_unreadable", bytes_read)
        finally:
            os.close(descriptor)

    def _open_relative(self, path: str) -> tuple[int | None, str]:
        assert self._root_descriptor is not None
        current = os.dup(self._root_descriptor)
        parts = path.split("/")
        try:
            for part in parts[:-1]:
                self._check_active()
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                )
                try:
                    child = os.open(part, flags, dir_fd=current)
                except OSError as exc:
                    return None, self._open_failure_code(exc, parent=True)
                os.close(current)
                current = child
            final_flags = (
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            try:
                descriptor = os.open(parts[-1], final_flags, dir_fd=current)
            except OSError as exc:
                return None, self._open_failure_code(exc, parent=False)
            return descriptor, ""
        finally:
            os.close(current)

    def _open_failure_code(self, error: OSError, *, parent: bool) -> str:
        if error.errno == errno.ENOENT:
            return "source_missing"
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            return "source_unsafe_path" if parent else "source_not_regular_file"
        return "source_unreadable"

    def _check_active(self) -> None:
        if self._cancel_event.is_set():
            raise EvidenceCancelled
        if time.monotonic() >= self._deadline:
            raise EvidenceDeadlineExceeded

    def _same_file(self, before: os.stat_result, after: os.stat_result) -> bool:
        return (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
