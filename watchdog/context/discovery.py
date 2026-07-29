from __future__ import annotations

import errno
import hashlib
import os
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from watchdog.context.limits import ContextLimits
from watchdog.domain.context import (
    ContextLimitation,
    ContextRuleCatalog,
    ContextWarning,
    SourceLanguage,
)

_READ_CHUNK_BYTES = 64 * 1024
_SOURCE_EXTENSIONS: dict[str, SourceLanguage] = {
    ".py": SourceLanguage.PYTHON,
    ".pyi": SourceLanguage.PYTHON,
    ".js": SourceLanguage.JAVASCRIPT,
    ".jsx": SourceLanguage.JAVASCRIPT,
    ".mjs": SourceLanguage.JAVASCRIPT,
    ".cjs": SourceLanguage.JAVASCRIPT,
    ".ts": SourceLanguage.JAVASCRIPT,
    ".tsx": SourceLanguage.JAVASCRIPT,
    ".go": SourceLanguage.GO,
}
_CONFIG_EXTENSIONS: dict[str, SourceLanguage] = {
    ".json": SourceLanguage.JSON,
    ".toml": SourceLanguage.TOML,
}
_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".cache",
        ".git",
        ".hg",
        ".mypy_cache",
        ".next",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "deps",
        "dist",
        "env",
        "node_modules",
        "site-packages",
        "snapshots",
        "target",
        "vendor",
        "venv",
    }
)


class ContextCancelled(Exception):
    """Internal cooperative-cancellation marker with no repository data."""


class _DeadlineExceeded(Exception):
    pass


@dataclass(frozen=True, slots=True)
class DiscoveredSource:
    path: str
    language: SourceLanguage
    file_sha256: str
    byte_count: int
    test_source: bool
    content: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class DiscoveryOmission:
    path: str
    language: SourceLanguage
    limitation: ContextLimitation
    test_source: bool


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    sources: tuple[DiscoveredSource, ...]
    omissions: tuple[DiscoveryOmission, ...]
    warnings: tuple[ContextWarning, ...]
    limitation_codes: tuple[ContextLimitation, ...]
    directories_enumerated: int
    candidate_paths: int
    excluded_directories: int
    eligible_source_files: int
    files_read: int
    source_bytes_read: int


@dataclass(slots=True)
class _DiscoveryState:
    limits: ContextLimits
    catalog: ContextRuleCatalog
    deadline: float
    cancel_event: threading.Event
    sources: list[DiscoveredSource] = field(default_factory=list)
    omissions: list[DiscoveryOmission] = field(default_factory=list)
    warning_candidates: list[ContextWarning] = field(default_factory=list)
    limitations: set[ContextLimitation] = field(default_factory=set)
    seen_directory_identities: set[tuple[int, int]] = field(default_factory=set)
    seen_file_identities: set[tuple[int, int]] = field(default_factory=set)
    directories_enumerated: int = 0
    candidate_paths: int = 0
    excluded_directories: int = 0
    eligible_source_files: int = 0
    source_bytes_read: int = 0
    stopped: bool = False


def discover_sources(
    root: Path,
    limits: ContextLimits,
    catalog: ContextRuleCatalog,
    *,
    deadline: float,
    cancel_event: threading.Event,
) -> DiscoveryResult:
    """Discover fixed-allowlist sources beneath an acquired repository root.

    The caller cannot provide paths or search expressions. Returned bytes are an
    internal lease-scoped transport and are deliberately excluded from repr.
    """

    state = _DiscoveryState(
        limits=limits,
        catalog=catalog,
        deadline=deadline,
        cancel_event=cancel_event,
    )
    root_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
    try:
        root_fd = os.open(root, root_flags)
    except OSError:
        _limit(
            state,
            ContextLimitation.UNSAFE_SOURCE_PATH,
            "repository root could not be opened as a no-follow directory",
        )
        return _finish(state)
    try:
        try:
            root_stat = os.fstat(root_fd)
        except OSError:
            _limit(
                state,
                ContextLimitation.SOURCE_TREE_CHANGED,
                "repository root metadata could not be verified",
            )
            return _finish(state)
        if not stat.S_ISDIR(root_stat.st_mode):
            _limit(
                state,
                ContextLimitation.UNSAFE_SOURCE_PATH,
                "repository root was not a real directory",
            )
            return _finish(state)
        state.seen_directory_identities.add((root_stat.st_dev, root_stat.st_ino))
        try:
            _walk_directory(state, root_fd, PurePosixPath(), depth=0)
        except _DeadlineExceeded:
            _limit(
                state,
                ContextLimitation.CONTEXT_DEADLINE_EXCEEDED,
                "context discovery deadline was exceeded",
            )
        except OSError:
            _limit(
                state,
                ContextLimitation.SOURCE_TREE_CHANGED,
                "source tree could not be enumerated consistently",
            )
            state.stopped = True
    finally:
        os.close(root_fd)
    return _finish(state)


def _walk_directory(
    state: _DiscoveryState,
    directory_fd: int,
    prefix: PurePosixPath,
    *,
    depth: int,
) -> None:
    if state.stopped:
        return
    _check(state)
    if state.directories_enumerated >= state.limits.max_directories:
        _limit(
            state,
            ContextLimitation.DIRECTORY_LIMIT_EXCEEDED,
            "context directory limit was exceeded",
            path=_optional_path(prefix),
        )
        state.stopped = True
        return
    state.directories_enumerated += 1
    try:
        before = os.fstat(directory_fd)
    except OSError:
        _directory_changed(state, prefix)
        return
    remaining = state.limits.max_candidate_paths - state.candidate_paths
    names: list[str] = []
    duplicate_fd: int | None = None
    close_failed = False
    try:
        duplicate_fd = os.dup(directory_fd)
        with os.scandir(duplicate_fd) as entries:
            for entry in entries:
                _check(state)
                names.append(entry.name)
                if len(names) > remaining:
                    _limit(
                        state,
                        ContextLimitation.CANDIDATE_PATH_LIMIT_EXCEEDED,
                        "context candidate-path limit was exceeded",
                        path=_optional_path(prefix),
                    )
                    state.stopped = True
                    return
    except OSError:
        _directory_changed(state, prefix)
        return
    finally:
        # scandir owns the duplicated descriptor on supported CPython versions;
        # close defensively only if it remains open.
        if duplicate_fd is not None:
            try:
                os.close(duplicate_fd)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    _directory_changed(state, prefix)
                    close_failed = True
    if close_failed:
        return
    try:
        after = os.fstat(directory_fd)
    except OSError:
        _directory_changed(state, prefix)
        return
    if _metadata_identity(before) != _metadata_identity(after):
        _limit(
            state,
            ContextLimitation.SOURCE_TREE_CHANGED,
            "source directory changed while it was enumerated",
            path=_optional_path(prefix),
        )
        state.stopped = True
        return
    state.candidate_paths += len(names)
    validated: list[str] = []
    case_names: dict[str, str] = {}
    for name in names:
        if not _valid_name(name):
            _limit(
                state,
                ContextLimitation.UNSAFE_SOURCE_PATH,
                "source directory contained an unsafe entry name",
                path=_optional_path(prefix),
            )
            continue
        folded = name.casefold()
        previous = case_names.get(folded)
        if previous is not None and previous != name:
            _limit(
                state,
                ContextLimitation.CASE_COLLIDING_PATH,
                "source directory contained case-colliding paths",
                path=_optional_path(prefix),
            )
            state.stopped = True
            return
        case_names[folded] = name
        validated.append(name)
    for name in sorted(validated, key=lambda value: value.encode("utf-8")):
        if state.stopped:
            return
        _check(state)
        relative = prefix / name
        path = relative.as_posix()
        if len(path.encode("utf-8")) > state.limits.max_path_bytes:
            _limit(
                state,
                ContextLimitation.PATH_LENGTH_LIMIT_EXCEEDED,
                "source path exceeded the configured UTF-8 byte limit",
                path=_optional_path(prefix),
            )
            continue
        child_fd = _open_child(state, directory_fd, name, path)
        if child_fd is None:
            continue
        try:
            try:
                child_stat = os.fstat(child_fd)
            except OSError:
                _limit(
                    state,
                    ContextLimitation.SOURCE_FILE_UNREADABLE,
                    "source entry metadata could not be verified",
                    path=path,
                )
                continue
            identity = (child_stat.st_dev, child_stat.st_ino)
            if stat.S_ISDIR(child_stat.st_mode):
                if name.casefold() in _EXCLUDED_DIRECTORIES:
                    state.excluded_directories += 1
                    _limit(
                        state,
                        ContextLimitation.DIRECTORY_EXCLUDED,
                        "fixed source-tree exclusion was not analyzed",
                        path=path,
                    )
                    continue
                if identity in state.seen_directory_identities:
                    _limit(
                        state,
                        ContextLimitation.DUPLICATE_FILE_IDENTITY,
                        "duplicate directory identity was rejected",
                        path=path,
                    )
                    continue
                if depth >= state.limits.max_directory_depth:
                    _limit(
                        state,
                        ContextLimitation.DIRECTORY_DEPTH_LIMIT_EXCEEDED,
                        "context directory depth limit was exceeded",
                        path=path,
                    )
                    continue
                state.seen_directory_identities.add(identity)
                _walk_directory(state, child_fd, relative, depth=depth + 1)
                continue
            language = _eligible_language(path, state.catalog)
            if language is None:
                continue
            state.eligible_source_files += 1
            if state.eligible_source_files > state.limits.max_source_files:
                _omit(
                    state,
                    path,
                    language,
                    ContextLimitation.SOURCE_FILE_LIMIT_EXCEEDED,
                )
                state.stopped = True
                continue
            if not stat.S_ISREG(child_stat.st_mode):
                _omit(state, path, language, ContextLimitation.SOURCE_NOT_REGULAR)
                continue
            if identity in state.seen_file_identities:
                _omit(state, path, language, ContextLimitation.DUPLICATE_FILE_IDENTITY)
                continue
            state.seen_file_identities.add(identity)
            _read_source(state, child_fd, path, language, child_stat)
        finally:
            os.close(child_fd)


def _open_child(
    state: _DiscoveryState,
    directory_fd: int,
    name: str,
    path: str,
) -> int | None:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        return os.open(name, flags, dir_fd=directory_fd)
    except OSError:
        code = ContextLimitation.SOURCE_FILE_UNREADABLE
        try:
            child_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(child_stat.st_mode):
                code = ContextLimitation.SOURCE_SYMLINK_REJECTED
        except OSError:
            pass
        _limit(state, code, "source entry could not be opened safely", path=path)
        return None


def _read_source(
    state: _DiscoveryState,
    file_fd: int,
    path: str,
    language: SourceLanguage,
    before: os.stat_result,
) -> None:
    if path.endswith((".min.js", ".min.mjs", ".min.cjs")):
        _omit(state, path, language, ContextLimitation.GENERATED_FILE_OMITTED)
        return
    if before.st_size > state.limits.max_bytes_per_source_file:
        _omit(state, path, language, ContextLimitation.SOURCE_FILE_BYTES_LIMIT_EXCEEDED)
        return
    if state.source_bytes_read + before.st_size > state.limits.max_total_source_bytes:
        _omit(state, path, language, ContextLimitation.SOURCE_TOTAL_BYTES_LIMIT_EXCEEDED)
        state.stopped = True
        return
    chunks: list[bytes] = []
    byte_count = 0
    while True:
        _check(state)
        try:
            chunk = os.read(file_fd, _READ_CHUNK_BYTES)
        except OSError:
            _omit(state, path, language, ContextLimitation.SOURCE_FILE_UNREADABLE)
            return
        if not chunk:
            break
        byte_count += len(chunk)
        if byte_count > state.limits.max_bytes_per_source_file:
            _omit(state, path, language, ContextLimitation.SOURCE_FILE_BYTES_LIMIT_EXCEEDED)
            return
        if state.source_bytes_read + byte_count > state.limits.max_total_source_bytes:
            _omit(state, path, language, ContextLimitation.SOURCE_TOTAL_BYTES_LIMIT_EXCEEDED)
            state.stopped = True
            return
        chunks.append(chunk)
    try:
        after = os.fstat(file_fd)
    except OSError:
        _omit(state, path, language, ContextLimitation.SOURCE_FILE_CHANGED)
        return
    if _metadata_identity(before) != _metadata_identity(after) or byte_count != after.st_size:
        _omit(state, path, language, ContextLimitation.SOURCE_FILE_CHANGED)
        return
    content = b"".join(chunks)
    digest = hashlib.sha256(content).hexdigest()
    state.sources.append(
        DiscoveredSource(
            path=path,
            language=language,
            file_sha256=digest,
            byte_count=byte_count,
            test_source=_is_test_source(path),
            content=content,
        )
    )
    state.source_bytes_read += byte_count


def _eligible_language(path: str, catalog: ContextRuleCatalog) -> SourceLanguage | None:
    suffix = PurePosixPath(path).suffix.lower()
    language = _SOURCE_EXTENSIONS.get(suffix)
    if language is not None:
        return language
    config_language = _CONFIG_EXTENSIONS.get(suffix)
    if config_language is None:
        return None
    eligible_paths = {
        configured_path
        for rule in catalog.configuration_rules
        for configured_path in rule.normalized_paths
    }
    return config_language if path in eligible_paths else None


def _omit(
    state: _DiscoveryState,
    path: str,
    language: SourceLanguage,
    code: ContextLimitation,
) -> None:
    state.omissions.append(
        DiscoveryOmission(
            path=path,
            language=language,
            limitation=code,
            test_source=_is_test_source(path),
        )
    )
    _limit(state, code, _message_for(code), path=path)


def _limit(
    state: _DiscoveryState,
    code: ContextLimitation,
    message: str,
    *,
    path: str | None = None,
) -> None:
    state.limitations.add(code)
    state.warning_candidates.append(ContextWarning(code=code, message=message, path=path))


def _directory_changed(state: _DiscoveryState, path: PurePosixPath) -> None:
    _limit(
        state,
        ContextLimitation.SOURCE_TREE_CHANGED,
        "source directory metadata or entries could not be verified consistently",
        path=_optional_path(path),
    )
    state.stopped = True


def _finish(state: _DiscoveryState) -> DiscoveryResult:
    sources = tuple(sorted(state.sources, key=lambda item: item.path.encode("utf-8")))
    omissions = tuple(sorted(state.omissions, key=lambda item: item.path.encode("utf-8")))
    warnings = _bounded_warnings(state)
    limitations = set(state.limitations)
    if any(warning.code == ContextLimitation.WARNING_LIMIT_EXCEEDED for warning in warnings):
        limitations.add(ContextLimitation.WARNING_LIMIT_EXCEEDED)
    return DiscoveryResult(
        sources=sources,
        omissions=omissions,
        warnings=warnings,
        limitation_codes=tuple(sorted(limitations)),
        directories_enumerated=state.directories_enumerated,
        candidate_paths=state.candidate_paths,
        excluded_directories=state.excluded_directories,
        eligible_source_files=state.eligible_source_files,
        files_read=len(sources),
        source_bytes_read=state.source_bytes_read,
    )


def _bounded_warnings(state: _DiscoveryState) -> tuple[ContextWarning, ...]:
    ordered = tuple(
        sorted(
            state.warning_candidates,
            key=lambda item: (item.code.value, item.path or "", item.message),
        )
    )
    maximum = state.limits.max_warnings
    if len(ordered) <= maximum:
        return ordered
    summary = ContextWarning(
        code=ContextLimitation.WARNING_LIMIT_EXCEEDED,
        message="additional context warnings were omitted after the configured limit",
    )
    if maximum == 1:
        return (summary,)
    return tuple(
        sorted(
            (*ordered[: maximum - 1], summary),
            key=lambda item: (
                item.code.value,
                item.path or "",
                item.message,
            ),
        )
    )


def _check(state: _DiscoveryState) -> None:
    if state.cancel_event.is_set():
        raise ContextCancelled
    if time.monotonic() >= state.deadline:
        raise _DeadlineExceeded


def _metadata_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _valid_name(name: str) -> bool:
    return (
        bool(name)
        and name not in {".", ".."}
        and "/" not in name
        and "\\" not in name
        and not any(
            ord(character) < 32 or ord(character) == 127 or 0xD800 <= ord(character) <= 0xDFFF
            for character in name
        )
    )


def _optional_path(path: PurePosixPath) -> str | None:
    value = path.as_posix()
    return None if value == "." else value


def _is_test_source(path: str) -> bool:
    parts = PurePosixPath(path).parts
    name = parts[-1].lower()
    return bool(
        any(part.lower() in {"test", "tests", "__tests__"} for part in parts[:-1])
        or name.startswith("test_")
        or name.endswith("_test.go")
        or ".test." in name
        or ".spec." in name
    )


def _message_for(code: ContextLimitation) -> str:
    messages = {
        ContextLimitation.SOURCE_FILE_LIMIT_EXCEEDED: "context source-file limit was exceeded",
        ContextLimitation.SOURCE_FILE_BYTES_LIMIT_EXCEEDED: (
            "source file exceeded the per-file byte limit"
        ),
        ContextLimitation.SOURCE_TOTAL_BYTES_LIMIT_EXCEEDED: (
            "context total source-byte limit was exceeded"
        ),
        ContextLimitation.SOURCE_NOT_REGULAR: "eligible source path was not a regular file",
        ContextLimitation.DUPLICATE_FILE_IDENTITY: "duplicate source-file identity was rejected",
        ContextLimitation.SOURCE_FILE_CHANGED: "source file changed while it was read",
        ContextLimitation.SOURCE_FILE_UNREADABLE: "source file could not be read safely",
        ContextLimitation.GENERATED_FILE_OMITTED: (
            "generated or minified source file was not analyzed"
        ),
    }
    return messages[code]
