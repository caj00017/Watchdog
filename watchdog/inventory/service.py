from __future__ import annotations

import asyncio
import fnmatch
import os
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from watchdog.domain.inventory import (
    CoverageKind,
    CoverageState,
    DependencyInventory,
    InventorySnapshot,
    ParserMetadata,
    ScannedFileStatus,
)
from watchdog.domain.repositories import AcquiredRepository
from watchdog.inventory.common import (
    InventoryBuilder,
    InventoryCancelled,
    InventoryStopped,
    repository_path,
)
from watchdog.inventory.go import parse_go_mod
from watchdog.inventory.limits import InventoryLimits
from watchdog.inventory.npm import parse_package_json, parse_package_lock
from watchdog.inventory.python import parse_pyproject, parse_requirements_tree, parse_uv_lock

_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".bzr",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".nox",
        "node_modules",
        "vendor",
        "vendors",
        "third_party",
    }
)
_UNSUPPORTED_MANIFESTS = {
    "npm-shrinkwrap.json": "npm-shrinkwrap",
    "yarn.lock": "yarn-lock",
    "pnpm-lock.yaml": "pnpm-lock",
    "go.work": "go-work",
}


@dataclass(frozen=True, slots=True)
class _Candidate:
    path: Path
    relative: str
    kind: str
    supported: bool


def _manifest_kind(name: str) -> tuple[str, bool] | None:
    if name == "pyproject.toml":
        return "pyproject", True
    if name == "uv.lock":
        return "uv-lock", True
    if fnmatch.fnmatchcase(name, "requirements*.txt"):
        return "requirements", True
    if name == "package.json":
        return "package-json", True
    if name == "package-lock.json":
        return "package-lock", True
    if name == "go.mod":
        return "go-mod", True
    if name == "go.sum":
        return "go-sum", True
    unsupported = _UNSUPPORTED_MANIFESTS.get(name)
    if unsupported is not None:
        return unsupported, False
    return None


class DependencyInventoryService:
    """Build a deterministic data-only dependency inventory inside an active lease."""

    def __init__(self, limits: InventoryLimits) -> None:
        self._limits = limits

    async def build(self, repository: AcquiredRepository) -> DependencyInventory:
        cancel_event = threading.Event()
        task = asyncio.create_task(asyncio.to_thread(self._build_sync, repository, cancel_event))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            cancel_event.set()
            with suppress(Exception):
                await task
            raise

    def _build_sync(
        self,
        repository: AcquiredRepository,
        cancel_event: threading.Event,
    ) -> DependencyInventory:
        started = datetime.now(UTC)
        deadline = time.monotonic() + self._limits.deadline_seconds
        root = repository.root
        if not root.is_dir() or root.is_symlink():
            raise ValueError("acquired repository root must be a real directory")
        builder = InventoryBuilder(
            root=root,
            commit_sha=repository.snapshot.commit_sha,
            limits=self._limits,
            deadline=deadline,
            cancel_event=cancel_event,
        )
        parser_names: set[str] = set()
        try:
            candidates = self._discover(builder)
            self._warn_competing_locks(builder, candidates)
            for candidate in candidates:
                builder.check_active()
                if not candidate.supported:
                    builder.unsupported_manifests += 1
                    try:
                        byte_count = candidate.path.lstat().st_size
                    except OSError:
                        byte_count = 0
                    builder.add_scanned_file(
                        path=candidate.relative,
                        digest=None,
                        byte_count=byte_count,
                        kind=candidate.kind,
                        status=ScannedFileStatus.UNSUPPORTED,
                        parser=None,
                    )
                    builder.warning(
                        f"{candidate.kind.replace('-', '_')}_unsupported",
                        "A recognized but unsupported dependency structure limited coverage.",
                        path=candidate.relative,
                    )
                    continue
                builder.supported_found += 1
                self._parse_candidate(builder, candidate, parser_names)
        except InventoryCancelled:
            raise
        except InventoryStopped:
            pass

        if builder.warning_limit_reached:
            # The boolean remains visible even when the warning collection itself is full.
            builder.partial = True
        coverage = self._coverage(builder)
        completed = datetime.now(UTC)
        return DependencyInventory(
            snapshot=InventorySnapshot(
                repository_url=repository.snapshot.repository.canonical_url,
                commit_sha=repository.snapshot.commit_sha,
                tree_sha=repository.snapshot.tree_sha,
                archive_sha256=repository.snapshot.archive_sha256,
            ),
            generated_at=started,
            completed_at=completed,
            projects=tuple(sorted(builder.projects.values(), key=lambda item: item.id)),
            components=tuple(sorted(builder.components.values(), key=lambda item: item.id)),
            edges=tuple(sorted(builder.edges.values(), key=lambda item: item.id)),
            scanned_files=tuple(sorted(builder.scanned_files.values(), key=lambda item: item.path)),
            warnings=tuple(builder.warnings),
            coverage=coverage,
            parser_metadata=tuple(
                ParserMetadata(name=name, version="1") for name in sorted(parser_names)
            ),
            partial=builder.partial,
        )

    def _discover(self, builder: InventoryBuilder) -> list[_Candidate]:
        candidates: list[_Candidate] = []
        for current, directory_names, file_names in os.walk(
            builder.root, topdown=True, followlinks=False
        ):
            builder.check_active()
            current_path = Path(current)
            retained: list[str] = []
            for directory_name in sorted(directory_names):
                directory = current_path / directory_name
                try:
                    is_link = directory.is_symlink()
                except OSError:
                    is_link = True
                if directory_name in _EXCLUDED_DIRECTORIES:
                    builder.warning(
                        "excluded_dependency_tree",
                        "A recognized generated, VCS, virtual-environment, or vendored tree "
                        "was excluded.",
                        path=repository_path(builder.root, directory),
                    )
                    continue
                if is_link:
                    builder.warning(
                        "symlinked_directory_skipped",
                        "A symlinked directory was not followed during manifest discovery.",
                        path=repository_path(builder.root, directory),
                    )
                    continue
                retained.append(directory_name)
            directory_names[:] = retained
            for file_name in sorted(file_names):
                recognized = _manifest_kind(file_name)
                if recognized is None:
                    continue
                path = current_path / file_name
                relative = repository_path(builder.root, path)
                if path.is_symlink():
                    builder.warning(
                        "symlinked_manifest_skipped",
                        "A recognized manifest symlink was not followed.",
                        path=relative,
                    )
                    continue
                if len(candidates) >= builder.limits.max_manifest_files:
                    builder.warning(
                        "manifest_file_count_limit_exceeded",
                        "The recognized-manifest count limit stopped discovery.",
                        path=relative,
                    )
                    return candidates
                kind, supported = recognized
                candidates.append(
                    _Candidate(path=path, relative=relative, kind=kind, supported=supported)
                )
        return sorted(candidates, key=lambda item: item.relative)

    def _warn_competing_locks(
        self,
        builder: InventoryBuilder,
        candidates: list[_Candidate],
    ) -> None:
        by_directory: dict[str, set[str]] = {}
        for candidate in candidates:
            parent = candidate.relative.rpartition("/")[0] or "."
            if candidate.kind in {"package-lock", "npm-shrinkwrap", "yarn-lock", "pnpm-lock"}:
                by_directory.setdefault(parent, set()).add(candidate.kind)
        for parent, kinds in sorted(by_directory.items()):
            if len(kinds) > 1:
                builder.warning(
                    "npm_competing_lockfiles",
                    "Multiple npm/Yarn/pnpm lockfiles in one project make lock authority "
                    "ambiguous.",
                    path=parent,
                )

    def _parse_candidate(
        self,
        builder: InventoryBuilder,
        candidate: _Candidate,
        parser_names: set[str],
    ) -> None:
        if candidate.kind == "requirements":
            parser_names.add("python-requirements")
            before = len(builder.components)
            try:
                parse_requirements_tree(builder, candidate.path)
            except InventoryStopped:
                raise
            except Exception as exc:
                self._malformed(builder, candidate, None, exc)
                return
            scanned = builder.scanned_files.get(candidate.relative)
            if scanned is not None and scanned.status != ScannedFileStatus.MALFORMED:
                builder.valid_manifests += 1
                if len(builder.components) == before:
                    builder.empty_valid_manifests += 1
            return
        read = builder.read_file(candidate.path, candidate.relative)
        if read is None:
            try:
                byte_count = candidate.path.lstat().st_size
            except OSError:
                byte_count = 0
            builder.add_scanned_file(
                path=candidate.relative,
                digest=None,
                byte_count=byte_count,
                kind=candidate.kind,
                status=ScannedFileStatus.SKIPPED,
                parser=None,
            )
            return
        data, digest = read
        parser_name = {
            "pyproject": "python-pyproject",
            "uv-lock": "python-uv-lock",
            "package-json": "npm-package-json",
            "package-lock": "npm-package-lock",
            "go-mod": "go-mod",
            "go-sum": "go-sum-integrity",
        }[candidate.kind]
        parser_names.add(parser_name)
        try:
            if candidate.kind == "pyproject":
                added = parse_pyproject(builder, candidate.path, candidate.relative, data, digest)
            elif candidate.kind == "uv-lock":
                added = parse_uv_lock(builder, candidate.relative, data, digest)
            elif candidate.kind == "package-json":
                added = parse_package_json(builder, candidate.relative, data, digest)
            elif candidate.kind == "package-lock":
                added = parse_package_lock(builder, candidate.relative, data, digest)
            elif candidate.kind == "go-mod":
                added = parse_go_mod(builder, candidate.relative, data, digest)
            else:
                data.decode("utf-8")
                added = 0
        except InventoryStopped:
            raise
        except Exception as exc:
            self._malformed(builder, candidate, (digest, len(data)), exc)
            return
        status = (
            ScannedFileStatus.UNSUPPORTED
            if added < 0
            else (ScannedFileStatus.VALID if added else ScannedFileStatus.EMPTY)
        )
        builder.add_scanned_file(
            path=candidate.relative,
            digest=digest,
            byte_count=len(data),
            kind=candidate.kind,
            status=status,
            parser=parser_name,
        )
        if added < 0:
            builder.unsupported_manifests += 1
        else:
            builder.valid_manifests += 1
            if added == 0:
                builder.empty_valid_manifests += 1

    def _malformed(
        self,
        builder: InventoryBuilder,
        candidate: _Candidate,
        file_info: tuple[str, int] | None,
        error: Exception,
    ) -> None:
        builder.malformed_manifests += 1
        builder.warning(
            "manifest_malformed",
            f"The {candidate.kind} file was malformed and skipped ({type(error).__name__}).",
            path=candidate.relative,
        )
        builder.add_scanned_file(
            path=candidate.relative,
            digest=file_info[0] if file_info else None,
            byte_count=file_info[1] if file_info else 0,
            kind=candidate.kind,
            status=ScannedFileStatus.MALFORMED,
            parser=None,
        )

    def _coverage(self, builder: InventoryBuilder) -> CoverageState:
        if builder.supported_found == 0:
            if builder.unsupported_manifests:
                kind = CoverageKind.UNSUPPORTED_MANIFESTS_ONLY
                builder.warning(
                    "unsupported_manifests_only",
                    "Only recognized unsupported dependency structures were discovered.",
                )
            else:
                kind = CoverageKind.NO_SUPPORTED_MANIFEST
                builder.warning(
                    "no_supported_manifest",
                    "No supported Phase 3 dependency manifest was discovered.",
                )
        elif builder.valid_manifests == 0 and builder.malformed_manifests:
            kind = CoverageKind.ALL_SUPPORTED_MANIFESTS_MALFORMED
            builder.partial = True
        elif builder.partial:
            kind = CoverageKind.PARTIAL
        elif builder.empty_valid_manifests == builder.valid_manifests:
            kind = CoverageKind.EMPTY_SUPPORTED_MANIFEST
        else:
            kind = CoverageKind.COMPLETE
        limitations = tuple(
            dict.fromkeys(warning.code for warning in builder.warnings if warning.coverage_limited)
        )
        return CoverageState(
            kind=kind,
            supported_manifests_found=builder.supported_found,
            valid_manifests=builder.valid_manifests,
            empty_valid_manifests=builder.empty_valid_manifests,
            malformed_manifests=builder.malformed_manifests,
            unsupported_manifests=builder.unsupported_manifests,
            limitations=limitations,
        )
