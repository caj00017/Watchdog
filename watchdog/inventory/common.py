from __future__ import annotations

import hashlib
import os
import stat
import threading
import time
from pathlib import Path, PurePosixPath

from watchdog.domain.inventory import (
    Applicability,
    DependencyComponent,
    DependencyEdge,
    DependencyRelationship,
    DependencyScope,
    Ecosystem,
    InventoryProject,
    InventoryWarning,
    ScannedFile,
    ScannedFileStatus,
    SelectorKind,
    SourceReference,
    SourceSelector,
    VersionKind,
)
from watchdog.inventory.identifiers import component_id, edge_id, project_id
from watchdog.inventory.limits import InventoryLimits

PARSER_VERSION = "1"


class InventoryStopped(Exception):
    pass


class InventoryDeadlineExceeded(InventoryStopped):
    pass


class InventoryCancelled(InventoryStopped):
    pass


class InventoryLimitReached(InventoryStopped):
    pass


class ParseFailure(ValueError):
    pass


def repository_path(root: Path, path: Path) -> str:
    relative = path.relative_to(root)
    value = PurePosixPath(*relative.parts).as_posix()
    if value in {"", "."} or value.startswith("/"):
        raise ValueError("manifest path was not repository-relative")
    return value


def project_root_for(path: str) -> str:
    parent = PurePosixPath(path).parent.as_posix()
    return "." if parent == "." else parent


def validate_nesting(value: object, maximum: int) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    seen: set[int] = set()
    while stack:
        current, depth = stack.pop()
        if depth > maximum:
            raise ParseFailure(f"structured data exceeded nesting depth {maximum}")
        if isinstance(current, dict):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            stack.extend((item, depth + 1) for item in current)


class InventoryBuilder:
    def __init__(
        self,
        *,
        root: Path,
        commit_sha: str,
        limits: InventoryLimits,
        deadline: float,
        cancel_event: threading.Event,
    ) -> None:
        self.root = root
        self.commit_sha = commit_sha
        self.limits = limits
        self.deadline = deadline
        self.cancel_event = cancel_event
        self.projects: dict[str, InventoryProject] = {}
        self.components: dict[str, DependencyComponent] = {}
        self.edges: dict[str, DependencyEdge] = {}
        self.scanned_files: dict[str, ScannedFile] = {}
        self.warnings: list[InventoryWarning] = []
        self.total_parsed_bytes = 0
        self.supported_found = 0
        self.valid_manifests = 0
        self.empty_valid_manifests = 0
        self.malformed_manifests = 0
        self.unsupported_manifests = 0
        self.partial = False
        self.warning_limit_reached = False
        self._read_cache: dict[Path, tuple[bytes, str]] = {}
        self._read_attempts: set[Path] = set()

    def check_active(self) -> None:
        if self.cancel_event.is_set():
            raise InventoryCancelled
        if time.monotonic() >= self.deadline:
            self.partial = True
            self.warning(
                "inventory_deadline_exceeded",
                "The Phase 3 inventory deadline expired before coverage completed.",
            )
            raise InventoryDeadlineExceeded

    def warning(
        self,
        code: str,
        message: str,
        *,
        path: str | None = None,
        selector: SourceSelector | None = None,
        coverage_limited: bool = True,
    ) -> None:
        if coverage_limited:
            self.partial = True
        candidate = InventoryWarning(
            code=code,
            message=message,
            path=path,
            selector=selector,
            coverage_limited=coverage_limited,
        )
        if candidate in self.warnings:
            return
        if len(self.warnings) < self.limits.max_warnings:
            self.warnings.append(candidate)
            return
        if not self.warning_limit_reached:
            self.warnings[-1] = InventoryWarning(
                code="warning_limit_exceeded",
                message=(
                    "The structured-warning limit was reached; additional warnings were omitted."
                ),
                coverage_limited=True,
            )
        self.warning_limit_reached = True
        self.partial = True

    def read_file(self, path: Path, relative: str) -> tuple[bytes, str] | None:
        self.check_active()
        cached = self._read_cache.get(path)
        if cached is not None:
            return cached
        if path not in self._read_attempts:
            if len(self._read_attempts) >= self.limits.max_manifest_files:
                self.warning(
                    "manifest_file_count_limit_exceeded",
                    "The parsed-manifest count limit stopped further inventory work.",
                    path=relative,
                )
                raise InventoryLimitReached
            self._read_attempts.add(path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError:
            self.warning(
                "manifest_unreadable",
                "The manifest could not be opened without following links.",
                path=relative,
            )
            return None
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                self.warning(
                    "manifest_not_regular_file",
                    "The recognized manifest is not a regular file and was skipped.",
                    path=relative,
                )
                return None
            if metadata.st_size > self.limits.max_bytes_per_manifest:
                self.warning(
                    "manifest_file_limit_exceeded",
                    "The recognized manifest exceeded the per-file byte limit and was skipped.",
                    path=relative,
                )
                return None
            if self.total_parsed_bytes + metadata.st_size > self.limits.max_total_parsed_bytes:
                self.warning(
                    "manifest_total_bytes_limit_exceeded",
                    "The total parsed-manifest byte limit stopped further inventory work.",
                    path=relative,
                )
                raise InventoryLimitReached
            chunks: list[bytes] = []
            remaining = metadata.st_size
            while remaining:
                self.check_active()
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) != metadata.st_size:
                self.warning(
                    "manifest_changed_during_read",
                    "The manifest changed while it was read and was skipped.",
                    path=relative,
                )
                return None
            self.total_parsed_bytes += len(data)
            result = data, hashlib.sha256(data).hexdigest()
            self._read_cache[path] = result
            return result
        finally:
            os.close(descriptor)

    def source(
        self,
        path: str,
        digest: str,
        selector_kind: SelectorKind,
        selector: str,
    ) -> SourceReference:
        return SourceReference(
            path=path,
            selector=SourceSelector(kind=selector_kind, value=selector),
            file_sha256=digest,
        )

    def add_scanned_file(
        self,
        *,
        path: str,
        digest: str | None,
        byte_count: int,
        kind: str,
        status: ScannedFileStatus,
        parser: str | None,
    ) -> None:
        candidate = ScannedFile(
            path=path,
            file_sha256=digest,
            byte_count=byte_count,
            kind=kind,
            status=status,
            parser=parser,
            parser_version=PARSER_VERSION if parser else None,
        )
        previous = self.scanned_files.get(path)
        if previous is None or previous.status != ScannedFileStatus.VALID:
            self.scanned_files[path] = candidate

    def add_project(
        self,
        *,
        root: str,
        ecosystem: Ecosystem,
        source: SourceReference,
        name: str | None = None,
        version: str | None = None,
    ) -> InventoryProject:
        identifier = project_id(commit_sha=self.commit_sha, root=root, ecosystem=ecosystem)
        existing = self.projects.get(identifier)
        if existing is not None:
            references = tuple(dict.fromkeys((*existing.source_references, source)))
            updated = existing.model_copy(
                update={
                    "source_references": references,
                    "name": existing.name or name,
                    "version": existing.version or version,
                }
            )
            self.projects[identifier] = updated
            return updated
        project = InventoryProject(
            id=identifier,
            root=root,
            ecosystem=ecosystem,
            name=name,
            version=version,
            source_references=(source,),
        )
        self.projects[identifier] = project
        return project

    def add_component(
        self,
        *,
        project: InventoryProject,
        name: str,
        normalized_name: str,
        version: str | None,
        version_kind: VersionKind,
        relationship: DependencyRelationship,
        scopes: tuple[DependencyScope, ...],
        applicability: Applicability,
        source: SourceReference,
        scanner_eligible: bool,
        resolved_name: str | None = None,
        source_type: str | None = None,
    ) -> DependencyComponent:
        self.check_active()
        identifier = component_id(
            commit_sha=self.commit_sha,
            project_root=project.root,
            ecosystem=project.ecosystem,
            normalized_name=normalized_name,
            version=version,
            applicability=applicability,
            source=source,
        )
        existing = self.components.get(identifier)
        if existing is not None:
            return existing
        if len(self.components) >= self.limits.max_components:
            self.warning(
                "component_limit_exceeded",
                "The component limit stopped further inventory work.",
                path=source.path,
                selector=source.selector,
            )
            raise InventoryLimitReached
        component = DependencyComponent(
            id=identifier,
            project_id=project.id,
            ecosystem=project.ecosystem,
            name=name,
            normalized_name=normalized_name,
            version=version,
            version_kind=version_kind,
            relationship=relationship,
            scopes=scopes,
            applicability=applicability,
            source_references=(source,),
            scanner_eligible=scanner_eligible,
            resolved_name=resolved_name,
            source_type=source_type,
        )
        self.components[identifier] = component
        return component

    def add_edge(
        self,
        *,
        project: InventoryProject,
        parent: DependencyComponent | None,
        child: DependencyComponent,
        relationship: DependencyRelationship,
        scopes: tuple[DependencyScope, ...],
        applicability: Applicability,
        source: SourceReference,
    ) -> DependencyEdge:
        self.check_active()
        identifier = edge_id(
            commit_sha=self.commit_sha,
            project_root=project.root,
            ecosystem=project.ecosystem,
            from_component_id=parent.id if parent else None,
            to_component_id=child.id,
            relationship=relationship.value,
            applicability=applicability,
            source=source,
        )
        existing = self.edges.get(identifier)
        if existing is not None:
            return existing
        if len(self.edges) >= self.limits.max_edges:
            self.warning(
                "edge_limit_exceeded",
                "The dependency-edge limit stopped further inventory work.",
                path=source.path,
                selector=source.selector,
            )
            raise InventoryLimitReached
        edge = DependencyEdge(
            id=identifier,
            project_id=project.id,
            from_component_id=parent.id if parent else None,
            to_component_id=child.id,
            relationship=relationship,
            scopes=scopes,
            applicability=applicability,
            source_references=(source,),
        )
        self.edges[identifier] = edge
        return edge
