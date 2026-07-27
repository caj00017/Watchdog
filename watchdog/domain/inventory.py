from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

NonEmptyString = Annotated[str, StringConstraints(min_length=1)]
DigestSha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class Ecosystem(StrEnum):
    PYPI = "PyPI"
    NPM = "npm"
    GO = "Go"


class DependencyRelationship(StrEnum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    UNKNOWN = "unknown"


class DependencyScope(StrEnum):
    RUNTIME = "runtime"
    DEVELOPMENT = "development"
    OPTIONAL = "optional"
    PEER = "peer"
    BUILD = "build"
    TOOL = "tool"
    UNKNOWN = "unknown"


class VersionKind(StrEnum):
    EXACT = "exact"
    CONSTRAINT = "constraint"
    UNKNOWN = "unknown"


class ApplicabilityKind(StrEnum):
    UNCONDITIONAL = "unconditional"
    CONDITIONAL = "conditional"
    UNKNOWN = "unknown"


class SelectorKind(StrEnum):
    JSON_POINTER = "json_pointer"
    TOML = "toml"
    LINE = "line"


class ScannedFileStatus(StrEnum):
    VALID = "valid"
    EMPTY = "empty"
    MALFORMED = "malformed"
    UNSUPPORTED = "unsupported"
    SKIPPED = "skipped"


class CoverageKind(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    EMPTY_SUPPORTED_MANIFEST = "empty_supported_manifest"
    NO_SUPPORTED_MANIFEST = "no_supported_manifest"
    ALL_SUPPORTED_MANIFESTS_MALFORMED = "all_supported_manifests_malformed"
    UNSUPPORTED_MANIFESTS_ONLY = "unsupported_manifests_only"


class InventoryModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Applicability(InventoryModel):
    kind: ApplicabilityKind = ApplicabilityKind.UNCONDITIONAL
    marker: str | None = None
    os: tuple[str, ...] = ()
    cpu: tuple[str, ...] = ()
    expressions: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_condition(self) -> Self:
        has_expression = bool(self.marker or self.os or self.cpu or self.expressions)
        if self.kind == ApplicabilityKind.UNCONDITIONAL and has_expression:
            raise ValueError("unconditional applicability cannot contain expressions")
        if self.kind == ApplicabilityKind.CONDITIONAL and not has_expression:
            raise ValueError("conditional applicability requires a preserved expression")
        return self


class SourceSelector(InventoryModel):
    kind: SelectorKind
    value: str

    @model_validator(mode="after")
    def validate_value(self) -> Self:
        if not self.value and self.kind != SelectorKind.JSON_POINTER:
            raise ValueError("only the JSON Pointer document-root selector may be empty")
        return self


class SourceReference(InventoryModel):
    path: NonEmptyString
    selector: SourceSelector
    file_sha256: DigestSha256

    @model_validator(mode="after")
    def validate_repository_path(self) -> Self:
        if self.path.startswith("/") or "\\" in self.path:
            raise ValueError("source path must be repository-relative POSIX")
        parts = self.path.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise ValueError("source path must be a normalized repository-relative POSIX path")
        return self


class InventoryProject(InventoryModel):
    id: NonEmptyString
    root: str
    ecosystem: Ecosystem
    name: str | None = None
    version: str | None = None
    source_references: tuple[SourceReference, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_root(self) -> Self:
        if self.root == ".":
            return self
        if self.root.startswith("/") or "\\" in self.root:
            raise ValueError("project root must be repository-relative POSIX")
        if any(part in {"", ".", ".."} for part in self.root.split("/")):
            raise ValueError("project root must be normalized")
        return self


class DependencyComponent(InventoryModel):
    id: NonEmptyString
    project_id: NonEmptyString
    ecosystem: Ecosystem
    name: NonEmptyString
    normalized_name: NonEmptyString
    version: str | None = None
    version_kind: VersionKind
    relationship: DependencyRelationship
    scopes: tuple[DependencyScope, ...] = Field(min_length=1)
    applicability: Applicability = Applicability()
    source_references: tuple[SourceReference, ...] = Field(min_length=1)
    scanner_eligible: bool = False
    resolved_name: str | None = None
    source_type: str | None = None

    @model_validator(mode="after")
    def validate_scanner_eligibility(self) -> Self:
        if self.scanner_eligible and (self.version_kind != VersionKind.EXACT or not self.version):
            raise ValueError("scanner-eligible components require an exact non-empty version")
        return self


class DependencyEdge(InventoryModel):
    id: NonEmptyString
    project_id: NonEmptyString
    from_component_id: str | None = None
    to_component_id: NonEmptyString
    relationship: DependencyRelationship
    scopes: tuple[DependencyScope, ...] = Field(min_length=1)
    applicability: Applicability = Applicability()
    source_references: tuple[SourceReference, ...] = Field(min_length=1)


class ScannedFile(InventoryModel):
    path: NonEmptyString
    file_sha256: DigestSha256 | None = None
    byte_count: int = Field(ge=0)
    kind: NonEmptyString
    status: ScannedFileStatus
    parser: str | None = None
    parser_version: str | None = None


class InventoryWarning(InventoryModel):
    code: NonEmptyString
    message: NonEmptyString
    path: str | None = None
    selector: SourceSelector | None = None
    coverage_limited: bool = True


class CoverageState(InventoryModel):
    kind: CoverageKind
    supported_manifests_found: int = Field(ge=0)
    valid_manifests: int = Field(ge=0)
    empty_valid_manifests: int = Field(ge=0)
    malformed_manifests: int = Field(ge=0)
    unsupported_manifests: int = Field(ge=0)
    limitations: tuple[str, ...] = ()


class ParserMetadata(InventoryModel):
    name: NonEmptyString
    version: NonEmptyString


class InventorySnapshot(InventoryModel):
    repository_url: NonEmptyString
    commit_sha: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    tree_sha: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    archive_sha256: DigestSha256


class DependencyInventory(InventoryModel):
    snapshot: InventorySnapshot
    generated_at: datetime
    completed_at: datetime
    projects: tuple[InventoryProject, ...] = ()
    components: tuple[DependencyComponent, ...] = ()
    edges: tuple[DependencyEdge, ...] = ()
    scanned_files: tuple[ScannedFile, ...] = ()
    warnings: tuple[InventoryWarning, ...] = ()
    coverage: CoverageState
    parser_metadata: tuple[ParserMetadata, ...] = ()
    partial: bool = False
