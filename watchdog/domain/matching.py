from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints

from watchdog.domain.advisories import FieldProvenance
from watchdog.domain.inventory import (
    Applicability,
    DependencyRelationship,
    DependencyScope,
    Ecosystem,
    InventorySnapshot,
    SourceReference,
)

NonEmptyString = Annotated[str, StringConstraints(min_length=1)]
DigestSha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class MatchState(StrEnum):
    AFFECTED = "affected"
    AFFECTED_CONDITIONAL = "affected_conditional"
    NOT_REPORTED_AFFECTED = "not_reported_affected"
    VERSION_UNKNOWN = "version_unknown"
    SCANNER_INCOMPLETE = "scanner_incomplete"
    UNSUPPORTED_ADVISORY_COMPONENT = "unsupported_advisory_component"


class ScannerRunStatus(StrEnum):
    SUCCESS = "success"
    INCOMPLETE = "incomplete"


class MatchingModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExactPackageCoordinate(MatchingModel):
    ecosystem: Ecosystem
    name: NonEmptyString
    version: NonEmptyString


class ScannerVulnerability(MatchingModel):
    id: NonEmptyString
    aliases: tuple[str, ...] = ()


class ScannerPackageResult(MatchingModel):
    coordinate: ExactPackageCoordinate
    vulnerabilities: tuple[ScannerVulnerability, ...] = ()


class ScannerRunEvidence(MatchingModel):
    tool: NonEmptyString
    tool_version: str | None = None
    arguments: tuple[str, ...]
    started_at: datetime
    completed_at: datetime
    exit_code: int | None = None
    input_sha256: DigestSha256 | None = None
    output_sha256: DigestSha256 | None = None
    validated_output: dict[str, JsonValue] | None = None
    diagnostics: str | None = None


class ScannerRunResult(MatchingModel):
    status: ScannerRunStatus
    packages: tuple[ScannerPackageResult, ...] = ()
    evidence: ScannerRunEvidence
    warning_code: str | None = None


class MatchWarning(MatchingModel):
    code: NonEmptyString
    message: NonEmptyString
    coverage_limited: bool = True


class DependencyMatch(MatchingModel):
    advisory_component_index: int = Field(ge=0)
    advisory_ecosystem: str | None = None
    advisory_name: str | None = None
    component_id: str | None = None
    state: MatchState
    coordinate: ExactPackageCoordinate | None = None
    relationship: DependencyRelationship | None = None
    scopes: tuple[DependencyScope, ...] = ()
    applicability: Applicability | None = None
    source_references: tuple[SourceReference, ...] = ()
    advisory_evidence: tuple[FieldProvenance, ...] = ()
    matched_vulnerability_ids: tuple[str, ...] = ()
    coverage_limitations: tuple[str, ...] = ()


class DependencyMatchReport(MatchingModel):
    advisory_id: NonEmptyString
    advisory_aliases: tuple[str, ...] = ()
    snapshot: InventorySnapshot
    generated_at: datetime
    completed_at: datetime
    matches: tuple[DependencyMatch, ...] = ()
    scanner: ScannerRunEvidence | None = None
    warnings: tuple[MatchWarning, ...] = ()
    coverage_limitations: tuple[str, ...] = ()
    partial: bool = False
