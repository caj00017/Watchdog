from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from watchdog.domain.investigation import (
    InvestigationAssumptionCode,
    InvestigationClaimKind,
    InvestigationDisposition,
    InvestigationRunStatus,
    MissingEvidenceCode,
    ValidationActionCode,
)
from watchdog.domain.matching import MatchState
from watchdog.domain.repositories import RepositoryRequest

BoundedText = Annotated[str, StringConstraints(max_length=16_384)]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=4_096)]
StableCode = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,127}$")]
DigestSha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
CommitSha = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
ReportId = Annotated[str, StringConstraints(pattern=r"^report:sha256:[0-9a-f]{64}$")]


class ReportModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class ReportView(StrEnum):
    SUMMARY = "summary"
    TECHNICAL = "technical"


class ReportFormat(StrEnum):
    JSON = "json"
    MARKDOWN = "markdown"


class ReportStatus(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"


class ReportCategory(StrEnum):
    TARGET_METADATA = "target_metadata"
    DETERMINISTIC_FACT = "deterministic_fact"
    MODEL_INFERENCE = "model_inference"
    ASSUMPTION = "assumption"
    COVERAGE_GAP = "coverage_gap"
    VALIDATION_ACTION = "validation_action"


class InvestigationWorkflowRequest(ReportModel):
    advisory_identifier: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    repository: RepositoryRequest
    view: ReportView = ReportView.SUMMARY
    format: ReportFormat = ReportFormat.JSON

    @field_validator("advisory_identifier")
    @classmethod
    def validate_advisory_identifier(cls, value: str) -> str:
        if value != value.strip() or len(value.encode("utf-8")) > 128:
            raise ValueError("advisory identifier must be trimmed and at most 128 bytes")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("advisory identifier must not contain control characters")
        return value

    @model_validator(mode="after")
    def validate_repository_bounds(self) -> Self:
        if len(self.repository.repository_url.encode("utf-8")) > 2_048:
            raise ValueError("repository URL exceeds 2048 bytes")
        if self.repository.ref is not None and len(self.repository.ref.encode("utf-8")) > 255:
            raise ValueError("repository ref exceeds 255 bytes")
        return self


class ReportProducer(ReportModel):
    name: Literal["watchdog-reporting"] = "watchdog-reporting"
    version: Literal["1"] = "1"
    schema_version: Literal["1"] = "1"
    wording_policy_version: Literal["1"] = "1"
    json_renderer_version: Literal["1"] = "1"
    markdown_renderer_version: Literal["1"] = "1"


class ReportProvenance(ReportModel):
    id: Annotated[str, StringConstraints(pattern=r"^advisory-provenance:sha256:[0-9a-f]{64}$")]
    field: ShortText
    source: ShortText
    record_id: ShortText
    source_url: ShortText
    retrieved_at: datetime
    path: ShortText


class ReportAdvisory(ReportModel):
    primary_id: ShortText
    aliases: tuple[ShortText, ...] = Field(default=(), max_length=1_000)
    summary: BoundedText | None = None
    modified: datetime | None = None
    provenance: tuple[ReportProvenance, ...] = Field(default=(), max_length=2_048)
    conflict_count: int = Field(ge=0)
    warning_count: int = Field(ge=0)
    partial: bool


class ReportRepository(ReportModel):
    canonical_url: ShortText
    requested_ref: ShortText | None = None
    resolved_ref: ShortText
    commit_sha: CommitSha
    tree_sha: CommitSha
    archive_sha256: DigestSha256


class ReportScanner(ReportModel):
    tool: ShortText | None = None
    tool_version: ShortText | None = None
    configuration_sha256: DigestSha256 | None = None
    exit_code: int | None = None
    input_sha256: DigestSha256 | None = None
    output_sha256: DigestSha256 | None = None
    completed: bool


class ReportMatch(ReportModel):
    ordinal: int = Field(ge=0)
    state: MatchState
    component_id: ShortText | None = None
    ecosystem: ShortText | None = None
    package: ShortText | None = None
    version: ShortText | None = None
    advisory_provenance_ids: tuple[str, ...] = Field(default=(), max_length=2_048)
    dependency_evidence_ids: tuple[str, ...] = Field(default=(), max_length=2_048)
    context_evidence_ids: tuple[str, ...] = Field(default=(), max_length=2_048)
    signal_ids: tuple[str, ...] = Field(default=(), max_length=2_048)
    limitations: tuple[BoundedText, ...] = Field(default=(), max_length=512)


class ReportEvidence(ReportModel):
    id: ShortText
    phase: Literal["phase4", "phase5"]
    kind: ShortText
    status: ShortText
    path: ShortText
    file_sha256: DigestSha256
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    content: BoundedText | None = None
    dependency_evidence_ids: tuple[str, ...] = Field(default=(), max_length=2_048)
    limitation_codes: tuple[ShortText, ...] = Field(default=(), max_length=512)


class ReportObservation(ReportModel):
    id: ShortText
    kind: ShortText
    evidence_id: ShortText
    path: ShortText
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)


class ReportSignal(ReportModel):
    id: ShortText
    kind: ShortText
    dependency_evidence_ids: tuple[str, ...] = Field(default=(), max_length=2_048)
    evidence_ids: tuple[str, ...] = Field(default=(), max_length=2_048)
    limitation_codes: tuple[ShortText, ...] = Field(default=(), max_length=512)


class ReportClaim(ReportModel):
    kind: InvestigationClaimKind
    summary: ShortText
    rationale: BoundedText | None = None
    advisory_provenance_ids: tuple[str, ...] = Field(default=(), max_length=128)
    evidence_ids: tuple[str, ...] = Field(default=(), max_length=128)
    signal_ids: tuple[str, ...] = Field(default=(), max_length=128)


class ReportInference(ReportModel):
    result_id: ShortText
    envelope_id: ShortText
    status: InvestigationRunStatus
    disposition: InvestigationDisposition | None = None
    claims: tuple[ReportClaim, ...] = Field(default=(), max_length=256)
    assumptions: tuple[InvestigationAssumptionCode, ...] = Field(default=(), max_length=128)
    missing_evidence: tuple[MissingEvidenceCode, ...] = Field(default=(), max_length=256)
    validation_actions: tuple[ValidationActionCode, ...] = Field(default=(), max_length=128)
    error_code: StableCode | None = None


class ReportDiagnostic(ReportModel):
    phase: Literal["phase1", "phase3", "phase4", "phase5", "phase6", "phase7"]
    code: StableCode
    message: BoundedText
    support_ids: tuple[str, ...] = Field(default=(), max_length=2_048)


class ReportEntry(ReportModel):
    category: ReportCategory
    code: StableCode
    text: BoundedText
    support_ids: tuple[str, ...] = Field(default=(), max_length=2_048)

    @model_validator(mode="after")
    def require_finding_support(self) -> Self:
        if (
            self.category
            in {
                ReportCategory.DETERMINISTIC_FACT,
                ReportCategory.MODEL_INFERENCE,
            }
            and not self.support_ids
        ):
            raise ValueError("every report finding requires evidence or provenance support")
        if self.support_ids != tuple(sorted(set(self.support_ids))):
            raise ValueError("report entry support IDs must be unique and sorted")
        return self


class ReportCoverage(ReportModel):
    advisory_partial: bool
    inventory_partial: bool
    matching_partial: bool
    evidence_partial: bool
    context_partial: bool
    investigation_incomplete: bool
    envelope_truncated: bool
    report_entries_omitted: int = Field(ge=0)
    evidence_references_omitted: int = Field(ge=0)
    diagnostics_omitted: int = Field(ge=0)


class InvestigationReport(ReportModel):
    id: ReportId
    producer: ReportProducer
    configuration_sha256: DigestSha256
    status: ReportStatus
    advisory: ReportAdvisory
    repository: ReportRepository
    scanner: ReportScanner
    inventory_configuration_sha256: DigestSha256
    evidence_bundle_id: ShortText
    evidence_configuration_sha256: DigestSha256
    context_bundle_id: ShortText
    context_configuration_sha256: DigestSha256
    investigation: ReportInference
    matches: tuple[ReportMatch, ...] = Field(default=(), max_length=1_024)
    evidence: tuple[ReportEvidence, ...] = Field(default=(), max_length=2_048)
    observations: tuple[ReportObservation, ...] = Field(default=(), max_length=2_048)
    signals: tuple[ReportSignal, ...] = Field(default=(), max_length=2_048)
    diagnostics: tuple[ReportDiagnostic, ...] = Field(default=(), max_length=512)
    summary: tuple[ReportEntry, ...] = Field(max_length=1_024)
    technical: tuple[ReportEntry, ...] = Field(max_length=1_024)
    coverage: ReportCoverage

    @model_validator(mode="after")
    def validate_identity_and_links(self) -> Self:
        from watchdog.reporting.identifiers import investigation_report_id

        if self.id != investigation_report_id(self):
            raise ValueError("report identity does not match its canonical payload")
        provenance_ids = {item.id for item in self.advisory.provenance}
        evidence_ids = {item.id for item in self.evidence}
        signal_ids = {item.id for item in self.signals}
        observation_ids = {item.id for item in self.observations}
        if len(evidence_ids) != len(self.evidence) or len(signal_ids) != len(self.signals):
            raise ValueError("report evidence and signal IDs must be unique")
        if len(observation_ids) != len(self.observations):
            raise ValueError("report observation IDs must be unique")
        if tuple(item.id for item in self.advisory.provenance) != tuple(sorted(provenance_ids)):
            raise ValueError("report provenance must be canonically ordered")
        for values, label in (
            (tuple(item.id for item in self.evidence), "evidence"),
            (tuple(item.id for item in self.observations), "observations"),
            (tuple(item.id for item in self.signals), "signals"),
        ):
            if values != tuple(sorted(values)):
                raise ValueError(f"report {label} must be canonically ordered")
        if tuple(item.ordinal for item in self.matches) != tuple(range(len(self.matches))):
            raise ValueError("report matches must use ordered contiguous ordinals")
        artifact_ids = {
            self.configuration_sha256,
            self.inventory_configuration_sha256,
            self.evidence_bundle_id,
            self.evidence_configuration_sha256,
            self.context_bundle_id,
            self.context_configuration_sha256,
            self.investigation.result_id,
            self.investigation.envelope_id,
            self.repository.archive_sha256,
        }
        if self.scanner.configuration_sha256 is not None:
            artifact_ids.add(self.scanner.configuration_sha256)
        allowed = provenance_ids | evidence_ids | signal_ids | observation_ids | artifact_ids
        for claim in self.investigation.claims:
            if not set(claim.advisory_provenance_ids).issubset(provenance_ids):
                raise ValueError("report claim has broken advisory provenance")
            if not set(claim.evidence_ids).issubset(evidence_ids | observation_ids):
                raise ValueError("report claim has broken evidence links")
            if not set(claim.signal_ids).issubset(signal_ids):
                raise ValueError("report claim has broken signal links")
        for entry in (*self.summary, *self.technical):
            if not set(entry.support_ids).issubset(allowed):
                raise ValueError("report entry has broken support links")
        return self


@dataclass(frozen=True, slots=True)
class RenderedReport:
    body: bytes
    media_type: str
    report_id: str
    status: ReportStatus
