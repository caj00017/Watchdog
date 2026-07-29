from __future__ import annotations

from dataclasses import dataclass
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

from watchdog.domain.advisories import FieldProvenance
from watchdog.domain.inventory import InventorySnapshot, SourceReference
from watchdog.domain.matching import ExactPackageCoordinate, MatchState
from watchdog.domain.reports import ReportFormat, ReportView
from watchdog.domain.repositories import RepositoryRequest

ShortText = Annotated[str, StringConstraints(min_length=1, max_length=4_096)]
VersionText = Annotated[str, StringConstraints(min_length=1, max_length=4_096)]
DigestSha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
SupportId = Annotated[str, StringConstraints(pattern=r"^remediation-support:sha256:[0-9a-f]{64}$")]
CandidateId = Annotated[
    str, StringConstraints(pattern=r"^remediation-candidate:sha256:[0-9a-f]{64}$")
]
PreviewId = Annotated[str, StringConstraints(pattern=r"^remediation-preview:sha256:[0-9a-f]{64}$")]
ConfigurationId = Annotated[
    str, StringConstraints(pattern=r"^remediation-config:sha256:[0-9a-f]{64}$")
]
PlanId = Annotated[str, StringConstraints(pattern=r"^remediation-plan:sha256:[0-9a-f]{64}$")]
ReportId = Annotated[str, StringConstraints(pattern=r"^report:sha256:[0-9a-f]{64}$")]
EvidenceId = Annotated[str, StringConstraints(pattern=r"^evidence:sha256:[0-9a-f]{64}$")]
NO_CHANGE_STATEMENT: Literal[
    "No change was applied. Availability, compatibility, deployment applicability, "
    "generated artifacts, testing, and remediation completeness remain unverified."
] = (
    "No change was applied. Availability, compatibility, deployment applicability, "
    "generated artifacts, testing, and remediation completeness remain unverified."
)


class RemediationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class RemediationPlanStatus(StrEnum):
    UNAVAILABLE = "unavailable"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"
    CANDIDATES_AVAILABLE = "candidates_available"
    PREVIEWS_AVAILABLE = "previews_available"


class CandidateClassification(StrEnum):
    SOURCE_REPORTED = "source_reported"
    COMPARATOR_SUPPORTED = "comparator_supported"
    AMBIGUOUS = "ambiguous"
    MANUAL_ONLY = "manual_only"
    PREVIEW_ELIGIBLE = "preview_eligible"
    PREVIEW_UNAVAILABLE = "preview_unavailable"


class CandidateSelectionOutcome(StrEnum):
    SELECTED = "selected_for_preview"
    CONDITIONAL = "conditional_manual_review"
    AMBIGUOUS = "ambiguous_manual_review"
    CONFLICTING = "conflicting_manual_review"
    COMPARATOR_UNSUPPORTED = "comparator_unsupported"
    NOT_GREATER = "target_not_greater"
    EVIDENCE_UNAVAILABLE = "evidence_unavailable"
    UPSTREAM_INCOMPLETE = "upstream_incomplete_manual_review"


class RemediationLimitation(StrEnum):
    CONDITIONAL_MATCH = "conditional_match"
    ADVISORY_CONFLICT = "advisory_conflict"
    PACKAGE_MAPPING_AMBIGUOUS = "remediation_package_mapping_ambiguous"
    MULTIPLE_TARGETS = "multiple_distinct_targets"
    COMPARATOR_UNSUPPORTED = "version_comparator_unsupported"
    TARGET_NOT_GREATER = "source_target_not_greater"
    EVIDENCE_UNAVAILABLE = "dependency_evidence_unavailable"
    CANDIDATE_LIMIT_EXCEEDED = "candidate_limit_exceeded"
    TARGET_LIMIT_EXCEEDED = "candidate_version_limit_exceeded"
    PREVIEW_DISABLED = "preview_generation_disabled"
    DECLARATION_UNAVAILABLE = "direct_declaration_unavailable"
    DECLARATION_AMBIGUOUS = "direct_declaration_ambiguous"
    DECLARATION_MISMATCH = "direct_declaration_version_mismatch"
    DECLARATION_UNSUPPORTED = "direct_declaration_unsupported"
    SOURCE_UNSAFE = "preview_source_unsafe"
    SOURCE_DIGEST_MISMATCH = "preview_source_digest_mismatch"
    SOURCE_CHANGED = "preview_source_changed"
    SOURCE_LIMIT_EXCEEDED = "preview_source_limit_exceeded"
    TOKEN_AMBIGUOUS = "preview_token_ambiguous"
    TOKEN_BOUNDARY_INVALID = "preview_token_boundary_invalid"
    SEMANTIC_REPARSE_FAILED = "semantic_reparse_failed"
    REDACTION_FAILED = "preview_redaction_failed"
    DIFF_LIMIT_EXCEEDED = "preview_diff_limit_exceeded"
    PREVIEW_LIMIT_EXCEEDED = "preview_limit_exceeded"
    UPSTREAM_COVERAGE_INCOMPLETE = "upstream_coverage_incomplete"
    VALIDATION_ACTION_LIMIT_EXCEEDED = "validation_action_limit_exceeded"
    WARNING_LIMIT_EXCEEDED = "warning_limit_exceeded"


class RemediationWarning(StrEnum):
    CANDIDATE_OMITTED = "candidate_omitted"
    CANDIDATE_LIMIT_EXCEEDED = "candidate_limit_exceeded"
    PREVIEW_OMITTED = "preview_omitted"
    PREVIEW_LIMIT_EXCEEDED = "preview_limit_exceeded"
    SOURCE_LIMIT_EXCEEDED = "source_limit_exceeded"
    VALIDATION_ACTION_LIMIT_EXCEEDED = "validation_action_limit_exceeded"
    WARNING_LIMIT_EXCEEDED = "warning_limit_exceeded"


class RemediationConflict(StrEnum):
    ADVISORY_FIXED_VERSION_CONFLICT = "advisory_fixed_version_conflict"
    MULTIPLE_SOURCE_REPORTED_TARGETS = "multiple_source_reported_targets"
    PACKAGE_MAPPING_AMBIGUOUS = "remediation_package_mapping_ambiguous"


class RemediationValidationAction(StrEnum):
    REVIEW_ADVISORY_PROVENANCE = "review_advisory_fixed_version_provenance"
    ASSESS_COMPATIBILITY = "assess_target_compatibility_and_release_notes_independently"
    REVIEW_DECLARATION_PREVIEW = "review_cited_declaration_and_preview"
    UPDATE_GENERATED_ARTIFACTS = "update_generated_artifacts_in_trusted_workflow"
    RUN_TRUSTED_TESTS = "run_project_tests_outside_watchdog"
    CONFIRM_APPLICABILITY = "confirm_deployment_and_conditional_applicability"
    RERUN_NEW_COMMIT = "rerun_watchdog_against_separately_acquired_new_commit"


class PreviewStatus(StrEnum):
    COMPLETE = "complete"
    DIFF_OMITTED = "diff_omitted"


class SemanticReparseStatus(StrEnum):
    VALIDATED_SINGLE_VERSION_CHANGE = "validated_single_version_change"


class RemediationCoverageState(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"


class RemediationWorkflowRequest(RemediationModel):
    advisory_identifier: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    repository: RepositoryRequest
    view: ReportView = ReportView.SUMMARY
    format: ReportFormat = ReportFormat.JSON

    @field_validator("advisory_identifier")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
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


class RemediationProducer(RemediationModel):
    name: Literal["watchdog-remediation"] = "watchdog-remediation"
    version: Literal["1"] = "1"
    schema_version: Literal["1"] = "1"
    candidate_policy_version: Literal["1"] = "1"
    preview_policy_version: Literal["1"] = "1"
    redaction_policy_version: Literal["1"] = "1"
    wording_policy_version: Literal["1"] = "1"
    json_renderer_version: Literal["1"] = "1"
    markdown_renderer_version: Literal["1"] = "1"


class AdvisoryFactSupport(RemediationModel):
    id: SupportId
    provenance: FieldProvenance
    normalized_field_path: ShortText
    affected_component_index: int = Field(ge=0)
    raw_source_value: VersionText

    @field_validator("normalized_field_path")
    @classmethod
    def validate_field_path(cls, value: str) -> str:
        if not value.startswith("/") or "//" in value:
            raise ValueError("normalized advisory field path must be absolute and normalized")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("normalized advisory field path contains controls")
        return value

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        from watchdog.remediation.identifiers import remediation_support_id

        if self.id != remediation_support_id(self):
            raise ValueError("remediation support identity does not match its canonical payload")
        return self


class RemediationCandidate(RemediationModel):
    id: CandidateId
    advisory_id: ShortText
    current_coordinate: ExactPackageCoordinate
    match_ordinal: int = Field(ge=0)
    match_state: Literal[MatchState.AFFECTED, MatchState.AFFECTED_CONDITIONAL]
    advisory_component_index: int = Field(ge=0)
    component_id: ShortText
    raw_source_reported_target: VersionText
    advisory_fact_supports: tuple[AdvisoryFactSupport, ...] = Field(min_length=1, max_length=2_048)
    dependency_evidence_ids: tuple[EvidenceId, ...] = Field(min_length=1, max_length=2_048)
    classifications: tuple[CandidateClassification, ...] = Field(min_length=1, max_length=6)
    limitations: tuple[RemediationLimitation, ...] = Field(default=(), max_length=64)
    selection: CandidateSelectionOutcome

    @model_validator(mode="after")
    def validate_links_and_identity(self) -> Self:
        from watchdog.remediation.identifiers import remediation_candidate_id

        support_ids = tuple(item.id for item in self.advisory_fact_supports)
        if support_ids != tuple(sorted(set(support_ids))):
            raise ValueError("candidate support facts must be unique and canonically ordered")
        if self.dependency_evidence_ids != tuple(sorted(set(self.dependency_evidence_ids))):
            raise ValueError("candidate evidence links must be unique and sorted")
        if any(
            support.affected_component_index != self.advisory_component_index
            or support.raw_source_value != self.raw_source_reported_target
            or not (
                support.normalized_field_path.startswith(
                    f"/affected_packages/{self.advisory_component_index}/"
                )
                or support.normalized_field_path.startswith("/remediation/")
            )
            for support in self.advisory_fact_supports
        ):
            raise ValueError("candidate support facts do not agree with the target fact")
        if self.classifications != tuple(sorted(set(self.classifications), key=str)):
            raise ValueError("candidate classifications must be unique and sorted")
        if self.limitations != tuple(sorted(set(self.limitations), key=str)):
            raise ValueError("candidate limitations must be unique and sorted")
        if CandidateClassification.SOURCE_REPORTED not in self.classifications:
            raise ValueError("candidate must be classified as source reported")
        selected = self.selection is CandidateSelectionOutcome.SELECTED
        preview_states = {
            CandidateClassification.PREVIEW_ELIGIBLE,
            CandidateClassification.PREVIEW_UNAVAILABLE,
        }.intersection(self.classifications)
        if selected != bool(preview_states) or len(preview_states) > 1:
            raise ValueError("candidate selection must agree with exactly one preview state")
        if self.id != remediation_candidate_id(self):
            raise ValueError("remediation candidate identity does not match its payload")
        return self


class ByteTokenReplacement(RemediationModel):
    offset: int = Field(ge=0)
    original_byte_count: int = Field(gt=0, le=4_096)
    original_sha256: DigestSha256
    original_token: VersionText
    replacement_token: VersionText

    @model_validator(mode="after")
    def validate_token(self) -> Self:
        import hashlib

        original = self.original_token.encode("utf-8")
        if len(original) != self.original_byte_count:
            raise ValueError("replacement original byte count does not match token")
        if hashlib.sha256(original).hexdigest() != self.original_sha256:
            raise ValueError("replacement original digest does not match token")
        if self.original_token == self.replacement_token:
            raise ValueError("replacement token must change")
        return self


class PatchPreview(RemediationModel):
    id: PreviewId
    candidate_id: CandidateId
    source_reference: SourceReference
    original_sha256: DigestSha256
    hypothetical_sha256: DigestSha256
    replacement: ByteTokenReplacement
    redacted_zero_context_diff: str | None = Field(default=None, max_length=65_536)
    status: PreviewStatus
    semantic_reparse_status: SemanticReparseStatus
    dependency_evidence_ids: tuple[EvidenceId, ...] = Field(min_length=1, max_length=2_048)
    limitations: tuple[RemediationLimitation, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def validate_preview(self) -> Self:
        from watchdog.remediation.identifiers import remediation_preview_id

        if self.original_sha256 != self.source_reference.file_sha256:
            raise ValueError("preview source and original digests disagree")
        if self.original_sha256 == self.hypothetical_sha256:
            raise ValueError("preview hypothetical digest must differ")
        if self.dependency_evidence_ids != tuple(sorted(set(self.dependency_evidence_ids))):
            raise ValueError("preview evidence links must be unique and sorted")
        if self.limitations != tuple(sorted(set(self.limitations), key=str)):
            raise ValueError("preview limitations must be unique and sorted")
        if self.status is PreviewStatus.COMPLETE and self.redacted_zero_context_diff is None:
            raise ValueError("complete preview requires a redacted display diff")
        if self.status is PreviewStatus.DIFF_OMITTED and (
            self.redacted_zero_context_diff is not None or not self.limitations
        ):
            raise ValueError("omitted preview diff requires a limitation and no display")
        if self.id != remediation_preview_id(self):
            raise ValueError("remediation preview identity does not match its payload")
        return self


class RemediationCoverage(RemediationModel):
    state: RemediationCoverageState
    eligible_matches: int = Field(ge=0)
    source_reported_targets: int = Field(ge=0)
    candidates: int = Field(ge=0)
    previews_attempted: int = Field(ge=0)
    previews_completed: int = Field(ge=0)
    omitted_candidates: int = Field(ge=0)
    omitted_previews: int = Field(ge=0)
    limitations: tuple[RemediationLimitation, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        if self.previews_completed > self.previews_attempted:
            raise ValueError("completed previews cannot exceed attempted previews")
        if self.limitations != tuple(sorted(set(self.limitations), key=str)):
            raise ValueError("coverage limitations must be unique and sorted")
        partial = bool(self.omitted_candidates or self.omitted_previews or self.limitations)
        if (self.state is RemediationCoverageState.PARTIAL) != partial:
            raise ValueError("coverage state must agree with omissions and limitations")
        return self


class RemediationPlan(RemediationModel):
    id: PlanId
    producer: RemediationProducer = RemediationProducer()
    configuration_id: ConfigurationId
    phase7_report_id: ReportId
    advisory_id: ShortText
    snapshot: InventorySnapshot
    status: RemediationPlanStatus
    candidates: tuple[RemediationCandidate, ...] = Field(default=(), max_length=256)
    previews: tuple[PatchPreview, ...] = Field(default=(), max_length=64)
    validation_actions: tuple[RemediationValidationAction, ...] = Field(default=(), max_length=64)
    conflicts: tuple[RemediationConflict, ...] = Field(default=(), max_length=64)
    warnings: tuple[RemediationWarning, ...] = Field(default=(), max_length=512)
    coverage: RemediationCoverage
    partial: bool
    no_change_statement: Literal[
        "No change was applied. Availability, compatibility, deployment applicability, "
        "generated artifacts, testing, and remediation completeness remain unverified."
    ] = NO_CHANGE_STATEMENT

    @model_validator(mode="after")
    def validate_plan(self) -> Self:
        from watchdog.remediation.identifiers import remediation_plan_id

        candidate_ids = tuple(item.id for item in self.candidates)
        preview_ids = tuple(item.id for item in self.previews)
        if candidate_ids != tuple(sorted(set(candidate_ids))):
            raise ValueError("remediation candidates must be unique and canonically ordered")
        if preview_ids != tuple(sorted(set(preview_ids))):
            raise ValueError("remediation previews must be unique and canonically ordered")
        if not {item.candidate_id for item in self.previews}.issubset(set(candidate_ids)):
            raise ValueError("remediation preview has a broken candidate link")
        evidence = {
            evidence_id
            for candidate in self.candidates
            for evidence_id in candidate.dependency_evidence_ids
        }
        for preview in self.previews:
            candidate = next(item for item in self.candidates if item.id == preview.candidate_id)
            if preview.dependency_evidence_ids != candidate.dependency_evidence_ids:
                raise ValueError("preview evidence must agree with its candidate")
            if not set(preview.dependency_evidence_ids).issubset(evidence):
                raise ValueError("preview has a broken evidence link")
        for values, label in (
            (self.validation_actions, "validation actions"),
            (self.conflicts, "conflicts"),
            (self.warnings, "warnings"),
        ):
            if values != tuple(sorted(set(values), key=str)):
                raise ValueError(f"remediation {label} must be unique and sorted")
        expected_status = self._expected_status()
        if self.status is not expected_status:
            raise ValueError("remediation plan status does not agree with its content")
        if self.coverage.candidates != len(self.candidates):
            raise ValueError("remediation coverage candidate count disagrees")
        if self.coverage.previews_completed != sum(
            item.status is PreviewStatus.COMPLETE for item in self.previews
        ):
            raise ValueError("remediation coverage preview count disagrees")
        if self.partial != (self.coverage.state is RemediationCoverageState.PARTIAL):
            raise ValueError("remediation partial state disagrees with coverage")
        if self.id != remediation_plan_id(self):
            raise ValueError("remediation plan identity does not match its canonical payload")
        return self

    def _expected_status(self) -> RemediationPlanStatus:
        if not self.candidates:
            return RemediationPlanStatus.UNAVAILABLE
        if any(item.status is PreviewStatus.COMPLETE for item in self.previews):
            return RemediationPlanStatus.PREVIEWS_AVAILABLE
        if any(
            candidate.selection is CandidateSelectionOutcome.SELECTED
            for candidate in self.candidates
        ):
            return RemediationPlanStatus.CANDIDATES_AVAILABLE
        return RemediationPlanStatus.MANUAL_REVIEW_REQUIRED


@dataclass(frozen=True, slots=True)
class RenderedRemediationPlan:
    body: bytes
    media_type: str
    plan_id: str
    status: RemediationPlanStatus
