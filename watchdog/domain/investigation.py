from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from watchdog.domain.inventory import InventorySnapshot

StableName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9._-]{0,127}$")]
StableCode = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,127}$")]
BoundedString = Annotated[str, StringConstraints(min_length=1, max_length=4096)]
ModelIdentifier = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$"),
]
DigestSha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
EnvelopeId = Annotated[
    str, StringConstraints(pattern=r"^investigation-envelope:sha256:[0-9a-f]{64}$")
]
ResultId = Annotated[str, StringConstraints(pattern=r"^investigation-result:sha256:[0-9a-f]{64}$")]
ProvenanceId = Annotated[
    str, StringConstraints(pattern=r"^advisory-provenance:sha256:[0-9a-f]{64}$")
]
EvidenceReferenceId = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^(?:evidence|context-evidence|context-observation|context-signal):"
            r"sha256:[0-9a-f]{64}$"
        )
    ),
]
GraphNodeId = Annotated[str, StringConstraints(pattern=r"^context-node:sha256:[0-9a-f]{64}$")]
GraphEdgeId = Annotated[str, StringConstraints(pattern=r"^context-edge:sha256:[0-9a-f]{64}$")]


class InvestigationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class InvestigationDisposition(StrEnum):
    DEPENDENCY_MATCH_AND_CONTEXT_OBSERVED = "dependency_match_and_context_observed"
    DEPENDENCY_MATCH_CONTEXT_UNCONFIRMED = "dependency_match_context_unconfirmed"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    UNSUPPORTED = "unsupported"


class InvestigationRunStatus(StrEnum):
    DISABLED = "disabled"
    COMPLETED = "completed"
    INCOMPLETE_INPUT = "incomplete_input"
    GATEWAY_UNAVAILABLE = "gateway_unavailable"
    TIMED_OUT = "timed_out"
    RESPONSE_TOO_LARGE = "response_too_large"
    INVALID_RESPONSE = "invalid_response"
    EVIDENCE_VALIDATION_FAILED = "evidence_validation_failed"
    POLICY_REJECTED = "policy_rejected"
    CANCELLED = "cancelled"


class InvestigationClaimKind(StrEnum):
    DEPENDENCY_RELATIONSHIP = "dependency_relationship"
    CONTEXTUAL_RELATIONSHIP = "contextual_relationship"
    ADVISORY_CONDITION = "advisory_condition"
    MATERIAL_EVIDENCE_LIMITATION = "material_evidence_limitation"


class InvestigationAssumptionCode(StrEnum):
    LEXICAL_OBSERVATION_MAY_NOT_EXECUTE = "lexical_observation_may_not_execute"
    DEPLOYMENT_CONTEXT_UNKNOWN = "deployment_context_unknown"
    RUNTIME_CONFIGURATION_UNKNOWN = "runtime_configuration_unknown"
    ADVISORY_CONDITION_APPLICABILITY_UNKNOWN = "advisory_condition_applicability_unknown"
    DEPENDENCY_APPLICABILITY_PRESERVED = "dependency_applicability_preserved"


class MissingEvidenceCode(StrEnum):
    INVENTORY_PARTIAL = "inventory_partial"
    SCANNER_INCOMPLETE = "scanner_incomplete"
    VERSION_UNKNOWN = "version_unknown"
    UNSUPPORTED_ADVISORY_COMPONENT = "unsupported_advisory_component"
    DEPENDENCY_EVIDENCE_PARTIAL = "dependency_evidence_partial"
    CONTEXT_EVIDENCE_PARTIAL = "context_evidence_partial"
    CONTEXT_NOT_OBSERVED = "context_not_observed"
    ENVELOPE_TRUNCATED = "envelope_truncated"
    REDACTION_OMISSION = "redaction_omission"
    DEPLOYMENT_CONTEXT_ABSENT = "deployment_context_absent"
    RUNTIME_CONFIGURATION_ABSENT = "runtime_configuration_absent"
    LOCKFILE_EVIDENCE_ABSENT = "lockfile_evidence_absent"


class ValidationActionCode(StrEnum):
    REVIEW_CITED_DEPENDENCY_SOURCE = "review_cited_dependency_source"
    REVIEW_CITED_CONTEXT_SITE = "review_cited_context_site"
    REVIEW_ADVISORY_CONDITIONS = "review_advisory_conditions"
    CONFIRM_RUNTIME_CONFIGURATION = "confirm_runtime_configuration"
    CONFIRM_DEPLOYMENT_CONDITIONS = "confirm_deployment_conditions"
    OBTAIN_EXACT_VERSION_EVIDENCE = "obtain_exact_version_evidence"
    OBTAIN_SUPPORTED_MANIFEST_EVIDENCE = "obtain_supported_manifest_evidence"
    RESOLVE_SCANNER_FAILURE = "resolve_scanner_failure"


class InvestigationLimitationCode(StrEnum):
    ADVISORY_DATA_LIMIT_EXCEEDED = "advisory_data_limit_exceeded"
    ADVISORY_PARTIAL = "advisory_partial"
    INVENTORY_PARTIAL = "inventory_partial"
    MATCH_REPORT_PARTIAL = "match_report_partial"
    PHASE4_EVIDENCE_PARTIAL = "phase4_evidence_partial"
    PHASE5_CONTEXT_PARTIAL = "phase5_context_partial"
    MATCH_LIMIT_EXCEEDED = "match_limit_exceeded"
    EVIDENCE_ITEM_LIMIT_EXCEEDED = "evidence_item_limit_exceeded"
    ENVELOPE_BYTE_LIMIT_EXCEEDED = "envelope_byte_limit_exceeded"
    DECISIVE_EVIDENCE_OMITTED = "decisive_evidence_omitted"
    SCANNER_INCOMPLETE = "scanner_incomplete"
    VERSION_UNKNOWN = "version_unknown"
    UNSUPPORTED_COMPONENT = "unsupported_component"


class EnvelopeEvidenceKind(StrEnum):
    DEPENDENCY_SOURCE = "dependency_source"
    LEXICAL_CONTEXT = "lexical_context"


class InvestigationProducer(InvestigationModel):
    name: StableName = "watchdog-investigation"
    version: BoundedString = "1"
    envelope_schema_version: BoundedString = "1"
    response_schema_version: BoundedString = "1"
    response_schema_sha256: DigestSha256
    prompt_version: BoundedString = "1"
    prompt_sha256: DigestSha256
    policy_version: BoundedString = "1"
    gateway_protocol_version: BoundedString = "1"


class AdvisoryProvenanceReference(InvestigationModel):
    id: ProvenanceId
    field: BoundedString
    source: BoundedString
    record_id: BoundedString
    source_url: BoundedString
    retrieved_at: datetime
    path: BoundedString


class EnvelopeSeverity(InvestigationModel):
    type: BoundedString
    score: BoundedString


class EnvelopeVersionEvent(InvestigationModel):
    introduced: BoundedString | None = None
    fixed: BoundedString | None = None
    last_affected: BoundedString | None = None
    limit: BoundedString | None = None

    @model_validator(mode="after")
    def require_one_value(self) -> Self:
        values = (self.introduced, self.fixed, self.last_affected, self.limit)
        if sum(value is not None for value in values) != 1:
            raise ValueError("an envelope version event requires exactly one value")
        return self


class EnvelopeAffectedRange(InvestigationModel):
    type: BoundedString
    events: tuple[EnvelopeVersionEvent, ...] = Field(default=(), max_length=256)


class EnvelopeAffectedPackage(InvestigationModel):
    advisory_component_index: int = Field(ge=0)
    ecosystem: BoundedString | None = None
    name: BoundedString | None = None
    purl: BoundedString | None = None
    ranges: tuple[EnvelopeAffectedRange, ...] = Field(default=(), max_length=256)
    versions: tuple[BoundedString, ...] = Field(default=(), max_length=10_000)


class EnvelopeAdvisory(InvestigationModel):
    primary_id: BoundedString
    aliases: tuple[BoundedString, ...] = Field(default=(), max_length=1_000)
    affected_packages: tuple[EnvelopeAffectedPackage, ...] = Field(default=(), max_length=256)
    severity: tuple[EnvelopeSeverity, ...] = Field(default=(), max_length=256)
    provenance: tuple[AdvisoryProvenanceReference, ...] = Field(default=(), max_length=10_000)
    partial: bool
    conflict_count: int = Field(ge=0)
    warning_count: int = Field(ge=0)


class EnvelopeCoordinate(InvestigationModel):
    ecosystem: BoundedString
    name: BoundedString
    version: BoundedString


class EnvelopeMatch(InvestigationModel):
    ordinal: int = Field(ge=0)
    advisory_component_index: int = Field(ge=0)
    component_id: BoundedString | None = None
    state: BoundedString
    coordinate: EnvelopeCoordinate | None = None
    relationship: BoundedString | None = None
    scopes: tuple[BoundedString, ...] = Field(default=(), max_length=32)
    applicability: BoundedString | None = None
    advisory_provenance_ids: tuple[ProvenanceId, ...] = Field(default=(), max_length=1_000)
    dependency_evidence_ids: tuple[EvidenceReferenceId, ...] = Field(default=(), max_length=10_000)
    context_evidence_ids: tuple[EvidenceReferenceId, ...] = Field(default=(), max_length=10_000)
    observation_ids: tuple[EvidenceReferenceId, ...] = Field(default=(), max_length=50_000)
    signal_ids: tuple[EvidenceReferenceId, ...] = Field(default=(), max_length=100_000)
    limitations: tuple[BoundedString, ...] = Field(default=(), max_length=1_024)


class EnvelopeAnchor(InvestigationModel):
    start_line: int = Field(ge=1)
    start_column: int = Field(ge=0)
    end_line: int = Field(ge=1)
    end_column: int = Field(ge=0)


class EnvelopeEvidence(InvestigationModel):
    id: EvidenceReferenceId
    kind: EnvelopeEvidenceKind
    match_ordinals: tuple[int, ...] = Field(min_length=1, max_length=256)
    status: BoundedString
    path: BoundedString
    file_sha256: DigestSha256
    trust_level: Literal["untrusted_repository"] = "untrusted_repository"
    content: str | None = Field(default=None, max_length=5 * 1024 * 1024)
    content_sha256: DigestSha256 | None = None
    anchor: EnvelopeAnchor | None = None
    observation_kind: BoundedString | None = None
    dependency_evidence_ids: tuple[EvidenceReferenceId, ...] = Field(default=(), max_length=10_000)
    limitations: tuple[BoundedString, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_content(self) -> Self:
        if self.match_ordinals != tuple(sorted(set(self.match_ordinals))):
            raise ValueError("envelope evidence match ordinals must be unique and sorted")
        if (self.content is None) != (self.content_sha256 is None):
            raise ValueError("envelope evidence content and digest must appear together")
        return self


class EnvelopeObservation(InvestigationModel):
    id: EvidenceReferenceId
    kind: BoundedString
    match_ordinal: int = Field(ge=0)
    evidence_id: EvidenceReferenceId
    path: BoundedString
    anchor: EnvelopeAnchor
    binding: BoundedString | None = None
    member_path: tuple[BoundedString, ...] = Field(default=(), max_length=16)
    rule_id: BoundedString | None = None


class EnvelopeSignal(InvestigationModel):
    id: EvidenceReferenceId
    kind: BoundedString
    match_ordinal: int = Field(ge=0)
    rank: int = Field(ge=1, le=1_000)
    dependency_evidence_ids: tuple[EvidenceReferenceId, ...] = Field(default=(), max_length=10_000)
    evidence_ids: tuple[EvidenceReferenceId, ...] = Field(default=(), max_length=10_000)
    limitations: tuple[BoundedString, ...] = Field(default=(), max_length=128)


class EnvelopeGraphNode(InvestigationModel):
    id: GraphNodeId
    kind: BoundedString
    target_id: BoundedString | None = None
    path: BoundedString | None = None
    observation_id: EvidenceReferenceId | None = None
    evidence_ids: tuple[EvidenceReferenceId, ...] = Field(min_length=1, max_length=10_000)


class EnvelopeGraphEdge(InvestigationModel):
    id: GraphEdgeId
    kind: BoundedString
    from_node_id: GraphNodeId
    to_node_id: GraphNodeId
    evidence_ids: tuple[EvidenceReferenceId, ...] = Field(min_length=1, max_length=10_000)


class InvestigationCoverage(InvestigationModel):
    input_partial: bool
    envelope_truncated: bool
    advisory_values_omitted: int = Field(ge=0)
    matches_available: int = Field(ge=0)
    matches_included: int = Field(ge=0)
    matches_omitted: int = Field(ge=0)
    evidence_available: int = Field(ge=0)
    evidence_included: int = Field(ge=0)
    evidence_omitted: int = Field(ge=0)
    limitations: tuple[InvestigationLimitationCode, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        if self.matches_included > self.matches_available:
            raise ValueError("included matches exceed available matches")
        if self.matches_included + self.matches_omitted != self.matches_available:
            raise ValueError("investigation match coverage counts disagree")
        if self.evidence_included + self.evidence_omitted != self.evidence_available:
            raise ValueError("investigation evidence coverage counts disagree")
        if self.limitations != tuple(sorted(set(self.limitations))):
            raise ValueError("investigation limitations must be unique and sorted")
        if self.input_partial != bool(self.limitations):
            raise ValueError("input partial flag must agree with limitations")
        return self


class InvestigationEnvelope(InvestigationModel):
    id: EnvelopeId
    schema_version: Literal["1"] = "1"
    producer: InvestigationProducer
    advisory: EnvelopeAdvisory
    snapshot: InventorySnapshot
    matches: tuple[EnvelopeMatch, ...] = Field(default=(), max_length=256)
    evidence: tuple[EnvelopeEvidence, ...] = Field(default=(), max_length=1_000)
    observations: tuple[EnvelopeObservation, ...] = Field(default=(), max_length=50_000)
    graph_nodes: tuple[EnvelopeGraphNode, ...] = Field(default=(), max_length=50_000)
    graph_edges: tuple[EnvelopeGraphEdge, ...] = Field(default=(), max_length=100_000)
    signals: tuple[EnvelopeSignal, ...] = Field(default=(), max_length=100_000)
    allowed_citation_ids: tuple[str, ...] = Field(default=(), max_length=200_000)
    allowed_assumption_codes: tuple[InvestigationAssumptionCode, ...] = Field(
        default=(), max_length=32
    )
    allowed_missing_evidence_codes: tuple[MissingEvidenceCode, ...] = Field(
        default=(), max_length=64
    )
    allowed_validation_action_codes: tuple[ValidationActionCode, ...] = Field(
        default=(), max_length=32
    )
    coverage: InvestigationCoverage

    @model_validator(mode="after")
    def validate_envelope(self) -> Self:
        from watchdog.investigation.identifiers import investigation_envelope_id

        evidence_ids = tuple(item.id for item in self.evidence)
        observation_ids = tuple(item.id for item in self.observations)
        graph_node_ids = tuple(item.id for item in self.graph_nodes)
        graph_edge_ids = tuple(item.id for item in self.graph_edges)
        signal_ids = tuple(item.id for item in self.signals)
        for values, label in (
            (evidence_ids, "evidence"),
            (observation_ids, "observations"),
            (graph_node_ids, "graph nodes"),
            (graph_edge_ids, "graph edges"),
            (signal_ids, "signals"),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"envelope {label} must be unique")
        phase4_ids = {
            item.id for item in self.evidence if item.kind == EnvelopeEvidenceKind.DEPENDENCY_SOURCE
        }
        phase5_ids = {
            item.id for item in self.evidence if item.kind == EnvelopeEvidenceKind.LEXICAL_CONTEXT
        }
        for evidence_item in self.evidence:
            if evidence_item.kind == EnvelopeEvidenceKind.LEXICAL_CONTEXT and not set(
                evidence_item.dependency_evidence_ids
            ).issubset(phase4_ids):
                raise ValueError("context envelope evidence has broken Phase 4 support")
        if not {item.evidence_id for item in self.observations}.issubset(phase5_ids):
            raise ValueError("envelope observations have broken context evidence links")
        node_ids = set(graph_node_ids)
        for node in self.graph_nodes:
            if not set(node.evidence_ids).issubset(phase5_ids):
                raise ValueError("envelope graph nodes have broken evidence links")
            if node.observation_id is not None and node.observation_id not in observation_ids:
                raise ValueError("envelope graph node has a broken observation link")
        for edge in self.graph_edges:
            if edge.from_node_id not in node_ids or edge.to_node_id not in node_ids:
                raise ValueError("envelope graph edge has a broken node link")
            if not set(edge.evidence_ids).issubset(phase5_ids):
                raise ValueError("envelope graph edge has broken evidence links")
        for signal in self.signals:
            if not set(signal.dependency_evidence_ids).issubset(phase4_ids) or not set(
                signal.evidence_ids
            ).issubset(phase5_ids):
                raise ValueError("envelope signals have broken evidence links")
        provenance_ids = {item.id for item in self.advisory.provenance}
        all_evidence_ids = phase4_ids | phase5_ids
        for match in self.matches:
            if not set(match.advisory_provenance_ids).issubset(provenance_ids):
                raise ValueError("envelope matches have broken advisory provenance links")
            if not set(match.dependency_evidence_ids).issubset(phase4_ids):
                raise ValueError("envelope matches have broken Phase 4 links")
            if not set(match.context_evidence_ids).issubset(phase5_ids):
                raise ValueError("envelope matches have broken Phase 5 links")
            if not set(match.observation_ids).issubset(observation_ids):
                raise ValueError("envelope matches have broken observation links")
            if not set(match.signal_ids).issubset(signal_ids):
                raise ValueError("envelope matches have broken signal links")
        for values, label in (
            (self.allowed_citation_ids, "citation IDs"),
            (self.allowed_assumption_codes, "assumption codes"),
            (self.allowed_missing_evidence_codes, "missing-evidence codes"),
            (self.allowed_validation_action_codes, "validation-action codes"),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"envelope {label} must be unique and sorted")
        actual_ids = {
            *(item.id for item in self.advisory.provenance),
            *all_evidence_ids,
            *(item.id for item in self.observations),
            *(item.id for item in self.signals),
        }
        if set(self.allowed_citation_ids) != actual_ids:
            raise ValueError("allowed citations must exactly match included canonical items")
        if self.id != investigation_envelope_id(self):
            raise ValueError("investigation envelope identity does not match its payload")
        return self


class InvestigationClaim(InvestigationModel):
    kind: InvestigationClaimKind
    summary: Annotated[str, StringConstraints(min_length=1, max_length=2048)]
    rationale: Annotated[str, StringConstraints(min_length=1, max_length=8192)] | None
    advisory_provenance_ids: tuple[ProvenanceId, ...] = Field(max_length=32)
    evidence_ids: tuple[EvidenceReferenceId, ...] = Field(max_length=32)
    signal_ids: tuple[EvidenceReferenceId, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def require_evidence(self) -> Self:
        for values in (self.advisory_provenance_ids, self.evidence_ids, self.signal_ids):
            if values != tuple(sorted(set(values))):
                raise ValueError("claim citations must be unique and sorted")
        if not (self.advisory_provenance_ids or self.evidence_ids or self.signal_ids):
            raise ValueError("every investigation claim requires a citation")
        return self


class ModelInvestigationDraft(InvestigationModel):
    disposition: InvestigationDisposition
    claims: tuple[InvestigationClaim, ...] = Field(max_length=256)
    assumptions: tuple[InvestigationAssumptionCode, ...] = Field(max_length=128)
    missing_evidence: tuple[MissingEvidenceCode, ...] = Field(max_length=256)
    validation_actions: tuple[ValidationActionCode, ...] = Field(max_length=128)

    @model_validator(mode="after")
    def validate_ordering(self) -> Self:
        for values in (self.assumptions, self.missing_evidence, self.validation_actions):
            if values != tuple(sorted(set(values))):
                raise ValueError("model draft codes must be unique and sorted")
        return self


class InvestigationResult(InvestigationModel):
    id: ResultId
    status: InvestigationRunStatus
    advisory_id: BoundedString
    snapshot: InventorySnapshot
    envelope_id: EnvelopeId
    configuration_sha256: DigestSha256
    producer: InvestigationProducer
    model: ModelIdentifier | None
    gateway_kind: StableCode | None
    disposition: InvestigationDisposition | None = None
    claims: tuple[InvestigationClaim, ...] = Field(default=(), max_length=256)
    assumptions: tuple[InvestigationAssumptionCode, ...] = Field(default=(), max_length=128)
    missing_evidence: tuple[MissingEvidenceCode, ...] = Field(default=(), max_length=256)
    validation_actions: tuple[ValidationActionCode, ...] = Field(default=(), max_length=128)
    coverage: InvestigationCoverage
    error_code: StableCode | None = None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        from watchdog.investigation.identifiers import investigation_result_id

        accepted = self.status in {
            InvestigationRunStatus.COMPLETED,
            InvestigationRunStatus.INCOMPLETE_INPUT,
        }
        if accepted:
            if (
                self.disposition is None
                or self.error_code is not None
                or self.model is None
                or self.gateway_kind is None
            ):
                raise ValueError(
                    "accepted investigation results require disposition and model metadata"
                )
            if self.status == InvestigationRunStatus.INCOMPLETE_INPUT and self.disposition not in {
                InvestigationDisposition.INSUFFICIENT_EVIDENCE,
                InvestigationDisposition.UNSUPPORTED,
            }:
                raise ValueError("incomplete input cannot produce a positive disposition")
        elif (
            self.disposition is not None
            or self.claims
            or self.assumptions
            or self.missing_evidence
            or self.validation_actions
        ):
            raise ValueError("failed investigation runs cannot contain model output")
        elif self.error_code is None:
            raise ValueError("failed investigation runs require a controlled error code")
        if self.id != investigation_result_id(self):
            raise ValueError("investigation result identity does not match its payload")
        return self
