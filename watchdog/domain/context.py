from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Annotated, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from watchdog.domain.evidence import EvidenceContent, EvidenceStatus, EvidenceTrustLevel
from watchdog.domain.inventory import Ecosystem, InventorySnapshot, VersionKind

StableName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9._-]{0,127}$")]
StableCode = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,127}$")]
SymbolToken = Annotated[str, StringConstraints(pattern=r"^[A-Za-z_$][A-Za-z0-9_$]{0,127}$")]
VersionString = Annotated[str, StringConstraints(min_length=1, max_length=128)]
BoundedString = Annotated[str, StringConstraints(min_length=1, max_length=4096)]
DigestSha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
ContextTargetId = Annotated[str, StringConstraints(pattern=r"^context-target:sha256:[0-9a-f]{64}$")]
ContextEvidenceId = Annotated[
    str, StringConstraints(pattern=r"^context-evidence:sha256:[0-9a-f]{64}$")
]
ContextObservationId = Annotated[
    str, StringConstraints(pattern=r"^context-observation:sha256:[0-9a-f]{64}$")
]
ContextNodeId = Annotated[str, StringConstraints(pattern=r"^context-node:sha256:[0-9a-f]{64}$")]
ContextEdgeId = Annotated[str, StringConstraints(pattern=r"^context-edge:sha256:[0-9a-f]{64}$")]
ContextSignalId = Annotated[str, StringConstraints(pattern=r"^context-signal:sha256:[0-9a-f]{64}$")]
ContextBundleId = Annotated[str, StringConstraints(pattern=r"^context-bundle:sha256:[0-9a-f]{64}$")]
Phase4EvidenceId = Annotated[str, StringConstraints(pattern=r"^evidence:sha256:[0-9a-f]{64}$")]


class ContextModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class MappingKind(StrEnum):
    GENERIC = "generic"
    CATALOG_EXACT = "catalog_exact"
    UNAVAILABLE = "unavailable"


class TargetApplicability(StrEnum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"


class SourceLanguage(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    GO = "go"
    JSON = "json"
    TOML = "toml"


class SourceFileStatus(StrEnum):
    ANALYZED = "analyzed"
    PARTIAL = "partial"
    OMITTED = "omitted"


class ContextCoverageKind(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"


class ContextEvidenceKind(StrEnum):
    LEXICAL_CONTEXT = "lexical_context"


class ObservationKind(StrEnum):
    IMPORT_DECLARATION = "import_declaration"
    TARGET_REFERENCE = "target_reference"
    EXPLICIT_CALL = "explicit_call"
    TARGET_CONFIGURATION = "target_configuration"
    ENDPOINT_DECLARATION = "endpoint_declaration"


class GraphNodeKind(StrEnum):
    SOURCE_FILE = "source_file"
    DEPENDENCY_TARGET = "dependency_target"
    IMPORT_DECLARATION = "import_declaration"
    BOUND_IDENTIFIER = "bound_identifier"
    EXPLICIT_REFERENCE = "explicit_reference"
    EXPLICIT_CALL = "explicit_call"
    CONFIGURATION_ENTRY = "configuration_entry"
    ENDPOINT_DECLARATION = "endpoint_declaration"


class GraphEdgeKind(StrEnum):
    IMPORTS = "imports"
    BINDS = "binds"
    REFERENCES = "references"
    CALLS = "calls"
    CONFIGURES = "configures"
    DECLARED_NEAR_ENDPOINT = "declared_near_endpoint"


class ContextSignalKind(StrEnum):
    EXPLICIT_TARGET_CALL_OBSERVED = "explicit_target_call_observed"
    TARGET_REFERENCE_OBSERVED = "target_reference_observed"
    DEPENDENCY_IMPORT_OBSERVED = "dependency_import_observed"
    TARGET_CONFIGURATION_OBSERVED = "target_configuration_observed"
    ENDPOINT_PROXIMITY_OBSERVED = "endpoint_proximity_observed"
    TARGET_USAGE_NOT_OBSERVED_WITHIN_COVERAGE = "target_usage_not_observed_within_coverage"
    CONTEXT_INCOMPLETE = "context_incomplete"
    CONTEXT_NOT_APPLICABLE = "context_not_applicable"


class ContextLimitation(StrEnum):
    IMPORT_MAPPING_INCOMPLETE = "import_mapping_incomplete"
    IMPORT_MAPPING_UNAVAILABLE = "import_mapping_unavailable"
    INVENTORY_INCOMPLETE = "inventory_incomplete"
    MATCH_REPORT_INCOMPLETE = "match_report_incomplete"
    DEPENDENCY_EVIDENCE_INCOMPLETE = "dependency_evidence_incomplete"
    DIRECTORY_EXCLUDED = "directory_excluded"
    CANDIDATE_PATH_LIMIT_EXCEEDED = "candidate_path_limit_exceeded"
    DIRECTORY_LIMIT_EXCEEDED = "directory_limit_exceeded"
    DIRECTORY_DEPTH_LIMIT_EXCEEDED = "directory_depth_limit_exceeded"
    PATH_LENGTH_LIMIT_EXCEEDED = "path_length_limit_exceeded"
    UNSAFE_SOURCE_PATH = "unsafe_source_path"
    SOURCE_TREE_CHANGED = "source_tree_changed"
    DUPLICATE_FILE_IDENTITY = "duplicate_file_identity"
    CASE_COLLIDING_PATH = "case_colliding_path"
    SOURCE_FILE_LIMIT_EXCEEDED = "source_file_limit_exceeded"
    SOURCE_FILE_BYTES_LIMIT_EXCEEDED = "source_file_bytes_limit_exceeded"
    SOURCE_TOTAL_BYTES_LIMIT_EXCEEDED = "source_total_bytes_limit_exceeded"
    SOURCE_FILE_UNREADABLE = "source_file_unreadable"
    SOURCE_FILE_CHANGED = "source_file_changed"
    SOURCE_NOT_REGULAR = "source_not_regular"
    SOURCE_SYMLINK_REJECTED = "source_symlink_rejected"
    INVALID_UTF8 = "invalid_utf8"
    RECOGNIZER_FAILED = "recognizer_failed"
    TOKEN_LIMIT_EXCEEDED = "token_limit_exceeded"
    TOTAL_TOKEN_LIMIT_EXCEEDED = "total_token_limit_exceeded"
    NESTING_DEPTH_EXCEEDED = "nesting_depth_exceeded"
    MALFORMED_SYNTAX = "malformed_syntax"
    UNSUPPORTED_SYNTAX = "unsupported_syntax"
    AMBIGUOUS_BINDING = "ambiguous_binding"
    RELATIVE_IMPORT_UNSUPPORTED = "relative_import_unsupported"
    STAR_IMPORT_UNSUPPORTED = "star_import_unsupported"
    DYNAMIC_IMPORT_UNSUPPORTED = "dynamic_import_unsupported"
    COMPUTED_MEMBER_UNSUPPORTED = "computed_member_unsupported"
    TEMPLATE_INTERPOLATION_UNSUPPORTED = "template_interpolation_unsupported"
    REEXPORT_UNSUPPORTED = "reexport_unsupported"
    DOT_IMPORT_UNSUPPORTED = "dot_import_unsupported"
    BLANK_IMPORT_UNSUPPORTED = "blank_import_unsupported"
    BUILD_CONSTRAINT_UNEVALUATED = "build_constraint_unevaluated"
    GENERATED_FILE_OMITTED = "generated_file_omitted"
    CGO_UNSUPPORTED = "cgo_unsupported"
    DYNAMIC_DISPATCH_UNRESOLVED = "dynamic_dispatch_unresolved"
    OBSERVATION_LIMIT_EXCEEDED = "observation_limit_exceeded"
    EVIDENCE_LIMIT_EXCEEDED = "evidence_limit_exceeded"
    LINE_SPAN_LIMIT_EXCEEDED = "line_span_limit_exceeded"
    DISPLAY_ITEM_BYTES_LIMIT_EXCEEDED = "display_item_bytes_limit_exceeded"
    BUNDLE_DISPLAY_BYTES_LIMIT_EXCEEDED = "bundle_display_bytes_limit_exceeded"
    REDACTION_FAILED = "redaction_failed"
    REDACTION_LIMIT_EXCEEDED = "redaction_limit_exceeded"
    GRAPH_NODE_LIMIT_EXCEEDED = "graph_node_limit_exceeded"
    GRAPH_EDGE_LIMIT_EXCEEDED = "graph_edge_limit_exceeded"
    WARNING_LIMIT_EXCEEDED = "warning_limit_exceeded"
    CONTEXT_DEADLINE_EXCEEDED = "context_deadline_exceeded"
    STATIC_NON_OBSERVATION_LIMITATION = (
        "static_non_observation_does_not_establish_runtime_absence_or_non_exposure"
    )


class ContextProducer(ContextModel):
    name: StableName
    version: VersionString
    python_recognizer_version: VersionString
    javascript_recognizer_version: VersionString
    go_recognizer_version: VersionString
    configuration_recognizer_version: VersionString
    graph_version: VersionString
    ranking_version: VersionString
    catalog_version: VersionString
    catalog_sha256: DigestSha256
    redaction_policy_version: VersionString


class CatalogMetadata(ContextModel):
    version: VersionString
    sha256: DigestSha256


class PackageMappingRule(ContextModel):
    id: StableName
    ecosystem: Ecosystem
    package_name: BoundedString
    import_roots: tuple[BoundedString, ...] = Field(min_length=1, max_length=32)
    complete: bool = True
    review_reference: BoundedString

    @model_validator(mode="after")
    def validate_roots(self) -> Self:
        _validate_package_identity(self.ecosystem, self.package_name)
        if self.import_roots != tuple(sorted(set(self.import_roots))):
            raise ValueError("catalog import roots must be unique and sorted")
        for root in self.import_roots:
            _validate_import_root(self.ecosystem, root)
        return self


class MemberRule(ContextModel):
    id: StableName
    ecosystem: Ecosystem
    package_name: BoundedString
    member_path: tuple[SymbolToken, ...] = Field(min_length=1, max_length=16)
    observation_kind: ObservationKind
    review_reference: BoundedString

    @model_validator(mode="after")
    def validate_member_rule(self) -> Self:
        _validate_package_identity(self.ecosystem, self.package_name)
        if self.observation_kind not in {
            ObservationKind.TARGET_REFERENCE,
            ObservationKind.EXPLICIT_CALL,
        }:
            raise ValueError("catalog member rules must describe a reference or call")
        return self


class ConfigurationRule(ContextModel):
    id: StableName
    ecosystem: Ecosystem
    package_name: BoundedString
    keys: tuple[BoundedString, ...] = Field(min_length=1, max_length=32)
    normalized_paths: tuple[BoundedString, ...] = Field(default=(), max_length=32)
    review_reference: BoundedString

    @model_validator(mode="after")
    def validate_ordering_and_paths(self) -> Self:
        _validate_package_identity(self.ecosystem, self.package_name)
        if self.keys != tuple(sorted(set(self.keys))):
            raise ValueError("catalog configuration keys must be unique and sorted")
        if self.normalized_paths != tuple(sorted(set(self.normalized_paths))):
            raise ValueError("catalog configuration paths must be unique and sorted")
        for path in self.normalized_paths:
            _validate_repository_path(path)
            if not path.endswith((".json", ".toml")):
                raise ValueError("catalog configuration paths must be JSON or TOML")
        return self


class EndpointRule(ContextModel):
    id: StableName
    ecosystem: Ecosystem
    package_name: BoundedString
    import_root: BoundedString
    member_paths: tuple[tuple[SymbolToken, ...], ...] = Field(min_length=1, max_length=32)
    proximity_lines: int = Field(default=100, ge=0, le=100)
    review_reference: BoundedString

    @model_validator(mode="after")
    def validate_members(self) -> Self:
        _validate_package_identity(self.ecosystem, self.package_name)
        _validate_import_root(self.ecosystem, self.import_root)
        if self.member_paths != tuple(sorted(set(self.member_paths))):
            raise ValueError("catalog endpoint members must be unique and sorted")
        if any(not path for path in self.member_paths):
            raise ValueError("catalog endpoint member paths must not be empty")
        return self


class ContextRuleCatalog(ContextModel):
    version: VersionString
    package_mappings: tuple[PackageMappingRule, ...] = Field(default=(), max_length=10_000)
    member_rules: tuple[MemberRule, ...] = Field(default=(), max_length=10_000)
    configuration_rules: tuple[ConfigurationRule, ...] = Field(default=(), max_length=10_000)
    endpoint_rules: tuple[EndpointRule, ...] = Field(default=(), max_length=10_000)

    @model_validator(mode="after")
    def validate_catalog(self) -> Self:
        families = (
            self.package_mappings,
            self.member_rules,
            self.configuration_rules,
            self.endpoint_rules,
        )
        all_ids = tuple(rule.id for family in families for rule in family)
        if len(set(all_ids)) != len(all_ids):
            raise ValueError("catalog rule IDs must be globally unique")
        for family in families:
            ids = tuple(rule.id for rule in family)
            if ids != tuple(sorted(ids)):
                raise ValueError("catalog rule families must be sorted by rule ID")
        mapping_keys = tuple(
            (rule.ecosystem.value, rule.package_name) for rule in self.package_mappings
        )
        if len(set(mapping_keys)) != len(mapping_keys):
            raise ValueError("catalog package mappings must not conflict")
        mapped_roots: list[tuple[Ecosystem, str, str]] = []
        for rule in self.package_mappings:
            for root in rule.import_roots:
                for ecosystem, other_root, other_id in mapped_roots:
                    separator = "." if ecosystem == Ecosystem.PYPI else "/"
                    if ecosystem == rule.ecosystem and (
                        root == other_root
                        or root.startswith(other_root + separator)
                        or other_root.startswith(root + separator)
                    ):
                        raise ValueError(
                            f"catalog import roots overlap between {other_id} and {rule.id}"
                        )
                mapped_roots.append((rule.ecosystem, root, rule.id))
        member_keys = tuple(
            (rule.ecosystem, rule.package_name, rule.member_path, rule.observation_kind)
            for rule in self.member_rules
        )
        if len(set(member_keys)) != len(member_keys):
            raise ValueError("catalog member rules must not be ambiguous")
        configuration_keys = tuple(
            (rule.ecosystem, rule.package_name, key, path)
            for rule in self.configuration_rules
            for key in rule.keys
            for path in (rule.normalized_paths or ("<language>",))
        )
        if len(set(configuration_keys)) != len(configuration_keys):
            raise ValueError("catalog configuration rules must not be ambiguous")
        endpoint_keys = tuple(
            (rule.ecosystem, rule.package_name, path)
            for rule in self.endpoint_rules
            for path in rule.member_paths
        )
        if len(set(endpoint_keys)) != len(endpoint_keys):
            raise ValueError("catalog endpoint rules must not be ambiguous")
        return self


class ContextTarget(ContextModel):
    id: ContextTargetId
    match_ordinal: int = Field(ge=0)
    component_id: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    ecosystem: Ecosystem
    package_name: BoundedString
    version: Annotated[str, StringConstraints(max_length=4096)] | None = None
    version_kind: VersionKind
    applicability: TargetApplicability = TargetApplicability.APPLICABLE
    mapping_kind: MappingKind
    mapping_complete: bool
    import_roots: tuple[BoundedString, ...] = Field(default=(), max_length=32)
    member_rule_ids: tuple[StableName, ...] = Field(default=(), max_length=128)
    configuration_rule_ids: tuple[StableName, ...] = Field(default=(), max_length=128)
    endpoint_rule_ids: tuple[StableName, ...] = Field(default=(), max_length=128)
    dependency_evidence_ids: tuple[Phase4EvidenceId, ...] = Field(default=(), max_length=10_000)
    limitation_codes: tuple[ContextLimitation, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        _validate_package_identity(self.ecosystem, self.package_name)
        for root in self.import_roots:
            _validate_import_root(self.ecosystem, root)
        for values, label in (
            (self.import_roots, "import roots"),
            (self.member_rule_ids, "member rule IDs"),
            (self.configuration_rule_ids, "configuration rule IDs"),
            (self.endpoint_rule_ids, "endpoint rule IDs"),
            (self.dependency_evidence_ids, "dependency evidence IDs"),
            (self.limitation_codes, "target limitations"),
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError(f"context target {label} must be unique and sorted")
        if self.mapping_kind == MappingKind.UNAVAILABLE:
            if self.import_roots or self.mapping_complete:
                raise ValueError("unavailable mappings cannot contain import roots")
            if ContextLimitation.IMPORT_MAPPING_UNAVAILABLE not in self.limitation_codes:
                raise ValueError("unavailable mappings require an explicit limitation")
        elif not self.import_roots:
            raise ValueError("available mappings require at least one import root")
        if (
            not self.mapping_complete
            and self.mapping_kind != MappingKind.UNAVAILABLE
            and ContextLimitation.IMPORT_MAPPING_INCOMPLETE not in self.limitation_codes
        ):
            raise ValueError("incomplete mappings require an explicit limitation")
        if self.mapping_complete and any(
            code
            in {
                ContextLimitation.IMPORT_MAPPING_INCOMPLETE,
                ContextLimitation.IMPORT_MAPPING_UNAVAILABLE,
            }
            for code in self.limitation_codes
        ):
            raise ValueError("complete mappings cannot carry mapping limitations")
        from watchdog.context.identifiers import context_target_id

        if self.id != context_target_id(self):
            raise ValueError("context target identity does not match its canonical payload")
        return self


class ContextAnchor(ContextModel):
    start_line: int = Field(ge=1)
    start_column: int = Field(ge=0)
    end_line: int = Field(ge=1)
    end_column: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        if (self.end_line, self.end_column) < (self.start_line, self.start_column):
            raise ValueError("context anchor end must not precede its start")
        return self


class ContextSource(ContextModel):
    repository_url: BoundedString
    commit_sha: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    tree_sha: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    path: BoundedString
    file_sha256: DigestSha256
    anchor: ContextAnchor
    trust_level: EvidenceTrustLevel = EvidenceTrustLevel.UNTRUSTED_REPOSITORY

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        _validate_repository_path(value)
        return value


class ContextEvidenceItem(ContextModel):
    id: ContextEvidenceId
    kind: ContextEvidenceKind = ContextEvidenceKind.LEXICAL_CONTEXT
    producer: ContextProducer
    source: ContextSource
    match_ordinal: int = Field(ge=0)
    target_id: ContextTargetId
    dependency_evidence_ids: tuple[Phase4EvidenceId, ...] = Field(min_length=1, max_length=10_000)
    observation_kind: ObservationKind
    rule_id: StableName | None = None
    status: EvidenceStatus
    content: EvidenceContent | None = None
    limitation_codes: tuple[ContextLimitation, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        if self.dependency_evidence_ids != tuple(sorted(set(self.dependency_evidence_ids))):
            raise ValueError("context evidence dependency links must be unique and sorted")
        if self.limitation_codes != tuple(sorted(set(self.limitation_codes))):
            raise ValueError("context evidence limitations must be unique and sorted")
        if self.status == EvidenceStatus.CONTENT_OMITTED:
            if self.content is not None or not self.limitation_codes:
                raise ValueError("omitted context evidence requires limitations and no content")
        elif self.content is None or self.limitation_codes:
            raise ValueError("included context evidence requires content and no limitations")
        elif self.status == EvidenceStatus.EXTRACTED and self.content.redacted:
            raise ValueError("extracted context evidence cannot have redactions")
        elif self.status == EvidenceStatus.REDACTED and not self.content.redacted:
            raise ValueError("redacted context evidence requires redaction records")
        elif self.content.truncated:
            raise ValueError("context evidence must omit display content that exceeds a limit")
        from watchdog.context.identifiers import context_evidence_id

        if self.id != context_evidence_id(self):
            raise ValueError("context evidence identity does not match its canonical payload")
        return self


class ContextObservation(ContextModel):
    id: ContextObservationId
    kind: ObservationKind
    match_ordinal: int = Field(ge=0)
    target_id: ContextTargetId
    evidence_id: ContextEvidenceId
    path: BoundedString
    anchor: ContextAnchor
    binding: SymbolToken | None = None
    member_path: tuple[SymbolToken, ...] = Field(default=(), max_length=16)
    rule_id: StableName | None = None

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        _validate_repository_path(value)
        return value

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        from watchdog.context.identifiers import context_observation_id

        if self.id != context_observation_id(self):
            raise ValueError("context observation identity does not match its canonical payload")
        return self


class ContextGraphNode(ContextModel):
    id: ContextNodeId
    kind: GraphNodeKind
    target_id: ContextTargetId | None = None
    path: BoundedString | None = None
    observation_id: ContextObservationId | None = None
    evidence_ids: tuple[ContextEvidenceId, ...] = Field(min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def validate_node(self) -> Self:
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise ValueError("graph node evidence IDs must be unique and sorted")
        if self.path is not None:
            _validate_repository_path(self.path)
        if self.kind == GraphNodeKind.DEPENDENCY_TARGET:
            if self.target_id is None or self.path is not None or self.observation_id is not None:
                raise ValueError("dependency target nodes require only a target ID")
        elif self.kind == GraphNodeKind.SOURCE_FILE:
            if self.path is None or self.target_id is not None or self.observation_id is not None:
                raise ValueError("source-file nodes require only a path")
        elif self.target_id is None or self.path is None or self.observation_id is None:
            raise ValueError("lexical graph nodes require target, path, and observation IDs")
        from watchdog.context.identifiers import context_node_id

        if self.id != context_node_id(self):
            raise ValueError("context graph node identity does not match its canonical payload")
        return self


class ContextGraphEdge(ContextModel):
    id: ContextEdgeId
    kind: GraphEdgeKind
    from_node_id: ContextNodeId
    to_node_id: ContextNodeId
    evidence_ids: tuple[ContextEvidenceId, ...] = Field(min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def validate_edge(self) -> Self:
        if self.from_node_id == self.to_node_id:
            raise ValueError("context graph edges cannot be self-referential")
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise ValueError("graph edge evidence IDs must be unique and sorted")
        from watchdog.context.identifiers import context_edge_id

        if self.id != context_edge_id(self):
            raise ValueError("context graph edge identity does not match its canonical payload")
        return self


class ContextSignal(ContextModel):
    id: ContextSignalId
    kind: ContextSignalKind
    match_ordinal: int = Field(ge=0)
    rank: int = Field(ge=1, le=1_000)
    target_id: ContextTargetId | None = None
    dependency_evidence_ids: tuple[Phase4EvidenceId, ...] = Field(default=(), max_length=10_000)
    evidence_ids: tuple[ContextEvidenceId, ...] = Field(default=(), max_length=10_000)
    limitation_codes: tuple[ContextLimitation, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_signal(self) -> Self:
        if self.dependency_evidence_ids != tuple(sorted(set(self.dependency_evidence_ids))):
            raise ValueError("context signal dependency evidence IDs must be unique and sorted")
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise ValueError("context signal context evidence IDs must be unique and sorted")
        if self.limitation_codes != tuple(sorted(set(self.limitation_codes))):
            raise ValueError("context signal limitations must be unique and sorted")
        positive = self.kind in {
            ContextSignalKind.EXPLICIT_TARGET_CALL_OBSERVED,
            ContextSignalKind.TARGET_REFERENCE_OBSERVED,
            ContextSignalKind.DEPENDENCY_IMPORT_OBSERVED,
            ContextSignalKind.TARGET_CONFIGURATION_OBSERVED,
            ContextSignalKind.ENDPOINT_PROXIMITY_OBSERVED,
        }
        if positive and (
            not self.evidence_ids or self.target_id is None or not self.dependency_evidence_ids
        ):
            raise ValueError(
                "positive context signals require target, Phase 4, and context evidence links"
            )
        if self.kind == ContextSignalKind.TARGET_USAGE_NOT_OBSERVED_WITHIN_COVERAGE:
            if self.evidence_ids or self.target_id is None or not self.dependency_evidence_ids:
                raise ValueError(
                    "non-observation requires a target, Phase 4 evidence, "
                    "and no invented context evidence"
                )
            required = ContextLimitation.STATIC_NON_OBSERVATION_LIMITATION
            if required not in self.limitation_codes:
                raise ValueError("non-observation requires the fixed static limitation")
        if self.kind == ContextSignalKind.CONTEXT_INCOMPLETE and not self.limitation_codes:
            raise ValueError("incomplete context signals require limitations")
        if self.kind == ContextSignalKind.CONTEXT_NOT_APPLICABLE and self.target_id is not None:
            raise ValueError("not-applicable signals cannot reference a target")
        if self.kind == ContextSignalKind.CONTEXT_NOT_APPLICABLE and self.dependency_evidence_ids:
            raise ValueError("not-applicable signals cannot reference dependency evidence")
        from watchdog.context.identifiers import context_signal_id

        if self.id != context_signal_id(self):
            raise ValueError("context signal identity does not match its canonical payload")
        return self


class SourceFileOutcome(ContextModel):
    path: BoundedString
    language: SourceLanguage
    status: SourceFileStatus
    file_sha256: DigestSha256 | None = None
    byte_count: int = Field(ge=0)
    lexical_tokens: int = Field(ge=0)
    observation_ids: tuple[ContextObservationId, ...] = Field(default=(), max_length=50_000)
    limitation_codes: tuple[ContextLimitation, ...] = Field(default=(), max_length=128)
    test_source: bool = False

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        _validate_repository_path(value)
        return value

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if self.observation_ids != tuple(sorted(set(self.observation_ids))):
            raise ValueError("file observation IDs must be unique and sorted")
        if self.limitation_codes != tuple(sorted(set(self.limitation_codes))):
            raise ValueError("file limitations must be unique and sorted")
        if self.status == SourceFileStatus.ANALYZED:
            if self.file_sha256 is None or self.limitation_codes:
                raise ValueError("analyzed files require a digest and no limitations")
        elif not self.limitation_codes:
            raise ValueError("partial or omitted files require limitations")
        if self.status == SourceFileStatus.PARTIAL and self.file_sha256 is None:
            raise ValueError("partially analyzed files require their complete digest")
        if self.status == SourceFileStatus.OMITTED and (
            self.observation_ids
            or self.file_sha256 is not None
            or self.byte_count
            or self.lexical_tokens
        ):
            raise ValueError("omitted files cannot contain digest, content counts, or observations")
        return self


class ContextWarning(ContextModel):
    code: ContextLimitation
    message: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    path: BoundedString | None = None
    match_ordinal: int | None = Field(default=None, ge=0)
    coverage_limited: bool = True

    @field_validator("path")
    @classmethod
    def validate_optional_path(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_repository_path(value)
        return value


class MatchContextLink(ContextModel):
    match_ordinal: int = Field(ge=0)
    target_id: ContextTargetId | None = None
    dependency_evidence_ids: tuple[Phase4EvidenceId, ...] = Field(default=(), max_length=10_000)
    context_evidence_ids: tuple[ContextEvidenceId, ...] = Field(default=(), max_length=10_000)
    observation_ids: tuple[ContextObservationId, ...] = Field(default=(), max_length=50_000)
    signal_ids: tuple[ContextSignalId, ...] = Field(min_length=1, max_length=16)
    limitation_codes: tuple[ContextLimitation, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_link(self) -> Self:
        for values in (
            self.dependency_evidence_ids,
            self.context_evidence_ids,
            self.observation_ids,
            self.signal_ids,
            self.limitation_codes,
        ):
            if values != tuple(sorted(set(values))):
                raise ValueError("match context links must contain unique sorted IDs and codes")
        return self


class ContextCoverage(ContextModel):
    kind: ContextCoverageKind
    directories_enumerated: int = Field(ge=0)
    candidate_paths: int = Field(ge=0)
    excluded_directories: int = Field(ge=0)
    eligible_source_files: int = Field(ge=0)
    files_read: int = Field(ge=0)
    source_bytes_read: int = Field(ge=0)
    lexical_tokens: int = Field(ge=0)
    observations: int = Field(ge=0)
    evidence_items: int = Field(ge=0)
    graph_nodes: int = Field(ge=0)
    graph_edges: int = Field(ge=0)
    signals: int = Field(ge=0)
    limitation_codes: tuple[ContextLimitation, ...] = Field(default=(), max_length=256)

    @model_validator(mode="after")
    def validate_coverage(self) -> Self:
        if self.files_read > self.eligible_source_files:
            raise ValueError("context files read cannot exceed eligible source files")
        if self.limitation_codes != tuple(sorted(set(self.limitation_codes))):
            raise ValueError("context coverage limitations must be unique and sorted")
        partial = bool(self.limitation_codes)
        if (self.kind == ContextCoverageKind.PARTIAL) != partial:
            raise ValueError("context coverage kind must agree with limitations")
        return self


class ContextBundle(ContextModel):
    id: ContextBundleId
    snapshot: InventorySnapshot
    configuration: ContextConfiguration
    configuration_sha256: DigestSha256
    catalog: CatalogMetadata
    targets: tuple[ContextTarget, ...] = Field(default=(), max_length=100_000)
    file_outcomes: tuple[SourceFileOutcome, ...] = Field(default=(), max_length=100_001)
    evidence: tuple[ContextEvidenceItem, ...] = Field(default=(), max_length=10_000)
    observations: tuple[ContextObservation, ...] = Field(default=(), max_length=50_000)
    graph_nodes: tuple[ContextGraphNode, ...] = Field(default=(), max_length=50_000)
    graph_edges: tuple[ContextGraphEdge, ...] = Field(default=(), max_length=100_000)
    signals: tuple[ContextSignal, ...] = Field(default=(), max_length=100_000)
    match_links: tuple[MatchContextLink, ...] = Field(default=(), max_length=100_000)
    warnings: tuple[ContextWarning, ...] = Field(default=(), max_length=1_000)
    coverage: ContextCoverage
    partial: bool

    @model_validator(mode="after")
    def validate_bundle(self) -> Self:
        from watchdog.context.identifiers import context_bundle_id, context_configuration_sha256

        if self.configuration_sha256 != context_configuration_sha256(self.configuration):
            raise ValueError("context configuration digest does not match configuration")
        if (
            self.catalog.version != self.configuration.catalog_version
            or self.catalog.sha256 != self.configuration.catalog_sha256
        ):
            raise ValueError("context catalog metadata disagrees with configuration")
        producer = ContextProducer(
            name=self.configuration.producer_name,
            version=self.configuration.producer_version,
            python_recognizer_version=self.configuration.python_recognizer_version,
            javascript_recognizer_version=self.configuration.javascript_recognizer_version,
            go_recognizer_version=self.configuration.go_recognizer_version,
            configuration_recognizer_version=self.configuration.configuration_recognizer_version,
            graph_version=self.configuration.graph_version,
            ranking_version=self.configuration.ranking_version,
            catalog_version=self.configuration.catalog_version,
            catalog_sha256=self.configuration.catalog_sha256,
            redaction_policy_version=self.configuration.redaction_policy_version,
        )
        for item in self.evidence:
            if item.producer != producer:
                raise ValueError("context evidence producer disagrees with configuration")
            if (
                item.source.repository_url != self.snapshot.repository_url
                or item.source.commit_sha != self.snapshot.commit_sha
                or item.source.tree_sha != self.snapshot.tree_sha
            ):
                raise ValueError("context evidence source snapshot disagrees with bundle")
            if item.source.anchor.end_line - item.source.anchor.start_line + 1 > (
                self.configuration.limits.max_line_span
            ):
                raise ValueError("context evidence line range exceeds configured limit")
            if item.content is not None and (
                item.content.byte_count > self.configuration.limits.max_display_bytes_per_item
                or len(item.content.redactions) > self.configuration.limits.max_redactions_per_item
            ):
                raise ValueError("context evidence content exceeds configured limit")
        collections = (
            (self.targets, lambda item: (item.match_ordinal, item.id), "targets"),
            (self.file_outcomes, lambda item: item.path.encode("utf-8"), "file outcomes"),
            (self.evidence, lambda item: item.id, "evidence"),
            (self.observations, lambda item: item.id, "observations"),
            (self.graph_nodes, lambda item: item.id, "graph nodes"),
            (self.graph_edges, lambda item: item.id, "graph edges"),
            (self.signals, lambda item: (item.match_ordinal, item.rank, item.id), "signals"),
        )
        for values, key, label in collections:
            if tuple(sorted(values, key=key)) != values:
                raise ValueError(f"context {label} must be canonically sorted")
            ids = tuple(getattr(item, "id", getattr(item, "path", None)) for item in values)
            if len(set(ids)) != len(ids):
                raise ValueError(f"context {label} must be unique")
        ordinals = tuple(link.match_ordinal for link in self.match_links)
        if ordinals != tuple(range(len(ordinals))):
            raise ValueError("context match links must use contiguous ordered ordinals")
        warning_keys = tuple(
            (
                warning.code.value,
                warning.path or "",
                warning.match_ordinal if warning.match_ordinal is not None else -1,
                warning.message,
            )
            for warning in self.warnings
        )
        if warning_keys != tuple(sorted(warning_keys)):
            raise ValueError("context warnings must be canonically sorted")
        if len(set(warning_keys)) != len(warning_keys):
            raise ValueError("context warnings must be unique")
        target_ids = {target.id for target in self.targets}
        targets_by_id = {target.id: target for target in self.targets}
        target_ordinals = tuple(target.match_ordinal for target in self.targets)
        if len(set(target_ordinals)) != len(target_ordinals):
            raise ValueError("context targets must contain at most one target per match")
        evidence_ids = {evidence_item.id for evidence_item in self.evidence}
        evidence_by_id = {evidence_item.id: evidence_item for evidence_item in self.evidence}
        observation_ids = {observation.id for observation in self.observations}
        observations_by_id = {observation.id: observation for observation in self.observations}
        node_ids = {node.id for node in self.graph_nodes}
        nodes_by_id = {node.id: node for node in self.graph_nodes}
        signal_ids = {signal.id for signal in self.signals}
        phase4_ids = {
            evidence_id for target in self.targets for evidence_id in target.dependency_evidence_ids
        }
        for evidence_item in self.evidence:
            linked_target = targets_by_id.get(evidence_item.target_id)
            if (
                linked_target is None
                or evidence_item.match_ordinal != linked_target.match_ordinal
                or evidence_item.dependency_evidence_ids != linked_target.dependency_evidence_ids
            ):
                raise ValueError("context evidence contains a broken target or Phase 4 link")
        for observation in self.observations:
            linked_target = targets_by_id.get(observation.target_id)
            supporting_evidence = evidence_by_id.get(observation.evidence_id)
            if (
                linked_target is None
                or observation.match_ordinal != linked_target.match_ordinal
                or supporting_evidence is None
                or supporting_evidence.target_id != observation.target_id
                or supporting_evidence.match_ordinal != observation.match_ordinal
                or supporting_evidence.observation_kind != observation.kind
                or supporting_evidence.source.path != observation.path
                or supporting_evidence.source.anchor != observation.anchor
                or supporting_evidence.rule_id != observation.rule_id
            ):
                raise ValueError("context observation contains a broken evidence or target link")
        for node in self.graph_nodes:
            if not set(node.evidence_ids) <= evidence_ids:
                raise ValueError("context graph node contains a broken evidence link")
            if node.target_id is not None and node.target_id not in target_ids:
                raise ValueError("context graph node contains a broken target link")
            if node.observation_id is not None and node.observation_id not in observation_ids:
                raise ValueError("context graph node contains a broken observation link")
            node_evidence = tuple(evidence_by_id[evidence_id] for evidence_id in node.evidence_ids)
            if node.kind == GraphNodeKind.DEPENDENCY_TARGET and any(
                item.target_id != node.target_id for item in node_evidence
            ):
                raise ValueError("dependency target graph node cites unrelated evidence")
            if node.kind == GraphNodeKind.SOURCE_FILE and any(
                item.source.path != node.path for item in node_evidence
            ):
                raise ValueError("source-file graph node cites unrelated evidence")
            if node.observation_id is not None:
                node_observation = observations_by_id[node.observation_id]
                if (
                    node_observation.target_id != node.target_id
                    or node_observation.path != node.path
                    or node_observation.evidence_id not in node.evidence_ids
                ):
                    raise ValueError("lexical graph node cites unrelated observation evidence")
        for edge in self.graph_edges:
            if (
                edge.from_node_id not in node_ids
                or edge.to_node_id not in node_ids
                or not set(edge.evidence_ids) <= evidence_ids
            ):
                raise ValueError("context graph edge contains a broken link")
            relationship = (
                nodes_by_id[edge.from_node_id].kind,
                nodes_by_id[edge.to_node_id].kind,
            )
            expected_relationships = {
                GraphEdgeKind.IMPORTS: (
                    GraphNodeKind.SOURCE_FILE,
                    GraphNodeKind.DEPENDENCY_TARGET,
                ),
                GraphEdgeKind.BINDS: (
                    GraphNodeKind.IMPORT_DECLARATION,
                    GraphNodeKind.BOUND_IDENTIFIER,
                ),
                GraphEdgeKind.REFERENCES: (
                    GraphNodeKind.BOUND_IDENTIFIER,
                    GraphNodeKind.EXPLICIT_REFERENCE,
                ),
                GraphEdgeKind.CALLS: (
                    GraphNodeKind.EXPLICIT_REFERENCE,
                    GraphNodeKind.EXPLICIT_CALL,
                ),
                GraphEdgeKind.CONFIGURES: (
                    GraphNodeKind.CONFIGURATION_ENTRY,
                    GraphNodeKind.DEPENDENCY_TARGET,
                ),
                GraphEdgeKind.DECLARED_NEAR_ENDPOINT: (
                    GraphNodeKind.EXPLICIT_CALL,
                    GraphNodeKind.ENDPOINT_DECLARATION,
                ),
            }
            if relationship != expected_relationships[edge.kind]:
                raise ValueError("context graph edge has an invalid lexical relationship")
            related_evidence = {
                *nodes_by_id[edge.from_node_id].evidence_ids,
                *nodes_by_id[edge.to_node_id].evidence_ids,
            }
            if not set(edge.evidence_ids).issubset(related_evidence):
                raise ValueError("context graph edge cites evidence unrelated to its nodes")
        for signal in self.signals:
            linked_target = (
                targets_by_id.get(signal.target_id) if signal.target_id is not None else None
            )
            if signal.target_id is not None and (
                linked_target is None
                or signal.match_ordinal != linked_target.match_ordinal
                or signal.dependency_evidence_ids != linked_target.dependency_evidence_ids
            ):
                raise ValueError("context signal contains a broken target or Phase 4 link")
            if not set(signal.dependency_evidence_ids) <= phase4_ids:
                raise ValueError("context signal contains broken dependency evidence IDs")
            if not set(signal.evidence_ids) <= evidence_ids:
                raise ValueError("context signal contains a broken evidence link")
            if signal.target_id is not None and any(
                evidence_by_id[evidence_id].target_id != signal.target_id
                or evidence_by_id[evidence_id].match_ordinal != signal.match_ordinal
                for evidence_id in signal.evidence_ids
            ):
                raise ValueError("context signal cites evidence unrelated to its target")
            allowed_signal_evidence = {
                ContextSignalKind.EXPLICIT_TARGET_CALL_OBSERVED: {ObservationKind.EXPLICIT_CALL},
                ContextSignalKind.TARGET_REFERENCE_OBSERVED: {ObservationKind.TARGET_REFERENCE},
                ContextSignalKind.DEPENDENCY_IMPORT_OBSERVED: {ObservationKind.IMPORT_DECLARATION},
                ContextSignalKind.TARGET_CONFIGURATION_OBSERVED: {
                    ObservationKind.TARGET_CONFIGURATION
                },
                ContextSignalKind.ENDPOINT_PROXIMITY_OBSERVED: {
                    ObservationKind.EXPLICIT_CALL,
                    ObservationKind.ENDPOINT_DECLARATION,
                },
            }
            expected_evidence_kinds = allowed_signal_evidence.get(signal.kind)
            if expected_evidence_kinds is not None and any(
                evidence_by_id[evidence_id].observation_kind not in expected_evidence_kinds
                for evidence_id in signal.evidence_ids
            ):
                raise ValueError("context signal cites evidence of an invalid observation kind")
        for link in self.match_links:
            linked_target = (
                targets_by_id.get(link.target_id) if link.target_id is not None else None
            )
            if link.target_id is not None and (
                linked_target is None
                or linked_target.match_ordinal != link.match_ordinal
                or link.dependency_evidence_ids != linked_target.dependency_evidence_ids
            ):
                raise ValueError("match context link contains a broken target or Phase 4 link")
            if link.target_id is None and link.dependency_evidence_ids:
                raise ValueError("not-applicable match links cannot contain dependency evidence")
            expected_context_ids = tuple(
                item.id for item in self.evidence if item.match_ordinal == link.match_ordinal
            )
            expected_observation_ids = tuple(
                item.id for item in self.observations if item.match_ordinal == link.match_ordinal
            )
            expected_signal_ids = tuple(
                sorted(item.id for item in self.signals if item.match_ordinal == link.match_ordinal)
            )
            if (
                link.context_evidence_ids != expected_context_ids
                or link.observation_ids != expected_observation_ids
                or link.signal_ids != expected_signal_ids
            ):
                raise ValueError("match context link does not exactly represent its match items")
        linked_target_ids = {
            link.target_id for link in self.match_links if link.target_id is not None
        }
        if linked_target_ids != target_ids:
            raise ValueError("context targets must be represented by exactly one match link")
        linked_context_ids = {
            evidence_id for link in self.match_links for evidence_id in link.context_evidence_ids
        }
        linked_observation_ids = {
            observation_id for link in self.match_links for observation_id in link.observation_ids
        }
        linked_signal_ids = {
            signal_id for link in self.match_links for signal_id in link.signal_ids
        }
        if (
            linked_context_ids != evidence_ids
            or linked_observation_ids != observation_ids
            or linked_signal_ids != signal_ids
        ):
            raise ValueError("context bundle contains items not represented by match links")
        for outcome in self.file_outcomes:
            expected_file_observations = tuple(
                item.id for item in self.observations if item.path == outcome.path
            )
            if outcome.observation_ids != expected_file_observations:
                raise ValueError("context file outcome does not exactly represent its observations")
            if any(
                evidence_by_id[observations_by_id[observation_id].evidence_id].source.file_sha256
                != outcome.file_sha256
                for observation_id in outcome.observation_ids
            ):
                raise ValueError("context file outcome digest disagrees with its evidence")
        counts = (
            len(self.observations),
            len(self.evidence),
            len(self.graph_nodes),
            len(self.graph_edges),
            len(self.signals),
        )
        coverage_counts = (
            self.coverage.observations,
            self.coverage.evidence_items,
            self.coverage.graph_nodes,
            self.coverage.graph_edges,
            self.coverage.signals,
        )
        if counts != coverage_counts:
            raise ValueError("context bundle collections disagree with coverage counts")
        read_outcomes = tuple(
            outcome for outcome in self.file_outcomes if outcome.status != SourceFileStatus.OMITTED
        )
        if (
            self.coverage.files_read != len(read_outcomes)
            or self.coverage.source_bytes_read
            != sum(outcome.byte_count for outcome in read_outcomes)
            or self.coverage.lexical_tokens
            != sum(outcome.lexical_tokens for outcome in read_outcomes)
        ):
            raise ValueError("context file outcomes disagree with coverage counts")
        limits = self.configuration.limits
        if (
            self.coverage.directories_enumerated > limits.max_directories
            or self.coverage.candidate_paths > limits.max_candidate_paths
            or self.coverage.eligible_source_files > limits.max_source_files + 1
            or self.coverage.files_read > limits.max_source_files
            or self.coverage.source_bytes_read > limits.max_total_source_bytes
            or self.coverage.lexical_tokens > limits.max_total_tokens
            or self.coverage.observations > limits.max_observations
            or self.coverage.graph_nodes > limits.max_graph_nodes
            or self.coverage.graph_edges > limits.max_graph_edges
        ):
            raise ValueError("context coverage exceeds configured limits")
        if any(outcome.byte_count > limits.max_bytes_per_source_file for outcome in read_outcomes):
            raise ValueError("context file outcome exceeds the per-file byte limit")
        if len(self.evidence) > self.configuration.limits.max_evidence_items:
            raise ValueError("context bundle exceeds configured evidence-item limit")
        if len(self.warnings) > self.configuration.limits.max_warnings:
            raise ValueError("context bundle exceeds configured warning limit")
        represented_limitations = (
            {code for target in self.targets for code in target.limitation_codes}
            | {code for outcome in self.file_outcomes for code in outcome.limitation_codes}
            | {warning.code for warning in self.warnings}
            | {code for item in self.evidence for code in item.limitation_codes}
        )
        if not represented_limitations.issubset(set(self.coverage.limitation_codes)):
            raise ValueError("context bundle limitations disagree with represented outcomes")
        if sum(item.content.byte_count for item in self.evidence if item.content is not None) > (
            self.configuration.limits.max_bundle_display_bytes
        ):
            raise ValueError("context bundle exceeds configured display-byte limit")
        if self.partial != (self.coverage.kind == ContextCoverageKind.PARTIAL):
            raise ValueError("context bundle partial flag disagrees with coverage")
        if self.id != context_bundle_id(self):
            raise ValueError("context bundle identity does not match its canonical payload")
        return self


# Resolve the forward reference without making the domain module filesystem-facing.
from watchdog.context.limits import ContextConfiguration  # noqa: E402

ContextBundle.model_rebuild()


def _validate_repository_path(path: str) -> None:
    if path.startswith("/") or "\\" in path:
        raise ValueError("context path must be repository-relative POSIX")
    if any(part in {"", ".", ".."} for part in path.split("/")):
        raise ValueError("context path must be normalized")
    if len(path.encode("utf-8")) > 4096:
        raise ValueError("context path exceeds the schema byte bound")
    if any(ord(character) < 32 or ord(character) == 127 for character in path):
        raise ValueError("context path must not contain control characters")


def _validate_package_identity(ecosystem: Ecosystem, value: str) -> None:
    if value != value.strip() or any(
        character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ValueError("catalog package identity must be normalized and contain no controls")
    if ecosystem == Ecosystem.PYPI:
        if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", value) is None:
            raise ValueError("catalog Python package identity must use its normalized name")
    elif ecosystem == Ecosystem.NPM:
        if re.fullmatch(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*", value) is None:
            raise ValueError("catalog npm package identity must use its normalized name")
    elif (
        value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ValueError("catalog Go module identity must be a normalized module path")


def _validate_import_root(ecosystem: Ecosystem, value: str) -> None:
    if ecosystem == Ecosystem.PYPI:
        parts = value.split(".")
        if any(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part) is None for part in parts):
            raise ValueError("catalog Python import root must be a dotted identifier")
        return
    if ecosystem == Ecosystem.NPM:
        package = "/".join(value.split("/")[:2]) if value.startswith("@") else value.split("/")[0]
        _validate_package_identity(ecosystem, package)
        if any(part in {"", ".", ".."} for part in value.split("/")):
            raise ValueError("catalog npm import root must be a normalized package subpath")
        return
    _validate_package_identity(ecosystem, value)


def content_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
