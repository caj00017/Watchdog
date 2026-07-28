from __future__ import annotations

import hashlib
import re
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

from watchdog.domain.inventory import InventorySnapshot, SourceReference, SourceSelector
from watchdog.domain.matching import MatchState

NonEmptyString = Annotated[str, StringConstraints(min_length=1, max_length=4096)]
VersionString = Annotated[str, StringConstraints(min_length=1, max_length=128)]
BoundedLimitation = Annotated[str, StringConstraints(max_length=4096)]
StableName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9._-]{0,127}$")]
StableCode = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,127}$")]
DigestSha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
CommitSha = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
EvidenceId = Annotated[str, StringConstraints(pattern=r"^evidence:sha256:[0-9a-f]{64}$")]
BundleId = Annotated[str, StringConstraints(pattern=r"^bundle:sha256:[0-9a-f]{64}$")]


class EvidenceKind(StrEnum):
    DEPENDENCY_SOURCE = "dependency_source"


class EvidenceStatus(StrEnum):
    EXTRACTED = "extracted"
    REDACTED = "redacted"
    CONTENT_OMITTED = "content_omitted"


class EvidenceTrustLevel(StrEnum):
    UNTRUSTED_REPOSITORY = "untrusted_repository"


class EvidenceCoverageKind(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"


class EvidenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class EvidenceProducer(EvidenceModel):
    name: StableName
    version: VersionString
    selector_resolver_version: VersionString
    redaction_policy_version: VersionString


class SourceLineRange(EvidenceModel):
    start: int = Field(ge=1)
    end: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        if self.end < self.start:
            raise ValueError("source line range end must not precede its start")
        return self


class EvidenceSource(EvidenceModel):
    repository_url: NonEmptyString
    commit_sha: CommitSha
    tree_sha: CommitSha
    path: NonEmptyString
    selector: SourceSelector
    line_range: SourceLineRange | None = None
    file_sha256: DigestSha256
    trust_level: EvidenceTrustLevel = EvidenceTrustLevel.UNTRUSTED_REPOSITORY

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if value.startswith("/") or "\\" in value:
            raise ValueError("evidence source path must be repository-relative POSIX")
        if any(part in {"", ".", ".."} for part in value.split("/")):
            raise ValueError("evidence source path must be normalized")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("evidence source path must not contain control characters")
        return value

    @field_validator("selector")
    @classmethod
    def validate_selector(cls, value: SourceSelector) -> SourceSelector:
        _validate_source_selector(value)
        return value


class RedactionRecord(EvidenceModel):
    category: StableCode
    detector: StableName
    detector_version: VersionString
    ordinal: int = Field(ge=1)
    replacement: Literal["[REDACTED]"] = "[REDACTED]"


class EvidenceContent(EvidenceModel):
    text: Annotated[str, StringConstraints(max_length=5 * 1024 * 1024)]
    sha256: DigestSha256
    byte_count: int = Field(ge=0, le=5 * 1024 * 1024)
    redacted: bool
    truncated: bool
    redactions: tuple[RedactionRecord, ...] = Field(default=(), max_length=100_000)

    @model_validator(mode="after")
    def validate_content(self) -> Self:
        encoded = self.text.encode("utf-8")
        if len(encoded) != self.byte_count:
            raise ValueError("evidence content byte count does not match text")
        if hashlib.sha256(encoded).hexdigest() != self.sha256:
            raise ValueError("evidence content digest does not match text")
        if self.redacted != bool(self.redactions):
            raise ValueError("evidence redacted flag must agree with redaction records")
        ordinals = tuple(record.ordinal for record in self.redactions)
        if ordinals != tuple(range(1, len(ordinals) + 1)):
            raise ValueError("redaction ordinals must be contiguous and ordered")
        return self


class EvidenceItem(EvidenceModel):
    id: EvidenceId
    kind: EvidenceKind = EvidenceKind.DEPENDENCY_SOURCE
    producer: EvidenceProducer
    source: EvidenceSource
    status: EvidenceStatus
    content: EvidenceContent | None = None
    limitation_codes: tuple[StableCode, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_status_and_identity(self) -> Self:
        if self.status == EvidenceStatus.CONTENT_OMITTED:
            if self.content is not None or not self.limitation_codes:
                raise ValueError("omitted evidence requires limitations and no content")
        elif self.content is None or self.limitation_codes:
            raise ValueError("included evidence requires content and no limitation codes")
        elif self.status == EvidenceStatus.EXTRACTED and self.content.redacted:
            raise ValueError("extracted evidence cannot contain redaction records")
        elif self.status == EvidenceStatus.REDACTED and not self.content.redacted:
            raise ValueError("redacted evidence requires at least one redaction record")
        if len(set(self.limitation_codes)) != len(self.limitation_codes):
            raise ValueError("evidence limitation codes must be unique")
        from watchdog.evidence.identifiers import evidence_item_id

        if self.id != evidence_item_id(self):
            raise ValueError("evidence item identity does not match its canonical payload")
        return self


class MatchSourceOutcome(EvidenceModel):
    source: SourceReference
    evidence_id: EvidenceId | None = None
    limitation_codes: tuple[StableCode, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if len(self.source.path) > 4096 or any(
            ord(character) < 32 or ord(character) == 127 for character in self.source.path
        ):
            raise ValueError("match source path exceeds the evidence schema bound")
        _validate_source_selector(self.source.selector)
        if self.evidence_id is None and not self.limitation_codes:
            raise ValueError("a source outcome without evidence requires a limitation")
        if len(set(self.limitation_codes)) != len(self.limitation_codes):
            raise ValueError("source outcome limitation codes must be unique")
        return self


class MatchEvidenceLink(EvidenceModel):
    match_ordinal: int = Field(ge=0)
    advisory_component_index: int = Field(ge=0)
    component_id: Annotated[str, StringConstraints(min_length=1, max_length=256)] | None = None
    match_state: MatchState
    match_coverage_limitations: tuple[BoundedLimitation, ...] = Field(default=(), max_length=1024)
    evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=10_000)
    source_outcomes: tuple[MatchSourceOutcome, ...] = Field(default=(), max_length=10_000)
    limitation_codes: tuple[StableCode, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def validate_link(self) -> Self:
        source_keys = tuple(
            _source_reference_key(outcome.source) for outcome in self.source_outcomes
        )
        if source_keys != tuple(sorted(source_keys)) or len(set(source_keys)) != len(source_keys):
            raise ValueError("match source outcomes must be unique and canonically ordered")
        outcome_ids = tuple(
            outcome.evidence_id
            for outcome in self.source_outcomes
            if outcome.evidence_id is not None
        )
        if self.evidence_ids != outcome_ids:
            raise ValueError("match evidence IDs must agree with source outcomes")
        expected_limitations = tuple(
            dict.fromkeys(
                code for outcome in self.source_outcomes for code in outcome.limitation_codes
            )
        )
        if self.limitation_codes != expected_limitations:
            raise ValueError("match limitation codes must agree with source outcomes")
        return self


class EvidenceWarning(EvidenceModel):
    code: StableCode
    message: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    path: Annotated[str, StringConstraints(min_length=1, max_length=4096)] | None = None
    selector: SourceSelector | None = None
    coverage_limited: bool = True

    @field_validator("path")
    @classmethod
    def validate_optional_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value.startswith("/") or "\\" in value:
            raise ValueError("warning path must be repository-relative POSIX")
        if any(part in {"", ".", ".."} for part in value.split("/")):
            raise ValueError("warning path must be normalized")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("warning path must not contain control characters")
        return value

    @field_validator("selector")
    @classmethod
    def validate_optional_selector(cls, value: SourceSelector | None) -> SourceSelector | None:
        if value is not None:
            _validate_source_selector(value)
        return value


class EvidenceCoverage(EvidenceModel):
    kind: EvidenceCoverageKind
    source_references: int = Field(ge=0)
    unique_source_files: int = Field(ge=0)
    files_read: int = Field(ge=0)
    source_bytes_read: int = Field(ge=0)
    evidence_items: int = Field(ge=0)
    extracted_items: int = Field(ge=0)
    redacted_items: int = Field(ge=0)
    omitted_items: int = Field(ge=0)
    overflow_outcomes: int = Field(ge=0)
    limitation_codes: tuple[StableCode, ...] = Field(default=(), max_length=256)

    @model_validator(mode="after")
    def validate_counts(self) -> Self:
        if self.evidence_items != self.extracted_items + self.redacted_items + self.omitted_items:
            raise ValueError("evidence coverage item counts disagree")
        if self.files_read > self.unique_source_files:
            raise ValueError("files read cannot exceed unique source files")
        partial = bool(self.omitted_items or self.overflow_outcomes or self.limitation_codes)
        if (self.kind == EvidenceCoverageKind.PARTIAL) != partial:
            raise ValueError("evidence coverage kind does not agree with limitations")
        return self


class EvidenceBundle(EvidenceModel):
    id: BundleId
    snapshot: InventorySnapshot
    configuration: EvidenceConfiguration
    configuration_sha256: DigestSha256
    items: tuple[EvidenceItem, ...] = Field(default=(), max_length=10_000)
    match_links: tuple[MatchEvidenceLink, ...] = Field(default=(), max_length=100_000)
    warnings: tuple[EvidenceWarning, ...] = Field(default=(), max_length=1_000)
    coverage: EvidenceCoverage
    partial: bool

    @model_validator(mode="after")
    def validate_bundle(self) -> Self:
        from watchdog.evidence.identifiers import (
            evidence_bundle_id,
            evidence_configuration_sha256,
        )

        if self.configuration_sha256 != evidence_configuration_sha256(self.configuration):
            raise ValueError("evidence configuration digest does not match configuration")
        if tuple(sorted(self.items, key=lambda item: item.id)) != self.items:
            raise ValueError("evidence items must be sorted by evidence ID")
        item_ids = tuple(item.id for item in self.items)
        if len(set(item_ids)) != len(item_ids):
            raise ValueError("evidence item IDs must be unique")
        ordinals = tuple(link.match_ordinal for link in self.match_links)
        if ordinals != tuple(range(len(ordinals))):
            raise ValueError("match links must be ordered with contiguous ordinals")
        warning_keys = tuple(
            (
                warning.code,
                warning.path or "",
                warning.selector.kind.value if warning.selector else "",
                warning.selector.value if warning.selector else "",
                warning.message,
            )
            for warning in self.warnings
        )
        if warning_keys != tuple(sorted(warning_keys)):
            raise ValueError("evidence warnings must be deterministically sorted")
        linked_ids = {evidence_id for link in self.match_links for evidence_id in link.evidence_ids}
        if not linked_ids.issubset(set(item_ids)):
            raise ValueError("match links contain broken evidence IDs")
        if set(item_ids) != linked_ids:
            raise ValueError("evidence bundles cannot contain unlinked items")
        item_by_id = {item.id: item for item in self.items}
        for link in self.match_links:
            for outcome in link.source_outcomes:
                if outcome.evidence_id is None:
                    continue
                linked = item_by_id[outcome.evidence_id]
                if (
                    linked.source.path != outcome.source.path
                    or linked.source.selector != outcome.source.selector
                    or linked.source.file_sha256 != outcome.source.file_sha256
                ):
                    raise ValueError("match source outcome points to unrelated evidence")
        for item in self.items:
            source = item.source
            if (
                source.repository_url != self.snapshot.repository_url
                or source.commit_sha != self.snapshot.commit_sha
                or source.tree_sha != self.snapshot.tree_sha
            ):
                raise ValueError("evidence source snapshot disagrees with bundle snapshot")
            if item.producer != EvidenceProducer(
                name=self.configuration.producer_name,
                version=self.configuration.producer_version,
                selector_resolver_version=self.configuration.selector_resolver_version,
                redaction_policy_version=self.configuration.redaction_policy_version,
            ):
                raise ValueError("evidence producer disagrees with bundle configuration")
            if item.source.line_range is not None and (
                item.source.line_range.end - item.source.line_range.start + 1
                > self.configuration.limits.max_line_span
            ):
                raise ValueError("evidence line range exceeds configured limit")
            if item.content is not None:
                if item.content.byte_count > self.configuration.limits.max_display_bytes_per_item:
                    raise ValueError("evidence content exceeds configured item display limit")
                if len(item.content.redactions) > self.configuration.limits.max_redactions_per_item:
                    raise ValueError("evidence content exceeds configured redaction limit")
        if len(self.items) > self.configuration.limits.max_evidence_items:
            raise ValueError("bundle exceeds configured evidence-item limit")
        if len(self.warnings) > self.configuration.limits.max_warnings:
            raise ValueError("bundle exceeds configured warning limit")
        if (
            sum(item.content.byte_count for item in self.items if item.content is not None)
            > self.configuration.limits.max_bundle_display_bytes
        ):
            raise ValueError("bundle exceeds configured display-byte limit")
        actual_counts = (
            len(self.items),
            sum(item.status == EvidenceStatus.EXTRACTED for item in self.items),
            sum(item.status == EvidenceStatus.REDACTED for item in self.items),
            sum(item.status == EvidenceStatus.CONTENT_OMITTED for item in self.items),
        )
        coverage_counts = (
            self.coverage.evidence_items,
            self.coverage.extracted_items,
            self.coverage.redacted_items,
            self.coverage.omitted_items,
        )
        if actual_counts != coverage_counts:
            raise ValueError("bundle items disagree with coverage counts")
        source_outcomes = tuple(
            outcome for link in self.match_links for outcome in link.source_outcomes
        )
        source_keys = {_source_reference_key(outcome.source) for outcome in source_outcomes}
        if self.coverage.source_references != len(source_keys):
            raise ValueError("bundle source outcomes disagree with coverage counts")
        if self.coverage.unique_source_files != len(
            {outcome.source.path for outcome in source_outcomes}
        ):
            raise ValueError("bundle source files disagree with coverage counts")
        overflow_keys = {
            _source_reference_key(outcome.source)
            for outcome in source_outcomes
            if outcome.evidence_id is None
        }
        if self.coverage.overflow_outcomes != len(overflow_keys):
            raise ValueError("bundle overflow outcomes disagree with coverage counts")
        represented_limitations = {
            code for item in self.items for code in item.limitation_codes
        } | {code for link in self.match_links for code in link.limitation_codes}
        if not represented_limitations.issubset(set(self.coverage.limitation_codes)):
            raise ValueError("bundle limitations disagree with evidence and match links")
        if self.partial != (self.coverage.kind == EvidenceCoverageKind.PARTIAL):
            raise ValueError("bundle partial flag disagrees with evidence coverage")
        if self.id != evidence_bundle_id(self):
            raise ValueError("bundle identity does not match its canonical payload")
        return self


# Resolve the forward reference without importing filesystem-facing modules.
from watchdog.evidence.limits import EvidenceConfiguration  # noqa: E402

EvidenceBundle.model_rebuild()


def _validate_source_selector(selector: SourceSelector) -> None:
    value = selector.value
    if len(value) > 8192 or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ValueError("source selector must be bounded and contain no controls")
    if selector.kind.value == "line" and re.fullmatch(r"line:[1-9][0-9]*", value) is None:
        raise ValueError("line source selector is invalid")
    if selector.kind.value == "json_pointer":
        if value and not value.startswith("/"):
            raise ValueError("JSON Pointer source selector is invalid")
        if re.search(r"~(?![01])", value):
            raise ValueError("JSON Pointer source selector has invalid escaping")
    if selector.kind.value == "toml" and not value:
        raise ValueError("TOML source selector must be non-empty")


def _source_reference_key(reference: SourceReference) -> tuple[str, str, str, str]:
    return (
        reference.path,
        reference.selector.kind.value,
        reference.selector.value,
        reference.file_sha256,
    )
