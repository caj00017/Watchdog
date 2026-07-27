from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints, model_validator

NonEmptyString = Annotated[str, StringConstraints(min_length=1)]


class DomainModel(BaseModel):
    """Base for immutable, source-neutral advisory domain models."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class FieldProvenance(DomainModel):
    """Identifies the exact upstream location supporting a normalized field."""

    source: NonEmptyString
    record_id: NonEmptyString
    source_url: NonEmptyString
    retrieved_at: datetime
    path: NonEmptyString


class Severity(DomainModel):
    type: NonEmptyString
    score: NonEmptyString


class VersionEvent(DomainModel):
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None

    @model_validator(mode="after")
    def require_exactly_one_event(self) -> Self:
        values = (self.introduced, self.fixed, self.last_affected, self.limit)
        if sum(value is not None for value in values) != 1:
            raise ValueError("a version event must contain exactly one event value")
        return self


class AffectedRange(DomainModel):
    type: NonEmptyString
    repository: str | None = None
    events: tuple[VersionEvent, ...] = ()


class AffectedPackage(DomainModel):
    ecosystem: NonEmptyString | None = None
    name: NonEmptyString | None = None
    purl: str | None = None
    ranges: tuple[AffectedRange, ...] = ()
    versions: tuple[str, ...] = ()

    @model_validator(mode="after")
    def require_component_identity(self) -> Self:
        if (self.ecosystem is None) != (self.name is None):
            raise ValueError("package ecosystem and name must be supplied together")
        has_repository = any(affected_range.repository for affected_range in self.ranges)
        if self.name is None and not has_repository:
            raise ValueError("a package-less affected component must identify a repository")
        return self


class AdvisoryReference(DomainModel):
    type: str | None = None
    url: NonEmptyString


class Remediation(DomainModel):
    type: NonEmptyString
    description: NonEmptyString
    package: str | None = None
    fixed_version: str | None = None


class SourceRecord(DomainModel):
    source: NonEmptyString
    record_id: NonEmptyString
    source_url: NonEmptyString
    retrieved_at: datetime
    raw: dict[str, JsonValue] = Field(default_factory=dict)


class ConflictValue(DomainModel):
    value: JsonValue
    provenance: tuple[FieldProvenance, ...] = Field(min_length=1)


class FieldConflict(DomainModel):
    field: NonEmptyString
    values: tuple[ConflictValue, ...] = Field(min_length=2)
    description: NonEmptyString


class AdvisoryRecord(DomainModel):
    """A normalized advisory with explicit provenance and uncertainty."""

    primary_id: NonEmptyString
    aliases: tuple[str, ...] = ()
    summary: str | None = None
    details: str | None = None
    published: datetime | None = None
    modified: datetime | None = None
    severity: tuple[Severity, ...] = ()
    affected_packages: tuple[AffectedPackage, ...] = ()
    cwes: tuple[str, ...] = ()
    references: tuple[AdvisoryReference, ...] = ()
    remediation: tuple[Remediation, ...] = ()
    sources: tuple[SourceRecord, ...] = Field(min_length=1)
    field_provenance: dict[str, tuple[FieldProvenance, ...]]
    conflicts: tuple[FieldConflict, ...] = ()
    partial: bool = False
    warnings: tuple[str, ...] = ()


def json_compatible(value: Any) -> JsonValue:
    """Convert a domain value into the JSON value used by conflict records."""

    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    return value  # type: ignore[no-any-return]
