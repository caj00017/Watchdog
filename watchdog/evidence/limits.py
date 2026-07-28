from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from watchdog.config.settings import Settings

DEFAULT_EVIDENCE_DETECTORS = tuple(
    sorted(
        (
            "private_key",
            "github_token",
            "gitlab_token",
            "slack_token",
            "npm_token",
            "pypi_token",
            "stripe_key",
            "google_api_key",
            "aws_access_key",
            "jwt",
            "uri_userinfo",
            "credential_assignment",
        )
    )
)


class EvidenceLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    deadline_seconds: float = Field(gt=0, le=600)
    max_source_files: int = Field(gt=0)
    max_bytes_per_source_file: int = Field(gt=0)
    max_total_source_bytes: int = Field(gt=0)
    max_evidence_items: int = Field(gt=0, le=10_000)
    max_line_span: int = Field(gt=0)
    max_display_bytes_per_item: int = Field(gt=0, le=5 * 1024 * 1024)
    max_bundle_display_bytes: int = Field(gt=0, le=5 * 1024 * 1024)
    max_redactions_per_item: int = Field(gt=0, le=100_000)
    max_warnings: int = Field(gt=0, le=1_000)

    @model_validator(mode="after")
    def validate_related_limits(self) -> Self:
        if self.max_bytes_per_source_file > self.max_total_source_bytes:
            raise ValueError("per-file evidence bytes cannot exceed total source bytes")
        if self.max_display_bytes_per_item > self.max_bundle_display_bytes:
            raise ValueError("per-item display bytes cannot exceed bundle display bytes")
        return self

    @classmethod
    def from_settings(cls, settings: Settings) -> EvidenceLimits:
        return cls(
            deadline_seconds=settings.evidence_deadline_seconds,
            max_source_files=settings.evidence_max_source_files,
            max_bytes_per_source_file=settings.evidence_max_bytes_per_source_file,
            max_total_source_bytes=settings.evidence_max_total_source_bytes,
            max_evidence_items=settings.evidence_max_items,
            max_line_span=settings.evidence_max_line_span,
            max_display_bytes_per_item=settings.evidence_max_display_bytes_per_item,
            max_bundle_display_bytes=settings.evidence_max_bundle_display_bytes,
            max_redactions_per_item=settings.evidence_max_redactions_per_item,
            max_warnings=settings.evidence_max_warnings,
        )


class EvidenceConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    limits: EvidenceLimits
    context_lines: int = Field(default=0, ge=0, le=0)
    enabled_detectors: tuple[str, ...] = Field(default=DEFAULT_EVIDENCE_DETECTORS, min_length=1)
    producer_name: str = Field(default="watchdog-evidence", pattern=r"^[a-z][a-z0-9._-]{0,127}$")
    producer_version: str = Field(default="1", min_length=1, max_length=128)
    selector_resolver_version: str = Field(default="1", min_length=1, max_length=128)
    redaction_policy_version: str = Field(default="1", min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_catalog(self) -> Self:
        if self.enabled_detectors != tuple(sorted(set(self.enabled_detectors))):
            raise ValueError("enabled evidence detectors must be unique and sorted")
        unknown = set(self.enabled_detectors).difference(DEFAULT_EVIDENCE_DETECTORS)
        if unknown:
            raise ValueError("evidence configuration contains an unknown detector")
        return self

    @classmethod
    def from_settings(cls, settings: Settings) -> EvidenceConfiguration:
        return cls(
            limits=EvidenceLimits.from_settings(settings),
            enabled_detectors=tuple(sorted(DEFAULT_EVIDENCE_DETECTORS)),
        )
