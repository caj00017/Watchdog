from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from watchdog.config.settings import Settings


class RemediationLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    deadline_seconds: float = Field(gt=0, le=600)
    max_concurrent_requests: int = Field(ge=1, le=1)
    max_candidates: int = Field(gt=0, le=256)
    max_candidate_versions_per_match: int = Field(gt=0, le=64)
    max_preview_source_files: int = Field(gt=0, le=64)
    max_bytes_per_preview_source_file: int = Field(gt=0, le=5 * 1024 * 1024)
    max_total_preview_source_bytes: int = Field(gt=0, le=25 * 1024 * 1024)
    max_previews: int = Field(gt=0, le=64)
    max_diff_bytes_per_preview: int = Field(gt=0, le=64 * 1024)
    max_total_preview_display_bytes: int = Field(gt=0, le=1024 * 1024)
    max_warnings: int = Field(gt=0, le=512)
    max_validation_actions: int = Field(gt=0, le=64)
    max_json_bytes: int = Field(gt=0, le=1024 * 1024)
    max_markdown_bytes: int = Field(gt=0, le=1024 * 1024)

    @model_validator(mode="after")
    def validate_related_limits(self) -> Self:
        if self.max_bytes_per_preview_source_file > self.max_total_preview_source_bytes:
            raise ValueError("per-file remediation bytes cannot exceed total source bytes")
        if self.max_diff_bytes_per_preview > self.max_total_preview_display_bytes:
            raise ValueError("per-preview remediation display cannot exceed total display")
        return self

    @classmethod
    def from_settings(cls, settings: Settings) -> RemediationLimits:
        return cls(
            deadline_seconds=settings.remediation_deadline_seconds,
            max_concurrent_requests=settings.remediation_max_concurrent_requests,
            max_candidates=settings.remediation_max_candidates,
            max_candidate_versions_per_match=settings.remediation_max_candidate_versions_per_match,
            max_preview_source_files=settings.remediation_max_preview_source_files,
            max_bytes_per_preview_source_file=settings.remediation_max_bytes_per_preview_source_file,
            max_total_preview_source_bytes=settings.remediation_max_total_preview_source_bytes,
            max_previews=settings.remediation_max_previews,
            max_diff_bytes_per_preview=settings.remediation_max_diff_bytes_per_preview,
            max_total_preview_display_bytes=settings.remediation_max_total_preview_display_bytes,
            max_warnings=settings.remediation_max_warnings,
            max_validation_actions=settings.remediation_max_validation_actions,
            max_json_bytes=settings.remediation_max_json_bytes,
            max_markdown_bytes=settings.remediation_max_markdown_bytes,
        )


class RemediationConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^remediation-config:sha256:[0-9a-f]{64}$")
    enabled: bool = False
    preview_enabled: bool = False
    limits: RemediationLimits
    producer_version: Literal["1"] = "1"
    schema_version: Literal["1"] = "1"
    candidate_policy_version: Literal["1"] = "1"
    preview_policy_version: Literal["1"] = "1"
    locator_version: Literal["1"] = "1"
    semantic_reparse_version: Literal["1"] = "1"
    redaction_policy_version: Literal["1"] = "1"
    wording_policy_version: Literal["1"] = "1"
    json_renderer_version: Literal["1"] = "1"
    markdown_renderer_version: Literal["1"] = "1"

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        from watchdog.remediation.identifiers import remediation_configuration_id

        if self.id != remediation_configuration_id(self):
            raise ValueError("remediation configuration identity does not match its payload")
        return self

    @classmethod
    def from_settings(cls, settings: Settings) -> RemediationConfiguration:
        from watchdog.remediation.identifiers import remediation_configuration_id

        payload = {
            "enabled": settings.remediation_enabled,
            "preview_enabled": settings.remediation_preview_enabled,
            "limits": RemediationLimits.from_settings(settings),
            "producer_version": "1",
            "schema_version": "1",
            "candidate_policy_version": "1",
            "preview_policy_version": "1",
            "locator_version": "1",
            "semantic_reparse_version": "1",
            "redaction_policy_version": "1",
            "wording_policy_version": "1",
            "json_renderer_version": "1",
            "markdown_renderer_version": "1",
        }
        return cls(id=remediation_configuration_id(payload), **payload)
