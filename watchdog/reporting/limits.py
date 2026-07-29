from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from watchdog.config.settings import Settings


class ReportingLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_json_bytes: int = Field(gt=0, le=1_048_576)
    max_markdown_bytes: int = Field(gt=0, le=1_048_576)
    max_entries: int = Field(gt=0, le=1_024)
    max_evidence_references: int = Field(gt=0, le=2_048)
    max_diagnostics: int = Field(gt=0, le=512)

    @model_validator(mode="after")
    def validate_related_limits(self) -> Self:
        if self.max_entries > self.max_evidence_references:
            raise ValueError("report entries cannot exceed the evidence-reference ceiling")
        return self

    @classmethod
    def from_settings(cls, settings: Settings) -> ReportingLimits:
        return cls(
            max_json_bytes=settings.workflow_max_report_json_bytes,
            max_markdown_bytes=settings.workflow_max_markdown_bytes,
            max_entries=settings.workflow_max_report_entries,
            max_evidence_references=settings.workflow_max_evidence_references,
            max_diagnostics=settings.workflow_max_report_diagnostics,
        )


class ReportingConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    limits: ReportingLimits
    producer_name: Literal["watchdog-reporting"] = "watchdog-reporting"
    producer_version: Literal["1"] = "1"
    schema_version: Literal["1"] = "1"
    wording_policy_version: Literal["1"] = "1"
    json_renderer_version: Literal["1"] = "1"
    markdown_renderer_version: Literal["1"] = "1"

    @classmethod
    def from_settings(cls, settings: Settings) -> ReportingConfiguration:
        return cls(limits=ReportingLimits.from_settings(settings))
