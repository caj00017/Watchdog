from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from watchdog.config.settings import Settings
from watchdog.domain.investigation import ModelIdentifier


class InvestigationLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    deadline_seconds: float = Field(gt=0, le=600)
    max_concurrent_requests: Literal[1] = 1
    max_input_bytes: int = Field(gt=0, le=1024 * 1024)
    max_output_bytes: int = Field(gt=0, le=256 * 1024)
    max_evidence_items: int = Field(gt=0, le=1_000)
    max_matches: int = Field(default=256, gt=0, le=256)
    max_claims: int = Field(gt=0, le=256)
    max_evidence_links_per_claim: int = Field(gt=0, le=128)
    max_assumptions: int = Field(gt=0, le=128)
    max_missing_evidence_codes: int = Field(gt=0, le=256)
    max_validation_actions: int = Field(gt=0, le=128)
    max_rationale_bytes_per_claim: int = Field(gt=0, le=8_192)
    max_output_tokens: int = Field(gt=0, le=16_384)

    @classmethod
    def from_settings(cls, settings: Settings) -> InvestigationLimits:
        return cls(
            deadline_seconds=settings.investigation_deadline_seconds,
            max_concurrent_requests=settings.investigation_max_concurrent_requests,
            max_input_bytes=settings.investigation_max_input_bytes,
            max_output_bytes=settings.investigation_max_output_bytes,
            max_evidence_items=settings.investigation_max_evidence_items,
            max_claims=settings.investigation_max_claims,
            max_evidence_links_per_claim=settings.investigation_max_evidence_links_per_claim,
            max_assumptions=settings.investigation_max_assumptions,
            max_missing_evidence_codes=settings.investigation_max_missing_evidence_codes,
            max_validation_actions=settings.investigation_max_validation_actions,
            max_rationale_bytes_per_claim=settings.investigation_max_rationale_bytes_per_claim,
            max_output_tokens=settings.investigation_max_output_tokens,
        )


class InvestigationConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    loopback_host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    loopback_port: int = Field(default=11434, ge=1, le=65535)
    model: ModelIdentifier | None = None
    limits: InvestigationLimits
    producer_name: Literal["watchdog-investigation"] = "watchdog-investigation"
    producer_version: Literal["1"] = "1"
    envelope_schema_version: Literal["1"] = "1"
    response_schema_version: Literal["1"] = "1"
    prompt_version: Literal["1"] = "1"
    policy_version: Literal["1"] = "1"
    gateway_protocol_version: Literal["1"] = "1"

    @model_validator(mode="after")
    def validate_enabled_configuration(self) -> Self:
        if self.enabled and self.model is None:
            raise ValueError("enabled investigation requires an explicit model identifier")
        return self

    @classmethod
    def from_settings(cls, settings: Settings) -> InvestigationConfiguration:
        return cls(
            enabled=settings.investigation_enabled,
            loopback_host=settings.investigation_loopback_host,
            loopback_port=settings.investigation_loopback_port,
            model=settings.investigation_model,
            limits=InvestigationLimits.from_settings(settings),
        )
