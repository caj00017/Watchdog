from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, model_validator

from watchdog.domain.investigation import ModelIdentifier, StableName


class GatewayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    model: ModelIdentifier
    system_instruction: str = Field(min_length=1, max_length=16_384)
    data_message: str = Field(min_length=1, max_length=1024 * 1024)
    response_schema: dict[str, JsonValue]
    response_schema_name: StableName = "watchdog_investigation_v1"
    max_output_tokens: int = Field(gt=0, le=16_384)
    temperature: float = Field(default=0.0, ge=0.0, le=0.0)

    @model_validator(mode="after")
    def validate_fixed_assets_and_envelope(self) -> Self:
        from watchdog.domain.investigation import InvestigationEnvelope
        from watchdog.investigation.identifiers import canonical_json_bytes, canonical_sha256
        from watchdog.investigation.prompts import (
            MODEL_RESPONSE_SCHEMA_SHA256,
            SYSTEM_INSTRUCTION,
        )

        if self.system_instruction != SYSTEM_INSTRUCTION:
            raise ValueError("gateway request must use the fixed system instruction")
        if canonical_sha256(self.response_schema) != MODEL_RESPONSE_SCHEMA_SHA256:
            raise ValueError("gateway request must use the fixed response schema")
        if self.response_schema_name != "watchdog_investigation_v1":
            raise ValueError("gateway request must use the fixed response schema name")
        try:
            envelope = InvestigationEnvelope.model_validate_json(self.data_message)
        except ValidationError as exc:
            raise ValueError("gateway data message must be a validated envelope") from exc
        if canonical_json_bytes(envelope).decode("utf-8") != self.data_message:
            raise ValueError("gateway data message must use canonical JSON")
        return self


@dataclass(frozen=True, slots=True)
class GatewayResponse:
    body: bytes
    gateway_kind: str


class ModelGateway(Protocol):
    async def complete(
        self,
        request: GatewayRequest,
        *,
        deadline: float,
        max_response_bytes: int,
    ) -> GatewayResponse: ...


class GatewayError(Exception):
    """Controlled provider-neutral gateway failure without response content."""

    code = "gateway_unavailable"


class GatewayTimeoutError(GatewayError):
    code = "gateway_timeout"


class GatewayResponseTooLargeError(GatewayError):
    code = "gateway_response_too_large"


class GatewayInvalidResponseError(GatewayError):
    code = "gateway_invalid_response"
