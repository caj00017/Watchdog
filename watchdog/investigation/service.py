from __future__ import annotations

import asyncio
import time

from watchdog.config.settings import Settings
from watchdog.domain.advisories import AdvisoryRecord
from watchdog.domain.context import ContextBundle
from watchdog.domain.evidence import EvidenceBundle
from watchdog.domain.inventory import DependencyInventory
from watchdog.domain.investigation import (
    InvestigationEnvelope,
    InvestigationResult,
    InvestigationRunStatus,
    ModelInvestigationDraft,
)
from watchdog.domain.matching import DependencyMatchReport
from watchdog.investigation.envelope import build_investigation_envelope
from watchdog.investigation.gateway import (
    GatewayError,
    GatewayInvalidResponseError,
    GatewayRequest,
    GatewayResponseTooLargeError,
    GatewayTimeoutError,
    ModelGateway,
)
from watchdog.investigation.identifiers import (
    canonical_json_bytes,
    investigation_configuration_sha256,
    investigation_result_id,
)
from watchdog.investigation.limits import InvestigationConfiguration
from watchdog.investigation.policy import InvestigationPolicyError, enforce_investigation_policy
from watchdog.investigation.prompts import MODEL_RESPONSE_SCHEMA, SYSTEM_INSTRUCTION
from watchdog.investigation.validation import (
    ModelResponseError,
    ModelResponseEvidenceError,
    validate_model_response,
)


class InvestigationService:
    """Internal evidence-bound model synthesis over immutable Phase 1–5 artifacts."""

    def __init__(
        self,
        configuration: InvestigationConfiguration | None = None,
        gateway: ModelGateway | None = None,
    ) -> None:
        configured = configuration or InvestigationConfiguration.from_settings(Settings())
        configured = InvestigationConfiguration.model_validate(configured.model_dump(mode="python"))
        self._configuration = configured
        self._configuration_sha256 = investigation_configuration_sha256(configured)
        self._semaphore = asyncio.Semaphore(configured.limits.max_concurrent_requests)
        self._gateway_kind: str | None
        if gateway is None and configured.enabled:
            from watchdog.investigation.loopback import LoopbackModelGateway

            gateway = LoopbackModelGateway(
                configured.loopback_host,
                configured.loopback_port,
            )
            self._gateway_kind = "loopback_openai_compatible"
        elif gateway is not None:
            self._gateway_kind = "injected_model_gateway"
        else:
            self._gateway_kind = None
        self._gateway = gateway

    @property
    def configuration(self) -> InvestigationConfiguration:
        return self._configuration

    async def investigate(
        self,
        advisory: AdvisoryRecord,
        inventory: DependencyInventory,
        match_report: DependencyMatchReport,
        evidence_bundle: EvidenceBundle,
        context_bundle: ContextBundle,
    ) -> InvestigationResult:
        envelope = build_investigation_envelope(
            advisory,
            inventory,
            match_report,
            evidence_bundle,
            context_bundle,
            self._configuration,
        )
        if not self._configuration.enabled:
            return self._failure_result(
                envelope,
                InvestigationRunStatus.DISABLED,
                "investigation_disabled",
            )
        if self._gateway is None or self._configuration.model is None:
            return self._failure_result(
                envelope,
                InvestigationRunStatus.GATEWAY_UNAVAILABLE,
                "investigation_gateway_unavailable",
            )
        request = GatewayRequest(
            model=self._configuration.model,
            system_instruction=SYSTEM_INSTRUCTION,
            data_message=canonical_json_bytes(envelope).decode("utf-8"),
            response_schema=MODEL_RESPONSE_SCHEMA,
            max_output_tokens=self._configuration.limits.max_output_tokens,
        )
        deadline = time.monotonic() + self._configuration.limits.deadline_seconds
        try:
            async with asyncio.timeout(self._configuration.limits.deadline_seconds):
                async with self._semaphore:
                    response = await self._gateway.complete(
                        request,
                        deadline=deadline,
                        max_response_bytes=self._configuration.limits.max_output_bytes,
                    )
            if response.gateway_kind != self._gateway_kind:
                return self._failure_result(
                    envelope,
                    InvestigationRunStatus.INVALID_RESPONSE,
                    "investigation_invalid_gateway_metadata",
                )
            if len(response.body) > self._configuration.limits.max_output_bytes:
                return self._failure_result(
                    envelope,
                    InvestigationRunStatus.RESPONSE_TOO_LARGE,
                    "investigation_response_too_large",
                )
            draft = validate_model_response(
                response.body,
                envelope,
                self._configuration.limits,
            )
            enforce_investigation_policy(draft, envelope)
            if time.monotonic() >= deadline:
                return self._failure_result(
                    envelope,
                    InvestigationRunStatus.TIMED_OUT,
                    "investigation_timed_out",
                )
            return self._accepted_result(envelope, draft)
        except asyncio.CancelledError:
            return self._failure_result(
                envelope,
                InvestigationRunStatus.CANCELLED,
                "investigation_cancelled",
            )
        except (TimeoutError, GatewayTimeoutError):
            return self._failure_result(
                envelope,
                InvestigationRunStatus.TIMED_OUT,
                "investigation_timed_out",
            )
        except GatewayResponseTooLargeError:
            return self._failure_result(
                envelope,
                InvestigationRunStatus.RESPONSE_TOO_LARGE,
                "investigation_response_too_large",
            )
        except GatewayInvalidResponseError:
            return self._failure_result(
                envelope,
                InvestigationRunStatus.INVALID_RESPONSE,
                "investigation_invalid_gateway_response",
            )
        except GatewayError:
            return self._failure_result(
                envelope,
                InvestigationRunStatus.GATEWAY_UNAVAILABLE,
                "investigation_gateway_unavailable",
            )
        except ModelResponseEvidenceError:
            return self._failure_result(
                envelope,
                InvestigationRunStatus.EVIDENCE_VALIDATION_FAILED,
                "investigation_evidence_validation_failed",
            )
        except ModelResponseError:
            return self._failure_result(
                envelope,
                InvestigationRunStatus.INVALID_RESPONSE,
                "investigation_invalid_response",
            )
        except InvestigationPolicyError:
            return self._failure_result(
                envelope,
                InvestigationRunStatus.POLICY_REJECTED,
                "investigation_policy_rejected",
            )

    def _accepted_result(
        self,
        envelope: InvestigationEnvelope,
        draft: ModelInvestigationDraft,
    ) -> InvestigationResult:
        status = (
            InvestigationRunStatus.INCOMPLETE_INPUT
            if envelope.coverage.input_partial
            else InvestigationRunStatus.COMPLETED
        )
        payload = {
            "status": status,
            "advisory_id": envelope.advisory.primary_id,
            "snapshot": envelope.snapshot,
            "envelope_id": envelope.id,
            "configuration_sha256": self._configuration_sha256,
            "producer": envelope.producer,
            "model": self._configuration.model,
            "gateway_kind": self._gateway_kind,
            "disposition": draft.disposition,
            "claims": draft.claims,
            "assumptions": draft.assumptions,
            "missing_evidence": draft.missing_evidence,
            "validation_actions": draft.validation_actions,
            "coverage": envelope.coverage,
            "error_code": None,
        }
        return InvestigationResult(id=investigation_result_id(payload), **payload)

    def _failure_result(
        self,
        envelope: InvestigationEnvelope,
        status: InvestigationRunStatus,
        error_code: str,
    ) -> InvestigationResult:
        payload = {
            "status": status,
            "advisory_id": envelope.advisory.primary_id,
            "snapshot": envelope.snapshot,
            "envelope_id": envelope.id,
            "configuration_sha256": self._configuration_sha256,
            "producer": envelope.producer,
            "model": self._configuration.model,
            "gateway_kind": self._gateway_kind,
            "disposition": None,
            "claims": (),
            "assumptions": (),
            "missing_evidence": (),
            "validation_actions": (),
            "coverage": envelope.coverage,
            "error_code": error_code,
        }
        return InvestigationResult(id=investigation_result_id(payload), **payload)
