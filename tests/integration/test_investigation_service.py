from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tests.investigation_fixtures import build_investigation_inputs
from tests.unit.test_investigation_configuration import (
    investigation_configuration,
    investigation_limits,
)
from tests.unit.test_investigation_validation import valid_observed_draft
from watchdog.domain.investigation import (
    EnvelopeEvidenceKind,
    InvestigationClaimKind,
    InvestigationDisposition,
    InvestigationRunStatus,
)
from watchdog.investigation.gateway import (
    GatewayResponse,
    GatewayTimeoutError,
    ModelGateway,
)
from watchdog.investigation.identifiers import canonical_json_bytes
from watchdog.investigation.service import InvestigationService


class FakeGateway(ModelGateway):
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.calls = 0

    async def complete(
        self,
        request: object,
        *,
        deadline: float,
        max_response_bytes: int,
    ) -> GatewayResponse:
        del request, deadline, max_response_bytes
        self.calls += 1
        return GatewayResponse(body=self.body, gateway_kind="injected_model_gateway")


class BlockingGateway(ModelGateway):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.stopped = asyncio.Event()

    async def complete(
        self,
        request: object,
        *,
        deadline: float,
        max_response_bytes: int,
    ) -> GatewayResponse:
        del request, deadline, max_response_bytes
        self.started.set()
        try:
            await asyncio.Event().wait()
        finally:
            self.stopped.set()
        raise AssertionError("unreachable")


class TimeoutGateway(ModelGateway):
    def __init__(self) -> None:
        self.calls = 0

    async def complete(
        self,
        request: object,
        *,
        deadline: float,
        max_response_bytes: int,
    ) -> GatewayResponse:
        del request, deadline, max_response_bytes
        self.calls += 1
        raise GatewayTimeoutError


class ConcurrencyGateway(ModelGateway):
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.active = 0
        self.maximum = 0
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def complete(
        self,
        request: object,
        *,
        deadline: float,
        max_response_bytes: int,
    ) -> GatewayResponse:
        del request, deadline, max_response_bytes
        self.active += 1
        self.maximum = max(self.maximum, self.active)
        self.entered.set()
        try:
            await self.release.wait()
            return GatewayResponse(body=self.body, gateway_kind="injected_model_gateway")
        finally:
            self.active -= 1


async def test_service_runs_after_cleanup_and_returns_content_addressed_inference(
    tmp_path: Path,
) -> None:
    inputs = await build_investigation_inputs(tmp_path)
    disabled = InvestigationService(investigation_configuration(enabled=False, model=None))
    disabled_result = await disabled.investigate(*inputs)
    assert disabled_result.status == InvestigationRunStatus.DISABLED

    from watchdog.investigation.envelope import build_investigation_envelope

    configuration = investigation_configuration()
    envelope = build_investigation_envelope(*inputs, configuration)
    gateway = FakeGateway(canonical_json_bytes(valid_observed_draft(envelope)))
    service = InvestigationService(configuration, gateway)

    first = await service.investigate(*inputs)
    second = await service.investigate(*inputs)

    assert first == second
    assert first.status == InvestigationRunStatus.COMPLETED
    assert first.disposition == InvestigationDisposition.DEPENDENCY_MATCH_AND_CONTEXT_OBSERVED
    assert first.claims[0].kind == InvestigationClaimKind.CONTEXTUAL_RELATIONSHIP
    assert first.model == "local-model"
    assert first.gateway_kind == "injected_model_gateway"
    assert gateway.calls == 2
    assert "IGNORE PRIOR INSTRUCTIONS" not in repr(first)


async def test_service_rejects_fabricated_evidence_and_partial_positive_result(
    tmp_path: Path,
) -> None:
    inputs = await build_investigation_inputs(tmp_path)
    configuration = investigation_configuration()
    from watchdog.investigation.envelope import build_investigation_envelope

    envelope = build_investigation_envelope(*inputs, configuration)
    fabricated = valid_observed_draft(envelope)
    claim = dict(fabricated["claims"][0])  # type: ignore[index]
    claim["evidence_ids"] = ["evidence:sha256:" + "f" * 64]
    fabricated["claims"] = [claim]
    invalid_result = await InvestigationService(
        configuration, FakeGateway(canonical_json_bytes(fabricated))
    ).investigate(*inputs)
    assert invalid_result.status == InvestigationRunStatus.EVIDENCE_VALIDATION_FAILED
    assert not invalid_result.claims

    partial_configuration = configuration.model_copy(
        update={"limits": investigation_limits(max_evidence_items=1)}
    )
    partial_envelope = build_investigation_envelope(*inputs, partial_configuration)
    phase4_id = next(
        item.id
        for item in partial_envelope.evidence
        if item.kind == EnvelopeEvidenceKind.DEPENDENCY_SOURCE
    )
    unconfirmed = {
        "disposition": InvestigationDisposition.DEPENDENCY_MATCH_CONTEXT_UNCONFIRMED,
        "claims": [
            {
                "kind": InvestigationClaimKind.DEPENDENCY_RELATIONSHIP,
                "summary": "An exact dependency match is present.",
                "rationale": None,
                "advisory_provenance_ids": [],
                "evidence_ids": [phase4_id],
                "signal_ids": [],
            }
        ],
        "assumptions": [],
        "missing_evidence": [],
        "validation_actions": [],
    }
    rejected = await InvestigationService(
        partial_configuration,
        FakeGateway(canonical_json_bytes(unconfirmed)),
    ).investigate(*inputs)
    assert rejected.status == InvestigationRunStatus.POLICY_REJECTED
    assert rejected.disposition is None


async def test_cancellation_waits_for_gateway_cleanup_and_returns_controlled_status(
    tmp_path: Path,
) -> None:
    inputs = await build_investigation_inputs(tmp_path)
    gateway = BlockingGateway()
    service = InvestigationService(investigation_configuration(), gateway)
    task = asyncio.create_task(service.investigate(*inputs))
    await gateway.started.wait()

    task.cancel()
    result = await task

    assert gateway.stopped.is_set()
    assert result.status == InvestigationRunStatus.CANCELLED
    assert not result.claims


async def test_invalid_input_never_invokes_gateway(tmp_path: Path) -> None:
    advisory, inventory, report, evidence, context = await build_investigation_inputs(tmp_path)
    gateway = FakeGateway(b"{}")
    service = InvestigationService(investigation_configuration(), gateway)
    mismatched = inventory.model_copy(
        update={"snapshot": inventory.snapshot.model_copy(update={"tree_sha": "f" * 40})}
    )

    with pytest.raises(ValueError, match="exact snapshot"):
        await service.investigate(advisory, mismatched, report, evidence, context)
    assert gateway.calls == 0


async def test_oversized_fake_response_is_rejected_before_parsing(tmp_path: Path) -> None:
    inputs = await build_investigation_inputs(tmp_path)
    configuration = investigation_configuration()
    gateway = FakeGateway(b"x" * (configuration.limits.max_output_bytes + 1))

    result = await InvestigationService(configuration, gateway).investigate(*inputs)

    assert result.status == InvestigationRunStatus.RESPONSE_TOO_LARGE
    assert result.disposition is None


async def test_timeout_has_no_retry_and_concurrency_is_one(tmp_path: Path) -> None:
    inputs = await build_investigation_inputs(tmp_path)
    configuration = investigation_configuration()
    timeout_gateway = TimeoutGateway()
    timeout_result = await InvestigationService(configuration, timeout_gateway).investigate(*inputs)
    assert timeout_result.status == InvestigationRunStatus.TIMED_OUT
    assert timeout_gateway.calls == 1

    from watchdog.investigation.envelope import build_investigation_envelope

    envelope = build_investigation_envelope(*inputs, configuration)
    gateway = ConcurrencyGateway(canonical_json_bytes(valid_observed_draft(envelope)))
    service = InvestigationService(configuration, gateway)
    first = asyncio.create_task(service.investigate(*inputs))
    second = asyncio.create_task(service.investigate(*inputs))
    await gateway.entered.wait()
    await asyncio.sleep(0)
    assert gateway.maximum == 1
    gateway.release.set()
    results = await asyncio.gather(first, second)
    assert all(result.status == InvestigationRunStatus.COMPLETED for result in results)
    assert gateway.maximum == 1
