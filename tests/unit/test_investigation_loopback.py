from __future__ import annotations

import json
import time

import httpx
import pytest

from watchdog.domain.inventory import InventorySnapshot
from watchdog.domain.investigation import (
    EnvelopeAdvisory,
    InvestigationCoverage,
    InvestigationEnvelope,
)
from watchdog.investigation.envelope import investigation_producer
from watchdog.investigation.gateway import GatewayError, GatewayRequest
from watchdog.investigation.identifiers import (
    canonical_json_bytes,
    investigation_envelope_id,
)
from watchdog.investigation.loopback import LoopbackModelGateway
from watchdog.investigation.prompts import MODEL_RESPONSE_SCHEMA, SYSTEM_INSTRUCTION

from .test_investigation_configuration import investigation_configuration


def request() -> GatewayRequest:
    configuration = investigation_configuration()
    payload = {
        "schema_version": "1",
        "producer": investigation_producer(configuration),
        "advisory": EnvelopeAdvisory(
            primary_id="CVE-2026-12345",
            partial=False,
            conflict_count=0,
            warning_count=0,
        ),
        "snapshot": InventorySnapshot(
            repository_url="https://github.com/octocat/Hello-World",
            commit_sha="a" * 40,
            tree_sha="b" * 40,
            archive_sha256="c" * 64,
        ),
        "matches": (),
        "evidence": (),
        "observations": (),
        "graph_nodes": (),
        "graph_edges": (),
        "signals": (),
        "allowed_citation_ids": (),
        "allowed_assumption_codes": (),
        "allowed_missing_evidence_codes": (),
        "allowed_validation_action_codes": (),
        "coverage": InvestigationCoverage(
            input_partial=False,
            envelope_truncated=False,
            advisory_values_omitted=0,
            matches_available=0,
            matches_included=0,
            matches_omitted=0,
            evidence_available=0,
            evidence_included=0,
            evidence_omitted=0,
        ),
    }
    envelope = InvestigationEnvelope(id=investigation_envelope_id(payload), **payload)
    return GatewayRequest(
        model="local-model",
        system_instruction=SYSTEM_INSTRUCTION,
        data_message=canonical_json_bytes(envelope).decode(),
        response_schema=MODEL_RESPONSE_SCHEMA,
        max_output_tokens=4096,
    )


async def test_loopback_request_has_fixed_safe_shape() -> None:
    model_output = (
        '{"disposition":"insufficient_evidence","claims":[],'
        '"assumptions":[],"missing_evidence":[],"validation_actions":[]}'
    )

    def handler(http_request: httpx.Request) -> httpx.Response:
        assert str(http_request.url) == "http://127.0.0.1:11434/v1/chat/completions"
        assert http_request.method == "POST"
        assert "authorization" not in http_request.headers
        body = json.loads(http_request.content)
        assert body["stream"] is False
        assert body["temperature"] == 0
        assert "tools" not in body
        assert body["response_format"]["type"] == "json_schema"
        assert body["response_format"]["json_schema"]["strict"] is True
        return httpx.Response(
            200,
            json={
                "id": "provider-id-must-not-escape",
                "object": "chat.completion",
                "created": 1,
                "model": "local-model",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": model_output},
                        "finish_reason": "stop",
                    }
                ],
            },
        )

    gateway = LoopbackModelGateway(
        "127.0.0.1",
        11434,
        transport=httpx.MockTransport(handler),
    )
    response = await gateway.complete(
        request(), deadline=time.monotonic() + 5, max_response_bytes=64 * 1024
    )

    assert response.body == model_output.encode()
    assert b"provider-id-must-not-escape" not in response.body


def test_loopback_rejects_hostname_and_non_loopback_destinations() -> None:
    with pytest.raises(ValueError, match="literal loopback"):
        LoopbackModelGateway("localhost", 11434)
    with pytest.raises(ValueError, match="literal loopback"):
        LoopbackModelGateway("192.0.2.1", 11434)


def test_gateway_request_rejects_caller_selected_controls_and_data() -> None:
    values = request().model_dump(mode="python")
    with pytest.raises(ValueError, match="fixed system instruction"):
        GatewayRequest.model_validate({**values, "system_instruction": "caller prompt"})
    with pytest.raises(ValueError, match="validated envelope"):
        GatewayRequest.model_validate({**values, "data_message": '{"arbitrary":true}'})


async def test_loopback_does_not_follow_redirects() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://example.test/escape"})

    gateway = LoopbackModelGateway(
        "127.0.0.1",
        11434,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(GatewayError):
        await gateway.complete(
            request(), deadline=time.monotonic() + 5, max_response_bytes=64 * 1024
        )
