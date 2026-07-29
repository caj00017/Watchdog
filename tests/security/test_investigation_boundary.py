from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from tests.investigation_fixtures import build_investigation_inputs
from tests.unit.test_investigation_configuration import investigation_configuration
from tests.unit.test_investigation_loopback import request as gateway_request
from watchdog.domain.investigation import InvestigationRunStatus
from watchdog.investigation.gateway import (
    GatewayInvalidResponseError,
    GatewayRequest,
    GatewayResponse,
    ModelGateway,
)
from watchdog.investigation.loopback import LoopbackModelGateway
from watchdog.investigation.service import InvestigationService


class SecretResponseGateway(ModelGateway):
    def __init__(self, secret: str) -> None:
        self.secret = secret

    async def complete(
        self,
        request: GatewayRequest,
        *,
        deadline: float,
        max_response_bytes: int,
    ) -> GatewayResponse:
        del request, deadline, max_response_bytes
        return GatewayResponse(body=self.secret.encode(), gateway_kind="injected_model_gateway")


class BlockingStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.closed = asyncio.Event()

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.started.set()
        await asyncio.Event().wait()
        yield b"unreachable"

    async def aclose(self) -> None:
        self.closed.set()


async def test_invalid_provider_text_never_enters_logs_or_result(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "SYNTHETIC_PHASE6_PROVIDER_SECRET"
    inputs = await build_investigation_inputs(tmp_path)
    caplog.set_level(logging.DEBUG)

    result = await InvestigationService(
        investigation_configuration(), SecretResponseGateway(secret)
    ).investigate(*inputs)

    assert result.status == InvestigationRunStatus.INVALID_RESPONSE
    assert secret not in repr(result)
    assert secret not in caplog.text


async def test_loopback_rejects_unknown_outer_fields_and_response_overflow() -> None:
    def unknown_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=(
                b'{"choices":[{"message":{"role":"assistant","content":"{}"}}],'
                b'"redirect_destination":"https://example.test"}'
            ),
        )

    gateway = LoopbackModelGateway(
        "127.0.0.1",
        11434,
        transport=httpx.MockTransport(unknown_handler),
    )
    with pytest.raises(GatewayInvalidResponseError):
        await gateway.complete(
            gateway_request(),
            deadline=time.monotonic() + 5,
            max_response_bytes=64 * 1024,
        )

    def oversized_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 1025)

    gateway = LoopbackModelGateway(
        "127.0.0.1",
        11434,
        transport=httpx.MockTransport(oversized_handler),
    )
    from watchdog.investigation.gateway import GatewayResponseTooLargeError

    with pytest.raises(GatewayResponseTooLargeError):
        await gateway.complete(
            gateway_request(),
            deadline=time.monotonic() + 5,
            max_response_bytes=1024,
        )


async def test_loopback_cancellation_closes_the_response_stream() -> None:
    stream = BlockingStream()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    gateway = LoopbackModelGateway(
        "127.0.0.1",
        11434,
        transport=httpx.MockTransport(handler),
    )
    task = asyncio.create_task(
        gateway.complete(
            gateway_request(),
            deadline=time.monotonic() + 5,
            max_response_bytes=64 * 1024,
        )
    )
    await stream.started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert stream.closed.is_set()
