from __future__ import annotations

import asyncio
import time
from typing import cast

import httpx

from watchdog.investigation.gateway import (
    GatewayError,
    GatewayInvalidResponseError,
    GatewayRequest,
    GatewayResponse,
    GatewayResponseTooLargeError,
    GatewayTimeoutError,
)
from watchdog.investigation.identifiers import canonical_json_bytes
from watchdog.investigation.validation import ModelResponseError, decode_json_object


class LoopbackModelGateway:
    """Credential-free OpenAI-compatible transport to one literal loopback endpoint."""

    def __init__(self, host: str, port: int, *, transport: httpx.AsyncBaseTransport | None = None):
        if host not in {"127.0.0.1", "::1"}:
            raise ValueError("model gateway host must be a literal loopback address")
        if not 1 <= port <= 65535:
            raise ValueError("model gateway port is invalid")
        self._host = host
        self._port = port
        self._transport = transport

    @property
    def url(self) -> str:
        authority = f"[{self._host}]" if self._host == "::1" else self._host
        return f"http://{authority}:{self._port}/v1/chat/completions"

    async def complete(
        self,
        request: GatewayRequest,
        *,
        deadline: float,
        max_response_bytes: int,
    ) -> GatewayResponse:
        request = GatewayRequest.model_validate(request.model_dump(mode="python"))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GatewayTimeoutError
        request_body = canonical_json_bytes(
            {
                "model": request.model,
                "messages": [
                    {"role": "system", "content": request.system_instruction},
                    {"role": "user", "content": request.data_message},
                ],
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": request.response_schema_name,
                        "strict": True,
                        "schema": request.response_schema,
                    },
                },
                "max_tokens": request.max_output_tokens,
                "temperature": request.temperature,
                "stream": False,
            }
        )
        timeout = httpx.Timeout(remaining, connect=remaining, read=remaining, write=remaining)
        try:
            async with asyncio.timeout(remaining):
                async with httpx.AsyncClient(
                    trust_env=False,
                    follow_redirects=False,
                    timeout=timeout,
                    transport=self._transport,
                ) as client:
                    async with client.stream(
                        "POST",
                        self.url,
                        content=request_body,
                        headers={"Content-Type": "application/json"},
                    ) as response:
                        if response.status_code != httpx.codes.OK:
                            raise GatewayError
                        raw = bytearray()
                        async for chunk in response.aiter_bytes():
                            if len(raw) + len(chunk) > max_response_bytes:
                                raise GatewayResponseTooLargeError
                            raw.extend(chunk)
        except TimeoutError as exc:
            raise GatewayTimeoutError from exc
        except httpx.TimeoutException as exc:
            raise GatewayTimeoutError from exc
        except GatewayError:
            raise
        except httpx.RequestError as exc:
            raise GatewayError from exc
        content = _extract_content(bytes(raw))
        if len(content) > max_response_bytes:
            raise GatewayResponseTooLargeError
        return GatewayResponse(body=content, gateway_kind="loopback_openai_compatible")


def _extract_content(raw: bytes) -> bytes:
    try:
        payload = decode_json_object(raw)
    except ModelResponseError as exc:
        raise GatewayInvalidResponseError from exc
    allowed_top_level = {
        "id",
        "object",
        "created",
        "model",
        "choices",
        "usage",
        "system_fingerprint",
    }
    if not set(payload).issubset(allowed_top_level):
        raise GatewayInvalidResponseError
    choices = payload.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise GatewayInvalidResponseError
    choice = choices[0]
    if not isinstance(choice, dict) or not set(choice).issubset(
        {"index", "message", "finish_reason", "logprobs"}
    ):
        raise GatewayInvalidResponseError
    if choice.get("index") != 0 or choice.get("finish_reason") != "stop":
        raise GatewayInvalidResponseError
    message = choice.get("message")
    if not isinstance(message, dict) or not set(message).issubset({"role", "content", "refusal"}):
        raise GatewayInvalidResponseError
    if message.get("role") != "assistant" or not isinstance(message.get("content"), str):
        raise GatewayInvalidResponseError
    if message.get("refusal") not in {None, ""}:
        raise GatewayInvalidResponseError
    return cast(str, message["content"]).encode("utf-8")
