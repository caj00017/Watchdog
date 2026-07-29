from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from watchdog.config import Settings

LOCAL_REQUEST_HEADER = "X-Watchdog-Local-Request"
LOCAL_REQUEST_VALUE = "1"


def validate_loopback_configuration(settings: Settings) -> None:
    if settings.local_interfaces_host not in {"127.0.0.1", "::1"}:
        raise ValueError("local interface host must be a literal loopback address")
    if not 1 <= settings.local_interfaces_port <= 65_535:
        raise ValueError("local interface port is invalid")


def expected_host(settings: Settings) -> str:
    if settings.local_interfaces_host == "::1":
        return f"[::1]:{settings.local_interfaces_port}"
    return f"127.0.0.1:{settings.local_interfaces_port}"


def expected_origin(settings: Settings) -> str:
    return f"http://{expected_host(settings)}"


def generic_error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


def apply_security_headers(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'none'; font-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def local_request_is_allowed(request: Request, settings: Settings) -> bool:
    if request.headers.get("host") != expected_host(settings):
        return False
    origin = request.headers.get("origin")
    if origin is not None and origin != expected_origin(settings):
        return False
    fetch_site = request.headers.get("sec-fetch-site")
    return fetch_site is None or fetch_site == "same-origin"


def guided_entry_navigation_is_allowed(request: Request, settings: Settings) -> bool:
    """Allow only an operator-opened top-level navigation to the guided document."""
    return (
        request.app.state.guided
        and request.method == "GET"
        and request.url.path == "/"
        and request.scope.get("query_string", b"") == b""
        and request.headers.get("host") == expected_host(settings)
        and request.headers.get("origin") is None
        and request.headers.get("sec-fetch-site") == "none"
        and request.headers.get("sec-fetch-mode") == "navigate"
        and request.headers.get("sec-fetch-dest") == "document"
    )


async def security_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    settings: Settings = request.app.state.settings
    if not (
        local_request_is_allowed(request, settings)
        or guided_entry_navigation_is_allowed(request, settings)
    ):
        response: Response = generic_error(
            403, "local_request_rejected", "The local request was rejected."
        )
    else:
        response = await call_next(request)
    return apply_security_headers(response)
