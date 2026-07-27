from fastapi import Request
from fastapi.responses import JSONResponse

from watchdog.domain.errors import (
    AdvisoryNotFoundError,
    InvalidIdentifierError,
    MalformedSourceResponseError,
    PartialResultError,
    SourceUnavailableError,
    WatchdogError,
)


async def watchdog_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, WatchdogError):
        raise exc

    if isinstance(exc, InvalidIdentifierError):
        status_code = 400
    elif isinstance(exc, AdvisoryNotFoundError):
        status_code = 404
    elif isinstance(exc, SourceUnavailableError):
        status_code = 503
    elif isinstance(exc, (MalformedSourceResponseError, PartialResultError)):
        status_code = 502
    else:
        status_code = 500
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": exc.code, "message": str(exc)}},
    )
