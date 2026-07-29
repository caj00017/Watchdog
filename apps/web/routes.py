from __future__ import annotations

import asyncio
import json
from contextlib import suppress
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.requests import ClientDisconnect

from apps.web.security import (
    LOCAL_REQUEST_HEADER,
    LOCAL_REQUEST_VALUE,
    generic_error,
)
from watchdog.domain.errors import InvalidIdentifierError, WatchdogError
from watchdog.domain.remediation import (
    RemediationWorkflowRequest,
    RenderedRemediationPlan,
)
from watchdog.domain.reports import (
    InvestigationWorkflowRequest,
    RenderedReport,
    ReportFormat,
    ReportView,
)
from watchdog.domain.repositories import RepositoryRequest
from watchdog.remediation.assembler import RemediationAssemblyError
from watchdog.remediation.candidates import CandidateDerivationError
from watchdog.remediation.preview import PreviewCollectionError
from watchdog.remediation.report_json import RemediationRenderError
from watchdog.reporting.report_json import ReportRenderError
from watchdog.repository.errors import (
    InvalidRepositoryRefError,
    InvalidRepositoryUrlError,
    RepositoryCleanupError,
    RepositoryIntakeError,
)
from watchdog.workflow.errors import (
    RemediationDisabledError,
    WorkflowCancelledError,
    WorkflowCleanupError,
    WorkflowTimeoutError,
)
from watchdog.workflow.runtime import WorkflowRuntime

router = APIRouter()
remediation_router = APIRouter()


class LocalInvestigationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    advisory_id: str = Field(min_length=1, max_length=128)
    repository_url: str = Field(min_length=1, max_length=2_048)
    ref: str | None = Field(default=None, min_length=1, max_length=255)
    view: ReportView = ReportView.SUMMARY
    format: ReportFormat = ReportFormat.JSON


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON value")


async def _bounded_body(request: Request, limit: int) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if declared < 0 or declared > limit:
            raise OverflowError
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise OverflowError
    return bytes(body)


async def _run_until_disconnect(
    request: Request,
    runtime: WorkflowRuntime,
    workflow_request: InvestigationWorkflowRequest,
) -> RenderedReport:
    task: asyncio.Task[RenderedReport] = asyncio.create_task(
        runtime.workflow.run_rendered(workflow_request, runtime.renderer)
    )
    monitor = asyncio.create_task(_disconnect_monitor(request, task))
    try:
        return await task
    finally:
        monitor.cancel()
        with suppress(asyncio.CancelledError):
            await monitor


async def _disconnect_monitor(request: Request, task: asyncio.Task[object]) -> None:
    while not task.done():
        try:
            disconnected = await request.is_disconnected()
        except Exception:
            task.cancel()
            return
        if disconnected:
            task.cancel()
            return
        await asyncio.sleep(0.05)


async def _run_remediation_until_disconnect(
    request: Request,
    runtime: WorkflowRuntime,
    workflow_request: RemediationWorkflowRequest,
) -> RenderedRemediationPlan:
    if runtime.remediation_workflow is None or runtime.remediation_renderer is None:
        raise RemediationDisabledError("remediation runtime is unavailable")
    task: asyncio.Task[RenderedRemediationPlan] = asyncio.create_task(
        runtime.remediation_workflow.run_rendered(workflow_request, runtime.remediation_renderer)
    )
    monitor = asyncio.create_task(_disconnect_monitor(request, task))
    try:
        return await task
    finally:
        monitor.cancel()
        with suppress(asyncio.CancelledError):
            await monitor


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return HTMLResponse(request.app.state.assets["index.html"])


@router.get("/assets/watchdog.css")
async def stylesheet(request: Request) -> Response:
    return Response(request.app.state.assets["watchdog.css"], media_type="text/css")


@router.get("/assets/watchdog.js")
async def script(request: Request) -> Response:
    return Response(
        request.app.state.assets["watchdog.js"],
        media_type="application/javascript",
    )


@router.post("/api/v1/investigations")
async def investigate(request: Request) -> Response:
    if request.headers.get(LOCAL_REQUEST_HEADER) != LOCAL_REQUEST_VALUE:
        return generic_error(
            403, "local_request_header_required", "The local request was rejected."
        )
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
    if content_type != "application/json":
        return generic_error(415, "unsupported_media_type", "Expected application/json.")
    try:
        body = await _bounded_body(
            request,
            request.app.state.settings.local_interfaces_max_request_bytes,
        )
    except OverflowError:
        return generic_error(413, "request_too_large", "The request exceeded its byte limit.")
    except ClientDisconnect:
        return generic_error(503, "client_disconnected", "The request was interrupted.")
    except ValueError:
        return generic_error(400, "invalid_request", "The request is invalid.")
    try:
        payload = json.loads(
            body,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        local_request = LocalInvestigationRequest.model_validate(payload)
        workflow_request = InvestigationWorkflowRequest(
            advisory_identifier=local_request.advisory_id,
            repository=RepositoryRequest(
                repository_url=local_request.repository_url,
                ref=local_request.ref,
            ),
            view=local_request.view,
            format=local_request.format,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        return generic_error(400, "invalid_request", "The request is invalid.")

    runtime: WorkflowRuntime = request.app.state.runtime
    try:
        rendered = await _run_until_disconnect(request, runtime, workflow_request)
    except (WorkflowTimeoutError, WorkflowCancelledError):
        return generic_error(503, "workflow_stopped", "The workflow did not produce a report.")
    except (InvalidIdentifierError, InvalidRepositoryUrlError, InvalidRepositoryRefError):
        return generic_error(400, "invalid_request", "The request is invalid.")
    except (RepositoryCleanupError, WorkflowCleanupError):
        return generic_error(500, "cleanup_failed", "Repository cleanup could not be verified.")
    except RepositoryIntakeError:
        return generic_error(503, "repository_unavailable", "The repository is unavailable.")
    except WatchdogError:
        return generic_error(503, "advisory_unavailable", "The advisory is unavailable.")
    except ReportRenderError:
        return generic_error(500, "report_render_failed", "The report could not be rendered.")
    except Exception:
        return generic_error(500, "workflow_failed", "The workflow failed.")
    return Response(
        content=rendered.body,
        media_type=rendered.media_type,
        headers={
            "X-Watchdog-Report-ID": rendered.report_id,
            "X-Watchdog-Report-Status": rendered.status.value,
        },
    )


@remediation_router.post("/api/v1/remediations")
async def remediate(request: Request) -> Response:
    if request.headers.get(LOCAL_REQUEST_HEADER) != LOCAL_REQUEST_VALUE:
        return generic_error(
            403, "local_request_header_required", "The local request was rejected."
        )
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().casefold()
    if content_type != "application/json":
        return generic_error(415, "unsupported_media_type", "Expected application/json.")
    try:
        body = await _bounded_body(
            request,
            request.app.state.settings.local_interfaces_max_request_bytes,
        )
    except OverflowError:
        return generic_error(413, "request_too_large", "The request exceeded its byte limit.")
    except ClientDisconnect:
        return generic_error(503, "client_disconnected", "The request was interrupted.")
    except ValueError:
        return generic_error(400, "invalid_request", "The request is invalid.")
    try:
        payload = json.loads(
            body,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        local_request = LocalInvestigationRequest.model_validate(payload)
        workflow_request = RemediationWorkflowRequest(
            advisory_identifier=local_request.advisory_id,
            repository=RepositoryRequest(
                repository_url=local_request.repository_url,
                ref=local_request.ref,
            ),
            view=local_request.view,
            format=local_request.format,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        return generic_error(400, "invalid_request", "The request is invalid.")

    runtime: WorkflowRuntime = request.app.state.runtime
    try:
        rendered = await _run_remediation_until_disconnect(request, runtime, workflow_request)
    except RemediationDisabledError:
        return generic_error(404, "remediation_disabled", "The remediation route is unavailable.")
    except (WorkflowTimeoutError, WorkflowCancelledError):
        return generic_error(503, "workflow_stopped", "The workflow did not produce a plan.")
    except (InvalidIdentifierError, InvalidRepositoryUrlError, InvalidRepositoryRefError):
        return generic_error(400, "invalid_request", "The request is invalid.")
    except (RepositoryCleanupError, WorkflowCleanupError):
        return generic_error(500, "cleanup_failed", "Repository cleanup could not be verified.")
    except RepositoryIntakeError:
        return generic_error(503, "repository_unavailable", "The repository is unavailable.")
    except WatchdogError:
        return generic_error(503, "advisory_unavailable", "The advisory is unavailable.")
    except (
        CandidateDerivationError,
        PreviewCollectionError,
        RemediationAssemblyError,
        RemediationRenderError,
    ):
        return generic_error(500, "remediation_failed", "The plan could not be produced.")
    except Exception:
        return generic_error(500, "workflow_failed", "The workflow failed.")
    return Response(
        content=rendered.body,
        media_type=rendered.media_type,
        headers={
            "X-Watchdog-Remediation-Plan-ID": rendered.plan_id,
            "X-Watchdog-Remediation-Status": rendered.status.value,
        },
    )
