from enum import StrEnum
from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from apps.api.dependencies.advisories import get_advisory_service
from watchdog.advisory_service import AdvisoryService
from watchdog.domain.advisories import AdvisoryRecord
from watchdog.reporting.exporters import advisory_to_markdown

router = APIRouter(prefix="/api/v1/advisories", tags=["advisories"])


class AdvisoryExportFormat(StrEnum):
    JSON = "json"
    MARKDOWN = "markdown"


@router.get(
    "/{identifier}",
    response_model=AdvisoryRecord,
    responses={
        200: {
            "content": {
                "application/json": {},
                "text/markdown": {"schema": {"type": "string"}},
            }
        }
    },
)
async def get_advisory(
    identifier: str,
    service: Annotated[AdvisoryService, Depends(get_advisory_service)],
    export_format: Annotated[AdvisoryExportFormat | None, Query(alias="format")] = None,
    accept: Annotated[str, Header()] = "application/json",
) -> Response:
    advisory = await service.resolve(identifier)
    wants_markdown = export_format is AdvisoryExportFormat.MARKDOWN or (
        export_format is None and "text/markdown" in accept.lower()
    )
    if wants_markdown:
        return PlainTextResponse(advisory_to_markdown(advisory), media_type="text/markdown")
    return JSONResponse(advisory.model_dump(mode="json"))
