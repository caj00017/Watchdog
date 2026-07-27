from typing import cast

from fastapi import Request

from watchdog.advisory_service import AdvisoryService


def get_advisory_service(request: Request) -> AdvisoryService:
    return cast(AdvisoryService, request.app.state.advisory_service)
