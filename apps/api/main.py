from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from apps.api.errors import watchdog_error_handler
from apps.api.routes.advisories import router as advisories_router
from apps.api.routes.health import router as health_router
from watchdog.advisory_service import AdvisoryService
from watchdog.config import get_settings
from watchdog.domain.errors import WatchdogError
from watchdog.vulnerability_sources.osv import OsvSource


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    client = httpx.AsyncClient(timeout=settings.upstream_timeout_seconds)
    app.state.advisory_service = AdvisoryService(
        OsvSource(
            client,
            base_url=str(settings.osv_base_url),
            include_raw_record=settings.include_raw_source_records,
        )
    )
    try:
        yield
    finally:
        await client.aclose()


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="Evidence-driven advisory normalization API",
        lifespan=lifespan,
    )
    application.add_exception_handler(WatchdogError, watchdog_error_handler)
    application.include_router(health_router)
    application.include_router(advisories_router)
    return application


app = create_app()
