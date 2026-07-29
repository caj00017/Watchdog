from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from apps.web.routes import router
from apps.web.security import security_middleware, validate_loopback_configuration
from watchdog.config import Settings
from watchdog.workflow.runtime import WorkflowRuntime, workflow_runtime

_ASSET_NAMES = ("index.html", "watchdog.css", "watchdog.js")


def _load_assets(settings: Settings) -> dict[str, bytes]:
    root = Path(__file__).with_name("static")
    assets = {name: (root / name).read_bytes() for name in _ASSET_NAMES}
    if (
        sum(len(value) for value in assets.values())
        > settings.local_interfaces_max_static_asset_bytes
    ):
        raise RuntimeError("checked-in local interface assets exceed their byte limit")
    return assets


def create_app(
    settings: Settings | None = None,
    *,
    runtime: WorkflowRuntime | None = None,
) -> FastAPI:
    configured = settings or Settings()
    validate_loopback_configuration(configured)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.assets = _load_assets(configured)
        if runtime is not None:
            application.state.runtime = runtime
            yield
        else:
            async with workflow_runtime(configured) as active_runtime:
                application.state.runtime = active_runtime
                yield

    application = FastAPI(
        title="Nexura Watchdog Local Investigations",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    application.state.settings = configured
    application.middleware("http")(security_middleware)
    application.include_router(router)
    return application
