from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict

from watchdog import __version__

router = APIRouter(tags=["system"])


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok"]
    version: str


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)
