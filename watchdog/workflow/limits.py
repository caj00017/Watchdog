from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from watchdog.config.settings import Settings


class WorkflowConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    deadline_seconds: float = Field(gt=0, le=600)
    max_concurrent_requests: int = Field(ge=1, le=1)
    max_advisory_identifier_bytes: int = Field(gt=0, le=128)
    max_repository_url_bytes: int = Field(gt=0, le=2_048)
    max_repository_ref_bytes: int = Field(gt=0, le=255)

    @classmethod
    def from_settings(cls, settings: Settings) -> WorkflowConfiguration:
        return cls(
            deadline_seconds=settings.workflow_deadline_seconds,
            max_concurrent_requests=settings.workflow_max_concurrent_requests,
            max_advisory_identifier_bytes=settings.workflow_max_advisory_identifier_bytes,
            max_repository_url_bytes=settings.workflow_max_repository_url_bytes,
            max_repository_ref_bytes=settings.workflow_max_repository_ref_bytes,
        )
