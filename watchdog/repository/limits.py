from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from watchdog.config.settings import Settings


class RepositoryLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    network_timeout_seconds: float = Field(gt=0)
    max_duration_seconds: float = Field(gt=0)
    max_archive_bytes: int = Field(gt=0)
    max_extracted_bytes: int = Field(gt=0)
    max_files: int = Field(gt=0)
    max_path_length: int = Field(gt=0)
    max_concurrent_intakes: int = Field(gt=0)
    workspace_root: Path | None = None

    @classmethod
    def from_settings(cls, settings: Settings) -> "RepositoryLimits":
        return cls(
            network_timeout_seconds=settings.repository_network_timeout_seconds,
            max_duration_seconds=settings.repository_max_duration_seconds,
            max_archive_bytes=settings.repository_max_archive_bytes,
            max_extracted_bytes=settings.repository_max_extracted_bytes,
            max_files=settings.repository_max_files,
            max_path_length=settings.repository_max_path_length,
            max_concurrent_intakes=settings.repository_max_concurrent_intakes,
            workspace_root=settings.repository_workspace_root,
        )
