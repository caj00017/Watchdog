from pydantic import BaseModel, ConfigDict, Field

from watchdog.config.settings import Settings


class ScannerLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    timeout_seconds: float = Field(gt=0)
    max_input_bytes: int = Field(gt=0)
    max_stdout_bytes: int = Field(gt=0)
    max_stderr_bytes: int = Field(gt=0)

    @classmethod
    def from_settings(cls, settings: Settings) -> "ScannerLimits":
        return cls(
            timeout_seconds=settings.scanner_timeout_seconds,
            max_input_bytes=settings.scanner_max_input_bytes,
            max_stdout_bytes=settings.scanner_max_stdout_bytes,
            max_stderr_bytes=settings.scanner_max_stderr_bytes,
        )
