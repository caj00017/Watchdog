from __future__ import annotations

import asyncio
import os
import re
import shutil
import stat
import tempfile
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from watchdog.config.settings import Settings
from watchdog.investigation.limits import InvestigationConfiguration
from watchdog.remediation.limits import RemediationConfiguration
from watchdog.scanners.limits import ScannerLimits
from watchdog.scanners.osv_scanner import (
    OSV_SCANNER_VERSION,
    AsyncSubprocessRunner,
    ProcessRunner,
    ScannerBoundaryError,
)
from watchdog.workflow.limits import WorkflowConfiguration

_VERSION_PATTERN = re.compile(
    r"^osv-scanner version:[ \t]*([0-9]+\.[0-9]+\.[0-9]+)[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)
_VERSION_TIMEOUT_SECONDS = 10.0
_VERSION_OUTPUT_BYTES = 64 * 1024


class ScannerReadinessCode(StrEnum):
    READY = "ready"
    MISSING = "missing"
    NOT_REGULAR = "not_regular"
    NOT_EXECUTABLE = "not_executable"
    TIMED_OUT = "timed_out"
    OUTPUT_LIMIT = "output_limit"
    INVOCATION_FAILED = "invocation_failed"
    VERSION_FAILED = "version_failed"
    VERSION_MALFORMED = "version_malformed"
    VERSION_MISMATCH = "version_mismatch"


class ScannerReadiness(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ready: bool
    code: ScannerReadinessCode


class GuidedReadiness(BaseModel):
    """Controlled capability projection safe for the guided local interface."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scanner: Literal["ready", "unavailable"]
    ai: Literal["off", "configured", "unavailable"]
    remediation: Literal["enabled"] = "enabled"
    previews: Literal["enabled", "disabled"]


def _prepare_control_directory() -> tuple[Path, Path, Path, Path]:
    control_directory = Path(tempfile.mkdtemp(prefix="nexura-watchdog-readiness-"))
    control_directory.chmod(0o700)
    home = control_directory / "home"
    cache = control_directory / "cache"
    temporary = control_directory / "tmp"
    for directory in (home, cache, temporary):
        directory.mkdir(mode=0o700)
    return control_directory, home, cache, temporary


def validate_runtime_configuration(settings: Settings) -> None:
    """Validate bounded cross-field runtime configuration without constructing I/O clients."""

    if settings.local_interfaces_host not in {"127.0.0.1", "::1"}:
        raise ValueError("local interface host is not literal loopback")
    ScannerLimits.from_settings(settings)
    WorkflowConfiguration.from_settings(settings)
    InvestigationConfiguration.from_settings(settings)
    RemediationConfiguration.from_settings(settings)


def guided_readiness(
    settings: Settings,
    scanner: ScannerReadiness,
) -> GuidedReadiness:
    if settings.investigation_enabled:
        ai: Literal["off", "configured", "unavailable"] = (
            "configured" if settings.investigation_model is not None else "unavailable"
        )
    else:
        ai = "off"
    return GuidedReadiness(
        scanner="ready" if scanner.ready else "unavailable",
        ai=ai,
        previews="enabled" if settings.remediation_preview_enabled else "disabled",
    )


async def check_scanner_readiness(
    settings: Settings,
    *,
    runner: ProcessRunner | None = None,
) -> ScannerReadiness:
    """Run only the pinned scanner's bounded, proxy-free version operation."""

    executable = settings.osv_scanner_path
    try:
        metadata = executable.stat(follow_symlinks=False)
    except (FileNotFoundError, NotADirectoryError, OSError):
        return ScannerReadiness(ready=False, code=ScannerReadinessCode.MISSING)
    if not stat.S_ISREG(metadata.st_mode):
        return ScannerReadiness(ready=False, code=ScannerReadinessCode.NOT_REGULAR)
    if not os.access(executable, os.X_OK):
        return ScannerReadiness(ready=False, code=ScannerReadinessCode.NOT_EXECUTABLE)

    control_directory, home, cache, temporary = _prepare_control_directory()
    try:
        limits = ScannerLimits.from_settings(settings)
        process_runner = runner or AsyncSubprocessRunner()
        try:
            result = await process_runner.run(
                (str(executable), "--version"),
                environment={
                    "HOME": str(home),
                    "XDG_CACHE_HOME": str(cache),
                    "TMPDIR": str(temporary),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                },
                cwd=control_directory,
                timeout_seconds=min(limits.timeout_seconds, _VERSION_TIMEOUT_SECONDS),
                stdout_limit=min(limits.max_stdout_bytes, _VERSION_OUTPUT_BYTES),
                stderr_limit=min(limits.max_stderr_bytes, _VERSION_OUTPUT_BYTES),
            )
        except asyncio.CancelledError:
            raise
        except ScannerBoundaryError as exc:
            code = (
                ScannerReadinessCode.TIMED_OUT
                if exc.code == "scanner_timeout"
                else ScannerReadinessCode.OUTPUT_LIMIT
                if exc.code in {"scanner_stdout_overflow", "scanner_stderr_overflow"}
                else ScannerReadinessCode.INVOCATION_FAILED
            )
            return ScannerReadiness(ready=False, code=code)
        except (OSError, RuntimeError):
            return ScannerReadiness(
                ready=False,
                code=ScannerReadinessCode.INVOCATION_FAILED,
            )
        if result.exit_code != 0:
            return ScannerReadiness(ready=False, code=ScannerReadinessCode.VERSION_FAILED)
        try:
            output = (result.stdout + b"\n" + result.stderr).decode("utf-8")
        except UnicodeDecodeError:
            return ScannerReadiness(ready=False, code=ScannerReadinessCode.VERSION_MALFORMED)
        versions = _VERSION_PATTERN.findall(output)
        if not versions:
            return ScannerReadiness(ready=False, code=ScannerReadinessCode.VERSION_MALFORMED)
        if versions != [OSV_SCANNER_VERSION]:
            return ScannerReadiness(ready=False, code=ScannerReadinessCode.VERSION_MISMATCH)
        return ScannerReadiness(ready=True, code=ScannerReadinessCode.READY)
    finally:
        shutil.rmtree(control_directory, ignore_errors=True)
