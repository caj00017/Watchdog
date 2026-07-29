from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from watchdog.config import Settings
from watchdog.readiness import (
    ScannerReadiness,
    ScannerReadinessCode,
    check_scanner_readiness,
    guided_readiness,
)
from watchdog.scanners.osv_scanner import (
    ProcessResult,
    ScannerOutputOverflow,
    ScannerProcessTimeout,
)


class RecordingRunner:
    def __init__(self, result: ProcessResult | Exception) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], Mapping[str, str], Path, float, int, int]] = []

    async def run(
        self,
        arguments: tuple[str, ...],
        *,
        environment: Mapping[str, str],
        cwd: Path,
        timeout_seconds: float,
        stdout_limit: int,
        stderr_limit: int,
    ) -> ProcessResult:
        self.calls.append(
            (
                arguments,
                environment,
                cwd,
                timeout_seconds,
                stdout_limit,
                stderr_limit,
            )
        )
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _executable(tmp_path: Path) -> Path:
    path = tmp_path / "osv-scanner"
    path.write_bytes(b"trusted test executable")
    path.chmod(0o700)
    return path


async def test_scanner_readiness_uses_only_bounded_proxy_free_version_operation(
    tmp_path: Path,
) -> None:
    executable = _executable(tmp_path)
    runner = RecordingRunner(
        ProcessResult(
            exit_code=0,
            stdout=b"osv-scanner version: 2.4.0\n",
            stderr=b"",
        )
    )

    result = await check_scanner_readiness(
        Settings(osv_scanner_path=executable),
        runner=runner,
    )

    assert result.ready
    assert result.code is ScannerReadinessCode.READY
    assert len(runner.calls) == 1
    arguments, environment, cwd, timeout, stdout_limit, stderr_limit = runner.calls[0]
    assert arguments == (str(executable), "--version")
    assert set(environment) == {"HOME", "XDG_CACHE_HOME", "TMPDIR", "LANG", "LC_ALL"}
    assert not any("proxy" in key.casefold() for key in environment)
    assert timeout == 10
    assert stdout_limit == stderr_limit == 64 * 1024
    assert not cwd.exists()


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (
            ProcessResult(exit_code=1, stdout=b"", stderr=b"failure"),
            ScannerReadinessCode.VERSION_FAILED,
        ),
        (
            ProcessResult(exit_code=0, stdout=b"not a version", stderr=b""),
            ScannerReadinessCode.VERSION_MALFORMED,
        ),
        (
            ProcessResult(
                exit_code=0,
                stdout=b"osv-scanner version: 2.5.0\n",
                stderr=b"",
            ),
            ScannerReadinessCode.VERSION_MISMATCH,
        ),
        (ScannerProcessTimeout(), ScannerReadinessCode.TIMED_OUT),
        (ScannerOutputOverflow("stdout"), ScannerReadinessCode.OUTPUT_LIMIT),
        (OSError("synthetic path that must not escape"), ScannerReadinessCode.INVOCATION_FAILED),
    ],
)
async def test_scanner_readiness_failures_are_controlled(
    tmp_path: Path,
    result: ProcessResult | Exception,
    expected: ScannerReadinessCode,
) -> None:
    runner = RecordingRunner(result)
    readiness = await check_scanner_readiness(
        Settings(osv_scanner_path=_executable(tmp_path)),
        runner=runner,
    )

    assert not readiness.ready
    assert readiness.code is expected
    assert len(runner.calls) == 1


async def test_scanner_readiness_rejects_missing_wrong_type_and_permissions_before_process(
    tmp_path: Path,
) -> None:
    runner = RecordingRunner(ProcessResult(exit_code=0, stdout=b"", stderr=b""))
    missing = await check_scanner_readiness(
        Settings(osv_scanner_path=tmp_path / "missing"), runner=runner
    )
    directory = tmp_path / "directory"
    directory.mkdir()
    wrong_type = await check_scanner_readiness(Settings(osv_scanner_path=directory), runner=runner)
    blocked = tmp_path / "blocked"
    blocked.write_bytes(b"not executable")
    blocked.chmod(0o600)
    non_executable = await check_scanner_readiness(
        Settings(osv_scanner_path=blocked), runner=runner
    )

    assert missing.code is ScannerReadinessCode.MISSING
    assert wrong_type.code is ScannerReadinessCode.NOT_REGULAR
    assert non_executable.code is ScannerReadinessCode.NOT_EXECUTABLE
    assert not runner.calls


def test_guided_readiness_projects_only_controlled_capability_states() -> None:
    scanner = {"ready": True, "code": "ready"}
    off = guided_readiness(Settings(), scanner=ScannerReadiness.model_validate(scanner))
    configured = guided_readiness(
        Settings(
            investigation_enabled=True,
            investigation_model="local-model",
            remediation_preview_enabled=True,
        ),
        scanner=ScannerReadiness.model_validate(scanner),
    )

    assert off.model_dump(mode="json") == {
        "scanner": "ready",
        "ai": "off",
        "remediation": "enabled",
        "previews": "disabled",
    }
    assert configured.ai == "configured"
    assert configured.previews == "enabled"
