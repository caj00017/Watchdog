from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from watchdog.domain.inventory import Ecosystem
from watchdog.domain.matching import ExactPackageCoordinate, ScannerRunStatus
from watchdog.scanners.limits import ScannerLimits
from watchdog.scanners.osv_scanner import (
    AsyncSubprocessRunner,
    OsvScanner,
    ProcessResult,
    ScannerOutputOverflow,
    ScannerProcessTimeout,
)


def scanner_limits(**overrides: object) -> ScannerLimits:
    values: dict[str, object] = {
        "timeout_seconds": 2.0,
        "max_input_bytes": 5 * 1024 * 1024,
        "max_stdout_bytes": 25 * 1024 * 1024,
        "max_stderr_bytes": 1024 * 1024,
    }
    values.update(overrides)
    return ScannerLimits.model_validate(values)


def executable_path(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "osv-scanner"
    path.write_bytes(b"controlled test placeholder")
    path.chmod(0o700)
    return path


class ControlledRunner:
    def __init__(
        self,
        *,
        version: str = "2.4.0",
        version_output: bytes | None = None,
        exit_code: int = 1,
        output: bytes | None = None,
    ) -> None:
        self.version = version
        self.version_output = version_output
        self.exit_code = exit_code
        self.output = output
        self.calls: list[tuple[tuple[str, ...], dict[str, str], Path]] = []
        self.generated_input: dict[str, object] | None = None

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
        del timeout_seconds, stdout_limit, stderr_limit
        self.calls.append((arguments, dict(environment), cwd))
        if arguments[-1] == "--version":
            return ProcessResult(
                exit_code=0,
                stdout=(
                    self.version_output
                    if self.version_output is not None
                    else f"osv-scanner version: {self.version}\n".encode()
                ),
                stderr=b"",
            )
        input_argument = next(item for item in arguments if item.startswith("--lockfile="))
        input_path = Path(input_argument.removeprefix("--lockfile=osv-scanner:"))
        raw_input = await asyncio.to_thread(input_path.read_text, encoding="utf-8")
        self.generated_input = json.loads(raw_input)
        if self.output is None:
            package = self.generated_input["results"][0]["packages"][0]["package"]  # type: ignore[index]
            output = json.dumps(
                {
                    "results": [
                        {
                            "source": {"path": str(input_path), "type": "lockfile"},
                            "packages": [
                                {
                                    "package": package,
                                    "vulnerabilities": [
                                        {"id": "GO-2021-0053", "aliases": ["CVE-2021-3121"]}
                                    ],
                                }
                            ],
                        }
                    ]
                }
            ).encode()
        else:
            output = self.output
        return ProcessResult(exit_code=self.exit_code, stdout=output, stderr=b"fixture diagnostic")


async def test_scanner_uses_generated_input_exact_argv_and_sanitized_environment(
    tmp_path: Path,
) -> None:
    runner = ControlledRunner()
    executable = executable_path(tmp_path)
    scanner = OsvScanner(executable, scanner_limits(), runner=runner)
    coordinate = ExactPackageCoordinate(
        ecosystem=Ecosystem.GO,
        name="github.com/gogo/protobuf",
        version="v1.3.1",
    )

    result = await scanner.scan((coordinate,))

    assert result.status == ScannerRunStatus.SUCCESS
    assert result.evidence.tool_version == "2.4.0"
    assert result.evidence.exit_code == 1
    assert result.packages[0].coordinate == coordinate
    assert result.packages[0].vulnerabilities[0].id == "GO-2021-0053"
    assert runner.generated_input == {
        "results": [
            {
                "packages": [
                    {
                        "package": {
                            "ecosystem": "Go",
                            "name": "github.com/gogo/protobuf",
                            "version": "v1.3.1",
                        }
                    }
                ]
            }
        ]
    }
    scan_arguments, environment, _cwd = runner.calls[1]
    assert scan_arguments[1:6] == (
        "scan",
        "source",
        "--format=json",
        "--verbosity=error",
        "--no-resolve",
    )
    assert not any(key.lower().endswith("proxy") for key in environment)
    assert set(environment) == {"HOME", "XDG_CACHE_HOME", "TMPDIR", "LANG", "LC_ALL"}
    assert result.evidence.arguments[-1] == "--lockfile=osv-scanner:<generated-input>"
    assert result.evidence.input_sha256
    assert result.evidence.output_sha256
    assert result.evidence.validated_output is not None
    validated_results = result.evidence.validated_output["results"]
    assert isinstance(validated_results, list)
    first_result = validated_results[0]
    assert isinstance(first_result, dict)
    source = first_result["source"]
    assert isinstance(source, dict)
    assert source["path"] == "<generated-input>"


async def test_version_is_checked_lazily_once(tmp_path: Path) -> None:
    runner = ControlledRunner(exit_code=0)
    scanner = OsvScanner(executable_path(tmp_path), scanner_limits(), runner=runner)
    coordinate = ExactPackageCoordinate(ecosystem=Ecosystem.NPM, name="react", version="1.0.0")

    await scanner.scan((coordinate,))
    await scanner.scan((coordinate,))

    assert sum(call[0][-1] == "--version" for call in runner.calls) == 1


async def test_version_check_uses_explicit_scanner_version_line(tmp_path: Path) -> None:
    runner = ControlledRunner(
        version_output=(
            b"osv-scanner version: 2.4.0\n"
            b"osv-scalibr version: 0.4.5\n"
            b"commit: b56b5191101d5f27d4787d5583d8d01e9518a7af\n"
            b"built at: 2026-06-18T12:55:27Z\n"
        ),
        exit_code=0,
    )
    scanner = OsvScanner(executable_path(tmp_path), scanner_limits(), runner=runner)
    coordinate = ExactPackageCoordinate(ecosystem=Ecosystem.NPM, name="react", version="1.0.0")

    result = await scanner.scan((coordinate,))

    assert result.status == ScannerRunStatus.SUCCESS
    assert result.evidence.tool_version == "2.4.0"


async def test_version_mismatch_and_malformed_json_are_incomplete(tmp_path: Path) -> None:
    mismatch = OsvScanner(
        executable_path(tmp_path / "mismatch"),
        scanner_limits(),
        runner=ControlledRunner(version="2.4.1"),
    )
    coordinate = ExactPackageCoordinate(ecosystem=Ecosystem.NPM, name="react", version="1.0.0")
    mismatch_result = await mismatch.scan((coordinate,))
    assert mismatch_result.status == ScannerRunStatus.INCOMPLETE
    assert mismatch_result.warning_code == "scanner_version_mismatch"

    malformed = OsvScanner(
        executable_path(tmp_path / "malformed"),
        scanner_limits(),
        runner=ControlledRunner(output=b"not JSON", exit_code=0),
    )
    malformed_result = await malformed.scan((coordinate,))
    assert malformed_result.status == ScannerRunStatus.INCOMPLETE
    assert malformed_result.warning_code == "scanner_boundary_failure"


async def test_input_limit_and_other_exit_are_incomplete(tmp_path: Path) -> None:
    coordinate = ExactPackageCoordinate(ecosystem=Ecosystem.NPM, name="react", version="1.0.0")
    limited = OsvScanner(
        executable_path(tmp_path / "limited"),
        scanner_limits(max_input_bytes=10),
        runner=ControlledRunner(),
    )
    limited_result = await limited.scan((coordinate,))
    assert limited_result.status == ScannerRunStatus.INCOMPLETE
    assert limited_result.warning_code == "scanner_input_overflow"

    failed = OsvScanner(
        executable_path(tmp_path / "failed"),
        scanner_limits(),
        runner=ControlledRunner(exit_code=2),
    )
    failed_result = await failed.scan((coordinate,))
    assert failed_result.status == ScannerRunStatus.INCOMPLETE
    assert failed_result.warning_code == "scanner_exit_failure"
    assert failed_result.evidence.exit_code == 2
    assert failed_result.evidence.output_sha256
    assert "fixture diagnostic" in (failed_result.evidence.diagnostics or "")


async def test_default_runner_bounds_output_timeout_and_cancellation(tmp_path: Path) -> None:
    runner = AsyncSubprocessRunner()
    environment = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}

    with pytest.raises(ScannerOutputOverflow):
        await runner.run(
            (sys.executable, "-c", "import sys; sys.stdout.write('x' * 1024)"),
            environment=environment,
            cwd=tmp_path,
            timeout_seconds=2,
            stdout_limit=10,
            stderr_limit=100,
        )

    with pytest.raises(ScannerProcessTimeout):
        await runner.run(
            (sys.executable, "-c", "import time; time.sleep(5)"),
            environment=environment,
            cwd=tmp_path,
            timeout_seconds=0.01,
            stdout_limit=100,
            stderr_limit=100,
        )

    task = asyncio.create_task(
        runner.run(
            (sys.executable, "-c", "import time; time.sleep(5)"),
            environment=environment,
            cwd=tmp_path,
            timeout_seconds=2,
            stdout_limit=100,
            stderr_limit=100,
        )
    )
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
