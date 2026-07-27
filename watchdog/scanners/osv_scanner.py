from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import signal
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from watchdog.domain.inventory import Ecosystem
from watchdog.domain.matching import (
    ExactPackageCoordinate,
    ScannerPackageResult,
    ScannerRunEvidence,
    ScannerRunResult,
    ScannerRunStatus,
    ScannerVulnerability,
)
from watchdog.inventory.identifiers import normalize_package_name
from watchdog.scanners.limits import ScannerLimits

OSV_SCANNER_VERSION = "2.4.0"
_READ_CHUNK = 64 * 1024
_OSV_SCANNER_VERSION_PATTERN = re.compile(
    r"^osv-scanner version:[ \t]*([0-9]+\.[0-9]+\.[0-9]+)[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)
_URL_CREDENTIALS = re.compile(r"(https?://)[^/@\s]+@", re.IGNORECASE)
_SECRET_ASSIGNMENT = re.compile(r"(?i)\b(token|password|secret|authorization)\s*[=:]\s*[^\s,;]+")


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant {value}")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


class ScannerBoundaryError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ScannerOutputOverflow(ScannerBoundaryError):
    def __init__(self, stream: str) -> None:
        super().__init__(f"scanner_{stream}_overflow", f"scanner {stream} exceeded its limit")


class ScannerProcessTimeout(ScannerBoundaryError):
    def __init__(self) -> None:
        super().__init__("scanner_timeout", "scanner exceeded its execution timeout")


@dataclass(frozen=True, slots=True)
class ProcessResult:
    exit_code: int
    stdout: bytes
    stderr: bytes


class ProcessRunner(Protocol):
    async def run(
        self,
        arguments: tuple[str, ...],
        *,
        environment: Mapping[str, str],
        cwd: Path,
        timeout_seconds: float,
        stdout_limit: int,
        stderr_limit: int,
    ) -> ProcessResult: ...


class AsyncSubprocessRunner:
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
        process = await asyncio.create_subprocess_exec(
            *arguments,
            cwd=cwd,
            env=dict(environment),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_task = asyncio.create_task(
            self._read_bounded(process.stdout, stdout_limit, "stdout")
        )
        stderr_task = asyncio.create_task(
            self._read_bounded(process.stderr, stderr_limit, "stderr")
        )
        try:
            async with asyncio.timeout(timeout_seconds):
                stdout, stderr, exit_code = await asyncio.gather(
                    stdout_task, stderr_task, process.wait()
                )
            return ProcessResult(exit_code=exit_code, stdout=stdout, stderr=stderr)
        except TimeoutError as exc:
            await self._terminate(process)
            raise ScannerProcessTimeout from exc
        except BaseException:
            await self._terminate(process)
            raise
        finally:
            for task in (stdout_task, stderr_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

    async def _read_bounded(
        self,
        stream: asyncio.StreamReader,
        limit: int,
        label: str,
    ) -> bytes:
        result = bytearray()
        while True:
            chunk = await stream.read(min(_READ_CHUNK, limit - len(result) + 1))
            if not chunk:
                return bytes(result)
            result.extend(chunk)
            if len(result) > limit:
                raise ScannerOutputOverflow(label)

    async def _terminate(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            await process.wait()
            return
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            async with asyncio.timeout(0.5):
                await process.wait()
                return
        except TimeoutError:
            pass
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        await process.wait()


class _BoundaryModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class _OsvPackage(_BoundaryModel):
    name: StrictStr
    version: StrictStr | None = None
    ecosystem: StrictStr | None = None


class _OsvVulnerability(_BoundaryModel):
    id: StrictStr
    aliases: list[StrictStr] = Field(default_factory=list)


class _OsvPackageResult(_BoundaryModel):
    package: _OsvPackage
    vulnerabilities: list[_OsvVulnerability] = Field(default_factory=list)


class _OsvResult(_BoundaryModel):
    packages: list[_OsvPackageResult] = Field(default_factory=list)


class _OsvOutput(_BoundaryModel):
    results: list[_OsvResult] = Field(default_factory=list)


class OsvScanner:
    """Pinned OSV-Scanner adapter receiving generated exact coordinates only."""

    def __init__(
        self,
        executable: Path,
        limits: ScannerLimits,
        *,
        runner: ProcessRunner | None = None,
    ) -> None:
        if not executable.is_absolute():
            raise ValueError("OSV-Scanner executable path must be absolute")
        self._executable = executable
        self._limits = limits
        self._runner = runner or AsyncSubprocessRunner()
        self._version: str | None = None
        self._version_lock = asyncio.Lock()

    async def scan(
        self,
        coordinates: tuple[ExactPackageCoordinate, ...],
    ) -> ScannerRunResult:
        started = datetime.now(UTC)
        ordered = tuple(
            sorted(
                set(coordinates), key=lambda item: (item.ecosystem.value, item.name, item.version)
            )
        )
        (
            control_directory,
            input_path,
            config_path,
            home,
            cache,
            temporary,
        ) = self._prepare_control_directory()
        logical_arguments = (
            str(self._executable),
            "scan",
            "source",
            "--format=json",
            "--verbosity=error",
            "--no-resolve",
            "--config=<trusted-config>",
            "--lockfile=osv-scanner:<generated-input>",
        )
        input_bytes: bytes | None = None
        process_result: ProcessResult | None = None
        diagnostics: str | None = None
        try:
            version = await self._require_version(
                control_directory, home=home, cache=cache, temporary=temporary
            )
            input_bytes = self._generate_input(ordered)
            if len(input_bytes) > self._limits.max_input_bytes:
                raise ScannerBoundaryError(
                    "scanner_input_overflow", "generated scanner input exceeded its limit"
                )
            self._write_control_files(input_path, input_bytes, config_path)
            arguments = (
                str(self._executable),
                "scan",
                "source",
                "--format=json",
                "--verbosity=error",
                "--no-resolve",
                f"--config={config_path}",
                f"--lockfile=osv-scanner:{input_path}",
            )
            process_result = await self._runner.run(
                arguments,
                environment=self._environment(home, cache, temporary),
                cwd=control_directory,
                timeout_seconds=self._limits.timeout_seconds,
                stdout_limit=self._limits.max_stdout_bytes,
                stderr_limit=self._limits.max_stderr_bytes,
            )
            diagnostics = self._sanitize_diagnostics(process_result.stderr, control_directory)
            if process_result.exit_code not in {0, 1}:
                raise ScannerBoundaryError(
                    "scanner_exit_failure",
                    f"scanner exited with code {process_result.exit_code}",
                )
            packages, validated = self._validate_output(process_result.stdout, ordered)
            validated = self._sanitize_validated_output(validated, control_directory)
            completed = datetime.now(UTC)
            evidence = ScannerRunEvidence(
                tool="OSV-Scanner",
                tool_version=version,
                arguments=logical_arguments,
                started_at=started,
                completed_at=completed,
                exit_code=process_result.exit_code,
                input_sha256=hashlib.sha256(input_bytes).hexdigest(),
                output_sha256=hashlib.sha256(process_result.stdout).hexdigest(),
                validated_output=validated,
                diagnostics=diagnostics or None,
            )
            return ScannerRunResult(
                status=ScannerRunStatus.SUCCESS,
                packages=packages,
                evidence=evidence,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            completed = datetime.now(UTC)
            code = exc.code if isinstance(exc, ScannerBoundaryError) else "scanner_boundary_failure"
            return ScannerRunResult(
                status=ScannerRunStatus.INCOMPLETE,
                evidence=ScannerRunEvidence(
                    tool="OSV-Scanner",
                    tool_version=self._version,
                    arguments=logical_arguments,
                    started_at=started,
                    completed_at=completed,
                    exit_code=process_result.exit_code if process_result else None,
                    input_sha256=(
                        hashlib.sha256(input_bytes).hexdigest() if input_bytes is not None else None
                    ),
                    output_sha256=(
                        hashlib.sha256(process_result.stdout).hexdigest()
                        if process_result is not None
                        else None
                    ),
                    diagnostics=(
                        "\n".join(
                            item
                            for item in (
                                diagnostics,
                                self._sanitize_text(str(exc), control_directory),
                            )
                            if item
                        )
                        or None
                    ),
                ),
                warning_code=code,
            )
        finally:
            self._remove_control_directory(control_directory)

    async def _require_version(
        self,
        cwd: Path,
        *,
        home: Path,
        cache: Path,
        temporary: Path,
    ) -> str:
        async with self._version_lock:
            if self._version is not None:
                return self._version
            if not self._is_executable():
                raise ScannerBoundaryError(
                    "scanner_missing", "configured OSV-Scanner binary is missing or not executable"
                )
            result = await self._runner.run(
                (str(self._executable), "--version"),
                environment=self._environment(home, cache, temporary),
                cwd=cwd,
                timeout_seconds=min(self._limits.timeout_seconds, 10.0),
                stdout_limit=min(self._limits.max_stdout_bytes, 64 * 1024),
                stderr_limit=min(self._limits.max_stderr_bytes, 64 * 1024),
            )
            if result.exit_code != 0:
                raise ScannerBoundaryError(
                    "scanner_version_failed", "OSV-Scanner --version did not succeed"
                )
            output = (result.stdout + b"\n" + result.stderr).decode("utf-8")
            versions = _OSV_SCANNER_VERSION_PATTERN.findall(output)
            if versions != [OSV_SCANNER_VERSION]:
                raise ScannerBoundaryError(
                    "scanner_version_mismatch",
                    f"OSV-Scanner must report exactly version {OSV_SCANNER_VERSION}",
                )
            self._version = OSV_SCANNER_VERSION
            return self._version

    def _generate_input(self, coordinates: tuple[ExactPackageCoordinate, ...]) -> bytes:
        value = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "name": coordinate.name,
                                "version": coordinate.version,
                                "ecosystem": coordinate.ecosystem.value,
                            }
                        }
                        for coordinate in coordinates
                    ]
                }
            ]
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _prepare_control_directory(
        self,
    ) -> tuple[Path, Path, Path, Path, Path, Path]:
        control_directory = Path(tempfile.mkdtemp(prefix="nexura-watchdog-scanner-"))
        control_directory.chmod(0o700)
        input_path = control_directory / "exact-coordinates.json"
        config_path = control_directory / "trusted-empty-config.toml"
        home = control_directory / "home"
        cache = control_directory / "cache"
        temporary = control_directory / "tmp"
        for directory in (home, cache, temporary):
            directory.mkdir(mode=0o700)
        return control_directory, input_path, config_path, home, cache, temporary

    def _is_executable(self) -> bool:
        return os.path.isfile(self._executable) and os.access(self._executable, os.X_OK)

    def _write_control_files(
        self,
        input_path: Path,
        input_bytes: bytes,
        config_path: Path,
    ) -> None:
        input_path.write_bytes(input_bytes)
        input_path.chmod(0o600)
        config_path.write_bytes(b"")
        config_path.chmod(0o600)

    def _remove_control_directory(self, control_directory: Path) -> None:
        shutil.rmtree(control_directory, ignore_errors=True)

    def _validate_output(
        self,
        raw: bytes,
        requested: tuple[ExactPackageCoordinate, ...],
    ) -> tuple[tuple[ScannerPackageResult, ...], dict[str, object]]:
        decoded = json.loads(
            raw.decode("utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_unique_json_object,
        )
        output = _OsvOutput.model_validate(decoded)
        requested_keys = {(item.ecosystem, item.name, item.version): item for item in requested}
        collected: dict[ExactPackageCoordinate, list[ScannerVulnerability]] = {
            item: [] for item in requested
        }
        for result in output.results:
            for package_result in result.packages:
                package = package_result.package
                if package.ecosystem is None or package.version is None:
                    raise ScannerBoundaryError(
                        "scanner_output_malformed",
                        "scanner package output lacked ecosystem or exact version",
                    )
                try:
                    ecosystem = Ecosystem(package.ecosystem)
                    name = normalize_package_name(ecosystem, package.name)
                except ValueError as exc:
                    raise ScannerBoundaryError(
                        "scanner_output_malformed", "scanner returned an invalid package coordinate"
                    ) from exc
                coordinate = requested_keys.get((ecosystem, name, package.version))
                if coordinate is None:
                    raise ScannerBoundaryError(
                        "scanner_output_coordinate_mismatch",
                        "scanner returned a coordinate that was not generated by Watchdog",
                    )
                for vulnerability in package_result.vulnerabilities:
                    candidate = ScannerVulnerability(
                        id=vulnerability.id,
                        aliases=tuple(vulnerability.aliases),
                    )
                    if candidate not in collected[coordinate]:
                        collected[coordinate].append(candidate)
        packages = tuple(
            ScannerPackageResult(coordinate=coordinate, vulnerabilities=tuple(vulnerabilities))
            for coordinate, vulnerabilities in sorted(
                collected.items(),
                key=lambda item: (
                    item[0].ecosystem.value,
                    item[0].name,
                    item[0].version,
                ),
            )
        )
        if not isinstance(decoded, dict):
            raise ScannerBoundaryError(
                "scanner_output_malformed", "scanner JSON root was not an object"
            )
        return packages, decoded

    def _environment(self, home: Path, cache: Path, temporary: Path) -> dict[str, str]:
        return {
            "HOME": str(home),
            "XDG_CACHE_HOME": str(cache),
            "TMPDIR": str(temporary),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }

    def _sanitize_diagnostics(self, value: bytes, control_directory: Path) -> str:
        return self._sanitize_text(value.decode("utf-8", errors="replace"), control_directory)

    def _sanitize_validated_output(
        self,
        value: dict[str, object],
        control_directory: Path,
    ) -> dict[str, object]:
        def sanitize(item: object) -> object:
            if isinstance(item, str):
                return self._logicalize_paths(item.replace(str(control_directory), "<control-dir>"))
            if isinstance(item, list):
                return [sanitize(child) for child in item]
            if isinstance(item, dict):
                return {str(key): sanitize(child) for key, child in item.items()}
            return item

        result = sanitize(value)
        assert isinstance(result, dict)
        return result

    def _sanitize_text(self, value: str, control_directory: Path) -> str:
        sanitized = self._logicalize_paths(value.replace(str(control_directory), "<control-dir>"))
        sanitized = _URL_CREDENTIALS.sub(r"\1<redacted>@", sanitized)
        sanitized = _SECRET_ASSIGNMENT.sub(r"\1=<redacted>", sanitized)
        return "".join(
            character for character in sanitized if character.isprintable() or character == "\n"
        ).strip()

    def _logicalize_paths(self, value: str) -> str:
        return value.replace("<control-dir>/exact-coordinates.json", "<generated-input>").replace(
            "<control-dir>/trusted-empty-config.toml", "<trusted-config>"
        )
