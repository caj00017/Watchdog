from __future__ import annotations

import builtins
import io
import socket
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import cast

import pytest

from watchdog import launcher
from watchdog.config import Settings
from watchdog.readiness import GuidedReadiness, ScannerReadiness, ScannerReadinessCode


class _TtyBuffer(io.StringIO):
    def isatty(self) -> bool:
        return True


def _readiness() -> GuidedReadiness:
    return GuidedReadiness(
        scanner="ready",
        ai="off",
        remediation="enabled",
        previews="disabled",
    )


def test_console_entry_point_is_installed_and_legacy_commands_delegate_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tomllib

    project = tomllib.loads(Path("pyproject.toml").read_text())
    assert project["project"]["scripts"] == {"watchdog": "watchdog.launcher:main"}
    received: list[list[str]] = []

    async def fake_main(arguments: list[str]) -> int:
        received.append(arguments)
        return 4

    monkeypatch.setattr("watchdog.launcher.legacy_cli._async_main", fake_main)

    arguments = [
        "investigate",
        "--advisory",
        "CVE-2026-12345",
        "--repository",
        "https://github.com/octocat/Hello-World",
    ]
    assert launcher.main(arguments) == 4
    assert received == [arguments]


def test_guided_settings_are_per_process_and_previews_require_cli_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WATCHDOG_REMEDIATION_PREVIEW_ENABLED", "true")
    configured = launcher._configured_settings(model=None, enable_previews=False)
    with_model = launcher._configured_settings(model="local-model", enable_previews=True)

    assert configured.local_interfaces_enabled
    assert configured.remediation_enabled
    assert not configured.remediation_preview_enabled
    assert not configured.investigation_enabled
    assert with_model.investigation_enabled
    assert with_model.investigation_model == "local-model"
    assert with_model.remediation_preview_enabled
    assert Settings().remediation_preview_enabled


def test_browser_opener_uses_fixed_controller_and_rejects_untrusted_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    class Browser:
        def open(self, url: str, *, new: int, autoraise: bool) -> bool:
            assert new == 2
            assert autoraise
            calls.append(("open", url))
            return True

    def get_browser(name: str) -> Browser:
        calls.append(("get", name))
        return Browser()

    monkeypatch.setenv("BROWSER", "sh -c hostile %s")
    monkeypatch.setattr("watchdog.launcher.webbrowser.get", get_browser)

    assert launcher._open_browser("http://127.0.0.1:8765/")
    assert calls == [("get", "xdg-open"), ("open", "http://127.0.0.1:8765/")]
    try:
        launcher._open_browser("https://example.invalid/")
    except ValueError:
        pass
    else:
        raise AssertionError("a non-loopback browser target was accepted")
    with pytest.raises(ValueError):
        launcher._open_browser("http://127.0.0.1:8765/hostile-repository/")


def test_server_prints_and_opens_only_after_binding_then_closes_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class Listener:
        def close(self) -> None:
            events.append("close")

    listener = cast(socket.socket, Listener())

    def fake_listener(_settings: Settings) -> socket.socket:
        events.append("bind")
        return listener

    class Server:
        def __init__(self, _configuration: object) -> None:
            events.append("server")

        def run(self, *, sockets: list[socket.socket]) -> None:
            assert sockets == [listener]
            events.append("run")
            raise KeyboardInterrupt

    def fake_open(url: str) -> bool:
        assert url == "http://127.0.0.1:8765/"
        events.append("open")
        return False

    monkeypatch.setattr(launcher, "_listener", fake_listener)
    monkeypatch.setattr("watchdog.launcher.uvicorn.Config", lambda *args, **kwargs: object())
    monkeypatch.setattr("watchdog.launcher.uvicorn.Server", Server)
    monkeypatch.setattr(launcher, "_open_browser", fake_open)
    monkeypatch.setattr(launcher, "create_app", lambda *args, **kwargs: object())
    stdout = io.StringIO()
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)

    result = launcher._run_server(
        Settings(local_interfaces_enabled=True, remediation_enabled=True),
        _readiness(),
        open_browser=True,
    )

    assert result == 0
    assert stdout.getvalue() == "http://127.0.0.1:8765/\n"
    assert stderr.getvalue() == ("browser_unavailable: Open the printed local URL in a browser.\n")
    assert events == ["bind", "server", "open", "run", "close"]


def test_port_conflict_does_not_print_or_open_url(monkeypatch: pytest.MonkeyPatch) -> None:
    def conflict(_settings: Settings) -> socket.socket:
        raise OSError("synthetic bind detail")

    opened = False

    def browser(_url: str) -> bool:
        nonlocal opened
        opened = True
        return True

    stdout = io.StringIO()
    stderr = io.StringIO()
    monkeypatch.setattr(launcher, "_listener", conflict)
    monkeypatch.setattr(launcher, "_open_browser", browser)
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)

    result = launcher._run_server(
        Settings(local_interfaces_enabled=True, remediation_enabled=True),
        _readiness(),
        open_browser=True,
    )

    assert result == 1
    assert stdout.getvalue() == ""
    assert not opened
    assert stderr.getvalue() == "ui_start_failed: The local interface port is unavailable.\n"
    assert "synthetic" not in stderr.getvalue()


async def test_doctor_output_is_fixed_and_contains_no_configured_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scanner_path = tmp_path / "SENSITIVE-SCANNER-PATH"
    settings = Settings(osv_scanner_path=scanner_path)

    async def unavailable(_settings: Settings) -> ScannerReadiness:
        return ScannerReadiness(ready=False, code=ScannerReadinessCode.MISSING)

    monkeypatch.setattr(launcher, "check_scanner_readiness", unavailable)
    stdout = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stdout)

    assert await launcher._doctor(settings) == 1
    assert stdout.getvalue() == (
        "configuration: ready\n"
        "scanner: unavailable\n"
        "Install or configure OSV-Scanner 2.4.0, then run watchdog doctor again.\n"
    )
    assert str(scanner_path) not in stdout.getvalue()


def test_ui_no_open_reaches_server_without_browser_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scanner_ready(_settings: Settings) -> ScannerReadiness:
        return ScannerReadiness(ready=True, code=ScannerReadinessCode.READY)

    captured: list[tuple[Settings, GuidedReadiness, bool]] = []

    def run_server(
        settings: Settings,
        readiness: GuidedReadiness,
        *,
        open_browser: bool,
    ) -> int:
        captured.append((settings, readiness, open_browser))
        return 0

    monkeypatch.delenv("WATCHDOG_INVESTIGATION_ENABLED", raising=False)
    monkeypatch.delenv("WATCHDOG_REMEDIATION_PREVIEW_ENABLED", raising=False)
    monkeypatch.setattr(launcher, "check_scanner_readiness", scanner_ready)
    monkeypatch.setattr(launcher, "_run_server", run_server)

    assert launcher._run_ui(["--no-open"]) == 0
    settings, readiness, open_browser = captured[0]
    assert settings.local_interfaces_enabled
    assert settings.remediation_enabled
    assert not settings.remediation_preview_enabled
    assert readiness.scanner == "ready"
    assert not open_browser


def test_bare_and_explicit_tui_are_lazy_and_use_separate_local_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scanner_ready(_settings: Settings) -> ScannerReadiness:
        return ScannerReadiness(ready=True, code=ScannerReadinessCode.READY)

    captured: list[tuple[Settings, GuidedReadiness]] = []

    def run_tui(settings: Settings, readiness: GuidedReadiness) -> int:
        captured.append((settings, readiness))
        return 0

    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(sys, "stdin", _TtyBuffer())
    monkeypatch.setattr(sys, "stdout", _TtyBuffer())
    monkeypatch.setattr(launcher, "check_scanner_readiness", scanner_ready)
    monkeypatch.setattr("watchdog.tui.runner.run_tui", run_tui)

    assert launcher.main([]) == 0
    assert launcher.main(["tui", "--enable-previews"]) == 0

    assert len(captured) == 2
    assert all(not settings.local_interfaces_enabled for settings, _readiness in captured)
    assert all(settings.remediation_enabled for settings, _readiness in captured)
    assert not captured[0][0].remediation_preview_enabled
    assert captured[1][0].remediation_preview_enabled
    assert all(readiness.scanner == "ready" for _settings, readiness in captured)


def test_tui_preflight_failure_is_plain_and_imports_no_tui_or_textual(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imported: list[str] = []
    real_import = builtins.__import__

    def recording_import(
        name: str,
        globals: Mapping[str, object] | None = None,
        locals: Mapping[str, object] | None = None,
        fromlist: Sequence[str] = (),
        level: int = 0,
    ) -> ModuleType:
        if name == "textual" or name.startswith("textual.") or name.startswith("watchdog.tui"):
            imported.append(name)
        return real_import(name, globals, locals, fromlist, level)

    stdout = io.StringIO()
    stderr = io.StringIO()
    monkeypatch.setattr(builtins, "__import__", recording_import)
    monkeypatch.setattr(sys, "stdin", io.StringIO())
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)

    assert launcher.main([]) == 2
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == launcher._TUI_PREFLIGHT_DIAGNOSTIC
    assert "\x1b" not in stderr.getvalue()
    assert imported == []


def test_launcher_help_mentions_tui_without_importing_textual(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imported: list[str] = []
    real_import = builtins.__import__

    def recording_import(
        name: str,
        globals: Mapping[str, object] | None = None,
        locals: Mapping[str, object] | None = None,
        fromlist: Sequence[str] = (),
        level: int = 0,
    ) -> ModuleType:
        if name == "textual" or name.startswith("textual."):
            imported.append(name)
        return real_import(name, globals, locals, fromlist, level)

    stdout = io.StringIO()
    monkeypatch.setattr(builtins, "__import__", recording_import)
    monkeypatch.setattr(sys, "stdout", stdout)

    assert launcher.main(["--help"]) == 0
    assert stdout.getvalue() == "Usage: watchdog {tui|ui|doctor|investigate|remediate} ...\n"
    assert imported == []


def test_tui_runtime_failure_is_fixed_and_does_not_expose_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scanner_ready(_settings: Settings) -> ScannerReadiness:
        return ScannerReadiness(ready=True, code=ScannerReadinessCode.READY)

    def fail_tui(_settings: Settings, _readiness: GuidedReadiness) -> int:
        raise LookupError("SENSITIVE RENDER FAILURE")

    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setattr(sys, "stdin", _TtyBuffer())
    monkeypatch.setattr(sys, "stdout", _TtyBuffer())
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stderr)
    monkeypatch.setattr(launcher, "check_scanner_readiness", scanner_ready)
    monkeypatch.setattr("watchdog.tui.runner.run_tui", fail_tui)

    assert launcher.main(["tui"]) == 1
    assert stderr.getvalue() == "tui_stopped: The local TUI stopped safely.\n"
    assert "SENSITIVE" not in stderr.getvalue()
