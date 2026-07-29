from __future__ import annotations

import argparse
import asyncio
import socket
import sys
import webbrowser
from collections.abc import Sequence
from typing import Never
from urllib.parse import urlsplit

import uvicorn
from pydantic import ValidationError

from apps.cli import __main__ as legacy_cli
from apps.web.main import create_app
from apps.web.security import expected_origin, validate_loopback_configuration
from watchdog.config import Settings
from watchdog.readiness import (
    GuidedReadiness,
    check_scanner_readiness,
    guided_readiness,
    validate_runtime_configuration,
)

_USAGE = "Usage: watchdog {ui|doctor|investigate|remediate} ...\n"


class LauncherArgumentError(ValueError):
    pass


class _SafeParser(argparse.ArgumentParser):
    def error(self, _message: str) -> Never:
        raise LauncherArgumentError


def _ui_parser() -> _SafeParser:
    parser = _SafeParser(prog="watchdog ui")
    parser.add_argument("--model")
    parser.add_argument("--enable-previews", action="store_true")
    parser.add_argument("--no-open", action="store_true")
    return parser


def _diagnostic(code: str, message: str) -> None:
    sys.stderr.write(f"{code}: {message}\n")


def _configured_settings(*, model: str | None, enable_previews: bool) -> Settings:
    current = Settings()
    values = current.model_dump(mode="python")
    values.update(
        {
            "local_interfaces_enabled": True,
            "remediation_enabled": True,
            "remediation_preview_enabled": enable_previews,
        }
    )
    if model is not None:
        values.update(
            {
                "investigation_enabled": True,
                "investigation_model": model,
            }
        )
    configured = Settings.model_validate(values)
    validate_runtime_configuration(configured)
    validate_loopback_configuration(configured)
    return configured


def _listener(settings: Settings) -> socket.socket:
    family = socket.AF_INET6 if settings.local_interfaces_host == "::1" else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    try:
        listener.bind((settings.local_interfaces_host, settings.local_interfaces_port))
        listener.listen(2048)
        listener.setblocking(False)
        return listener
    except BaseException:
        listener.close()
        raise


def _open_browser(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("browser URL is not fixed literal loopback") from exc
    expected_netloc = (
        f"[{parsed.hostname}]:{port}" if parsed.hostname == "::1" else f"{parsed.hostname}:{port}"
    )
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or port is None
        or not 1 <= port <= 65_535
        or parsed.netloc != expected_netloc
        or parsed.path != "/"
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("browser URL is not fixed literal loopback")
    controller_name = (
        "windows-default"
        if sys.platform == "win32"
        else "macosx"
        if sys.platform == "darwin"
        else "xdg-open"
    )
    try:
        return bool(webbrowser.get(controller_name).open(url, new=2, autoraise=True))
    except Exception:
        return False


def _run_server(
    settings: Settings,
    readiness: GuidedReadiness,
    *,
    open_browser: bool,
) -> int:
    try:
        listener = _listener(settings)
    except OSError:
        _diagnostic("ui_start_failed", "The local interface port is unavailable.")
        return 1
    url = expected_origin(settings) + "/"
    try:
        configuration = uvicorn.Config(
            create_app(settings, guided=True, readiness=readiness),
            host=settings.local_interfaces_host,
            port=settings.local_interfaces_port,
            access_log=False,
            proxy_headers=False,
            server_header=False,
            date_header=False,
        )
        server = uvicorn.Server(configuration)
        sys.stdout.write(url + "\n")
        sys.stdout.flush()
        if open_browser and not _open_browser(url):
            _diagnostic(
                "browser_unavailable",
                "Open the printed local URL in a browser.",
            )
        server.run(sockets=[listener])
        return 0
    except KeyboardInterrupt:
        return 0
    except (OSError, RuntimeError):
        _diagnostic("ui_stopped", "The local interface stopped safely.")
        return 1
    finally:
        listener.close()


async def _doctor(settings: Settings) -> int:
    scanner = await check_scanner_readiness(settings)
    sys.stdout.write("configuration: ready\n")
    if scanner.ready:
        sys.stdout.write("scanner: ready (OSV-Scanner 2.4.0)\n")
        return 0
    sys.stdout.write("scanner: unavailable\n")
    sys.stdout.write("Install or configure OSV-Scanner 2.4.0, then run watchdog doctor again.\n")
    return 1


def _run_doctor() -> int:
    try:
        settings = Settings()
        validate_runtime_configuration(settings)
    except (ValidationError, ValueError):
        sys.stdout.write("configuration: unavailable\nscanner: not checked\n")
        return 2
    return asyncio.run(_doctor(settings))


def _run_ui(arguments: Sequence[str]) -> int:
    try:
        namespace = _ui_parser().parse_args(list(arguments))
        settings = _configured_settings(
            model=namespace.model,
            enable_previews=namespace.enable_previews,
        )
    except (LauncherArgumentError, ValidationError, ValueError):
        _diagnostic("invalid_arguments", "The UI options or configuration are invalid.")
        return 2
    scanner = asyncio.run(check_scanner_readiness(settings))
    readiness = guided_readiness(settings, scanner)
    return _run_server(settings, readiness, open_browser=not namespace.no_open)


def main(arguments: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if arguments is None else arguments)
    if not values:
        sys.stderr.write(_USAGE)
        return 2
    command, remainder = values[0], values[1:]
    if command in {"investigate", "remediate"}:
        return asyncio.run(legacy_cli._async_main(values))
    if command == "doctor" and not remainder:
        return _run_doctor()
    if command == "ui":
        return _run_ui(remainder)
    if command in {"-h", "--help"}:
        sys.stdout.write(_USAGE)
        return 0
    _diagnostic("invalid_arguments", "The command arguments are invalid.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
