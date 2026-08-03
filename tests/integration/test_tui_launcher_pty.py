from __future__ import annotations

import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX PTY coverage")

_LAUNCH = [
    sys.executable,
    "-c",
    "from watchdog.launcher import main; raise SystemExit(main())",
]


def _scanner(tmp_path: Path) -> Path:
    scanner = tmp_path / "trusted-test-osv-scanner"
    scanner.write_bytes(b"#!/bin/sh\nprintf 'osv-scanner version: 2.4.0\\n'\n")
    scanner.chmod(0o700)
    return scanner


def _environment(scanner: Path, *, terminal: str) -> dict[str, str]:
    return {
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONPATH": str(Path.cwd()),
        "TERM": terminal,
        "WATCHDOG_OSV_SCANNER_PATH": str(scanner),
    }


def _spawn(
    tmp_path: Path,
    *,
    terminal: str = "xterm-256color",
    size: tuple[int, int] = (100, 30),
) -> tuple[int, subprocess.Popen[bytes]]:
    master, slave = pty.openpty()
    width, height = size
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))
    process = subprocess.Popen(
        _LAUNCH,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        cwd=Path.cwd(),
        env=_environment(_scanner(tmp_path), terminal=terminal),
        close_fds=True,
    )
    os.close(slave)
    return master, process


def _read_until(master: int, needle: bytes, *, limit: int = 256 * 1024) -> bytes:
    output = bytearray()
    while len(output) < limit:
        readable, _writable, _exceptional = select.select([master], [], [], 5)
        if not readable:
            break
        try:
            block = os.read(master, min(16_384, limit - len(output)))
        except OSError:
            break
        if not block:
            break
        output.extend(block)
        if needle in output:
            break
    return bytes(output)


def test_unsupported_terminal_preflight_is_plain_text(tmp_path: Path) -> None:
    master, process = _spawn(tmp_path, terminal="dumb")
    try:
        output = _read_until(master, b"stdin and stdout")
        assert process.wait(timeout=5) == 2
    finally:
        os.close(master)

    normalized = output.replace(b"\r\n", b"\n")
    assert normalized == (
        b"tui_unavailable: Watchdog TUI requires an interactive supported terminal "
        b"on stdin and stdout.\n"
    )
    assert b"\x1b" not in output


def test_small_terminal_shows_guidance_without_starting_work(tmp_path: Path) -> None:
    master, process = _spawn(tmp_path, size=(59, 19))
    try:
        output = _read_until(master, b"60 columns by 20 rows")
        assert b"60 columns by 20 rows" in output
        os.write(master, b"\x11")
        assert process.wait(timeout=10) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)


@pytest.mark.parametrize("stop", ["ctrl-q", "sigterm"])
def test_bare_tui_catchable_exit_is_clean(tmp_path: Path, stop: str) -> None:
    master, process = _spawn(tmp_path)
    try:
        output = _read_until(master, b"NEXURA WATCHDOG")
        assert b"NEXURA WATCHDOG" in output
        if stop == "ctrl-q":
            os.write(master, b"\x11")
        else:
            process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)
