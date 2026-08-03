from __future__ import annotations

import sys

from textual.driver import Driver

_ENABLE_FOCUS_REPORTING = "\x1b[?1004h"
_ENABLE_BRACKETED_PASTE = "\x1b[?2004h"


def filter_terminal_modes(data: str) -> str:
    """Remove terminal modes that the TUI does not require or authorize."""

    return data.replace(_ENABLE_FOCUS_REPORTING, "").replace(_ENABLE_BRACKETED_PASTE, "")


if sys.platform == "win32":
    from textual.drivers.windows_driver import WindowsDriver

    class WatchdogTerminalDriver(WindowsDriver):
        def write(self, data: str) -> None:
            super().write(filter_terminal_modes(data))

else:
    from textual.drivers.linux_driver import LinuxDriver

    class WatchdogTerminalDriver(LinuxDriver):
        def write(self, data: str) -> None:
            super().write(filter_terminal_modes(data))


type TerminalDriver = type[Driver]


def terminal_driver_class() -> TerminalDriver:
    return WatchdogTerminalDriver
