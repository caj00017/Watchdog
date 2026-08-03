from __future__ import annotations

import shutil
import sys

from textual import events
from textual.driver import Driver
from textual.geometry import Size
from textual.message import Message

_ENABLE_FOCUS_REPORTING = "\x1b[?1004h"
_ENABLE_BRACKETED_PASTE = "\x1b[?2004h"
MAXIMUM_TERMINAL_WIDTH = 240
MAXIMUM_TERMINAL_HEIGHT = 80


def filter_terminal_modes(data: str) -> str:
    """Remove terminal modes that the TUI does not require or authorize."""

    return data.replace(_ENABLE_FOCUS_REPORTING, "").replace(_ENABLE_BRACKETED_PASTE, "")


def clamp_terminal_dimensions(width: int, height: int) -> tuple[int, int]:
    return (
        min(max(width, 0), MAXIMUM_TERMINAL_WIDTH),
        min(max(height, 0), MAXIMUM_TERMINAL_HEIGHT),
    )


def detected_terminal_dimensions() -> tuple[int, int]:
    detected = shutil.get_terminal_size(fallback=(80, 25))
    return clamp_terminal_dimensions(detected.columns, detected.lines)


def _clamp_resize(message: Message) -> Message:
    if not isinstance(message, events.Resize):
        return message
    width, height = clamp_terminal_dimensions(message.size.width, message.size.height)
    size = Size(width, height)
    return events.Resize(size, size, size, message.pixel_size)


if sys.platform == "win32":
    from textual.drivers.windows_driver import WindowsDriver

    class WatchdogTerminalDriver(WindowsDriver):
        def write(self, data: str) -> None:
            super().write(filter_terminal_modes(data))

        def process_message(self, message: Message) -> None:
            super().process_message(_clamp_resize(message))

else:
    from textual.drivers.linux_driver import LinuxDriver

    class WatchdogTerminalDriver(LinuxDriver):
        def write(self, data: str) -> None:
            super().write(filter_terminal_modes(data))

        def _get_terminal_size(self) -> tuple[int, int]:
            return clamp_terminal_dimensions(*super()._get_terminal_size())

        def process_message(self, message: Message) -> None:
            super().process_message(_clamp_resize(message))


type TerminalDriver = type[Driver]


def terminal_driver_class() -> TerminalDriver:
    return WatchdogTerminalDriver
