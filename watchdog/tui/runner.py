from __future__ import annotations

from watchdog.config import Settings
from watchdog.readiness import GuidedReadiness


def run_tui(settings: Settings, readiness: GuidedReadiness) -> int:
    """Import Textual only after launcher preflight and scanner readiness."""

    from watchdog.tui.app import WatchdogTuiApp
    from watchdog.tui.backend import ProductionTuiBackend
    from watchdog.tui.driver import terminal_driver_class

    backend = ProductionTuiBackend(settings, readiness)
    app = WatchdogTuiApp(backend, driver_class=terminal_driver_class())
    result = app.run(mouse=False)
    return 0 if result is None else int(result)
