from pathlib import Path

import pytest
from pydantic import ValidationError

from watchdog.config.settings import Settings
from watchdog.inventory.limits import InventoryLimits
from watchdog.scanners.limits import ScannerLimits


def test_phase3_settings_and_limit_factories_have_locked_defaults() -> None:
    settings = Settings()
    inventory = InventoryLimits.from_settings(settings)
    scanner = ScannerLimits.from_settings(settings)

    assert inventory.deadline_seconds == 120
    assert inventory.max_manifest_files == 200
    assert inventory.max_bytes_per_manifest == 5 * 1024 * 1024
    assert inventory.max_total_parsed_bytes == 25 * 1024 * 1024
    assert inventory.max_components == 50_000
    assert inventory.max_edges == 200_000
    assert inventory.max_parser_nesting_depth == 64
    assert inventory.max_requirements_include_depth == 10
    assert inventory.max_warnings == 1_000
    assert scanner.timeout_seconds == 120
    assert scanner.max_input_bytes == 5 * 1024 * 1024
    assert scanner.max_stdout_bytes == 25 * 1024 * 1024
    assert scanner.max_stderr_bytes == 1024 * 1024
    assert settings.osv_scanner_path == Path("/usr/local/bin/osv-scanner")


def test_scanner_path_must_be_absolute() -> None:
    with pytest.raises(ValidationError):
        Settings(osv_scanner_path=Path("relative/osv-scanner"))
