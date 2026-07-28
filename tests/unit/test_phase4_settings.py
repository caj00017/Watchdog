from __future__ import annotations

import pytest
from pydantic import ValidationError

from watchdog.config.settings import Settings
from watchdog.evidence.limits import EvidenceConfiguration, EvidenceLimits


def test_phase4_settings_and_limits_have_locked_defaults() -> None:
    settings = Settings()
    limits = EvidenceLimits.from_settings(settings)
    configuration = EvidenceConfiguration.from_settings(settings)

    assert limits.deadline_seconds == 60
    assert limits.max_source_files == 200
    assert limits.max_bytes_per_source_file == 5 * 1024 * 1024
    assert limits.max_total_source_bytes == 25 * 1024 * 1024
    assert limits.max_evidence_items == 10_000
    assert limits.max_line_span == 200
    assert limits.max_display_bytes_per_item == 16 * 1024
    assert limits.max_bundle_display_bytes == 5 * 1024 * 1024
    assert limits.max_redactions_per_item == 100
    assert limits.max_warnings == 1_000
    assert configuration.context_lines == 0
    assert configuration.enabled_detectors == tuple(sorted(configuration.enabled_detectors))


def test_phase4_environment_prefix_and_related_limit_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WATCHDOG_EVIDENCE_MAX_ITEMS", "17")
    assert EvidenceLimits.from_settings(Settings()).max_evidence_items == 17

    with pytest.raises(ValidationError):
        EvidenceLimits.from_settings(
            Settings(
                evidence_max_bytes_per_source_file=20,
                evidence_max_total_source_bytes=10,
            )
        )
