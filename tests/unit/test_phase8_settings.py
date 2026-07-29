from __future__ import annotations

import pytest
from pydantic import ValidationError

from watchdog.config import Settings
from watchdog.remediation.limits import RemediationConfiguration


def test_phase8_defaults_are_independently_disabled_and_bounded() -> None:
    settings = Settings()
    configuration = RemediationConfiguration.from_settings(settings)

    assert not configuration.enabled
    assert not configuration.preview_enabled
    assert configuration.limits.max_concurrent_requests == 1
    assert configuration.limits.deadline_seconds == 180
    assert configuration.limits.max_candidates == 64
    assert configuration.limits.max_bytes_per_preview_source_file == 5 * 1024 * 1024
    assert configuration.id.startswith("remediation-config:sha256:")


def test_phase8_settings_reject_broader_values_and_broken_identity() -> None:
    with pytest.raises(ValidationError):
        Settings(remediation_max_concurrent_requests=2)
    with pytest.raises(ValidationError):
        Settings(remediation_max_candidates=257)
    with pytest.raises(ValidationError):
        Settings(remediation_max_total_preview_source_bytes=25 * 1024 * 1024 + 1)
    configuration = RemediationConfiguration.from_settings(Settings())
    with pytest.raises(ValidationError, match="identity"):
        RemediationConfiguration.model_validate(
            {
                **configuration.model_dump(mode="python"),
                "id": "remediation-config:sha256:" + "0" * 64,
            }
        )
