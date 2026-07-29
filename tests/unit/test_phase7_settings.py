import pytest
from pydantic import ValidationError

from watchdog.config import Settings
from watchdog.reporting.limits import ReportingConfiguration
from watchdog.workflow.limits import WorkflowConfiguration


def test_phase7_defaults_are_disabled_local_and_bounded() -> None:
    settings = Settings()
    workflow = WorkflowConfiguration.from_settings(settings)
    reporting = ReportingConfiguration.from_settings(settings)

    assert not settings.local_interfaces_enabled
    assert settings.local_interfaces_host == "127.0.0.1"
    assert settings.local_interfaces_port == 8765
    assert settings.local_interfaces_max_request_bytes == 8192
    assert workflow.max_concurrent_requests == 1
    assert workflow.deadline_seconds == 180
    assert reporting.limits.max_json_bytes == 1_048_576
    assert reporting.limits.max_evidence_references == 2_048


def test_phase7_settings_reject_broader_or_unbounded_values() -> None:
    with pytest.raises(ValidationError):
        Settings(local_interfaces_host="0.0.0.0")
    with pytest.raises(ValidationError):
        Settings(workflow_max_concurrent_requests=2)
    with pytest.raises(ValidationError):
        Settings(local_interfaces_max_request_bytes=8193)
