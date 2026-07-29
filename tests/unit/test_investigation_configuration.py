from __future__ import annotations

import pytest
from pydantic import ValidationError

from watchdog.config.settings import Settings
from watchdog.domain.investigation import ValidationActionCode
from watchdog.investigation.limits import InvestigationConfiguration, InvestigationLimits
from watchdog.investigation.policy import VALIDATION_ACTION_TEXT
from watchdog.investigation.prompts import MODEL_RESPONSE_SCHEMA


def investigation_limits(**overrides: object) -> InvestigationLimits:
    values: dict[str, object] = {
        "deadline_seconds": 10,
        "max_concurrent_requests": 1,
        "max_input_bytes": 256 * 1024,
        "max_output_bytes": 64 * 1024,
        "max_evidence_items": 256,
        "max_matches": 256,
        "max_claims": 64,
        "max_evidence_links_per_claim": 32,
        "max_assumptions": 32,
        "max_missing_evidence_codes": 64,
        "max_validation_actions": 32,
        "max_rationale_bytes_per_claim": 2048,
        "max_output_tokens": 4096,
    }
    values.update(overrides)
    return InvestigationLimits.model_validate(values)


def investigation_configuration(
    *, enabled: bool = True, model: str | None = "local-model"
) -> InvestigationConfiguration:
    return InvestigationConfiguration(
        enabled=enabled,
        model=model,
        limits=investigation_limits(),
    )


def test_phase6_settings_are_disabled_and_bounded_by_default() -> None:
    configuration = InvestigationConfiguration.from_settings(Settings())

    assert not configuration.enabled
    assert configuration.model is None
    assert configuration.loopback_host == "127.0.0.1"
    assert configuration.loopback_port == 11434
    assert configuration.limits.max_input_bytes == 262_144
    assert configuration.limits.max_output_bytes == 65_536
    assert configuration.limits.max_concurrent_requests == 1


def test_enabled_configuration_requires_model_and_literal_loopback() -> None:
    with pytest.raises(ValidationError, match="explicit model"):
        InvestigationConfiguration(
            enabled=True,
            model=None,
            limits=investigation_limits(),
        )
    with pytest.raises(ValidationError):
        InvestigationConfiguration(
            enabled=True,
            model="local-model",
            loopback_host="localhost",
            limits=investigation_limits(),
        )


def test_response_schema_is_strict_and_action_text_is_checked_in() -> None:
    draft_schema = MODEL_RESPONSE_SCHEMA
    assert draft_schema["additionalProperties"] is False
    assert set(draft_schema["required"]) == {
        "disposition",
        "claims",
        "assumptions",
        "missing_evidence",
        "validation_actions",
    }
    claim_schema = draft_schema["$defs"]["InvestigationClaim"]
    assert claim_schema["additionalProperties"] is False
    assert set(claim_schema["required"]) == {
        "kind",
        "summary",
        "rationale",
        "advisory_provenance_ids",
        "evidence_ids",
        "signal_ids",
    }
    assert set(VALIDATION_ACTION_TEXT) == {item.value for item in ValidationActionCode}
