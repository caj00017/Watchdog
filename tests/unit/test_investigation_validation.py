from __future__ import annotations

from pathlib import Path

import pytest

from tests.investigation_fixtures import build_investigation_inputs
from watchdog.domain.investigation import (
    EnvelopeEvidenceKind,
    InvestigationClaimKind,
    InvestigationDisposition,
)
from watchdog.investigation.envelope import build_investigation_envelope
from watchdog.investigation.identifiers import canonical_json_bytes
from watchdog.investigation.validation import (
    ModelResponseEvidenceError,
    ModelResponseSchemaError,
    ModelResponseSyntaxError,
    validate_model_response,
)

from .test_investigation_configuration import investigation_configuration


def valid_observed_draft(envelope: object) -> dict[str, object]:
    from watchdog.domain.investigation import InvestigationEnvelope

    validated = InvestigationEnvelope.model_validate(envelope)
    phase4_id = next(
        item.id
        for item in validated.evidence
        if item.kind == EnvelopeEvidenceKind.DEPENDENCY_SOURCE
    )
    phase5_id = next(
        item.id for item in validated.evidence if item.kind == EnvelopeEvidenceKind.LEXICAL_CONTEXT
    )
    return {
        "disposition": InvestigationDisposition.DEPENDENCY_MATCH_AND_CONTEXT_OBSERVED,
        "claims": [
            {
                "kind": InvestigationClaimKind.CONTEXTUAL_RELATIONSHIP,
                "summary": "The exact dependency match has linked lexical context.",
                "rationale": "This is model-generated inference, not runtime reachability.",
                "advisory_provenance_ids": [],
                "evidence_ids": sorted([phase4_id, phase5_id]),
                "signal_ids": [],
            }
        ],
        "assumptions": [],
        "missing_evidence": [],
        "validation_actions": [],
    }


async def test_strict_response_validation_accepts_only_envelope_citations(
    tmp_path: Path,
) -> None:
    inputs = await build_investigation_inputs(tmp_path)
    configuration = investigation_configuration()
    envelope = build_investigation_envelope(*inputs, configuration)
    valid = valid_observed_draft(envelope)

    draft = validate_model_response(canonical_json_bytes(valid), envelope, configuration.limits)

    assert draft.disposition == InvestigationDisposition.DEPENDENCY_MATCH_AND_CONTEXT_OBSERVED
    invented = dict(valid)
    invented_claim = dict(valid["claims"][0])  # type: ignore[index]
    invented_claim["evidence_ids"] = ["evidence:sha256:" + "f" * 64]
    invented["claims"] = [invented_claim]
    with pytest.raises(ModelResponseEvidenceError):
        validate_model_response(canonical_json_bytes(invented), envelope, configuration.limits)


async def test_response_rejects_duplicate_keys_unknown_fields_and_fences(
    tmp_path: Path,
) -> None:
    inputs = await build_investigation_inputs(tmp_path)
    configuration = investigation_configuration()
    envelope = build_investigation_envelope(*inputs, configuration)

    with pytest.raises(ModelResponseSyntaxError):
        validate_model_response(
            b'{"disposition":"insufficient_evidence","disposition":"unsupported"}',
            envelope,
            configuration.limits,
        )
    with pytest.raises(ModelResponseSyntaxError):
        validate_model_response(b"```json\n{}\n```", envelope, configuration.limits)
    invalid = valid_observed_draft(envelope)
    invalid["unknown"] = True
    with pytest.raises(ModelResponseSchemaError):
        validate_model_response(canonical_json_bytes(invalid), envelope, configuration.limits)


async def test_context_claim_requires_phase4_and_phase5_support(tmp_path: Path) -> None:
    inputs = await build_investigation_inputs(tmp_path)
    configuration = investigation_configuration()
    envelope = build_investigation_envelope(*inputs, configuration)
    invalid = valid_observed_draft(envelope)
    claim = dict(invalid["claims"][0])  # type: ignore[index]
    claim["evidence_ids"] = [
        next(
            item.id
            for item in envelope.evidence
            if item.kind == EnvelopeEvidenceKind.LEXICAL_CONTEXT
        )
    ]
    invalid["claims"] = [claim]

    with pytest.raises(ModelResponseEvidenceError, match="Phase 4"):
        validate_model_response(canonical_json_bytes(invalid), envelope, configuration.limits)
