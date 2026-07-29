from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from watchdog.domain.investigation import (
    EnvelopeEvidenceKind,
    InvestigationClaimKind,
    InvestigationEnvelope,
    ModelInvestigationDraft,
)
from watchdog.investigation.limits import InvestigationLimits


class ModelResponseError(ValueError):
    code = "invalid_model_response"


class ModelResponseSyntaxError(ModelResponseError):
    code = "invalid_model_response_syntax"


class ModelResponseSchemaError(ModelResponseError):
    code = "invalid_model_response_schema"


class ModelResponseEvidenceError(ModelResponseError):
    code = "invalid_model_response_evidence"


class _DuplicateKeyError(ValueError):
    pass


def decode_json_object(data: bytes) -> dict[str, Any]:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ModelResponseSyntaxError("model response is not valid UTF-8") from exc
    if text.lstrip().startswith("```"):
        raise ModelResponseSyntaxError("model response contains a Markdown fence")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateKeyError
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite number")

    decoder = json.JSONDecoder(object_pairs_hook=object_pairs, parse_constant=reject_constant)
    try:
        value, end = decoder.raw_decode(text.lstrip())
    except (_DuplicateKeyError, ValueError, RecursionError, json.JSONDecodeError) as exc:
        raise ModelResponseSyntaxError("model response is not one strict JSON value") from exc
    if text.lstrip()[end:].strip():
        raise ModelResponseSyntaxError("model response contains trailing data")
    if not isinstance(value, dict):
        raise ModelResponseSyntaxError("model response must be one JSON object")
    _validate_nesting(value)
    return value


def validate_model_response(
    data: bytes,
    envelope: InvestigationEnvelope,
    limits: InvestigationLimits,
) -> ModelInvestigationDraft:
    if len(data) > limits.max_output_bytes:
        raise ModelResponseSyntaxError("model response exceeds the output limit")
    decoded = decode_json_object(data)
    try:
        draft = ModelInvestigationDraft.model_validate(decoded)
    except ValidationError as exc:
        raise ModelResponseSchemaError("model response failed its strict schema") from exc
    if len(draft.claims) > limits.max_claims:
        raise ModelResponseSchemaError("model response exceeds the claim limit")
    if len(draft.assumptions) > limits.max_assumptions:
        raise ModelResponseSchemaError("model response exceeds the assumption limit")
    if len(draft.missing_evidence) > limits.max_missing_evidence_codes:
        raise ModelResponseSchemaError("model response exceeds the missing-evidence limit")
    if len(draft.validation_actions) > limits.max_validation_actions:
        raise ModelResponseSchemaError("model response exceeds the validation-action limit")
    _validate_controlled_codes(draft, envelope)
    _validate_claims(draft, envelope, limits)
    return draft


def _validate_controlled_codes(
    draft: ModelInvestigationDraft,
    envelope: InvestigationEnvelope,
) -> None:
    if not set(draft.assumptions).issubset(envelope.allowed_assumption_codes):
        raise ModelResponseEvidenceError("model selected an unavailable assumption")
    if not set(draft.missing_evidence).issubset(envelope.allowed_missing_evidence_codes):
        raise ModelResponseEvidenceError("model selected an unavailable evidence gap")
    if not set(draft.validation_actions).issubset(envelope.allowed_validation_action_codes):
        raise ModelResponseEvidenceError("model selected an unavailable validation action")


def _validate_claims(
    draft: ModelInvestigationDraft,
    envelope: InvestigationEnvelope,
    limits: InvestigationLimits,
) -> None:
    allowed = set(envelope.allowed_citation_ids)
    provenance_ids = {item.id for item in envelope.advisory.provenance}
    phase4_ids = {
        item.id for item in envelope.evidence if item.kind == EnvelopeEvidenceKind.DEPENDENCY_SOURCE
    }
    phase5_ids = {
        item.id for item in envelope.evidence if item.kind == EnvelopeEvidenceKind.LEXICAL_CONTEXT
    }
    phase5_by_id = {
        item.id: item
        for item in envelope.evidence
        if item.kind == EnvelopeEvidenceKind.LEXICAL_CONTEXT
    }
    observation_ids = {item.id for item in envelope.observations}
    observation_by_id = {item.id: item for item in envelope.observations}
    signal_ids = {item.id for item in envelope.signals}
    signal_by_id = {item.id: item for item in envelope.signals}
    evidence_field_ids = phase4_ids | phase5_ids | observation_ids
    for claim in draft.claims:
        all_links = {
            *claim.advisory_provenance_ids,
            *claim.evidence_ids,
            *claim.signal_ids,
        }
        if len(all_links) > limits.max_evidence_links_per_claim:
            raise ModelResponseEvidenceError("claim exceeds the evidence-link limit")
        if not all_links.issubset(allowed):
            raise ModelResponseEvidenceError("claim cites evidence outside the envelope")
        if not set(claim.advisory_provenance_ids).issubset(provenance_ids):
            raise ModelResponseEvidenceError("claim misuses an advisory provenance field")
        if not set(claim.evidence_ids).issubset(evidence_field_ids):
            raise ModelResponseEvidenceError("claim misuses an evidence field")
        if not set(claim.signal_ids).issubset(signal_ids):
            raise ModelResponseEvidenceError("claim misuses a signal field")
        if claim.rationale is not None and len(claim.rationale.encode("utf-8")) > (
            limits.max_rationale_bytes_per_claim
        ):
            raise ModelResponseSchemaError("claim rationale exceeds the byte limit")
        if claim.kind == InvestigationClaimKind.CONTEXTUAL_RELATIONSHIP:
            cited_evidence = set(claim.evidence_ids)
            cited_phase5 = cited_evidence & phase5_ids
            cited_observations = cited_evidence & observation_ids
            if not (cited_phase5 or cited_observations):
                raise ModelResponseEvidenceError("contextual claim lacks Phase 5 evidence")
            cited_phase4 = cited_evidence & phase4_ids
            if not cited_phase4:
                raise ModelResponseEvidenceError("contextual claim lacks Phase 4 support")
            supporting_phase5 = set(cited_phase5)
            supporting_phase5.update(
                observation_by_id[item_id].evidence_id for item_id in cited_observations
            )
            for item_id in supporting_phase5:
                if not (set(phase5_by_id[item_id].dependency_evidence_ids) & cited_phase4):
                    raise ModelResponseEvidenceError(
                        "contextual claim cites unrelated Phase 4 support"
                    )
            for signal_id in claim.signal_ids:
                if not (set(signal_by_id[signal_id].dependency_evidence_ids) & cited_phase4):
                    raise ModelResponseEvidenceError(
                        "contextual claim signal lacks its Phase 4 support"
                    )
        elif claim.kind == InvestigationClaimKind.DEPENDENCY_RELATIONSHIP:
            if not (set(claim.evidence_ids) & phase4_ids):
                raise ModelResponseEvidenceError("dependency claim lacks Phase 4 evidence")
        elif claim.kind == InvestigationClaimKind.ADVISORY_CONDITION:
            if not claim.advisory_provenance_ids:
                raise ModelResponseEvidenceError("advisory claim lacks canonical provenance")


def _validate_nesting(value: object, *, max_depth: int = 64) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise ModelResponseSyntaxError("model response nesting exceeds the limit")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
