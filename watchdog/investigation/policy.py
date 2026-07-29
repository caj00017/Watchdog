from __future__ import annotations

from watchdog.domain.context import ContextSignalKind
from watchdog.domain.investigation import (
    InvestigationClaimKind,
    InvestigationDisposition,
    InvestigationEnvelope,
    ModelInvestigationDraft,
)
from watchdog.domain.matching import MatchState


class InvestigationPolicyError(ValueError):
    code = "investigation_policy_rejected"


_SUPPORTED_MATCH_STATES = {
    MatchState.AFFECTED.value,
    MatchState.AFFECTED_CONDITIONAL.value,
}
_POSITIVE_CONTEXT_SIGNALS = {
    ContextSignalKind.EXPLICIT_TARGET_CALL_OBSERVED.value,
    ContextSignalKind.TARGET_REFERENCE_OBSERVED.value,
    ContextSignalKind.DEPENDENCY_IMPORT_OBSERVED.value,
    ContextSignalKind.TARGET_CONFIGURATION_OBSERVED.value,
    ContextSignalKind.ENDPOINT_PROXIMITY_OBSERVED.value,
}

VALIDATION_ACTION_TEXT = {
    "review_cited_dependency_source": "Review the cited dependency declaration.",
    "review_cited_context_site": "Review the cited lexical context site.",
    "review_advisory_conditions": "Review the advisory's applicability conditions.",
    "confirm_runtime_configuration": "Confirm the relevant runtime configuration.",
    "confirm_deployment_conditions": "Confirm deployment-specific conditions.",
    "obtain_exact_version_evidence": "Obtain an exact dependency version from a lockfile.",
    "obtain_supported_manifest_evidence": "Obtain a supported dependency manifest.",
    "resolve_scanner_failure": "Resolve the scanner failure before drawing a conclusion.",
}


def enforce_investigation_policy(
    draft: ModelInvestigationDraft,
    envelope: InvestigationEnvelope,
) -> None:
    states = {item.state for item in envelope.matches}
    supported_ordinals = {
        item.ordinal for item in envelope.matches if item.state in _SUPPORTED_MATCH_STATES
    }
    supported_match = bool(supported_ordinals)
    all_unsupported = bool(states) and states == {MatchState.UNSUPPORTED_ADVISORY_COMPONENT.value}
    positive_ordinals = {
        signal.match_ordinal
        for signal in envelope.signals
        if signal.kind in _POSITIVE_CONTEXT_SIGNALS
    }
    eligible_observed_ordinals = supported_ordinals & positive_ordinals
    positive_context = bool(eligible_observed_ordinals)
    partial = envelope.coverage.input_partial

    if draft.disposition == InvestigationDisposition.DEPENDENCY_MATCH_AND_CONTEXT_OBSERVED:
        if partial or not supported_match or not positive_context:
            raise InvestigationPolicyError("observed-context disposition is ineligible")
        if not any(
            claim.kind == InvestigationClaimKind.CONTEXTUAL_RELATIONSHIP
            and _claim_match_ordinals(claim.evidence_ids, envelope) & eligible_observed_ordinals
            for claim in draft.claims
        ):
            raise InvestigationPolicyError("observed-context disposition requires a context claim")
    elif draft.disposition == InvestigationDisposition.DEPENDENCY_MATCH_CONTEXT_UNCONFIRMED:
        if partial or not supported_match:
            raise InvestigationPolicyError("unconfirmed-context disposition is ineligible")
    elif draft.disposition == InvestigationDisposition.UNSUPPORTED:
        if not all_unsupported:
            raise InvestigationPolicyError("unsupported disposition lacks deterministic support")
    elif draft.disposition == InvestigationDisposition.INSUFFICIENT_EVIDENCE:
        if all_unsupported:
            raise InvestigationPolicyError(
                "deterministically unsupported input must stay unsupported"
            )
    else:  # pragma: no cover - enum exhaustiveness guard
        raise InvestigationPolicyError("unknown investigation disposition")

    if partial and draft.disposition not in {
        InvestigationDisposition.INSUFFICIENT_EVIDENCE,
        InvestigationDisposition.UNSUPPORTED,
    }:
        raise InvestigationPolicyError("partial input cannot produce a positive disposition")


def _claim_match_ordinals(
    evidence_ids: tuple[str, ...],
    envelope: InvestigationEnvelope,
) -> set[int]:
    requested = set(evidence_ids)
    ordinals = {
        ordinal
        for item in envelope.evidence
        if item.id in requested
        for ordinal in item.match_ordinals
    }
    ordinals.update(item.match_ordinal for item in envelope.observations if item.id in requested)
    return ordinals
