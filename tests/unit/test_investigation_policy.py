from __future__ import annotations

from pathlib import Path

import pytest

from tests.investigation_fixtures import build_investigation_inputs
from watchdog.domain.investigation import (
    EnvelopeEvidenceKind,
    InvestigationClaim,
    InvestigationClaimKind,
    InvestigationDisposition,
    ModelInvestigationDraft,
)
from watchdog.domain.matching import MatchState
from watchdog.investigation.envelope import build_investigation_envelope
from watchdog.investigation.policy import (
    InvestigationPolicyError,
    enforce_investigation_policy,
)

from .test_investigation_configuration import investigation_configuration


async def test_disposition_policy_matrix_is_deterministic(tmp_path: Path) -> None:
    inputs = await build_investigation_inputs(tmp_path)
    envelope = build_investigation_envelope(*inputs, investigation_configuration())
    phase4_id = next(
        item.id for item in envelope.evidence if item.kind == EnvelopeEvidenceKind.DEPENDENCY_SOURCE
    )
    phase5_id = next(
        item.id for item in envelope.evidence if item.kind == EnvelopeEvidenceKind.LEXICAL_CONTEXT
    )
    dependency_claim = InvestigationClaim(
        kind=InvestigationClaimKind.DEPENDENCY_RELATIONSHIP,
        summary="An exact matched coordinate is present.",
        rationale=None,
        advisory_provenance_ids=(),
        evidence_ids=(phase4_id,),
        signal_ids=(),
    )
    context_claim = InvestigationClaim(
        kind=InvestigationClaimKind.CONTEXTUAL_RELATIONSHIP,
        summary="Linked lexical context is present.",
        rationale=None,
        advisory_provenance_ids=(),
        evidence_ids=tuple(sorted((phase4_id, phase5_id))),
        signal_ids=(),
    )

    def draft(
        disposition: InvestigationDisposition,
        claims: tuple[InvestigationClaim, ...],
    ) -> ModelInvestigationDraft:
        return ModelInvestigationDraft(
            disposition=disposition,
            claims=claims,
            assumptions=(),
            missing_evidence=(),
            validation_actions=(),
        )

    enforce_investigation_policy(
        draft(
            InvestigationDisposition.DEPENDENCY_MATCH_AND_CONTEXT_OBSERVED,
            (context_claim,),
        ),
        envelope,
    )
    enforce_investigation_policy(
        draft(
            InvestigationDisposition.DEPENDENCY_MATCH_CONTEXT_UNCONFIRMED,
            (dependency_claim,),
        ),
        envelope,
    )
    enforce_investigation_policy(
        draft(InvestigationDisposition.INSUFFICIENT_EVIDENCE, (dependency_claim,)),
        envelope,
    )

    without_context = envelope.model_copy(update={"signals": ()})
    with pytest.raises(InvestigationPolicyError, match="observed-context"):
        enforce_investigation_policy(
            draft(
                InvestigationDisposition.DEPENDENCY_MATCH_AND_CONTEXT_OBSERVED,
                (context_claim,),
            ),
            without_context,
        )
    partial = envelope.model_copy(
        update={"coverage": envelope.coverage.model_copy(update={"input_partial": True})}
    )
    with pytest.raises(InvestigationPolicyError, match="ineligible"):
        enforce_investigation_policy(
            draft(
                InvestigationDisposition.DEPENDENCY_MATCH_CONTEXT_UNCONFIRMED,
                (dependency_claim,),
            ),
            partial,
        )
    unsupported = envelope.model_copy(
        update={
            "matches": (
                envelope.matches[0].model_copy(
                    update={"state": MatchState.UNSUPPORTED_ADVISORY_COMPONENT.value}
                ),
            )
        }
    )
    enforce_investigation_policy(
        draft(InvestigationDisposition.UNSUPPORTED, (dependency_claim,)),
        unsupported,
    )
    with pytest.raises(InvestigationPolicyError, match="must stay unsupported"):
        enforce_investigation_policy(
            draft(InvestigationDisposition.INSUFFICIENT_EVIDENCE, (dependency_claim,)),
            unsupported,
        )
    with pytest.raises(InvestigationPolicyError, match="lacks deterministic"):
        enforce_investigation_policy(
            draft(InvestigationDisposition.UNSUPPORTED, (dependency_claim,)),
            envelope,
        )
