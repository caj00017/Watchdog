from __future__ import annotations

from pathlib import Path

import pytest

from tests.investigation_fixtures import build_investigation_inputs
from watchdog.domain.investigation import (
    EnvelopeEvidenceKind,
    InvestigationLimitationCode,
)
from watchdog.investigation.envelope import (
    InvestigationInputError,
    build_investigation_envelope,
)
from watchdog.investigation.identifiers import canonical_json_bytes

from .test_investigation_configuration import investigation_configuration, investigation_limits


async def test_envelope_is_deterministic_bounded_and_contains_only_linked_evidence(
    tmp_path: Path,
) -> None:
    advisory, inventory, report, evidence, context = await build_investigation_inputs(tmp_path)
    configuration = investigation_configuration()
    phase4_ids = tuple(item.id for item in evidence.items)
    phase5_ids = tuple(item.id for item in context.evidence)

    first = build_investigation_envelope(
        advisory, inventory, report, evidence, context, configuration
    )
    second = build_investigation_envelope(
        advisory, inventory, report, evidence, context, configuration
    )

    assert first == second
    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert len(canonical_json_bytes(first)) <= configuration.limits.max_input_bytes
    assert first.snapshot == inventory.snapshot
    assert first.coverage.input_partial is False
    assert {item.kind for item in first.evidence} == {
        EnvelopeEvidenceKind.DEPENDENCY_SOURCE,
        EnvelopeEvidenceKind.LEXICAL_CONTEXT,
    }
    assert first.graph_nodes
    assert first.graph_edges
    assert set(first.allowed_citation_ids) == {
        *(item.id for item in first.advisory.provenance),
        *(item.id for item in first.evidence),
        *(item.id for item in first.observations),
        *(item.id for item in first.signals),
    }
    encoded = canonical_json_bytes(first).decode("utf-8")
    assert "IGNORE PRIOR INSTRUCTIONS" in encoded
    assert "SourceRecord" not in encoded
    assert '"raw"' not in encoded
    assert str(tmp_path) not in encoded
    assert tuple(item.id for item in evidence.items) == phase4_ids
    assert tuple(item.id for item in context.evidence) == phase5_ids


async def test_envelope_limit_is_canonical_and_explicit(tmp_path: Path) -> None:
    advisory, inventory, report, evidence, context = await build_investigation_inputs(tmp_path)
    configuration = investigation_configuration().model_copy(
        update={"limits": investigation_limits(max_evidence_items=1, max_input_bytes=64 * 1024)}
    )

    envelope = build_investigation_envelope(
        advisory, inventory, report, evidence, context, configuration
    )

    assert envelope.coverage.input_partial
    assert envelope.coverage.envelope_truncated
    assert envelope.coverage.evidence_included == 1
    assert envelope.coverage.evidence_omitted >= 1
    assert InvestigationLimitationCode.EVIDENCE_ITEM_LIMIT_EXCEEDED in (
        envelope.coverage.limitations
    )


async def test_cross_snapshot_input_fails_before_envelope(tmp_path: Path) -> None:
    advisory, inventory, report, evidence, context = await build_investigation_inputs(tmp_path)
    mismatched = inventory.model_copy(
        update={"snapshot": inventory.snapshot.model_copy(update={"tree_sha": "a" * 40})}
    )

    with pytest.raises(InvestigationInputError, match="exact snapshot"):
        build_investigation_envelope(
            advisory,
            mismatched,
            report,
            evidence,
            context,
            investigation_configuration(),
        )
