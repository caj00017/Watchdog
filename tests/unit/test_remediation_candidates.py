from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from tests.integration.test_evidence_service import configuration as evidence_configuration
from tests.integration.test_phase3_pipeline import inventory_limits, repository_limits
from tests.remediation_fixtures import remediation_advisory, remediation_configuration
from tests.repository_fixtures import FakeRepositorySource, TarEntry, build_tar
from tests.unit.test_matching import FakeScanner
from watchdog.advisory_match_service import AdvisoryMatchService
from watchdog.domain.advisories import AdvisoryRecord
from watchdog.domain.evidence import EvidenceBundle
from watchdog.domain.inventory import DependencyInventory
from watchdog.domain.matching import (
    DependencyMatchReport,
    ExactPackageCoordinate,
    ScannerVulnerability,
)
from watchdog.domain.remediation import (
    CandidateSelectionOutcome,
    RemediationCandidate,
    RemediationConflict,
)
from watchdog.domain.repositories import RepositoryRequest
from watchdog.evidence.service import EvidenceService
from watchdog.inventory.service import DependencyInventoryService
from watchdog.remediation.candidates import derive_candidates
from watchdog.repository.intake import RepositoryIntakeService


async def _inputs(
    tmp_path: Path,
    *,
    manifest: bytes = b"requests==2.32.3\n",
    target: str = "2.32.4",
    second_target: str | None = None,
    mutate_before_evidence: bool = False,
) -> tuple[
    AdvisoryRecord,
    DependencyInventory,
    DependencyMatchReport,
    EvidenceBundle,
]:
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=manifest),
        ]
    )
    advisory = remediation_advisory(
        "PyPI", "requests", target, conditional_second_target=second_target
    )
    coordinate = ExactPackageCoordinate(ecosystem="PyPI", name="requests", version="2.32.3")
    scanner = FakeScanner(
        {coordinate: (ScannerVulnerability(id=advisory.primary_id, aliases=advisory.aliases),)}
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(
        RepositoryRequest(repository_url="https://github.com/octocat/Hello-World", ref="main")
    )
    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        matches = await AdvisoryMatchService(scanner).match(advisory, inventory)
        if mutate_before_evidence:
            (acquired.root / "requirements.txt").write_bytes(b"requests==9.9.9\n")
        evidence = await EvidenceService(evidence_configuration()).collect(
            acquired, inventory, matches
        )
    assert lease.cleanup_result.verified
    return advisory, inventory, matches, evidence


async def test_candidate_derivation_is_deterministic_after_repository_cleanup(
    tmp_path: Path,
) -> None:
    advisory, inventory, matches, evidence = await _inputs(tmp_path)
    configuration = remediation_configuration()

    first = derive_candidates(advisory, inventory, matches, evidence, configuration)
    second = derive_candidates(advisory, inventory, matches, evidence, configuration)

    assert first == second
    assert len(first.candidates) == 1
    candidate = first.candidates[0]
    assert candidate.current_coordinate.version == "2.32.3"
    assert candidate.raw_source_reported_target == "2.32.4"
    assert candidate.selection is CandidateSelectionOutcome.SELECTED
    assert candidate.advisory_fact_supports[0].normalized_field_path.endswith("/fixed")
    assert candidate.dependency_evidence_ids


async def test_conditional_match_is_visible_but_manual_only(tmp_path: Path) -> None:
    inputs = await _inputs(
        tmp_path,
        manifest=b"requests==2.32.3; sys_platform == 'linux'\n",
    )
    result = derive_candidates(
        inputs[0], inputs[1], inputs[2], inputs[3], remediation_configuration()
    )

    assert result.candidates[0].selection is CandidateSelectionOutcome.CONDITIONAL
    assert result.candidates[0].match_state.value == "affected_conditional"


async def test_multiple_source_targets_remain_ambiguous(tmp_path: Path) -> None:
    inputs = await _inputs(tmp_path, second_target="2.33.0")
    result = derive_candidates(
        inputs[0], inputs[1], inputs[2], inputs[3], remediation_configuration()
    )

    assert len(result.candidates) == 2
    assert {item.selection for item in result.candidates} == {CandidateSelectionOutcome.AMBIGUOUS}
    assert RemediationConflict.MULTIPLE_SOURCE_REPORTED_TARGETS in result.conflicts


async def test_omitted_phase4_content_cannot_authorize_candidate(tmp_path: Path) -> None:
    inputs = await _inputs(tmp_path, mutate_before_evidence=True)
    result = derive_candidates(
        inputs[0], inputs[1], inputs[2], inputs[3], remediation_configuration()
    )

    assert not result.candidates
    assert result.omitted_candidates == 1


async def test_candidate_schema_rejects_broken_support_value(tmp_path: Path) -> None:
    inputs = await _inputs(tmp_path)
    candidate = derive_candidates(
        inputs[0], inputs[1], inputs[2], inputs[3], remediation_configuration()
    ).candidates[0]
    payload = candidate.model_dump(mode="python")
    support = dict(payload["advisory_fact_supports"][0])
    support["raw_source_value"] = "9.9.9"
    payload["advisory_fact_supports"] = (support,)

    with pytest.raises(ValidationError):
        RemediationCandidate.model_validate(payload)


async def test_incomplete_deterministic_inputs_cannot_authorize_preview(tmp_path: Path) -> None:
    advisory, inventory, matches, evidence = await _inputs(tmp_path)
    advisory = advisory.model_copy(update={"partial": True})

    result = derive_candidates(advisory, inventory, matches, evidence, remediation_configuration())

    assert len(result.candidates) == 1
    assert result.candidates[0].selection is CandidateSelectionOutcome.UPSTREAM_INCOMPLETE
    assert "upstream_coverage_incomplete" in {
        item.value for item in result.candidates[0].limitations
    }
