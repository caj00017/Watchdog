from __future__ import annotations

from pathlib import Path

import pytest

from tests.factories import make_advisory
from tests.unit.test_inventory import acquired_repository, inventory_limits
from tests.unit.test_matching import FakeScanner
from watchdog.advisory_match_service import AdvisoryMatchService
from watchdog.context.catalog import DEFAULT_CONTEXT_CATALOG
from watchdog.context.targets import _mapping, build_context_targets, validate_context_inputs
from watchdog.domain.advisories import AffectedPackage
from watchdog.domain.context import ContextLimitation, MappingKind
from watchdog.domain.evidence import EvidenceBundle
from watchdog.domain.inventory import DependencyComponent, DependencyInventory
from watchdog.domain.matching import DependencyMatchReport
from watchdog.domain.repositories import AcquiredRepository
from watchdog.evidence.limits import EvidenceConfiguration, EvidenceLimits
from watchdog.evidence.service import EvidenceService
from watchdog.inventory.service import DependencyInventoryService


def _evidence_configuration() -> EvidenceConfiguration:
    return EvidenceConfiguration(
        limits=EvidenceLimits(
            deadline_seconds=10,
            max_source_files=20,
            max_bytes_per_source_file=1024 * 1024,
            max_total_source_bytes=2 * 1024 * 1024,
            max_evidence_items=100,
            max_line_span=50,
            max_display_bytes_per_item=4096,
            max_bundle_display_bytes=8192,
            max_redactions_per_item=20,
            max_warnings=100,
        )
    )


async def _inputs(
    tmp_path: Path, package: str
) -> tuple[AcquiredRepository, DependencyInventory, DependencyMatchReport, EvidenceBundle]:
    acquired = acquired_repository(
        tmp_path,
        {"requirements.txt": f"{package}==1.0.0\n"},
    )
    inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
    advisory = make_advisory().model_copy(
        update={"affected_packages": (AffectedPackage(ecosystem="PyPI", name=package),)}
    )
    report = await AdvisoryMatchService(FakeScanner()).match(advisory, inventory)
    evidence = await EvidenceService(_evidence_configuration()).collect(acquired, inventory, report)
    return acquired, inventory, report, evidence


async def test_python_generic_mapping_is_positive_only_and_identity_bound(tmp_path: Path) -> None:
    acquired, inventory, report, evidence = await _inputs(tmp_path, "requests")
    validate_context_inputs(acquired, inventory, report, evidence)

    first = build_context_targets(inventory, report, evidence)
    second = build_context_targets(inventory, report, evidence)

    assert first == second
    assert len(first) == 1
    target = first[0]
    assert target.mapping_kind == MappingKind.GENERIC
    assert target.import_roots == ("requests",)
    assert not target.mapping_complete
    assert ContextLimitation.IMPORT_MAPPING_INCOMPLETE in target.limitation_codes
    assert target.configuration_rule_ids == ("pypi-requests-verify",)
    assert target.dependency_evidence_ids == evidence.match_links[0].evidence_ids


async def test_reviewed_python_exception_mapping_is_complete(tmp_path: Path) -> None:
    acquired, inventory, report, evidence = await _inputs(tmp_path, "pyyaml")
    validate_context_inputs(acquired, inventory, report, evidence)

    target = build_context_targets(inventory, report, evidence)[0]

    assert target.mapping_kind == MappingKind.CATALOG_EXACT
    assert target.mapping_complete
    assert target.import_roots == ("yaml",)
    assert ContextLimitation.IMPORT_MAPPING_INCOMPLETE not in target.limitation_codes
    assert target.member_rule_ids == ("pypi-pyyaml-load",)


async def test_snapshot_and_phase4_linkage_disagreement_fail_before_discovery(
    tmp_path: Path,
) -> None:
    acquired, inventory, report, evidence = await _inputs(tmp_path, "requests")
    stale_report = report.model_copy(
        update={"snapshot": report.snapshot.model_copy(update={"tree_sha": "f" * 40})}
    )
    with pytest.raises(ValueError, match="same exact"):
        validate_context_inputs(acquired, inventory, stale_report, evidence)

    link = evidence.match_links[0].model_copy(update={"component_id": "stale"})
    stale_evidence = evidence.model_copy(update={"match_links": (link,)})
    with pytest.raises(ValueError, match="do not correspond"):
        validate_context_inputs(acquired, inventory, report, stale_evidence)


def test_go_replacement_mapping_keeps_original_and_resolved_import_prefixes() -> None:
    component = DependencyComponent.model_validate(
        {
            "id": "component",
            "project_id": "project",
            "ecosystem": "Go",
            "name": "example.com/original",
            "normalized_name": "example.com/original",
            "version": "v1.2.3",
            "version_kind": "exact",
            "relationship": "direct",
            "scopes": ("runtime",),
            "source_references": (
                {
                    "path": "go.mod",
                    "selector": {"kind": "line", "value": "line:1"},
                    "file_sha256": "a" * 64,
                },
            ),
            "scanner_eligible": True,
            "resolved_name": "example.com/replacement",
        }
    )
    _, complete, roots, limitations = _mapping(component, DEFAULT_CONTEXT_CATALOG)
    assert complete
    assert roots == ("example.com/original", "example.com/replacement")
    assert limitations == ()
