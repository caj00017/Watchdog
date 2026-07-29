from __future__ import annotations

import re

from watchdog.context.catalog import DEFAULT_CONTEXT_CATALOG
from watchdog.context.identifiers import context_target_id
from watchdog.domain.context import (
    ContextLimitation,
    ContextRuleCatalog,
    ContextTarget,
    MappingKind,
    TargetApplicability,
)
from watchdog.domain.evidence import EvidenceBundle
from watchdog.domain.inventory import DependencyComponent, DependencyInventory, Ecosystem
from watchdog.domain.matching import DependencyMatch, DependencyMatchReport
from watchdog.domain.repositories import AcquiredRepository

_PYTHON_IMPORT_ROOT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def validate_context_inputs(
    acquired: AcquiredRepository,
    inventory: DependencyInventory,
    report: DependencyMatchReport,
    evidence: EvidenceBundle,
) -> None:
    expected = inventory.snapshot
    if (
        report.snapshot != expected
        or evidence.snapshot != expected
        or (
            acquired.snapshot.repository.canonical_url != expected.repository_url
            or acquired.snapshot.commit_sha != expected.commit_sha
            or acquired.snapshot.tree_sha != expected.tree_sha
            or acquired.snapshot.archive_sha256 != expected.archive_sha256
        )
    ):
        raise ValueError("context inputs must reference the same exact repository snapshot")

    components: dict[str, DependencyComponent] = {}
    for component in inventory.components:
        if component.id in components:
            raise ValueError("context inventory contains duplicate component IDs")
        components[component.id] = component
    if len(evidence.match_links) != len(report.matches):
        raise ValueError("Phase 4 evidence links do not correspond to the match report")
    evidence_ids = {item.id for item in evidence.items}
    for ordinal, (match, link) in enumerate(zip(report.matches, evidence.match_links, strict=True)):
        if (
            link.match_ordinal != ordinal
            or link.advisory_component_index != match.advisory_component_index
            or link.component_id != match.component_id
            or link.match_state != match.state
            or link.match_coverage_limitations != match.coverage_limitations
            or tuple(outcome.source for outcome in link.source_outcomes) != match.source_references
            or not set(link.evidence_ids).issubset(evidence_ids)
        ):
            raise ValueError("Phase 4 evidence links do not correspond to the match report")
        if match.component_id is None:
            continue
        validated_component = components.get(match.component_id)
        if validated_component is None:
            raise ValueError("context match references an unknown inventory component")
        _validate_match_component(match, validated_component)


def build_context_targets(
    inventory: DependencyInventory,
    report: DependencyMatchReport,
    evidence: EvidenceBundle,
    *,
    catalog: ContextRuleCatalog = DEFAULT_CONTEXT_CATALOG,
) -> tuple[ContextTarget, ...]:
    components = {component.id: component for component in inventory.components}
    targets: list[ContextTarget] = []
    for ordinal, match in enumerate(report.matches):
        if match.component_id is None:
            continue
        component = components[match.component_id]
        mapping_kind, complete, roots, mapping_limitations = _mapping(component, catalog)
        package_name = component.normalized_name
        member_ids = tuple(
            rule.id
            for rule in catalog.member_rules
            if rule.ecosystem == component.ecosystem and rule.package_name == package_name
        )
        configuration_ids = tuple(
            rule.id
            for rule in catalog.configuration_rules
            if rule.ecosystem == component.ecosystem and rule.package_name == package_name
        )
        endpoint_ids = tuple(
            rule.id
            for rule in catalog.endpoint_rules
            if rule.ecosystem == component.ecosystem and rule.package_name == package_name
        )
        dependency_ids = evidence.match_links[ordinal].evidence_ids
        limitations = set(mapping_limitations)
        if inventory.partial:
            limitations.add(ContextLimitation.INVENTORY_INCOMPLETE)
        if report.partial:
            limitations.add(ContextLimitation.MATCH_REPORT_INCOMPLETE)
        if evidence.partial or evidence.match_links[ordinal].limitation_codes:
            limitations.add(ContextLimitation.DEPENDENCY_EVIDENCE_INCOMPLETE)
        payload = {
            "match_ordinal": ordinal,
            "component_id": component.id,
            "ecosystem": component.ecosystem,
            "package_name": package_name,
            "version": component.version,
            "version_kind": component.version_kind,
            "applicability": TargetApplicability.APPLICABLE,
            "mapping_kind": mapping_kind,
            "mapping_complete": complete,
            "import_roots": roots,
            "member_rule_ids": tuple(sorted(member_ids)),
            "configuration_rule_ids": tuple(sorted(configuration_ids)),
            "endpoint_rule_ids": tuple(sorted(endpoint_ids)),
            "dependency_evidence_ids": tuple(sorted(dependency_ids)),
            "limitation_codes": tuple(sorted(limitations)),
        }
        targets.append(ContextTarget(id=context_target_id(payload), **payload))
    return tuple(sorted(targets, key=lambda item: (item.match_ordinal, item.id)))


def _validate_match_component(match: DependencyMatch, component: DependencyComponent) -> None:
    if (
        match.advisory_ecosystem is not None
        and match.advisory_ecosystem != component.ecosystem.value
    ):
        raise ValueError("context match ecosystem disagrees with its inventory component")
    if match.coordinate is not None:
        expected_version = component.version
        if (
            component.ecosystem == Ecosystem.GO
            and expected_version is not None
            and expected_version.startswith("v")
        ):
            expected_version = expected_version[1:]
        if (
            match.coordinate.ecosystem != component.ecosystem
            or match.coordinate.name != component.normalized_name
            or match.coordinate.version != expected_version
        ):
            raise ValueError("context match coordinate disagrees with its inventory component")
    if match.source_references != component.source_references:
        raise ValueError("context match sources disagree with its inventory component")


def _mapping(
    component: DependencyComponent,
    catalog: ContextRuleCatalog,
) -> tuple[MappingKind, bool, tuple[str, ...], tuple[ContextLimitation, ...]]:
    package_name = component.normalized_name
    exact = next(
        (
            rule
            for rule in catalog.package_mappings
            if rule.ecosystem == component.ecosystem and rule.package_name == package_name
        ),
        None,
    )
    if exact is not None:
        limitations = () if exact.complete else (ContextLimitation.IMPORT_MAPPING_INCOMPLETE,)
        return MappingKind.CATALOG_EXACT, exact.complete, exact.import_roots, limitations
    if component.ecosystem == Ecosystem.NPM:
        return MappingKind.GENERIC, True, (package_name,), ()
    if component.ecosystem == Ecosystem.GO:
        root_candidates = {package_name}
        if component.resolved_name is not None:
            root_candidates.add(component.resolved_name)
        roots = tuple(sorted(root_candidates))
        if roots:
            return MappingKind.GENERIC, True, roots, ()
    if component.ecosystem == Ecosystem.PYPI:
        candidate = package_name.replace("-", "_")
        if _PYTHON_IMPORT_ROOT.fullmatch(candidate):
            return (
                MappingKind.GENERIC,
                False,
                (candidate,),
                (ContextLimitation.IMPORT_MAPPING_INCOMPLETE,),
            )
    return (
        MappingKind.UNAVAILABLE,
        False,
        (),
        (ContextLimitation.IMPORT_MAPPING_UNAVAILABLE,),
    )
