from __future__ import annotations

from dataclasses import dataclass

from watchdog.domain.advisories import AdvisoryRecord, FieldProvenance
from watchdog.domain.evidence import EvidenceBundle, EvidenceStatus
from watchdog.domain.inventory import DependencyInventory, Ecosystem, VersionKind
from watchdog.domain.matching import DependencyMatchReport, ExactPackageCoordinate, MatchState
from watchdog.domain.remediation import (
    AdvisoryFactSupport,
    CandidateClassification,
    CandidateSelectionOutcome,
    RemediationCandidate,
    RemediationConflict,
    RemediationLimitation,
    RemediationWarning,
)
from watchdog.inventory.identifiers import normalize_package_name
from watchdog.remediation.identifiers import remediation_candidate_id, remediation_support_id
from watchdog.remediation.limits import RemediationConfiguration
from watchdog.remediation.versions import compare_versions


class CandidateDerivationError(ValueError):
    code = "remediation_candidate_derivation_failed"


@dataclass(frozen=True, slots=True)
class CandidateDerivation:
    candidates: tuple[RemediationCandidate, ...]
    conflicts: tuple[RemediationConflict, ...]
    warnings: tuple[RemediationWarning, ...]
    limitations: tuple[RemediationLimitation, ...]
    eligible_matches: int
    source_reported_targets: int
    omitted_candidates: int


def _revalidate_inputs(
    advisory: AdvisoryRecord,
    inventory: DependencyInventory,
    matches: DependencyMatchReport,
    evidence: EvidenceBundle,
) -> tuple[AdvisoryRecord, DependencyInventory, DependencyMatchReport, EvidenceBundle]:
    values = (
        AdvisoryRecord.model_validate(advisory.model_dump(mode="python")),
        DependencyInventory.model_validate(inventory.model_dump(mode="python")),
        DependencyMatchReport.model_validate(matches.model_dump(mode="python")),
        EvidenceBundle.model_validate(evidence.model_dump(mode="python")),
    )
    validated_advisory, validated_inventory, validated_matches, validated_evidence = values
    if validated_matches.advisory_id != validated_advisory.primary_id or (
        validated_matches.advisory_aliases != validated_advisory.aliases
    ):
        raise CandidateDerivationError("candidate inputs do not identify one advisory")
    if not (
        validated_inventory.snapshot == validated_matches.snapshot == validated_evidence.snapshot
    ):
        raise CandidateDerivationError("candidate inputs do not identify one snapshot")
    if len(validated_matches.matches) != len(validated_evidence.match_links):
        raise CandidateDerivationError("candidate evidence links do not cover every match")
    return values


def _support(
    provenance: FieldProvenance,
    *,
    field_path: str,
    component_index: int,
    value: str,
) -> AdvisoryFactSupport:
    payload = {
        "provenance": provenance,
        "normalized_field_path": field_path,
        "affected_component_index": component_index,
        "raw_source_value": value,
    }
    return AdvisoryFactSupport(id=remediation_support_id(payload), **payload)


def _fixed_facts(
    advisory: AdvisoryRecord,
    *,
    component_index: int,
    ecosystem: Ecosystem,
    normalized_name: str,
) -> tuple[dict[str, dict[str, AdvisoryFactSupport]], bool]:
    values: dict[str, dict[str, AdvisoryFactSupport]] = {}
    package_mapping_ambiguous = False
    affected = advisory.affected_packages[component_index]
    for range_index, affected_range in enumerate(affected.ranges):
        for event_index, event in enumerate(affected_range.events):
            if event.fixed is None:
                continue
            path = (
                f"/affected_packages/{component_index}/ranges/{range_index}/"
                f"events/{event_index}/fixed"
            )
            for provenance in advisory.field_provenance.get(path, ()):
                item = _support(
                    provenance,
                    field_path=path,
                    component_index=component_index,
                    value=event.fixed,
                )
                values.setdefault(event.fixed, {})[item.id] = item

    for remediation_index, remediation in enumerate(advisory.remediation):
        if remediation.fixed_version is None or remediation.package is None:
            continue
        mappings: list[int] = []
        for index, package in enumerate(advisory.affected_packages):
            if package.ecosystem is None or package.name is None:
                continue
            try:
                package_ecosystem = Ecosystem(package.ecosystem)
            except ValueError:
                continue
            if normalize_package_name(package_ecosystem, package.name) == normalize_package_name(
                package_ecosystem, remediation.package
            ):
                mappings.append(index)
        if component_index in mappings and mappings != [component_index]:
            package_mapping_ambiguous = True
        if mappings != [component_index]:
            continue
        package = advisory.affected_packages[component_index]
        if package.ecosystem != ecosystem.value or package.name is None:
            continue
        if normalize_package_name(ecosystem, package.name) != normalized_name:
            continue
        path = f"/remediation/{remediation_index}/fixed_version"
        for provenance in advisory.field_provenance.get(path, ()):
            item = _support(
                provenance,
                field_path=path,
                component_index=component_index,
                value=remediation.fixed_version,
            )
            values.setdefault(remediation.fixed_version, {})[item.id] = item
    return values, package_mapping_ambiguous


def _relevant_conflict(advisory: AdvisoryRecord, component_index: int) -> bool:
    component_prefix = f"/affected_packages/{component_index}/"
    for conflict in advisory.conflicts:
        if conflict.field.startswith(component_prefix) or conflict.field.startswith("/remediation"):
            return True
    return False


def derive_candidates(
    advisory: AdvisoryRecord,
    inventory: DependencyInventory,
    matches: DependencyMatchReport,
    evidence: EvidenceBundle,
    configuration: RemediationConfiguration,
) -> CandidateDerivation:
    advisory, inventory, matches, evidence = _revalidate_inputs(
        advisory, inventory, matches, evidence
    )
    components = {component.id: component for component in inventory.components}
    evidence_ids = {
        item.id for item in evidence.items if item.status is not EvidenceStatus.CONTENT_OMITTED
    }
    candidate_drafts: list[dict[str, object]] = []
    conflicts: set[RemediationConflict] = set()
    warnings: set[RemediationWarning] = set()
    limitations: set[RemediationLimitation] = set()
    eligible_matches = 0
    source_reported_targets = 0
    omitted_candidates = 0

    for ordinal, match in enumerate(matches.matches):
        if match.state not in {MatchState.AFFECTED, MatchState.AFFECTED_CONDITIONAL}:
            continue
        if match.coordinate is None or match.component_id is None:
            continue
        component = components.get(match.component_id)
        component_coordinate_version = component.version if component is not None else None
        if (
            component is not None
            and component.ecosystem is Ecosystem.GO
            and component_coordinate_version is not None
            and component_coordinate_version.startswith("v")
        ):
            component_coordinate_version = component_coordinate_version[1:]
        if (
            component is None
            or not component.scanner_eligible
            or component.version_kind is not VersionKind.EXACT
            or component.version is None
            or component_coordinate_version != match.coordinate.version
            or component.ecosystem is not match.coordinate.ecosystem
            or component.normalized_name
            != normalize_package_name(match.coordinate.ecosystem, match.coordinate.name)
        ):
            continue
        if match.advisory_component_index >= len(advisory.affected_packages):
            raise CandidateDerivationError("match advisory component index is invalid")
        affected = advisory.affected_packages[match.advisory_component_index]
        if (
            affected.ecosystem != match.coordinate.ecosystem.value
            or affected.name is None
            or normalize_package_name(match.coordinate.ecosystem, affected.name)
            != component.normalized_name
        ):
            raise CandidateDerivationError("match package does not agree with advisory component")
        eligible_matches += 1
        link = evidence.match_links[ordinal]
        if (
            link.match_ordinal != ordinal
            or link.component_id != match.component_id
            or link.match_state is not match.state
        ):
            raise CandidateDerivationError("match evidence link does not agree with match")
        linked_evidence = tuple(
            sorted(evidence_id for evidence_id in link.evidence_ids if evidence_id in evidence_ids)
        )
        relevant_input_incomplete = any(
            (
                advisory.partial,
                bool(match.coverage_limitations),
                bool(link.match_coverage_limitations),
            )
        )
        facts, package_mapping_ambiguous = _fixed_facts(
            advisory,
            component_index=match.advisory_component_index,
            ecosystem=match.coordinate.ecosystem,
            normalized_name=component.normalized_name,
        )
        source_reported_targets += len(facts)
        if not linked_evidence:
            omitted_candidates += len(facts)
            if facts:
                warnings.add(RemediationWarning.CANDIDATE_OMITTED)
                limitations.add(RemediationLimitation.EVIDENCE_UNAVAILABLE)
            continue
        ordered_targets = sorted(facts)
        if len(ordered_targets) > configuration.limits.max_candidate_versions_per_match:
            omitted_candidates += (
                len(ordered_targets) - configuration.limits.max_candidate_versions_per_match
            )
            ordered_targets = ordered_targets[
                : configuration.limits.max_candidate_versions_per_match
            ]
            warnings.add(RemediationWarning.CANDIDATE_LIMIT_EXCEEDED)
            limitations.add(RemediationLimitation.TARGET_LIMIT_EXCEEDED)
        relevant_conflict = _relevant_conflict(advisory, match.advisory_component_index)
        if relevant_conflict:
            conflicts.add(RemediationConflict.ADVISORY_FIXED_VERSION_CONFLICT)
        if package_mapping_ambiguous:
            conflicts.add(RemediationConflict.PACKAGE_MAPPING_AMBIGUOUS)
        if len(facts) > 1:
            conflicts.add(RemediationConflict.MULTIPLE_SOURCE_REPORTED_TARGETS)
        comparisons = {
            value: compare_versions(match.coordinate.ecosystem, component.version, value)
            for value in ordered_targets
        }
        candidate_coordinate = ExactPackageCoordinate(
            ecosystem=match.coordinate.ecosystem,
            name=match.coordinate.name,
            version=component.version,
        )
        supported_greater = {
            value
            for value, comparison in comparisons.items()
            if comparison.supported and comparison.greater
        }
        select_target = (
            next(iter(supported_greater))
            if len(supported_greater) == 1
            and len(facts) == 1
            and not relevant_conflict
            and not package_mapping_ambiguous
            and not relevant_input_incomplete
            and match.state is MatchState.AFFECTED
            else None
        )
        for target in ordered_targets:
            if len(target.encode("utf-8")) > 4_096:
                omitted_candidates += 1
                warnings.add(RemediationWarning.CANDIDATE_OMITTED)
                continue
            comparison = comparisons[target]
            candidate_limitations: set[RemediationLimitation] = set()
            classifications = {CandidateClassification.SOURCE_REPORTED}
            if comparison.supported:
                classifications.add(CandidateClassification.COMPARATOR_SUPPORTED)
            if target == select_target:
                selection = CandidateSelectionOutcome.SELECTED
                classifications.add(CandidateClassification.PREVIEW_ELIGIBLE)
            elif match.state is MatchState.AFFECTED_CONDITIONAL:
                selection = CandidateSelectionOutcome.CONDITIONAL
                classifications.add(CandidateClassification.MANUAL_ONLY)
                candidate_limitations.add(RemediationLimitation.CONDITIONAL_MATCH)
            elif relevant_conflict or package_mapping_ambiguous:
                selection = CandidateSelectionOutcome.CONFLICTING
                classifications.update(
                    {CandidateClassification.AMBIGUOUS, CandidateClassification.MANUAL_ONLY}
                )
                candidate_limitations.add(
                    RemediationLimitation.PACKAGE_MAPPING_AMBIGUOUS
                    if package_mapping_ambiguous
                    else RemediationLimitation.ADVISORY_CONFLICT
                )
            elif len(facts) > 1:
                selection = CandidateSelectionOutcome.AMBIGUOUS
                classifications.update(
                    {CandidateClassification.AMBIGUOUS, CandidateClassification.MANUAL_ONLY}
                )
                candidate_limitations.add(RemediationLimitation.MULTIPLE_TARGETS)
            elif relevant_input_incomplete:
                selection = CandidateSelectionOutcome.UPSTREAM_INCOMPLETE
                classifications.add(CandidateClassification.MANUAL_ONLY)
                candidate_limitations.add(RemediationLimitation.UPSTREAM_COVERAGE_INCOMPLETE)
            elif not comparison.supported:
                selection = CandidateSelectionOutcome.COMPARATOR_UNSUPPORTED
                classifications.add(CandidateClassification.MANUAL_ONLY)
                candidate_limitations.add(RemediationLimitation.COMPARATOR_UNSUPPORTED)
            else:
                selection = CandidateSelectionOutcome.NOT_GREATER
                classifications.add(CandidateClassification.MANUAL_ONLY)
                candidate_limitations.add(RemediationLimitation.TARGET_NOT_GREATER)
            payload: dict[str, object] = {
                "advisory_id": advisory.primary_id,
                "current_coordinate": candidate_coordinate,
                "match_ordinal": ordinal,
                "match_state": match.state,
                "advisory_component_index": match.advisory_component_index,
                "component_id": match.component_id,
                "raw_source_reported_target": target,
                "advisory_fact_supports": tuple(
                    sorted(facts[target].values(), key=lambda item: item.id)
                ),
                "dependency_evidence_ids": linked_evidence,
                "classifications": tuple(sorted(classifications, key=lambda item: item.value)),
                "limitations": tuple(sorted(candidate_limitations, key=lambda item: item.value)),
                "selection": selection,
            }
            candidate_drafts.append(payload)

    candidate_drafts.sort(key=lambda item: remediation_candidate_id(item))
    if len(candidate_drafts) > configuration.limits.max_candidates:
        omitted_candidates += len(candidate_drafts) - configuration.limits.max_candidates
        candidate_drafts = candidate_drafts[: configuration.limits.max_candidates]
        warnings.add(RemediationWarning.CANDIDATE_LIMIT_EXCEEDED)
        limitations.add(RemediationLimitation.CANDIDATE_LIMIT_EXCEEDED)
    candidates = tuple(
        RemediationCandidate(id=remediation_candidate_id(payload), **payload)
        for payload in candidate_drafts
    )
    return CandidateDerivation(
        candidates=candidates,
        conflicts=tuple(sorted(conflicts, key=lambda item: item.value)),
        warnings=tuple(sorted(warnings, key=lambda item: item.value)),
        limitations=tuple(sorted(limitations, key=lambda item: item.value)),
        eligible_matches=eligible_matches,
        source_reported_targets=source_reported_targets,
        omitted_candidates=omitted_candidates,
    )
