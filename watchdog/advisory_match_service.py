from __future__ import annotations

from datetime import UTC, datetime

from watchdog.domain.advisories import AdvisoryRecord, AffectedPackage, FieldProvenance
from watchdog.domain.inventory import (
    ApplicabilityKind,
    DependencyComponent,
    DependencyInventory,
    Ecosystem,
    VersionKind,
)
from watchdog.domain.matching import (
    DependencyMatch,
    DependencyMatchReport,
    ExactPackageCoordinate,
    MatchState,
    MatchWarning,
    ScannerPackageResult,
    ScannerRunResult,
    ScannerRunStatus,
)
from watchdog.inventory.identifiers import normalize_package_name
from watchdog.scanners.base import VulnerabilityScanner

_BASE_LIMITATIONS = (
    "Dependency matching does not establish source-code reachability or runtime exposure.",
    "Conditional markers, operating systems, and CPU expressions are preserved but not evaluated.",
)
_NEGATIVE_LIMITATION = (
    "not_reported_affected means only that a successful pinned scanner run did not report "
    "the target advisory for this exact coordinate; it is not a repository-level "
    "not-affected result."
)


class AdvisoryMatchService:
    def __init__(self, scanner: VulnerabilityScanner) -> None:
        self._scanner = scanner

    async def match(
        self,
        advisory: AdvisoryRecord,
        inventory: DependencyInventory,
    ) -> DependencyMatchReport:
        started = datetime.now(UTC)
        warnings: list[MatchWarning] = []
        pending: list[tuple[int, AffectedPackage, DependencyComponent]] = []
        matches: list[DependencyMatch] = []
        coordinates: set[ExactPackageCoordinate] = set()
        partial = inventory.partial

        for index, affected in enumerate(advisory.affected_packages):
            evidence = self._advisory_evidence(advisory, index)
            ecosystem = self._ecosystem(affected.ecosystem)
            if ecosystem is None or affected.name is None:
                matches.append(
                    DependencyMatch(
                        advisory_component_index=index,
                        advisory_ecosystem=affected.ecosystem,
                        advisory_name=affected.name,
                        state=MatchState.UNSUPPORTED_ADVISORY_COMPONENT,
                        advisory_evidence=evidence,
                        coverage_limitations=(
                            "The advisory component lacks a supported package ecosystem and name; "
                            "package-less Git ranges are not matched in Phase 3.",
                        ),
                    )
                )
                warnings.append(
                    MatchWarning(
                        code="unsupported_advisory_component",
                        message=(
                            "An advisory component could not be represented as PyPI, npm, or Go."
                        ),
                    )
                )
                partial = True
                continue
            try:
                normalized_advisory_name = normalize_package_name(ecosystem, affected.name)
            except ValueError:
                matches.append(
                    DependencyMatch(
                        advisory_component_index=index,
                        advisory_ecosystem=affected.ecosystem,
                        advisory_name=affected.name,
                        state=MatchState.UNSUPPORTED_ADVISORY_COMPONENT,
                        advisory_evidence=evidence,
                        coverage_limitations=("The advisory package name was invalid.",),
                    )
                )
                partial = True
                continue
            candidates = [
                component
                for component in inventory.components
                if component.ecosystem == ecosystem
                and self._component_matches_name(component, normalized_advisory_name)
            ]
            if not candidates:
                warnings.append(
                    MatchWarning(
                        code="no_inventory_candidate",
                        message=(
                            f"No inventory component matched advisory component {index}; this is "
                            "candidate-selection evidence, not a repository not-affected "
                            "conclusion."
                        ),
                        coverage_limited=False,
                    )
                )
                continue
            for component in candidates:
                if (
                    component.version_kind != VersionKind.EXACT
                    or component.version is None
                    or not component.scanner_eligible
                ):
                    matches.append(
                        self._component_match(
                            advisory,
                            index,
                            affected,
                            component,
                            MatchState.VERSION_UNKNOWN,
                            limitations=(
                                "The component has no scanner-eligible exact registry coordinate; "
                                "constraints and local sources are not vulnerability-match inputs.",
                            ),
                        )
                    )
                    partial = True
                    continue
                coordinate = self._coordinate(component)
                coordinates.add(coordinate)
                pending.append((index, affected, component))

        scanner_result: ScannerRunResult | None = None
        if coordinates:
            scanner_result = await self._scanner.scan(
                tuple(
                    sorted(
                        coordinates,
                        key=lambda item: (item.ecosystem.value, item.name, item.version),
                    )
                )
            )
            if scanner_result.status == ScannerRunStatus.INCOMPLETE:
                partial = True
                warnings.append(
                    MatchWarning(
                        code=scanner_result.warning_code or "scanner_incomplete",
                        message=(
                            "The pinned scanner did not return a complete validated result; no "
                            "negative conclusion was inferred."
                        ),
                    )
                )
                for index, affected, component in pending:
                    matches.append(
                        self._component_match(
                            advisory,
                            index,
                            affected,
                            component,
                            MatchState.SCANNER_INCOMPLETE,
                            coordinate=self._coordinate(component),
                            limitations=(
                                "Scanner failure prevents both affected and not-reported-affected "
                                "conclusions for this exact coordinate.",
                            ),
                        )
                    )
            else:
                package_results = {
                    package.coordinate: package for package in scanner_result.packages
                }
                target_ids = {
                    advisory.primary_id.upper(),
                    *(item.upper() for item in advisory.aliases),
                }
                for index, affected, component in pending:
                    coordinate = self._coordinate(component)
                    package = package_results.get(
                        coordinate,
                        ScannerPackageResult(coordinate=coordinate),
                    )
                    matched_ids = self._matched_ids(package, target_ids)
                    if matched_ids:
                        state = (
                            MatchState.AFFECTED
                            if component.applicability.kind == ApplicabilityKind.UNCONDITIONAL
                            else MatchState.AFFECTED_CONDITIONAL
                        )
                        limitations: tuple[str, ...] = ()
                    else:
                        state = MatchState.NOT_REPORTED_AFFECTED
                        limitations = (_NEGATIVE_LIMITATION,)
                    matches.append(
                        self._component_match(
                            advisory,
                            index,
                            affected,
                            component,
                            state,
                            coordinate=coordinate,
                            matched_ids=matched_ids,
                            limitations=limitations,
                        )
                    )

        if not advisory.affected_packages:
            warnings.append(
                MatchWarning(
                    code="advisory_has_no_affected_components",
                    message="The advisory supplied no affected-package components to match.",
                )
            )
            partial = True
        coverage_limitations = tuple(
            dict.fromkeys(
                (
                    *_BASE_LIMITATIONS,
                    *(f"Inventory limitation: {code}." for code in inventory.coverage.limitations),
                    *(
                        (_NEGATIVE_LIMITATION,)
                        if any(item.state == MatchState.NOT_REPORTED_AFFECTED for item in matches)
                        else ()
                    ),
                )
            )
        )
        return DependencyMatchReport(
            advisory_id=advisory.primary_id,
            advisory_aliases=advisory.aliases,
            snapshot=inventory.snapshot,
            generated_at=started,
            completed_at=datetime.now(UTC),
            matches=tuple(
                sorted(
                    matches,
                    key=lambda item: (
                        item.advisory_component_index,
                        item.component_id or "",
                        item.state.value,
                    ),
                )
            ),
            scanner=scanner_result.evidence if scanner_result else None,
            warnings=tuple(dict.fromkeys(warnings)),
            coverage_limitations=coverage_limitations,
            partial=partial,
        )

    def _component_match(
        self,
        advisory: AdvisoryRecord,
        index: int,
        affected: AffectedPackage,
        component: DependencyComponent,
        state: MatchState,
        *,
        coordinate: ExactPackageCoordinate | None = None,
        matched_ids: tuple[str, ...] = (),
        limitations: tuple[str, ...] = (),
    ) -> DependencyMatch:
        return DependencyMatch(
            advisory_component_index=index,
            advisory_ecosystem=affected.ecosystem,
            advisory_name=affected.name,
            component_id=component.id,
            state=state,
            coordinate=coordinate,
            relationship=component.relationship,
            scopes=component.scopes,
            applicability=component.applicability,
            source_references=component.source_references,
            advisory_evidence=self._advisory_evidence(advisory, index),
            matched_vulnerability_ids=matched_ids,
            coverage_limitations=limitations,
        )

    def _component_matches_name(
        self,
        component: DependencyComponent,
        advisory_name: str,
    ) -> bool:
        if component.normalized_name == advisory_name:
            return True
        if component.resolved_name is None:
            return False
        try:
            return (
                normalize_package_name(component.ecosystem, component.resolved_name)
                == advisory_name
            )
        except ValueError:
            return False

    def _coordinate(self, component: DependencyComponent) -> ExactPackageCoordinate:
        assert component.version is not None
        name = normalize_package_name(
            component.ecosystem,
            component.resolved_name or component.normalized_name,
        )
        version = component.version
        if component.ecosystem == Ecosystem.GO and version.startswith("v"):
            version = version[1:]
        return ExactPackageCoordinate(
            ecosystem=component.ecosystem,
            name=name,
            version=version,
        )

    def _ecosystem(self, raw: str | None) -> Ecosystem | None:
        if raw is None:
            return None
        try:
            return Ecosystem(raw)
        except ValueError:
            return None

    def _matched_ids(
        self,
        package: ScannerPackageResult,
        target_ids: set[str],
    ) -> tuple[str, ...]:
        result: list[str] = []
        for vulnerability in package.vulnerabilities:
            identifiers = (vulnerability.id, *vulnerability.aliases)
            if target_ids.intersection(item.upper() for item in identifiers):
                result.extend(identifiers)
        return tuple(dict.fromkeys(result))

    def _advisory_evidence(
        self,
        advisory: AdvisoryRecord,
        index: int,
    ) -> tuple[FieldProvenance, ...]:
        prefix = f"/affected_packages/{index}"
        result: list[FieldProvenance] = []
        for path, values in advisory.field_provenance.items():
            if path == prefix or path.startswith(f"{prefix}/"):
                result.extend(values)
        if not result:
            result.extend(advisory.field_provenance.get("/affected_packages", ()))
        return tuple(dict.fromkeys(result))
