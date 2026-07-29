from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Protocol

from pydantic import BaseModel, ValidationError

from watchdog.domain.advisories import AdvisoryRecord
from watchdog.domain.context import ContextBundle
from watchdog.domain.evidence import EvidenceBundle
from watchdog.domain.inventory import DependencyInventory
from watchdog.domain.investigation import (
    InvestigationEnvelope,
    InvestigationResult,
    InvestigationRunStatus,
)
from watchdog.domain.matching import DependencyMatchReport, MatchState
from watchdog.domain.reports import (
    InvestigationReport,
    ReportAdvisory,
    ReportCategory,
    ReportClaim,
    ReportCoverage,
    ReportDiagnostic,
    ReportEntry,
    ReportEvidence,
    ReportInference,
    ReportMatch,
    ReportObservation,
    ReportProducer,
    ReportProvenance,
    ReportRepository,
    ReportScanner,
    ReportSignal,
    ReportStatus,
)
from watchdog.domain.repositories import RepositorySnapshot
from watchdog.investigation.envelope import (
    build_investigation_envelope,
    validate_investigation_inputs,
)
from watchdog.investigation.identifiers import canonical_json_bytes, canonical_sha256
from watchdog.investigation.limits import InvestigationConfiguration
from watchdog.reporting.identifiers import (
    investigation_report_id,
    reporting_configuration_sha256,
)
from watchdog.reporting.limits import ReportingConfiguration

_CODE_RE = re.compile(r"[^a-z0-9_]+")
_MATCH_WORDING = {
    MatchState.AFFECTED: (
        "The pinned scanner reported the target advisory for this exact dependency coordinate."
    ),
    MatchState.AFFECTED_CONDITIONAL: (
        "The pinned scanner reported the target advisory for this conditional dependency "
        "coordinate; "
        "the preserved condition was not evaluated."
    ),
    MatchState.NOT_REPORTED_AFFECTED: (
        "The successful pinned scanner run did not report the target advisory for this exact "
        "coordinate. This is not a repository not-affected result."
    ),
    MatchState.VERSION_UNKNOWN: (
        "The dependency did not provide a scanner-eligible exact version, so vulnerability status "
        "was not determined."
    ),
    MatchState.SCANNER_INCOMPLETE: (
        "The pinned scanner did not return a complete validated result; no negative "
        "conclusion was inferred."
    ),
    MatchState.UNSUPPORTED_ADVISORY_COMPONENT: (
        "The advisory component could not be represented by the supported package-coordinate "
        "boundary."
    ),
}
_ACTION_WORDING = {
    "review_cited_dependency_source": "Review the cited dependency source evidence.",
    "review_cited_context_site": "Review the cited lexical context evidence.",
    "review_advisory_conditions": "Review the cited advisory conditions.",
    "confirm_runtime_configuration": "Confirm runtime configuration outside Watchdog.",
    "confirm_deployment_conditions": "Confirm deployment conditions outside Watchdog.",
    "obtain_exact_version_evidence": "Obtain exact dependency-version evidence.",
    "obtain_supported_manifest_evidence": "Obtain evidence from a supported dependency manifest.",
    "resolve_scanner_failure": "Resolve the scanner failure and repeat the investigation.",
}


class ReportAssemblyError(ValueError):
    code = "report_assembly_failed"


class _Identified(Protocol):
    @property
    def id(self) -> str: ...


def _revalidate[T: BaseModel](value: T) -> T:
    return type(value).model_validate(value.model_dump(mode="python"))


def _stable_code(value: str, fallback: str) -> str:
    candidate = _CODE_RE.sub("_", value.casefold()).strip("_")[:128]
    if not candidate or not candidate[0].isalpha():
        return fallback
    return candidate


def _bounded_diagnostic(value: str) -> str:
    if len(value.encode("utf-8")) <= 16_384:
        return value
    return "Diagnostic display text exceeded the Phase 7 report limit and was omitted."


class ReportAssembler:
    def __init__(
        self,
        configuration: ReportingConfiguration,
        investigation_configuration: InvestigationConfiguration,
    ) -> None:
        self._configuration = _revalidate(configuration)
        self._investigation_configuration = _revalidate(investigation_configuration)

    @property
    def configuration(self) -> ReportingConfiguration:
        return self._configuration

    def assemble(
        self,
        advisory: AdvisoryRecord,
        repository: RepositorySnapshot,
        inventory: DependencyInventory,
        match_report: DependencyMatchReport,
        evidence_bundle: EvidenceBundle,
        context_bundle: ContextBundle,
        investigation_result: InvestigationResult,
    ) -> InvestigationReport:
        try:
            advisory = _revalidate(advisory)
            repository = _revalidate(repository)
            inventory = _revalidate(inventory)
            match_report = _revalidate(match_report)
            evidence_bundle = _revalidate(evidence_bundle)
            context_bundle = _revalidate(context_bundle)
            investigation_result = _revalidate(investigation_result)
            validate_investigation_inputs(
                advisory, inventory, match_report, evidence_bundle, context_bundle
            )
        except (ValidationError, ValueError) as exc:
            raise ReportAssemblyError("Phase 1-6 report inputs failed validation") from exc

        snapshot = inventory.snapshot
        if (
            repository.repository.canonical_url != snapshot.repository_url
            or repository.commit_sha != snapshot.commit_sha
            or repository.tree_sha != snapshot.tree_sha
            or repository.archive_sha256 != snapshot.archive_sha256
        ):
            raise ReportAssemblyError("repository snapshot disagrees with Phase 3-6 artifacts")
        if (
            investigation_result.advisory_id not in {advisory.primary_id, *advisory.aliases}
            or investigation_result.snapshot != snapshot
        ):
            raise ReportAssemblyError("Phase 6 result disagrees with the report target")

        envelope = build_investigation_envelope(
            advisory,
            inventory,
            match_report,
            evidence_bundle,
            context_bundle,
            self._investigation_configuration,
        )
        if investigation_result.envelope_id != envelope.id:
            raise ReportAssemblyError("Phase 6 result cites a different deterministic envelope")

        provenance = tuple(
            ReportProvenance(**item.model_dump(mode="python"))
            for item in envelope.advisory.provenance
        )
        reporting_identity = reporting_configuration_sha256(self._configuration)
        inventory_identity = canonical_sha256(
            {
                "producer": "watchdog-inventory",
                "version": "1",
                "parsers": inventory.parser_metadata,
            }
        )
        matches = self._matches(envelope)
        evidence, observations, signals, reference_omissions = self._evidence_projection(
            envelope, investigation_result
        )
        inference = ReportInference(
            result_id=investigation_result.id,
            envelope_id=envelope.id,
            status=investigation_result.status,
            disposition=investigation_result.disposition,
            claims=tuple(
                ReportClaim(
                    kind=claim.kind,
                    summary=claim.summary,
                    rationale=claim.rationale,
                    advisory_provenance_ids=claim.advisory_provenance_ids,
                    evidence_ids=claim.evidence_ids,
                    signal_ids=claim.signal_ids,
                )
                for claim in investigation_result.claims
            ),
            assumptions=investigation_result.assumptions,
            missing_evidence=investigation_result.missing_evidence,
            validation_actions=investigation_result.validation_actions,
            error_code=investigation_result.error_code,
        )
        advisory_summary = advisory.summary
        summary_omitted = bool(
            advisory_summary is not None and len(advisory_summary.encode("utf-8")) > 16_384
        )
        if summary_omitted:
            advisory_summary = None
        diagnostics, diagnostic_omissions = self._diagnostics(
            advisory,
            inventory,
            match_report,
            evidence_bundle,
            context_bundle,
            investigation_result,
            advisory_summary_omitted=summary_omitted,
            advisory_support=tuple(item.id for item in provenance if item.field == "/primary_id"),
            inventory_identity=inventory_identity,
            reporting_identity=reporting_identity,
        )
        partial = any(
            (
                advisory.partial,
                inventory.partial,
                match_report.partial,
                evidence_bundle.partial,
                context_bundle.partial,
                investigation_result.status
                not in {InvestigationRunStatus.COMPLETED, InvestigationRunStatus.DISABLED},
                envelope.coverage.envelope_truncated,
                reference_omissions > 0,
                diagnostic_omissions > 0,
                summary_omitted,
            )
        )
        summary, technical, entry_omissions = self._entries(
            advisory,
            repository,
            matches,
            inference,
            diagnostics,
        )
        partial = partial or entry_omissions > 0
        coverage = ReportCoverage(
            advisory_partial=advisory.partial,
            inventory_partial=inventory.partial,
            matching_partial=match_report.partial,
            evidence_partial=evidence_bundle.partial,
            context_partial=context_bundle.partial,
            investigation_incomplete=investigation_result.status
            not in {InvestigationRunStatus.COMPLETED, InvestigationRunStatus.DISABLED},
            envelope_truncated=envelope.coverage.envelope_truncated,
            report_entries_omitted=entry_omissions,
            evidence_references_omitted=(
                reference_omissions
                + envelope.coverage.evidence_omitted
                + envelope.coverage.matches_omitted
            ),
            diagnostics_omitted=diagnostic_omissions,
        )
        scanner = self._scanner(match_report)
        payload = {
            "producer": ReportProducer(),
            "configuration_sha256": reporting_identity,
            "status": ReportStatus.INCOMPLETE if partial else ReportStatus.COMPLETE,
            "advisory": ReportAdvisory(
                primary_id=advisory.primary_id,
                aliases=advisory.aliases,
                summary=advisory_summary,
                modified=advisory.modified,
                provenance=provenance,
                conflict_count=len(advisory.conflicts),
                warning_count=len(advisory.warnings),
                partial=advisory.partial,
            ),
            "repository": ReportRepository(
                canonical_url=repository.repository.canonical_url,
                requested_ref=repository.requested_ref,
                resolved_ref=repository.resolved_ref,
                commit_sha=repository.commit_sha,
                tree_sha=repository.tree_sha,
                archive_sha256=repository.archive_sha256,
            ),
            "scanner": scanner,
            "inventory_configuration_sha256": inventory_identity,
            "evidence_bundle_id": evidence_bundle.id,
            "evidence_configuration_sha256": evidence_bundle.configuration_sha256,
            "context_bundle_id": context_bundle.id,
            "context_configuration_sha256": context_bundle.configuration_sha256,
            "investigation": inference,
            "matches": matches,
            "evidence": evidence,
            "observations": observations,
            "signals": signals,
            "diagnostics": diagnostics,
            "summary": summary,
            "technical": technical,
            "coverage": coverage,
        }
        try:
            report = InvestigationReport(id=investigation_report_id(payload), **payload)
        except ValidationError as exc:
            raise ReportAssemblyError("canonical report failed validation") from exc
        if len(canonical_json_bytes(report)) > self._configuration.limits.max_json_bytes:
            raise ReportAssemblyError("canonical report exceeded its byte limit")
        return report

    def _scanner(self, report: DependencyMatchReport) -> ReportScanner:
        scanner = report.scanner
        if scanner is None:
            return ReportScanner(completed=not report.partial)
        safe_configuration = {
            "tool": scanner.tool,
            "version": scanner.tool_version,
            "arguments": scanner.arguments,
        }
        return ReportScanner(
            tool=scanner.tool,
            tool_version=scanner.tool_version,
            configuration_sha256=canonical_sha256(safe_configuration),
            exit_code=scanner.exit_code,
            input_sha256=scanner.input_sha256,
            output_sha256=scanner.output_sha256,
            completed=scanner.exit_code in {0, 1} and scanner.tool_version == "2.4.0",
        )

    def _matches(self, envelope: InvestigationEnvelope) -> tuple[ReportMatch, ...]:
        return tuple(
            ReportMatch(
                ordinal=item.ordinal,
                state=MatchState(item.state),
                component_id=item.component_id,
                ecosystem=item.coordinate.ecosystem if item.coordinate else None,
                package=item.coordinate.name if item.coordinate else None,
                version=item.coordinate.version if item.coordinate else None,
                advisory_provenance_ids=item.advisory_provenance_ids,
                dependency_evidence_ids=item.dependency_evidence_ids,
                context_evidence_ids=item.context_evidence_ids,
                signal_ids=item.signal_ids,
                limitations=item.limitations,
            )
            for item in envelope.matches[: self._configuration.limits.max_entries]
        )

    def _evidence_projection(
        self,
        envelope: InvestigationEnvelope,
        result: InvestigationResult,
    ) -> tuple[
        tuple[ReportEvidence, ...],
        tuple[ReportObservation, ...],
        tuple[ReportSignal, ...],
        int,
    ]:
        required_evidence = {
            reference
            for claim in result.claims
            for reference in claim.evidence_ids
            if reference.startswith(("evidence:", "context-evidence:"))
        }
        required_observations = {
            reference
            for claim in result.claims
            for reference in claim.evidence_ids
            if reference.startswith("context-observation:")
        }
        required_signals = {reference for claim in result.claims for reference in claim.signal_ids}
        max_refs = self._configuration.limits.max_evidence_references
        selected_evidence = self._select_by_id(envelope.evidence, required_evidence, max_refs)
        remaining = max_refs - len(selected_evidence)
        selected_observations = self._select_by_id(
            envelope.observations, required_observations, remaining
        )
        remaining -= len(selected_observations)
        selected_signals = self._select_by_id(envelope.signals, required_signals, remaining)
        selected_count = len(selected_evidence) + len(selected_observations) + len(selected_signals)
        available = len(envelope.evidence) + len(envelope.observations) + len(envelope.signals)
        display_omissions = 0
        projected_evidence: list[ReportEvidence] = []
        for item in selected_evidence:
            content = item.content
            limitations = item.limitations
            if content is not None and len(content.encode("utf-8")) > 16_384:
                content = None
                limitations = tuple(
                    sorted({*limitations, "report_display_item_bytes_limit_exceeded"})
                )
                display_omissions += 1
            projected_evidence.append(
                ReportEvidence(
                    id=item.id,
                    phase="phase4" if item.kind.value == "dependency_source" else "phase5",
                    kind=item.kind.value,
                    status=item.status,
                    path=item.path,
                    file_sha256=item.file_sha256,
                    start_line=item.anchor.start_line if item.anchor else None,
                    end_line=item.anchor.end_line if item.anchor else None,
                    content=content,
                    dependency_evidence_ids=item.dependency_evidence_ids,
                    limitation_codes=limitations,
                )
            )
        evidence = tuple(projected_evidence)
        observations = tuple(
            ReportObservation(
                id=item.id,
                kind=item.kind,
                evidence_id=item.evidence_id,
                path=item.path,
                start_line=item.anchor.start_line,
                end_line=item.anchor.end_line,
            )
            for item in selected_observations
        )
        signals = tuple(
            ReportSignal(
                id=item.id,
                kind=item.kind,
                dependency_evidence_ids=item.dependency_evidence_ids,
                evidence_ids=item.evidence_ids,
                limitation_codes=item.limitations,
            )
            for item in selected_signals
        )
        return evidence, observations, signals, available - selected_count + display_omissions

    @staticmethod
    def _select_by_id[T: _Identified](
        values: Iterable[T], required: set[str], limit: int
    ) -> tuple[T, ...]:
        ordered = sorted(values, key=lambda item: str(item.id))
        pinned = [item for item in ordered if str(item.id) in required]
        if len(pinned) > limit:
            raise ReportAssemblyError("required Phase 6 citations exceed the report limit")
        rest = [item for item in ordered if str(item.id) not in required]
        return tuple(
            sorted(
                (*pinned, *rest[: limit - len(pinned)]),
                key=lambda item: item.id,
            )
        )

    def _diagnostics(
        self,
        advisory: AdvisoryRecord,
        inventory: DependencyInventory,
        match_report: DependencyMatchReport,
        evidence: EvidenceBundle,
        context: ContextBundle,
        result: InvestigationResult,
        *,
        advisory_summary_omitted: bool,
        advisory_support: tuple[str, ...],
        inventory_identity: str,
        reporting_identity: str,
    ) -> tuple[tuple[ReportDiagnostic, ...], int]:
        values: list[ReportDiagnostic] = []
        if advisory_summary_omitted:
            values.append(
                ReportDiagnostic(
                    phase="phase7",
                    code="advisory_summary_omitted",
                    message="Advisory summary display exceeded the Phase 7 report limit.",
                    support_ids=(reporting_identity,),
                )
            )
        values.extend(
            ReportDiagnostic(
                phase="phase1",
                code="advisory_warning",
                message=_bounded_diagnostic(warning),
                support_ids=advisory_support,
            )
            for warning in advisory.warnings
        )
        values.extend(
            ReportDiagnostic(
                phase="phase1",
                code="advisory_conflict",
                message=_bounded_diagnostic(conflict.description),
                support_ids=advisory_support,
            )
            for conflict in advisory.conflicts
        )
        for phase, warnings, support_ids in (
            ("phase3", inventory.warnings, (inventory_identity,)),
            ("phase3", match_report.warnings, (inventory_identity,)),
            ("phase4", evidence.warnings, (evidence.id,)),
            ("phase5", context.warnings, (context.id,)),
        ):
            values.extend(
                ReportDiagnostic(
                    phase=phase,
                    code=_stable_code(str(warning.code), f"{phase}_warning"),
                    message=_bounded_diagnostic(warning.message),
                    support_ids=support_ids,
                )
                for warning in warnings
            )
        values.extend(
            ReportDiagnostic(
                phase="phase6",
                code=limitation.value,
                message=f"Phase 6 coverage limitation: {limitation.value}.",
                support_ids=(result.id,),
            )
            for limitation in result.coverage.limitations
        )
        if result.error_code is not None:
            values.append(
                ReportDiagnostic(
                    phase="phase6",
                    code=result.error_code,
                    message=f"Phase 6 inference status: {result.status.value}.",
                    support_ids=(result.id,),
                )
            )
        ordered = tuple(
            sorted(values, key=lambda item: (item.phase, item.code, item.message, item.support_ids))
        )
        limit = self._configuration.limits.max_diagnostics
        return ordered[:limit], max(0, len(ordered) - limit)

    def _entries(
        self,
        advisory: AdvisoryRecord,
        repository: RepositorySnapshot,
        matches: tuple[ReportMatch, ...],
        inference: ReportInference,
        diagnostics: tuple[ReportDiagnostic, ...],
    ) -> tuple[tuple[ReportEntry, ...], tuple[ReportEntry, ...], int]:
        target = [
            ReportEntry(
                category=ReportCategory.TARGET_METADATA,
                code="advisory_target",
                text=f"Advisory: {advisory.primary_id}.",
            ),
            ReportEntry(
                category=ReportCategory.TARGET_METADATA,
                code="repository_snapshot",
                text=(
                    f"Repository: {repository.repository.canonical_url} at exact commit "
                    f"{repository.commit_sha}."
                ),
            ),
        ]
        facts = [
            ReportEntry(
                category=ReportCategory.DETERMINISTIC_FACT,
                code=f"dependency_match_{item.ordinal}",
                text=_MATCH_WORDING[item.state],
                support_ids=tuple(
                    sorted(
                        {
                            *item.advisory_provenance_ids,
                            *item.dependency_evidence_ids,
                            *item.context_evidence_ids,
                            *item.signal_ids,
                        }
                    )
                ),
            )
            for item in matches
        ]
        model_entries = [
            ReportEntry(
                category=ReportCategory.MODEL_INFERENCE,
                code=f"model_inference_{index}",
                text=claim.summary,
                support_ids=tuple(
                    sorted(
                        {
                            *claim.advisory_provenance_ids,
                            *claim.evidence_ids,
                            *claim.signal_ids,
                        }
                    )
                ),
            )
            for index, claim in enumerate(inference.claims)
        ]
        assumptions = [
            ReportEntry(
                category=ReportCategory.ASSUMPTION,
                code=item.value,
                text=f"Model assumption: {item.value}.",
            )
            for item in inference.assumptions
        ]
        gaps = [
            ReportEntry(
                category=ReportCategory.COVERAGE_GAP,
                code=item.code,
                text=item.message,
                support_ids=item.support_ids,
            )
            for item in diagnostics
        ]
        actions = [
            ReportEntry(
                category=ReportCategory.VALIDATION_ACTION,
                code=item.value,
                text=_ACTION_WORDING[item.value],
            )
            for item in inference.validation_actions
        ]
        core = [*target, *facts, *model_entries, *assumptions, *actions]
        limit = self._configuration.limits.max_entries
        selected = gaps[:limit] if len(gaps) > limit else [*core[: limit - len(gaps)], *gaps]
        omitted = len(core) + len(gaps) - len(selected)
        summary = tuple(selected)
        technical_extras = (
            ReportEntry(
                category=ReportCategory.TARGET_METADATA,
                code="report_technical_projection",
                text="Technical projection includes canonical identities and evidence links.",
            ),
        )
        technical = tuple((*summary, *technical_extras[: max(0, limit - len(summary))]))
        return summary, technical, omitted
