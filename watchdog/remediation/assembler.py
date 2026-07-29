from __future__ import annotations

from pydantic import ValidationError

from watchdog.domain.advisories import AdvisoryRecord
from watchdog.domain.evidence import EvidenceBundle
from watchdog.domain.inventory import DependencyInventory, InventorySnapshot
from watchdog.domain.matching import DependencyMatchReport
from watchdog.domain.remediation import (
    NO_CHANGE_STATEMENT,
    CandidateSelectionOutcome,
    PreviewStatus,
    RemediationCoverage,
    RemediationCoverageState,
    RemediationLimitation,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationProducer,
    RemediationValidationAction,
    RemediationWarning,
)
from watchdog.domain.reports import InvestigationReport, ReportStatus
from watchdog.investigation.identifiers import canonical_json_bytes
from watchdog.remediation.candidates import CandidateDerivation
from watchdog.remediation.identifiers import remediation_plan_id
from watchdog.remediation.limits import RemediationConfiguration
from watchdog.remediation.preview import (
    PreviewCollection,
    mark_preview_unavailable,
)


class RemediationAssemblyError(ValueError):
    code = "remediation_assembly_failed"


class RemediationAssembler:
    def __init__(self, configuration: RemediationConfiguration) -> None:
        self._configuration = RemediationConfiguration.model_validate(
            configuration.model_dump(mode="python")
        )

    @property
    def configuration(self) -> RemediationConfiguration:
        return self._configuration

    def assemble(
        self,
        advisory: AdvisoryRecord,
        inventory: DependencyInventory,
        match_report: DependencyMatchReport,
        evidence: EvidenceBundle,
        report: InvestigationReport,
        derivation: CandidateDerivation,
        preview: PreviewCollection | None,
    ) -> RemediationPlan:
        try:
            advisory = AdvisoryRecord.model_validate(advisory.model_dump(mode="python"))
            inventory = DependencyInventory.model_validate(inventory.model_dump(mode="python"))
            match_report = DependencyMatchReport.model_validate(
                match_report.model_dump(mode="python")
            )
            evidence = EvidenceBundle.model_validate(evidence.model_dump(mode="python"))
            report = InvestigationReport.model_validate(report.model_dump(mode="python"))
        except ValidationError as exc:
            raise RemediationAssemblyError(
                "Phase 1-7 remediation inputs failed validation"
            ) from exc
        if match_report.advisory_id != advisory.primary_id:
            raise RemediationAssemblyError("remediation inputs identify different advisories")
        if not (inventory.snapshot == match_report.snapshot == evidence.snapshot):
            raise RemediationAssemblyError("remediation inputs identify different snapshots")
        snapshot = InventorySnapshot(
            repository_url=report.repository.canonical_url,
            commit_sha=report.repository.commit_sha,
            tree_sha=report.repository.tree_sha,
            archive_sha256=report.repository.archive_sha256,
        )
        if snapshot != inventory.snapshot or report.advisory.primary_id != advisory.primary_id:
            raise RemediationAssemblyError(
                "Phase 7 report does not identify the remediation target"
            )
        known_evidence = {item.id for item in evidence.items}
        known_provenance = {
            (
                provenance.source,
                provenance.record_id,
                provenance.source_url,
                provenance.retrieved_at,
                provenance.path,
            )
            for values in advisory.field_provenance.values()
            for provenance in values
        }
        for candidate in derivation.candidates:
            if candidate.advisory_id != advisory.primary_id:
                raise RemediationAssemblyError("candidate has a cross-advisory link")
            if not set(candidate.dependency_evidence_ids).issubset(known_evidence):
                raise RemediationAssemblyError("candidate has a broken evidence link")
            for support in candidate.advisory_fact_supports:
                key = (
                    support.provenance.source,
                    support.provenance.record_id,
                    support.provenance.source_url,
                    support.provenance.retrieved_at,
                    support.provenance.path,
                )
                if key not in known_provenance:
                    raise RemediationAssemblyError("candidate has a broken advisory fact support")

        if preview is not None:
            candidates = preview.candidates
            previews = preview.previews
            preview_warnings = preview.warnings
            preview_limitations = preview.limitations
            previews_attempted = preview.attempted
            omitted_previews = preview.omitted
        else:
            candidates = tuple(
                mark_preview_unavailable(candidate, RemediationLimitation.PREVIEW_DISABLED)
                if candidate.selection is CandidateSelectionOutcome.SELECTED
                else candidate
                for candidate in derivation.candidates
            )
            candidates = tuple(sorted(candidates, key=lambda item: item.id))
            previews = ()
            preview_warnings = ()
            preview_limitations = (
                (RemediationLimitation.PREVIEW_DISABLED,)
                if any(
                    item.selection is CandidateSelectionOutcome.SELECTED
                    for item in derivation.candidates
                )
                else ()
            )
            previews_attempted = 0
            omitted_previews = 0

        actions = {
            RemediationValidationAction.REVIEW_ADVISORY_PROVENANCE,
            RemediationValidationAction.ASSESS_COMPATIBILITY,
            RemediationValidationAction.CONFIRM_APPLICABILITY,
            RemediationValidationAction.RERUN_NEW_COMMIT,
        }
        if previews:
            actions.update(
                {
                    RemediationValidationAction.REVIEW_DECLARATION_PREVIEW,
                    RemediationValidationAction.UPDATE_GENERATED_ARTIFACTS,
                    RemediationValidationAction.RUN_TRUSTED_TESTS,
                }
            )
        ordered_actions = tuple(sorted(actions, key=lambda item: item.value))
        action_limit_exceeded = (
            len(ordered_actions) > self._configuration.limits.max_validation_actions
        )
        actions_tuple = ordered_actions[: self._configuration.limits.max_validation_actions]

        upstream_partial = any(
            (
                advisory.partial,
                inventory.partial,
                match_report.partial,
                evidence.partial,
                report.status is ReportStatus.INCOMPLETE,
            )
        )
        all_limitations = {
            *derivation.limitations,
            *preview_limitations,
            *(limitation for candidate in candidates for limitation in candidate.limitations),
            *(limitation for item in previews for limitation in item.limitations),
        }
        if upstream_partial:
            all_limitations.add(RemediationLimitation.UPSTREAM_COVERAGE_INCOMPLETE)
        warnings = {*derivation.warnings, *preview_warnings}
        if action_limit_exceeded:
            all_limitations.add(RemediationLimitation.VALIDATION_ACTION_LIMIT_EXCEEDED)
            warnings.add(RemediationWarning.VALIDATION_ACTION_LIMIT_EXCEEDED)
        if len(warnings) > self._configuration.limits.max_warnings:
            all_limitations.add(RemediationLimitation.WARNING_LIMIT_EXCEEDED)
            retained_warnings = [
                item
                for item in sorted(warnings, key=lambda item: item.value)
                if item is not RemediationWarning.WARNING_LIMIT_EXCEEDED
            ][: self._configuration.limits.max_warnings - 1]
            warnings_tuple = tuple(
                sorted(
                    {*retained_warnings, RemediationWarning.WARNING_LIMIT_EXCEEDED},
                    key=lambda item: item.value,
                )
            )
        else:
            warnings_tuple = tuple(sorted(warnings, key=lambda item: item.value))
        limitations = tuple(sorted(all_limitations, key=lambda item: item.value))
        coverage = RemediationCoverage(
            state=(
                RemediationCoverageState.PARTIAL
                if derivation.omitted_candidates or omitted_previews or limitations
                else RemediationCoverageState.COMPLETE
            ),
            eligible_matches=derivation.eligible_matches,
            source_reported_targets=derivation.source_reported_targets,
            candidates=len(candidates),
            previews_attempted=previews_attempted,
            previews_completed=sum(item.status is PreviewStatus.COMPLETE for item in previews),
            omitted_candidates=derivation.omitted_candidates,
            omitted_previews=omitted_previews,
            limitations=limitations,
        )
        if not candidates:
            status = RemediationPlanStatus.UNAVAILABLE
        elif any(item.status is PreviewStatus.COMPLETE for item in previews):
            status = RemediationPlanStatus.PREVIEWS_AVAILABLE
        elif any(item.selection is CandidateSelectionOutcome.SELECTED for item in candidates):
            status = RemediationPlanStatus.CANDIDATES_AVAILABLE
        else:
            status = RemediationPlanStatus.MANUAL_REVIEW_REQUIRED
        payload: dict[str, object] = {
            "producer": RemediationProducer(),
            "configuration_id": self._configuration.id,
            "phase7_report_id": report.id,
            "advisory_id": advisory.primary_id,
            "snapshot": inventory.snapshot,
            "status": status,
            "candidates": candidates,
            "previews": previews,
            "validation_actions": actions_tuple,
            "conflicts": derivation.conflicts,
            "warnings": warnings_tuple,
            "coverage": coverage,
            "partial": coverage.state is RemediationCoverageState.PARTIAL,
            "no_change_statement": NO_CHANGE_STATEMENT,
        }
        try:
            plan = RemediationPlan(id=remediation_plan_id(payload), **payload)
        except ValidationError as exc:
            raise RemediationAssemblyError("canonical remediation plan failed validation") from exc
        if len(canonical_json_bytes(plan)) > self._configuration.limits.max_json_bytes:
            raise RemediationAssemblyError("canonical remediation plan exceeded its byte limit")
        return plan
