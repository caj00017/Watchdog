from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from watchdog.config import Settings
from watchdog.domain.remediation import RemediationPlan, RemediationWorkflowRequest
from watchdog.domain.reports import (
    InvestigationReport,
    InvestigationWorkflowRequest,
    ReportFormat,
    ReportView,
)
from watchdog.readiness import GuidedReadiness
from watchdog.tui.display import contains_forbidden_input
from watchdog.workflow.observer import WorkflowObserver
from watchdog.workflow.runtime import workflow_runtime


@dataclass(frozen=True, slots=True)
class InvestigationArtifact:
    report: InvestigationReport
    canonical_json: bytes


@dataclass(frozen=True, slots=True)
class RemediationArtifact:
    plan: RemediationPlan
    canonical_json: bytes


class TuiBackend(Protocol):
    @property
    def readiness(self) -> GuidedReadiness: ...

    async def investigate(
        self,
        request: InvestigationWorkflowRequest,
        *,
        observer: WorkflowObserver,
    ) -> InvestigationArtifact: ...

    async def remediate(
        self,
        request: RemediationWorkflowRequest,
        *,
        observer: WorkflowObserver,
    ) -> RemediationArtifact: ...


def investigation_request(
    advisory: str,
    repository_url: str,
    repository_ref: str | None,
) -> InvestigationWorkflowRequest:
    from watchdog.domain.repositories import RepositoryRequest

    values = (advisory, repository_url, repository_ref or "")
    if any(contains_forbidden_input(value) for value in values):
        raise ValueError("TUI input contains a forbidden terminal control or format character")
    return InvestigationWorkflowRequest(
        advisory_identifier=advisory,
        repository=RepositoryRequest(repository_url=repository_url, ref=repository_ref),
        view=ReportView.TECHNICAL,
        format=ReportFormat.JSON,
    )


def remediation_request(request: InvestigationWorkflowRequest) -> RemediationWorkflowRequest:
    return RemediationWorkflowRequest(
        advisory_identifier=request.advisory_identifier,
        repository=request.repository,
        view=ReportView.TECHNICAL,
        format=ReportFormat.JSON,
    )


class ProductionTuiBackend:
    """Narrow adapter; the application never receives runtime capabilities."""

    def __init__(self, settings: Settings, readiness: GuidedReadiness) -> None:
        self._settings = Settings.model_validate(settings.model_dump(mode="python"))
        self._readiness = GuidedReadiness.model_validate(readiness.model_dump(mode="python"))

    @property
    def readiness(self) -> GuidedReadiness:
        return self._readiness

    async def investigate(
        self,
        request: InvestigationWorkflowRequest,
        *,
        observer: WorkflowObserver,
    ) -> InvestigationArtifact:
        validated = InvestigationWorkflowRequest.model_validate(request.model_dump(mode="python"))
        async with workflow_runtime(self._settings) as runtime:
            report = await runtime.workflow.run(validated, observer=observer)
            rendered = runtime.renderer.render(
                report,
                view=ReportView.TECHNICAL,
                format=ReportFormat.JSON,
            )
        return InvestigationArtifact(report=report, canonical_json=rendered.body)

    async def remediate(
        self,
        request: RemediationWorkflowRequest,
        *,
        observer: WorkflowObserver,
    ) -> RemediationArtifact:
        validated = RemediationWorkflowRequest.model_validate(request.model_dump(mode="python"))
        async with workflow_runtime(self._settings) as runtime:
            if runtime.remediation_workflow is None or runtime.remediation_renderer is None:
                raise RuntimeError("remediation runtime unavailable")
            plan = await runtime.remediation_workflow.run(validated, observer=observer)
            rendered = runtime.remediation_renderer.render(
                plan,
                view=ReportView.TECHNICAL,
                format=ReportFormat.JSON,
            )
        return RemediationArtifact(plan=plan, canonical_json=rendered.body)
