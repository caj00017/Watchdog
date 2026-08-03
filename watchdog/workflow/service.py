from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Coroutine
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Protocol

from watchdog.advisory_match_service import AdvisoryMatchService
from watchdog.advisory_service import AdvisoryService
from watchdog.context.service import ContextService
from watchdog.domain.advisories import AdvisoryRecord
from watchdog.domain.context import ContextBundle
from watchdog.domain.evidence import EvidenceBundle
from watchdog.domain.identifiers import parse_advisory_identifier
from watchdog.domain.inventory import DependencyInventory
from watchdog.domain.matching import DependencyMatchReport
from watchdog.domain.remediation import (
    RemediationPlan,
    RemediationWorkflowRequest,
    RenderedRemediationPlan,
)
from watchdog.domain.reports import (
    InvestigationReport,
    InvestigationWorkflowRequest,
    RenderedReport,
)
from watchdog.domain.repositories import AcquiredRepository, RepositoryRequest, RepositorySnapshot
from watchdog.evidence.reader import EvidenceDeadlineExceeded
from watchdog.evidence.service import EvidenceService
from watchdog.inventory.service import DependencyInventoryService
from watchdog.investigation.service import InvestigationService
from watchdog.remediation.assembler import RemediationAssembler
from watchdog.remediation.candidates import CandidateDerivation, derive_candidates
from watchdog.remediation.limits import RemediationConfiguration
from watchdog.remediation.preview import PreviewCollection, PreviewCollector
from watchdog.remediation.renderers import RemediationRenderer
from watchdog.reporting.assembler import ReportAssembler
from watchdog.reporting.renderers import ReportRenderer
from watchdog.repository.intake import RepositoryIntakeService
from watchdog.repository.validation import parse_github_repository_url
from watchdog.workflow.errors import (
    RemediationDisabledError,
    WorkflowCancelledError,
    WorkflowCleanupError,
    WorkflowObserverError,
    WorkflowTimeoutError,
)
from watchdog.workflow.limits import WorkflowConfiguration
from watchdog.workflow.observer import WorkflowObserver, WorkflowStage


class _WorkflowRequest(Protocol):
    @property
    def advisory_identifier(self) -> str: ...

    @property
    def repository(self) -> RepositoryRequest: ...


ArtifactHook = Callable[
    [
        AdvisoryRecord,
        DependencyInventory,
        DependencyMatchReport,
        EvidenceBundle,
        ContextBundle,
    ],
    Awaitable[object],
]
LeaseHook = Callable[
    [
        AcquiredRepository,
        AdvisoryRecord,
        DependencyInventory,
        DependencyMatchReport,
        EvidenceBundle,
        ContextBundle,
        object,
    ],
    Awaitable[object],
]


@dataclass(frozen=True, slots=True)
class _WorkflowArtifacts:
    advisory: AdvisoryRecord
    repository_snapshot: RepositorySnapshot
    inventory: DependencyInventory
    match_report: DependencyMatchReport
    evidence: EvidenceBundle
    context: ContextBundle
    report: InvestigationReport
    artifact_hook_result: object | None
    lease_hook_result: object | None


class _AdmissionBoundary:
    def __init__(self, *, deadline_seconds: float, max_concurrent_requests: int) -> None:
        self._deadline_seconds = deadline_seconds
        self._semaphore = asyncio.Semaphore(max_concurrent_requests)

    async def run[T](self, operation: Callable[[], Coroutine[Any, Any, T]]) -> T:
        task: asyncio.Task[T] | None = None
        try:
            async with asyncio.timeout(self._deadline_seconds):
                async with self._semaphore:
                    task = asyncio.create_task(operation())
                    return await asyncio.shield(task)
        except asyncio.CancelledError as exc:
            if task is not None:
                await self._cancel_and_join(task)
            raise WorkflowCancelledError("workflow cancelled after cleanup") from exc
        except TimeoutError as exc:
            if task is not None:
                await self._cancel_and_join(task)
            raise WorkflowTimeoutError("workflow deadline exceeded after cleanup") from exc

    @staticmethod
    async def _cancel_and_join[T](task: asyncio.Task[T]) -> None:
        if not task.done():
            task.cancel()
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                if task.done():
                    break
        with suppress(BaseException):
            task.result()


class _WorkflowExecutionCore:
    """The one Phase 1-7 execution path; a trusted hook exists only inside the lease."""

    def __init__(
        self,
        *,
        advisory_service: AdvisoryService,
        repository_service: RepositoryIntakeService,
        inventory_service: DependencyInventoryService,
        match_service: AdvisoryMatchService,
        evidence_service: EvidenceService,
        context_service: ContextService,
        investigation_service: InvestigationService,
        report_assembler: ReportAssembler,
    ) -> None:
        self._advisory_service = advisory_service
        self._repository_service = repository_service
        self._inventory_service = inventory_service
        self._match_service = match_service
        self._evidence_service = evidence_service
        self._context_service = context_service
        self._investigation_service = investigation_service
        self._report_assembler = report_assembler

    async def execute(
        self,
        request: _WorkflowRequest,
        *,
        artifact_hook: ArtifactHook | None = None,
        lease_hook: LeaseHook | None = None,
        observer: WorkflowObserver | None = None,
    ) -> _WorkflowArtifacts:
        _notify(observer, WorkflowStage.ADVISORY_RESOLUTION)
        advisory = await self._advisory_service.resolve(request.advisory_identifier)
        _notify(observer, WorkflowStage.SNAPSHOT_ACQUISITION)
        lease = self._repository_service.acquire(request.repository)
        repository_snapshot: RepositorySnapshot | None = None
        hook_result: object | None = None
        artifact_result: object | None = None
        async with lease as acquired:
            repository_snapshot = acquired.snapshot
            _notify(observer, WorkflowStage.INVENTORY)
            inventory = await self._inventory_service.build(acquired)
            _notify(observer, WorkflowStage.COORDINATE_MATCHING)
            match_report = await self._match_service.match(advisory, inventory)
            _notify(observer, WorkflowStage.EVIDENCE)
            evidence = await self._evidence_service.collect(acquired, inventory, match_report)
            _notify(observer, WorkflowStage.CONTEXT)
            context = await self._context_service.collect(
                acquired, inventory, match_report, evidence
            )
            if artifact_hook is not None:
                _notify(observer, WorkflowStage.CANDIDATE_DERIVATION)
                artifact_result = await artifact_hook(
                    advisory,
                    inventory,
                    match_report,
                    evidence,
                    context,
                )
            if lease_hook is not None:
                _notify(observer, WorkflowStage.PREVIEW_COLLECTION)
                hook_result = await lease_hook(
                    acquired,
                    advisory,
                    inventory,
                    match_report,
                    evidence,
                    context,
                    artifact_result,
                )
        _notify(observer, WorkflowStage.CLEANUP_VERIFICATION)
        if repository_snapshot is None or not lease.cleanup_result.verified:
            raise WorkflowCleanupError("repository cleanup was not verified")

        _notify(observer, WorkflowStage.INVESTIGATION)
        investigation = await self._investigation_service.investigate(
            advisory,
            inventory,
            match_report,
            evidence,
            context,
        )
        _notify(observer, WorkflowStage.OUTPUT_ASSEMBLY)
        report = self._report_assembler.assemble(
            advisory,
            repository_snapshot,
            inventory,
            match_report,
            evidence,
            context,
            investigation,
        )
        return _WorkflowArtifacts(
            advisory=advisory,
            repository_snapshot=repository_snapshot,
            inventory=inventory,
            match_report=match_report,
            evidence=evidence,
            context=context,
            report=report,
            artifact_hook_result=artifact_result,
            lease_hook_result=hook_result,
        )


def _notify(observer: WorkflowObserver | None, stage: WorkflowStage) -> None:
    if observer is None:
        return
    try:
        observer(stage)
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise WorkflowObserverError("workflow observer failed") from exc


def _validate_request_limits(
    request: _WorkflowRequest,
    *,
    max_advisory_identifier_bytes: int = 128,
    max_repository_url_bytes: int = 2_048,
    max_repository_ref_bytes: int = 255,
) -> None:
    if len(request.advisory_identifier.encode("utf-8")) > max_advisory_identifier_bytes:
        raise ValueError("advisory identifier exceeds the configured workflow limit")
    if len(request.repository.repository_url.encode("utf-8")) > max_repository_url_bytes:
        raise ValueError("repository URL exceeds the configured workflow limit")
    if request.repository.ref is not None and (
        len(request.repository.ref.encode("utf-8")) > max_repository_ref_bytes
    ):
        raise ValueError("repository ref exceeds the configured workflow limit")


class InvestigationWorkflowService:
    """Coordinate exactly one bounded advisory/repository investigation."""

    def __init__(
        self,
        configuration: WorkflowConfiguration,
        *,
        advisory_service: AdvisoryService,
        repository_service: RepositoryIntakeService,
        inventory_service: DependencyInventoryService,
        match_service: AdvisoryMatchService,
        evidence_service: EvidenceService,
        context_service: ContextService,
        investigation_service: InvestigationService,
        report_assembler: ReportAssembler,
    ) -> None:
        self._configuration = WorkflowConfiguration.model_validate(
            configuration.model_dump(mode="python")
        )
        self._core = _WorkflowExecutionCore(
            advisory_service=advisory_service,
            repository_service=repository_service,
            inventory_service=inventory_service,
            match_service=match_service,
            evidence_service=evidence_service,
            context_service=context_service,
            investigation_service=investigation_service,
            report_assembler=report_assembler,
        )
        self._admission = _AdmissionBoundary(
            deadline_seconds=configuration.deadline_seconds,
            max_concurrent_requests=configuration.max_concurrent_requests,
        )

    async def run(
        self,
        request: InvestigationWorkflowRequest,
        *,
        observer: WorkflowObserver | None = None,
    ) -> InvestigationReport:
        validated = self._validated_request(request)
        artifacts = await self._admission.run(
            lambda: self._core.execute(validated, observer=observer)
        )
        return artifacts.report

    async def run_rendered(
        self,
        request: InvestigationWorkflowRequest,
        renderer: ReportRenderer,
    ) -> RenderedReport:
        validated = self._validated_request(request)

        async def execute() -> RenderedReport:
            artifacts = await self._core.execute(validated)
            return renderer.render(artifacts.report, view=validated.view, format=validated.format)

        return await self._admission.run(execute)

    def _validated_request(
        self,
        request: InvestigationWorkflowRequest,
    ) -> InvestigationWorkflowRequest:
        validated = InvestigationWorkflowRequest.model_validate(request.model_dump(mode="python"))
        _validate_request_limits(
            validated,
            max_advisory_identifier_bytes=self._configuration.max_advisory_identifier_bytes,
            max_repository_url_bytes=self._configuration.max_repository_url_bytes,
            max_repository_ref_bytes=self._configuration.max_repository_ref_bytes,
        )
        parse_advisory_identifier(validated.advisory_identifier)
        parse_github_repository_url(validated.repository.repository_url)
        return validated


class RemediationWorkflowService:
    """Coordinate one disabled-by-default remediation plan without writing source."""

    def __init__(
        self,
        configuration: RemediationConfiguration,
        *,
        advisory_service: AdvisoryService,
        repository_service: RepositoryIntakeService,
        inventory_service: DependencyInventoryService,
        match_service: AdvisoryMatchService,
        evidence_service: EvidenceService,
        context_service: ContextService,
        investigation_service: InvestigationService,
        report_assembler: ReportAssembler,
        preview_collector: PreviewCollector,
        remediation_assembler: RemediationAssembler,
    ) -> None:
        self._configuration = RemediationConfiguration.model_validate(
            configuration.model_dump(mode="python")
        )
        self._core = _WorkflowExecutionCore(
            advisory_service=advisory_service,
            repository_service=repository_service,
            inventory_service=inventory_service,
            match_service=match_service,
            evidence_service=evidence_service,
            context_service=context_service,
            investigation_service=investigation_service,
            report_assembler=report_assembler,
        )
        self._preview_collector = preview_collector
        self._assembler = remediation_assembler
        self._admission = _AdmissionBoundary(
            deadline_seconds=configuration.limits.deadline_seconds,
            max_concurrent_requests=configuration.limits.max_concurrent_requests,
        )

    async def run(
        self,
        request: RemediationWorkflowRequest,
        *,
        observer: WorkflowObserver | None = None,
    ) -> RemediationPlan:
        self._require_enabled()
        validated = self._validated_request(request)
        return await self._admission.run(lambda: self._run_validated(validated, observer=observer))

    async def run_rendered(
        self,
        request: RemediationWorkflowRequest,
        renderer: RemediationRenderer,
    ) -> RenderedRemediationPlan:
        self._require_enabled()
        validated = self._validated_request(request)

        async def execute() -> RenderedRemediationPlan:
            plan = await self._run_validated(validated)
            return renderer.render(plan, view=validated.view, format=validated.format)

        return await self._admission.run(execute)

    def _require_enabled(self) -> None:
        if not self._configuration.enabled:
            raise RemediationDisabledError("remediation is disabled")

    def _validated_request(
        self,
        request: RemediationWorkflowRequest,
    ) -> RemediationWorkflowRequest:
        validated = RemediationWorkflowRequest.model_validate(request.model_dump(mode="python"))
        _validate_request_limits(validated)
        parse_advisory_identifier(validated.advisory_identifier)
        parse_github_repository_url(validated.repository.repository_url)
        return validated

    async def _run_validated(
        self,
        request: RemediationWorkflowRequest,
        *,
        observer: WorkflowObserver | None = None,
    ) -> RemediationPlan:
        async def candidate_hook(
            advisory: AdvisoryRecord,
            inventory: DependencyInventory,
            match_report: DependencyMatchReport,
            evidence: EvidenceBundle,
            _context: ContextBundle,
        ) -> object:
            return derive_candidates(
                advisory,
                inventory,
                match_report,
                evidence,
                self._configuration,
            )

        async def preview_hook(
            acquired: AcquiredRepository,
            _advisory: AdvisoryRecord,
            inventory: DependencyInventory,
            match_report: DependencyMatchReport,
            _evidence: EvidenceBundle,
            _context: ContextBundle,
            candidate_result: object,
        ) -> object:
            if not isinstance(candidate_result, CandidateDerivation):
                raise RuntimeError("remediation candidate hook returned invalid drafts")
            try:
                return await self._preview_collector.collect(
                    acquired,
                    inventory,
                    match_report,
                    candidate_result.candidates,
                )
            except EvidenceDeadlineExceeded as exc:
                raise WorkflowTimeoutError(
                    "remediation preview deadline exceeded after cleanup"
                ) from exc

        artifacts = await self._core.execute(
            request,
            artifact_hook=candidate_hook,
            lease_hook=preview_hook if self._configuration.preview_enabled else None,
            observer=observer,
        )
        derivation = artifacts.artifact_hook_result
        preview = artifacts.lease_hook_result
        if not isinstance(derivation, CandidateDerivation):
            raise RuntimeError("remediation candidate hook did not return drafts")
        if preview is not None and not isinstance(preview, PreviewCollection):
            raise RuntimeError("remediation preview hook returned invalid drafts")
        return self._assembler.assemble(
            artifacts.advisory,
            artifacts.inventory,
            artifacts.match_report,
            artifacts.evidence,
            artifacts.report,
            derivation,
            preview,
        )
