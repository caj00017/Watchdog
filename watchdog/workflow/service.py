from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from contextlib import suppress
from typing import Any

from watchdog.advisory_match_service import AdvisoryMatchService
from watchdog.advisory_service import AdvisoryService
from watchdog.context.service import ContextService
from watchdog.domain.identifiers import parse_advisory_identifier
from watchdog.domain.reports import (
    InvestigationReport,
    InvestigationWorkflowRequest,
    RenderedReport,
)
from watchdog.evidence.service import EvidenceService
from watchdog.inventory.service import DependencyInventoryService
from watchdog.investigation.service import InvestigationService
from watchdog.reporting.assembler import ReportAssembler
from watchdog.reporting.renderers import ReportRenderer
from watchdog.repository.intake import RepositoryIntakeService
from watchdog.repository.validation import parse_github_repository_url
from watchdog.workflow.errors import (
    WorkflowCancelledError,
    WorkflowCleanupError,
    WorkflowTimeoutError,
)
from watchdog.workflow.limits import WorkflowConfiguration


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
        self._advisory_service = advisory_service
        self._repository_service = repository_service
        self._inventory_service = inventory_service
        self._match_service = match_service
        self._evidence_service = evidence_service
        self._context_service = context_service
        self._investigation_service = investigation_service
        self._report_assembler = report_assembler
        self._semaphore = asyncio.Semaphore(configuration.max_concurrent_requests)

    async def run(self, request: InvestigationWorkflowRequest) -> InvestigationReport:
        validated = self._validated_request(request)
        return await self._admit(lambda: self._run_validated(validated))

    async def run_rendered(
        self,
        request: InvestigationWorkflowRequest,
        renderer: ReportRenderer,
    ) -> RenderedReport:
        """Run and fully render inside the shared admission/deadline boundary."""

        validated = self._validated_request(request)
        return await self._admit(lambda: self._run_and_render(validated, renderer))

    def _validated_request(
        self,
        request: InvestigationWorkflowRequest,
    ) -> InvestigationWorkflowRequest:
        validated = InvestigationWorkflowRequest.model_validate(request.model_dump(mode="python"))
        self._validate_request_limits(validated)
        parse_advisory_identifier(validated.advisory_identifier)
        parse_github_repository_url(validated.repository.repository_url)
        return validated

    async def _admit[T](self, operation: Callable[[], Coroutine[Any, Any, T]]) -> T:
        task: asyncio.Task[T] | None = None
        try:
            async with asyncio.timeout(self._configuration.deadline_seconds):
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

    def _validate_request_limits(self, request: InvestigationWorkflowRequest) -> None:
        if (
            len(request.advisory_identifier.encode("utf-8"))
            > self._configuration.max_advisory_identifier_bytes
        ):
            raise ValueError("advisory identifier exceeds the configured workflow limit")
        if (
            len(request.repository.repository_url.encode("utf-8"))
            > self._configuration.max_repository_url_bytes
        ):
            raise ValueError("repository URL exceeds the configured workflow limit")
        if request.repository.ref is not None and (
            len(request.repository.ref.encode("utf-8"))
            > self._configuration.max_repository_ref_bytes
        ):
            raise ValueError("repository ref exceeds the configured workflow limit")

    async def _run_validated(
        self,
        request: InvestigationWorkflowRequest,
    ) -> InvestigationReport:
        advisory = await self._advisory_service.resolve(request.advisory_identifier)
        lease = self._repository_service.acquire(request.repository)
        repository_snapshot = None
        async with lease as acquired:
            repository_snapshot = acquired.snapshot
            inventory = await self._inventory_service.build(acquired)
            match_report = await self._match_service.match(advisory, inventory)
            evidence = await self._evidence_service.collect(acquired, inventory, match_report)
            context = await self._context_service.collect(
                acquired, inventory, match_report, evidence
            )
        if repository_snapshot is None or not lease.cleanup_result.verified:
            raise WorkflowCleanupError("repository cleanup was not verified")

        investigation = await self._investigation_service.investigate(
            advisory,
            inventory,
            match_report,
            evidence,
            context,
        )
        return self._report_assembler.assemble(
            advisory,
            repository_snapshot,
            inventory,
            match_report,
            evidence,
            context,
            investigation,
        )

    async def _run_and_render(
        self,
        request: InvestigationWorkflowRequest,
        renderer: ReportRenderer,
    ) -> RenderedReport:
        report = await self._run_validated(request)
        return renderer.render(report, view=request.view, format=request.format)

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
