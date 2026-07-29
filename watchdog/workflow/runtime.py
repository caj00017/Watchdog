from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx

from watchdog.advisory_match_service import AdvisoryMatchService
from watchdog.advisory_service import AdvisoryService
from watchdog.config.settings import Settings
from watchdog.context.catalog import catalog_metadata
from watchdog.context.limits import ContextConfiguration
from watchdog.context.service import ContextService
from watchdog.evidence.limits import EvidenceConfiguration
from watchdog.evidence.service import EvidenceService
from watchdog.inventory.limits import InventoryLimits
from watchdog.inventory.service import DependencyInventoryService
from watchdog.investigation.limits import InvestigationConfiguration
from watchdog.investigation.service import InvestigationService
from watchdog.reporting.assembler import ReportAssembler
from watchdog.reporting.limits import ReportingConfiguration
from watchdog.reporting.renderers import ReportRenderer
from watchdog.repository.github import GitHubRepositorySource
from watchdog.repository.intake import RepositoryIntakeService
from watchdog.repository.limits import RepositoryLimits
from watchdog.scanners.limits import ScannerLimits
from watchdog.scanners.osv_scanner import OsvScanner
from watchdog.vulnerability_sources.osv import OsvSource
from watchdog.workflow.limits import WorkflowConfiguration
from watchdog.workflow.service import InvestigationWorkflowService


@dataclass(frozen=True, slots=True)
class WorkflowRuntime:
    workflow: InvestigationWorkflowService
    renderer: ReportRenderer


@asynccontextmanager
async def workflow_runtime(settings: Settings) -> AsyncIterator[WorkflowRuntime]:
    advisory_client = httpx.AsyncClient(
        timeout=settings.upstream_timeout_seconds,
        follow_redirects=False,
        trust_env=False,
    )
    repository_client = httpx.AsyncClient(
        timeout=settings.repository_network_timeout_seconds,
        follow_redirects=False,
        trust_env=False,
    )
    try:
        advisory_service = AdvisoryService(
            OsvSource(
                advisory_client,
                base_url=str(settings.osv_base_url),
                include_raw_record=settings.include_raw_source_records,
            )
        )
        repository_service = RepositoryIntakeService(
            GitHubRepositorySource(
                repository_client,
                api_version=settings.github_api_version,
                network_timeout_seconds=settings.repository_network_timeout_seconds,
            ),
            RepositoryLimits.from_settings(settings),
        )
        investigation_configuration = InvestigationConfiguration.from_settings(settings)
        reporting_configuration = ReportingConfiguration.from_settings(settings)
        investigation_service = InvestigationService(investigation_configuration)
        workflow = InvestigationWorkflowService(
            WorkflowConfiguration.from_settings(settings),
            advisory_service=advisory_service,
            repository_service=repository_service,
            inventory_service=DependencyInventoryService(InventoryLimits.from_settings(settings)),
            match_service=AdvisoryMatchService(
                OsvScanner(settings.osv_scanner_path, ScannerLimits.from_settings(settings))
            ),
            evidence_service=EvidenceService(EvidenceConfiguration.from_settings(settings)),
            context_service=ContextService(
                ContextConfiguration.from_settings(settings, catalog=catalog_metadata())
            ),
            investigation_service=investigation_service,
            report_assembler=ReportAssembler(
                reporting_configuration,
                investigation_configuration,
            ),
        )
        yield WorkflowRuntime(
            workflow=workflow,
            renderer=ReportRenderer(reporting_configuration),
        )
    finally:
        await repository_client.aclose()
        await advisory_client.aclose()
