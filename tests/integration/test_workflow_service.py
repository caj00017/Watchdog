from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path

import pytest

from tests.factories import make_advisory
from tests.integration.test_context_service import context_limits
from tests.integration.test_evidence_service import configuration as evidence_configuration
from tests.integration.test_phase3_pipeline import inventory_limits, repository_limits
from tests.repository_fixtures import FakeRepositorySource, TarEntry, build_tar
from tests.unit.test_investigation_configuration import investigation_configuration
from tests.unit.test_matching import FakeScanner
from watchdog.advisory_match_service import AdvisoryMatchService
from watchdog.context.service import ContextService
from watchdog.domain.advisories import AffectedPackage
from watchdog.domain.reports import InvestigationWorkflowRequest, ReportStatus
from watchdog.domain.repositories import RepositoryRequest
from watchdog.evidence.service import EvidenceService
from watchdog.inventory.service import DependencyInventoryService
from watchdog.investigation.service import InvestigationService
from watchdog.reporting.assembler import ReportAssembler
from watchdog.reporting.limits import ReportingConfiguration, ReportingLimits
from watchdog.reporting.renderers import ReportRenderer
from watchdog.repository.intake import RepositoryIntakeService
from watchdog.workflow.errors import WorkflowObserverError, WorkflowTimeoutError
from watchdog.workflow.limits import WorkflowConfiguration
from watchdog.workflow.observer import WorkflowStage
from watchdog.workflow.service import InvestigationWorkflowService


class FakeAdvisoryService:
    async def resolve(self, _identifier: str):  # type: ignore[no-untyped-def]
        return make_advisory().model_copy(
            update={"affected_packages": (AffectedPackage(ecosystem="PyPI", name="pyyaml"),)}
        )


def reporting_configuration() -> ReportingConfiguration:
    return ReportingConfiguration(
        limits=ReportingLimits(
            max_json_bytes=1_048_576,
            max_markdown_bytes=1_048_576,
            max_entries=1_024,
            max_evidence_references=2_048,
            max_diagnostics=512,
        )
    )


def workflow_configuration(*, deadline_seconds: float = 10) -> WorkflowConfiguration:
    return WorkflowConfiguration(
        deadline_seconds=deadline_seconds,
        max_concurrent_requests=1,
        max_advisory_identifier_bytes=128,
        max_repository_url_bytes=2_048,
        max_repository_ref_bytes=255,
    )


async def test_workflow_keeps_repository_work_inside_verified_lease(tmp_path: Path) -> None:
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=b"pyyaml==6.0.2\n"),
            TarEntry("root/app.py", content=b"import yaml\nyaml.safe_load('x')\n"),
        ]
    )
    source = FakeRepositorySource(archive)
    repository_service = RepositoryIntakeService(source, repository_limits(tmp_path))
    investigation_config = investigation_configuration(enabled=False, model=None)
    reporting_config = reporting_configuration()
    workflow = InvestigationWorkflowService(
        workflow_configuration(),
        advisory_service=FakeAdvisoryService(),  # type: ignore[arg-type]
        repository_service=repository_service,
        inventory_service=DependencyInventoryService(inventory_limits()),
        match_service=AdvisoryMatchService(FakeScanner()),
        evidence_service=EvidenceService(evidence_configuration()),
        context_service=ContextService(context_limits()),
        investigation_service=InvestigationService(investigation_config),
        report_assembler=ReportAssembler(reporting_config, investigation_config),
    )
    request = InvestigationWorkflowRequest(
        advisory_identifier="CVE-2026-12345",
        repository=RepositoryRequest(
            repository_url="https://github.com/octocat/Hello-World",
            ref="main",
        ),
    )

    report = await workflow.run(request)
    rendered = await workflow.run_rendered(request, ReportRenderer(reporting_config))

    assert report.status is ReportStatus.COMPLETE
    assert rendered.report_id.startswith("report:sha256:")
    assert report.repository.commit_sha == "a" * 40
    assert report.investigation.status.value == "disabled"
    assert source.destinations
    assert all(not destination.parent.exists() for destination in source.destinations)


async def test_invalid_request_fails_before_advisory_or_repository_activity(
    tmp_path: Path,
) -> None:
    class RecordingAdvisory(FakeAdvisoryService):
        called = False

        async def resolve(self, identifier: str):  # type: ignore[no-untyped-def]
            self.called = True
            return await super().resolve(identifier)

    source = FakeRepositorySource()
    advisory = RecordingAdvisory()
    investigation_config = investigation_configuration(enabled=False, model=None)
    workflow = InvestigationWorkflowService(
        workflow_configuration(),
        advisory_service=advisory,  # type: ignore[arg-type]
        repository_service=RepositoryIntakeService(source, repository_limits(tmp_path)),
        inventory_service=DependencyInventoryService(inventory_limits()),
        match_service=AdvisoryMatchService(FakeScanner()),
        evidence_service=EvidenceService(evidence_configuration()),
        context_service=ContextService(context_limits()),
        investigation_service=InvestigationService(investigation_config),
        report_assembler=ReportAssembler(reporting_configuration(), investigation_config),
    )
    request = InvestigationWorkflowRequest(
        advisory_identifier="CVE-2026-12345",
        repository=RepositoryRequest(repository_url="https://example.invalid/owner/repo"),
    )

    with suppress(Exception):
        await workflow.run(request)

    assert not advisory.called
    assert not source.started.is_set()


async def test_workflow_timeout_waits_for_repository_cleanup(tmp_path: Path) -> None:
    source = FakeRepositorySource(delay=1)
    investigation_config = investigation_configuration(enabled=False, model=None)
    workflow = InvestigationWorkflowService(
        workflow_configuration(deadline_seconds=0.01),
        advisory_service=FakeAdvisoryService(),  # type: ignore[arg-type]
        repository_service=RepositoryIntakeService(source, repository_limits(tmp_path)),
        inventory_service=DependencyInventoryService(inventory_limits()),
        match_service=AdvisoryMatchService(FakeScanner()),
        evidence_service=EvidenceService(evidence_configuration()),
        context_service=ContextService(context_limits()),
        investigation_service=InvestigationService(investigation_config),
        report_assembler=ReportAssembler(reporting_configuration(), investigation_config),
    )
    request = InvestigationWorkflowRequest(
        advisory_identifier="CVE-2026-12345",
        repository=RepositoryRequest(
            repository_url="https://github.com/octocat/Hello-World",
            ref="main",
        ),
    )

    with pytest.raises(WorkflowTimeoutError, match="after cleanup"):
        await workflow.run(request)

    assert source.started.is_set()
    assert await asyncio.to_thread(lambda: list(tmp_path.iterdir())) == []


async def test_optional_observer_is_data_free_ordered_and_identity_neutral(tmp_path: Path) -> None:
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=b"pyyaml==6.0.2\n"),
        ]
    )
    source = FakeRepositorySource(archive)
    investigation_config = investigation_configuration(enabled=False, model=None)
    workflow = InvestigationWorkflowService(
        workflow_configuration(),
        advisory_service=FakeAdvisoryService(),  # type: ignore[arg-type]
        repository_service=RepositoryIntakeService(source, repository_limits(tmp_path)),
        inventory_service=DependencyInventoryService(inventory_limits()),
        match_service=AdvisoryMatchService(FakeScanner()),
        evidence_service=EvidenceService(evidence_configuration()),
        context_service=ContextService(context_limits()),
        investigation_service=InvestigationService(investigation_config),
        report_assembler=ReportAssembler(reporting_configuration(), investigation_config),
    )
    request = InvestigationWorkflowRequest(
        advisory_identifier="CVE-2026-12345",
        repository=RepositoryRequest(repository_url="https://github.com/octocat/Hello-World"),
    )
    baseline = await workflow.run(request)
    stages: list[WorkflowStage] = []

    observed = await workflow.run(request, observer=stages.append)

    assert observed.id == baseline.id
    assert stages == [
        WorkflowStage.ADVISORY_RESOLUTION,
        WorkflowStage.SNAPSHOT_ACQUISITION,
        WorkflowStage.INVENTORY,
        WorkflowStage.COORDINATE_MATCHING,
        WorkflowStage.EVIDENCE,
        WorkflowStage.CONTEXT,
        WorkflowStage.CLEANUP_VERIFICATION,
        WorkflowStage.INVESTIGATION,
        WorkflowStage.OUTPUT_ASSEMBLY,
    ]
    assert all(type(stage) is WorkflowStage for stage in stages)


async def test_observer_failure_inside_lease_still_cleans_repository(tmp_path: Path) -> None:
    source = FakeRepositorySource()
    investigation_config = investigation_configuration(enabled=False, model=None)
    workflow = InvestigationWorkflowService(
        workflow_configuration(),
        advisory_service=FakeAdvisoryService(),  # type: ignore[arg-type]
        repository_service=RepositoryIntakeService(source, repository_limits(tmp_path)),
        inventory_service=DependencyInventoryService(inventory_limits()),
        match_service=AdvisoryMatchService(FakeScanner()),
        evidence_service=EvidenceService(evidence_configuration()),
        context_service=ContextService(context_limits()),
        investigation_service=InvestigationService(investigation_config),
        report_assembler=ReportAssembler(reporting_configuration(), investigation_config),
    )
    request = InvestigationWorkflowRequest(
        advisory_identifier="CVE-2026-12345",
        repository=RepositoryRequest(repository_url="https://github.com/octocat/Hello-World"),
    )

    def fail(stage: WorkflowStage) -> None:
        if stage is WorkflowStage.INVENTORY:
            raise RuntimeError("untrusted observer detail")

    with pytest.raises(WorkflowObserverError, match="observer failed"):
        await workflow.run(request, observer=fail)

    assert source.started.is_set()
    assert await asyncio.to_thread(lambda: list(tmp_path.iterdir())) == []
