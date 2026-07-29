from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tests.integration.test_context_service import context_limits
from tests.integration.test_evidence_service import configuration as evidence_configuration
from tests.integration.test_phase3_pipeline import inventory_limits, repository_limits
from tests.integration.test_workflow_service import reporting_configuration
from tests.remediation_fixtures import remediation_advisory, remediation_configuration
from tests.repository_fixtures import FakeRepositorySource, TarEntry, build_tar
from tests.unit.test_investigation_configuration import investigation_configuration
from tests.unit.test_matching import FakeScanner
from watchdog.advisory_match_service import AdvisoryMatchService
from watchdog.context.service import ContextService
from watchdog.domain.matching import ExactPackageCoordinate, ScannerVulnerability
from watchdog.domain.remediation import RemediationPlanStatus, RemediationWorkflowRequest
from watchdog.domain.reports import ReportFormat
from watchdog.domain.repositories import RepositoryRequest
from watchdog.evidence.service import EvidenceService
from watchdog.inventory.service import DependencyInventoryService
from watchdog.investigation.service import InvestigationService
from watchdog.remediation.assembler import RemediationAssembler
from watchdog.remediation.preview import PreviewCollector
from watchdog.remediation.renderers import RemediationRenderer
from watchdog.reporting.assembler import ReportAssembler
from watchdog.repository.intake import RepositoryIntakeService
from watchdog.workflow.errors import RemediationDisabledError
from watchdog.workflow.service import RemediationWorkflowService


class FakeAdvisoryService:
    def __init__(self, advisory) -> None:  # type: ignore[no-untyped-def]
        self.advisory = advisory
        self.called = False

    async def resolve(self, _identifier: str):  # type: ignore[no-untyped-def]
        self.called = True
        return self.advisory


def _service(
    tmp_path: Path,
    *,
    enabled: bool,
    preview_enabled: bool,
    **configuration_overrides: object,
) -> tuple[
    RemediationWorkflowService, RemediationRenderer, FakeRepositorySource, FakeAdvisoryService
]:
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=b"requests==2.32.3\n"),
        ]
    )
    source = FakeRepositorySource(archive)
    advisory = remediation_advisory("PyPI", "requests", "2.32.4")
    advisory_service = FakeAdvisoryService(advisory)
    coordinate = ExactPackageCoordinate(ecosystem="PyPI", name="requests", version="2.32.3")
    scanner = FakeScanner(
        {coordinate: (ScannerVulnerability(id=advisory.primary_id, aliases=advisory.aliases),)}
    )
    configuration = remediation_configuration(
        enabled=enabled,
        preview_enabled=preview_enabled,
        **configuration_overrides,
    )
    evidence_config = evidence_configuration()
    investigation_config = investigation_configuration(enabled=False, model=None)
    reporting_config = reporting_configuration()
    service = RemediationWorkflowService(
        configuration,
        advisory_service=advisory_service,  # type: ignore[arg-type]
        repository_service=RepositoryIntakeService(source, repository_limits(tmp_path)),
        inventory_service=DependencyInventoryService(inventory_limits()),
        match_service=AdvisoryMatchService(scanner),
        evidence_service=EvidenceService(evidence_config),
        context_service=ContextService(context_limits()),
        investigation_service=InvestigationService(investigation_config),
        report_assembler=ReportAssembler(reporting_config, investigation_config),
        preview_collector=PreviewCollector(
            configuration,
            inventory_limits=inventory_limits(),
            evidence_configuration=evidence_config,
        ),
        remediation_assembler=RemediationAssembler(configuration),
    )
    return service, RemediationRenderer(configuration), source, advisory_service


def _request(*, format: ReportFormat = ReportFormat.JSON) -> RemediationWorkflowRequest:
    return RemediationWorkflowRequest(
        advisory_identifier="CVE-2026-12345",
        repository=RepositoryRequest(
            repository_url="https://github.com/octocat/Hello-World", ref="main"
        ),
        format=format,
    )


async def test_disabled_remediation_rejects_before_advisory_or_repository_activity(
    tmp_path: Path,
) -> None:
    service, _renderer, source, advisory = _service(tmp_path, enabled=False, preview_enabled=False)

    with pytest.raises(RemediationDisabledError):
        await service.run(_request())

    assert not advisory.called
    assert not source.started.is_set()
    assert await asyncio.to_thread(lambda: list(tmp_path.iterdir())) == []


async def test_remediation_workflow_previews_inside_lease_then_renders_after_cleanup(
    tmp_path: Path,
) -> None:
    service, renderer, source, advisory = _service(tmp_path, enabled=True, preview_enabled=True)

    plan = await service.run(_request())
    rendered_json = await service.run_rendered(_request(), renderer)
    rendered_markdown = await service.run_rendered(_request(format=ReportFormat.MARKDOWN), renderer)

    assert advisory.called
    assert plan.status is RemediationPlanStatus.PREVIEWS_AVAILABLE
    assert len(plan.candidates) == len(plan.previews) == 1
    assert "upstream_coverage_incomplete" in {item.value for item in plan.coverage.limitations}
    assert rendered_json.body.startswith(b'{"advisory_id"')
    assert rendered_json.plan_id.startswith("remediation-plan:sha256:")
    assert rendered_markdown.body.startswith(b"No change was applied.")
    assert b"compatibility" in rendered_markdown.body
    assert source.destinations
    assert await asyncio.to_thread(
        lambda: all(not destination.parent.exists() for destination in source.destinations)
    )
    assert await asyncio.to_thread(lambda: list(tmp_path.iterdir())) == []


async def test_candidate_only_workflow_is_explicitly_partial_when_preview_disabled(
    tmp_path: Path,
) -> None:
    service, _renderer, _source, _advisory = _service(tmp_path, enabled=True, preview_enabled=False)

    plan = await service.run(_request())

    assert plan.status is RemediationPlanStatus.CANDIDATES_AVAILABLE
    assert not plan.previews
    assert plan.partial
    assert "preview_generation_disabled" in {item.value for item in plan.coverage.limitations}


async def test_narrow_validation_action_limit_is_explicitly_partial(tmp_path: Path) -> None:
    service, _renderer, _source, _advisory = _service(
        tmp_path,
        enabled=True,
        preview_enabled=False,
        remediation_max_validation_actions=1,
    )

    plan = await service.run(_request())

    assert len(plan.validation_actions) == 1
    assert "validation_action_limit_exceeded" in {item.value for item in plan.coverage.limitations}
    assert "validation_action_limit_exceeded" in {item.value for item in plan.warnings}
