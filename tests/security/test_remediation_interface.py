from __future__ import annotations

from pathlib import Path
from typing import cast

from fastapi.testclient import TestClient

from apps.web.main import create_app
from tests.integration.test_workflow_service import reporting_configuration
from tests.remediation_fixtures import remediation_configuration
from watchdog.config import Settings
from watchdog.domain.inventory import InventorySnapshot
from watchdog.domain.remediation import (
    NO_CHANGE_STATEMENT,
    RemediationCoverage,
    RemediationCoverageState,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationProducer,
)
from watchdog.remediation.identifiers import remediation_plan_id
from watchdog.remediation.renderers import RemediationRenderer
from watchdog.reporting.renderers import ReportRenderer
from watchdog.workflow.runtime import WorkflowRuntime
from watchdog.workflow.service import InvestigationWorkflowService, RemediationWorkflowService


class FakeInvestigationWorkflow:
    pass


class FakeRemediationWorkflow:
    def __init__(self, plan: RemediationPlan) -> None:
        self.plan = plan
        self.called = False

    async def run_rendered(self, request, renderer):  # type: ignore[no-untyped-def]
        self.called = True
        return renderer.render(self.plan, view=request.view, format=request.format)


def _plan(configuration_id: str) -> RemediationPlan:
    payload: dict[str, object] = {
        "producer": RemediationProducer(),
        "configuration_id": configuration_id,
        "phase7_report_id": "report:sha256:" + "1" * 64,
        "advisory_id": "CVE-2026-12345",
        "snapshot": InventorySnapshot(
            repository_url="https://github.com/octocat/Hello-World",
            commit_sha="a" * 40,
            tree_sha="b" * 40,
            archive_sha256="c" * 64,
        ),
        "status": RemediationPlanStatus.UNAVAILABLE,
        "candidates": (),
        "previews": (),
        "validation_actions": (),
        "conflicts": (),
        "warnings": (),
        "coverage": RemediationCoverage(
            state=RemediationCoverageState.COMPLETE,
            eligible_matches=0,
            source_reported_targets=0,
            candidates=0,
            previews_attempted=0,
            previews_completed=0,
            omitted_candidates=0,
            omitted_previews=0,
        ),
        "partial": False,
        "no_change_statement": NO_CHANGE_STATEMENT,
    }
    return RemediationPlan(id=remediation_plan_id(payload), **payload)


def _runtime(settings: Settings) -> tuple[WorkflowRuntime, FakeRemediationWorkflow]:
    configuration = remediation_configuration(
        enabled=settings.remediation_enabled,
        preview_enabled=settings.remediation_preview_enabled,
    )
    fake = FakeRemediationWorkflow(_plan(configuration.id))
    runtime = WorkflowRuntime(
        workflow=cast(InvestigationWorkflowService, FakeInvestigationWorkflow()),
        renderer=ReportRenderer(reporting_configuration()),
        remediation_workflow=cast(RemediationWorkflowService, fake),
        remediation_renderer=RemediationRenderer(configuration),
    )
    return runtime, fake


def _headers() -> dict[str, str]:
    return {
        "Host": "127.0.0.1:8765",
        "Content-Type": "application/json",
        "X-Watchdog-Local-Request": "1",
    }


def _payload() -> dict[str, object]:
    return {
        "advisory_id": "CVE-2026-12345",
        "repository_url": "https://github.com/octocat/Hello-World",
        "ref": "main",
        "view": "summary",
        "format": "json",
    }


def test_remediation_route_is_absent_unless_both_flags_are_enabled() -> None:
    for settings in (
        Settings(local_interfaces_enabled=True),
        Settings(remediation_enabled=True),
    ):
        runtime, fake = _runtime(settings)
        app = create_app(settings, runtime=runtime)
        with TestClient(app, base_url="http://127.0.0.1:8765") as client:
            response = client.post("/api/v1/remediations", headers=_headers(), json=_payload())
            assert response.status_code == 404
        assert not fake.called


def test_enabled_local_remediation_route_returns_only_buffered_plan() -> None:
    settings = Settings(local_interfaces_enabled=True, remediation_enabled=True)
    runtime, fake = _runtime(settings)
    app = create_app(settings, runtime=runtime)

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        response = client.post("/api/v1/remediations", headers=_headers(), json=_payload())

        assert response.status_code == 200
        assert response.json()["id"].startswith("remediation-plan:sha256:")
        assert response.headers["x-watchdog-remediation-plan-id"] == response.json()["id"]
        assert response.headers["x-watchdog-remediation-status"] == "unavailable"
        assert response.headers["cache-control"] == "no-store"
        assert "access-control-allow-origin" not in response.headers
        assert "set-cookie" not in response.headers
        assert fake.called


def test_remediation_ui_variant_has_text_only_non_apply_boundary() -> None:
    root = Path("apps/web/static")
    html = (root / "remediation-index.html").read_text()
    script = (root / "remediation-watchdog.js").read_text()

    assert "https://" not in html
    assert "http://" not in html
    assert "innerHTML" not in script
    assert "localStorage" not in script
    assert "sessionStorage" not in script
    assert "indexedDB" not in script
    assert "serviceWorker" not in script
    assert "clipboard" not in script.casefold()
    assert "createObjectURL" not in script
    assert 'fetch("/api/v1/remediations"' not in script
    assert '"/api/v1/remediations"' in script
