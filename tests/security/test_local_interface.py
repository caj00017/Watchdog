from __future__ import annotations

from pathlib import Path
from typing import cast

from fastapi.testclient import TestClient

from apps.web.main import create_app
from tests.report_fixtures import build_report
from watchdog.config import Settings
from watchdog.domain.reports import InvestigationWorkflowRequest
from watchdog.reporting.renderers import ReportRenderer
from watchdog.workflow.runtime import WorkflowRuntime
from watchdog.workflow.service import InvestigationWorkflowService


class FakeWorkflow:
    def __init__(self, report: object) -> None:
        self.report = report
        self.requests: list[InvestigationWorkflowRequest] = []

    async def run(self, request: InvestigationWorkflowRequest):  # type: ignore[no-untyped-def]
        self.requests.append(request)
        return self.report

    async def run_rendered(self, request, renderer):  # type: ignore[no-untyped-def]
        report = await self.run(request)
        return renderer.render(report, view=request.view, format=request.format)


def _headers(**overrides: str) -> dict[str, str]:
    values = {
        "Host": "127.0.0.1:8765",
        "Content-Type": "application/json",
        "X-Watchdog-Local-Request": "1",
    }
    values.update(overrides)
    return values


def _payload() -> dict[str, object]:
    return {
        "advisory_id": "CVE-2026-12345",
        "repository_url": "https://github.com/octocat/Hello-World",
        "ref": "main",
        "view": "summary",
        "format": "json",
    }


async def test_local_interface_exact_surface_and_security_controls(tmp_path: Path) -> None:
    report, reporting, _investigation = await build_report(tmp_path)
    fake = FakeWorkflow(report)
    runtime = WorkflowRuntime(
        workflow=cast(InvestigationWorkflowService, fake),
        renderer=ReportRenderer(reporting),
    )
    app = create_app(Settings(), runtime=runtime)

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        health = client.get("/health", headers={"Host": "127.0.0.1:8765"})
        assert health.status_code == 200
        assert health.headers["cache-control"] == "no-store"
        assert "default-src 'none'" in health.headers["content-security-policy"]
        assert health.headers["x-content-type-options"] == "nosniff"
        assert "access-control-allow-origin" not in health.headers
        assert "set-cookie" not in health.headers

        response = client.post(
            "/api/v1/investigations",
            headers=_headers(),
            json=_payload(),
        )
        assert response.status_code == 200
        assert response.json()["id"] == report.id
        assert response.headers["x-watchdog-report-id"] == report.id
        assert response.headers["x-watchdog-report-status"] == report.status.value
        assert fake.requests[0].repository.repository_url.endswith("Hello-World")

        assert client.get("/docs", headers={"Host": "127.0.0.1:8765"}).status_code == 404
        assert client.get("/openapi.json", headers={"Host": "127.0.0.1:8765"}).status_code == 404
        assert client.get("/assets/unknown", headers={"Host": "127.0.0.1:8765"}).status_code == 404


async def test_local_interface_rejects_cross_origin_and_browser_simple_requests(
    tmp_path: Path,
) -> None:
    report, reporting, _investigation = await build_report(tmp_path)
    fake = FakeWorkflow(report)
    runtime = WorkflowRuntime(
        workflow=cast(InvestigationWorkflowService, fake),
        renderer=ReportRenderer(reporting),
    )
    app = create_app(Settings(), runtime=runtime)

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        wrong_host = client.post(
            "/api/v1/investigations",
            headers=_headers(Host="attacker.invalid"),
            json=_payload(),
        )
        assert wrong_host.status_code == 403
        cross_origin = client.post(
            "/api/v1/investigations",
            headers=_headers(Origin="http://attacker.invalid", **{"Sec-Fetch-Site": "cross-site"}),
            json=_payload(),
        )
        assert cross_origin.status_code == 403
        missing_header = client.post(
            "/api/v1/investigations",
            headers={"Host": "127.0.0.1:8765", "Content-Type": "application/json"},
            json=_payload(),
        )
        assert missing_header.status_code == 403
        form = client.post(
            "/api/v1/investigations",
            headers={
                "Host": "127.0.0.1:8765",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Watchdog-Local-Request": "1",
            },
            content="advisory_id=CVE-2026-12345",
        )
        assert form.status_code == 415
        duplicate = client.post(
            "/api/v1/investigations",
            headers=_headers(),
            content=b'{"advisory_id":"CVE-2026-12345","advisory_id":"CVE-2026-12345"}',
        )
        assert duplicate.status_code == 400
        oversized = client.post(
            "/api/v1/investigations",
            headers=_headers(**{"Content-Length": "8193"}),
            content=b"{}",
        )
        assert oversized.status_code == 413
        assert not fake.requests


def test_checked_in_ui_has_no_external_or_persistent_browser_boundary() -> None:
    root = Path("apps/web/static")
    html = (root / "index.html").read_text()
    script = (root / "watchdog.js").read_text()
    launcher = Path("apps/web/__main__.py").read_text()

    assert "https://" not in html
    assert "http://" not in html
    assert "innerHTML" not in script
    assert "localStorage" not in script
    assert "sessionStorage" not in script
    assert "indexedDB" not in script
    assert "serviceWorker" not in script
    assert 'fetch("/api/v1/investigations"' in script
    assert "access_log=False" in launcher
    assert "proxy_headers=False" in launcher
