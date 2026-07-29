from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal, cast

from fastapi.testclient import TestClient

from apps.web.main import create_app
from tests.integration.test_workflow_service import reporting_configuration
from tests.report_fixtures import build_report
from watchdog.config import Settings
from watchdog.readiness import GuidedReadiness
from watchdog.reporting.renderers import ReportRenderer
from watchdog.workflow.runtime import WorkflowRuntime
from watchdog.workflow.service import InvestigationWorkflowService


class ForbiddenWorkflow:
    def __init__(self) -> None:
        self.calls = 0

    async def run_rendered(self, _request, _renderer):  # type: ignore[no-untyped-def]
        self.calls += 1
        raise AssertionError("guided scanner admission allowed workflow activity")


class ReportWorkflow:
    def __init__(self, report: object) -> None:
        self.report = report

    async def run_rendered(self, request, renderer):  # type: ignore[no-untyped-def]
        return renderer.render(self.report, view=request.view, format=request.format)


def _settings() -> Settings:
    return Settings(local_interfaces_enabled=True, remediation_enabled=True)


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
        "ref": None,
        "view": "summary",
        "format": "json",
    }


def _readiness(scanner: Literal["ready", "unavailable"] = "ready") -> GuidedReadiness:
    return GuidedReadiness(
        scanner=scanner,
        ai="off",
        remediation="enabled",
        previews="disabled",
    )


def _runtime(workflow: ForbiddenWorkflow) -> WorkflowRuntime:
    return WorkflowRuntime(
        workflow=cast(InvestigationWorkflowService, workflow),
        renderer=ReportRenderer(reporting_configuration()),
    )


def test_guided_readiness_route_is_separate_controlled_and_hardened() -> None:
    workflow = ForbiddenWorkflow()
    legacy = create_app(_settings(), runtime=_runtime(workflow))
    guided = create_app(
        _settings(),
        runtime=_runtime(workflow),
        guided=True,
        readiness=_readiness(),
    )

    with TestClient(legacy, base_url="http://127.0.0.1:8765") as client:
        assert client.get("/api/v1/readiness", headers=_headers()).status_code == 404

    with TestClient(guided, base_url="http://127.0.0.1:8765") as client:
        missing_header = client.get(
            "/api/v1/readiness",
            headers={"Host": "127.0.0.1:8765"},
        )
        assert missing_header.status_code == 403
        response = client.get("/api/v1/readiness", headers=_headers())
        assert response.status_code == 200
        assert response.json() == {
            "scanner": "ready",
            "ai": "off",
            "remediation": "enabled",
            "previews": "disabled",
        }
        assert response.headers["cache-control"] == "no-store"
        assert "access-control-allow-origin" not in response.headers
        assert "set-cookie" not in response.headers


def test_guided_entry_allows_only_fixed_operator_navigation() -> None:
    workflow = ForbiddenWorkflow()
    legacy = create_app(_settings(), runtime=_runtime(workflow))
    guided = create_app(
        _settings(),
        runtime=_runtime(workflow),
        guided=True,
        readiness=_readiness(),
    )
    navigation_headers = {
        "Host": "127.0.0.1:8765",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
    }

    with TestClient(legacy, base_url="http://127.0.0.1:8765") as client:
        assert client.get("/", headers=navigation_headers).status_code == 403

    with TestClient(guided, base_url="http://127.0.0.1:8765") as client:
        response = client.get("/", headers=navigation_headers)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        assert b"Nexura Watchdog" in response.content

        rejected_headers = (
            {**navigation_headers, "Host": "attacker.invalid"},
            {**navigation_headers, "Origin": "http://attacker.invalid"},
            {**navigation_headers, "Sec-Fetch-Site": "cross-site"},
            {**navigation_headers, "Sec-Fetch-Mode": "no-cors"},
            {**navigation_headers, "Sec-Fetch-Dest": "script"},
        )
        for headers in rejected_headers:
            assert client.get("/", headers=headers).status_code == 403
        assert client.get("/?unexpected=1", headers=navigation_headers).status_code == 403
        assert (
            client.get(
                "/api/v1/readiness",
                headers={**navigation_headers, "X-Watchdog-Local-Request": "1"},
            ).status_code
            == 403
        )


def test_unavailable_scanner_rejects_both_guided_workflows_before_body_or_service() -> None:
    workflow = ForbiddenWorkflow()
    app = create_app(
        _settings(),
        runtime=_runtime(workflow),
        guided=True,
        readiness=_readiness("unavailable"),
    )

    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        for endpoint in ("/api/v1/investigations", "/api/v1/remediations"):
            response = client.post(
                endpoint,
                headers={**_headers(), "Content-Length": "8193"},
                content=b"hostile body must not be consumed",
            )
            assert response.status_code == 503
            assert response.json() == {
                "error": {
                    "code": "scanner_unavailable",
                    "message": (
                        "OSV-Scanner 2.4.0 is required. Run watchdog doctor for readiness guidance."
                    ),
                }
            }
    assert workflow.calls == 0


def test_guided_assets_are_separate_text_only_and_have_no_expanded_browser_boundary() -> None:
    root = Path("apps/web/static")
    html = (root / "guided-index.html").read_text()
    css = (root / "guided-watchdog.css").read_text()
    script = (root / "guided-watchdog.js").read_text()
    combined = html + css + script

    for prohibited in (
        "innerHTML",
        "outerHTML",
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "serviceWorker",
        "clipboard",
        "createObjectURL",
        "showOpenFilePicker",
        "showSaveFilePicker",
        "download=",
        '<input type="file"',
    ):
        assert prohibited not in combined
    assert '<script src="/assets/watchdog.js"' in html
    assert '<link rel="stylesheet" href="/assets/watchdog.css"' in html
    assert 'src="http' not in html
    assert 'href="http' not in html
    assert "textContent" in script
    assert "AbortController" in script
    assert 'fetch("/api/v1/readiness"' in script
    assert 'runWorkflow("/api/v1/investigations"' in script
    assert 'runWorkflow("/api/v1/remediations"' in script
    assert "Nothing is applied or written" in html
    assert "unicode-bidi: plaintext" in css


def test_phase9_preserves_legacy_module_and_asset_bytes() -> None:
    expected = {
        "apps/cli/__main__.py": "190f54cbcfbc57cc9431f99e2d60bdb3f92acc7572c2574e1a3caa278838d69c",
        "apps/web/__main__.py": "247c3512e2b3352afb0ac9b8a814e617df18ecbfbf140c494f13f9cc29cd1cb8",
        "apps/web/static/index.html": (
            "898279266470170034e15e49ff3e68004b2a7bb03443ceacfd861618cf5cbcf2"
        ),
        "apps/web/static/watchdog.css": (
            "7a48da85ca9bf297dc5fbe101b9e330b32afeee5dd235bc62c4dee102a01b2aa"
        ),
        "apps/web/static/watchdog.js": (
            "e8f0d79f1f650740702c6d6aba19ec8f4f446366c56f226f3888701e8859f2b0"
        ),
        "apps/web/static/remediation-index.html": (
            "954687c4a051c865d135326d1ab2ff010ddac2dc1edbe5bf8a1ffadc5ce01f9c"
        ),
        "apps/web/static/remediation-watchdog.js": (
            "ea2008aa669032df2fa9d06a2e76f38ddcffc16c7f6cd119ae0e32ca79bb5935"
        ),
    }

    assert {
        name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in expected
    } == expected


def test_guided_asset_selection_does_not_replace_legacy_variants() -> None:
    from apps.web.main import _load_assets

    settings = _settings()
    legacy = _load_assets(settings)
    guided = _load_assets(settings, guided=True)

    assert legacy["index.html"] == Path("apps/web/static/remediation-index.html").read_bytes()
    assert guided["index.html"] == Path("apps/web/static/guided-index.html").read_bytes()
    assert legacy != guided


async def test_guided_and_legacy_routes_return_identical_canonical_report_bytes(
    tmp_path: Path,
) -> None:
    report, configuration, _investigation = await build_report(tmp_path)
    workflow = ReportWorkflow(report)
    runtime = WorkflowRuntime(
        workflow=cast(InvestigationWorkflowService, workflow),
        renderer=ReportRenderer(configuration),
    )
    legacy = create_app(_settings(), runtime=runtime)
    guided = create_app(
        _settings(),
        runtime=runtime,
        guided=True,
        readiness=_readiness(),
    )

    with (
        TestClient(legacy, base_url="http://127.0.0.1:8765") as legacy_client,
        TestClient(guided, base_url="http://127.0.0.1:8765") as guided_client,
    ):
        legacy_response = legacy_client.post(
            "/api/v1/investigations", headers=_headers(), json=_payload()
        )
        guided_response = guided_client.post(
            "/api/v1/investigations", headers=_headers(), json=_payload()
        )

    assert legacy_response.status_code == guided_response.status_code == 200
    assert legacy_response.content == guided_response.content
    assert legacy_response.headers["x-watchdog-report-id"] == report.id
    assert guided_response.headers["x-watchdog-report-id"] == report.id
