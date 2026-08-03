from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from textual.binding import Binding

from tests.integration.test_remediation_workflow import _request, _service
from tests.report_fixtures import build_report
from watchdog.domain.remediation import RemediationWorkflowRequest
from watchdog.domain.reports import (
    InvestigationWorkflowRequest,
    ReportFormat,
    ReportView,
)
from watchdog.readiness import GuidedReadiness
from watchdog.remediation.renderers import RemediationRenderer
from watchdog.reporting.renderers import ReportRenderer
from watchdog.tui.app import TuiState, WatchdogTuiApp
from watchdog.tui.backend import (
    InvestigationArtifact,
    RemediationArtifact,
)
from watchdog.workflow.errors import WorkflowCancelledError, WorkflowCleanupError
from watchdog.workflow.observer import WorkflowObserver, WorkflowStage


class FixtureBackend:
    def __init__(
        self,
        investigation: InvestigationArtifact,
        remediation: RemediationArtifact,
        *,
        scanner: str = "ready",
    ) -> None:
        self._investigation = investigation
        self._remediation = remediation
        self._readiness = GuidedReadiness(
            scanner=scanner,
            ai="off",
            remediation="enabled",
            previews="enabled",
        )
        self.investigation_calls = 0
        self.remediation_calls = 0

    @property
    def readiness(self) -> GuidedReadiness:
        return self._readiness

    async def investigate(
        self,
        _request: InvestigationWorkflowRequest,
        *,
        observer: WorkflowObserver,
    ) -> InvestigationArtifact:
        self.investigation_calls += 1
        observer(WorkflowStage.ADVISORY_RESOLUTION)
        observer(WorkflowStage.CLEANUP_VERIFICATION)
        observer(WorkflowStage.OUTPUT_ASSEMBLY)
        return self._investigation

    async def remediate(
        self,
        _request: RemediationWorkflowRequest,
        *,
        observer: WorkflowObserver,
    ) -> RemediationArtifact:
        self.remediation_calls += 1
        observer(WorkflowStage.CANDIDATE_DERIVATION)
        observer(WorkflowStage.CLEANUP_VERIFICATION)
        observer(WorkflowStage.OUTPUT_ASSEMBLY)
        return self._remediation


async def _artifacts(tmp_path: Path) -> tuple[InvestigationArtifact, RemediationArtifact]:
    report_root = tmp_path / "report"
    report_root.mkdir()
    report, reporting, _investigation = await build_report(report_root)
    report_json = ReportRenderer(reporting).render(
        report, view=ReportView.TECHNICAL, format=ReportFormat.JSON
    )
    remediation_root = tmp_path / "remediation"
    remediation_root.mkdir()
    service, renderer, _source, _advisory = _service(
        remediation_root, enabled=True, preview_enabled=True
    )
    plan = await service.run(_request())
    assert isinstance(renderer, RemediationRenderer)
    plan_json = renderer.render(plan, view=ReportView.TECHNICAL, format=ReportFormat.JSON)
    return (
        InvestigationArtifact(report=report, canonical_json=report_json.body),
        RemediationArtifact(plan=plan, canonical_json=plan_json.body),
    )


async def _wait_for_state(app: WatchdogTuiApp, state: TuiState) -> None:
    for _ in range(100):
        if app.state is state:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"TUI did not reach {state}")


async def test_guided_workspace_report_evidence_remediation_and_canonical_views(
    tmp_path: Path,
) -> None:
    investigation, remediation = await _artifacts(tmp_path)
    backend = FixtureBackend(investigation, remediation)
    app = WatchdogTuiApp(backend)

    async with app.run_test(size=(100, 35)) as pilot:
        app.query_one("#advisory").value = "CVE-2026-12345"  # type: ignore[attr-defined]
        app.query_one("#repository").value = (  # type: ignore[attr-defined]
            "https://github.com/octocat/Hello-World"
        )
        await pilot.click("#submit")
        await _wait_for_state(app, TuiState.SHOWING_REPORT)

        assert backend.investigation_calls == 1
        assert app._canonical_bytes == investigation.canonical_json
        assert investigation.report.repository.commit_sha in str(app.query_one("#summary").render())
        assert str(len(investigation.canonical_json)) in str(app.query_one("#canonical").render())

        evidence_id = investigation.report.evidence[0].id
        app.query_one("#evidence-select").value = evidence_id  # type: ignore[attr-defined]
        await pilot.pause()
        assert evidence_id in str(app.query_one("#evidence-detail").render())
        await pilot.press("escape")
        assert "No evidence selected" in str(app.query_one("#evidence-detail").render())

        await pilot.click("#plan-remediation")
        await _wait_for_state(app, TuiState.SHOWING_PLAN)
        assert backend.remediation_calls == 1
        assert app._canonical_bytes == remediation.canonical_json
        assert remediation.plan.id in str(app.query_one("#remediation").render())
        assert "No change was applied" in str(app.query_one("#remediation").render())

        await pilot.click("#new-investigation")
        assert app.state is TuiState.READY
        assert app._canonical_bytes == b""
        assert app._report is None
        assert app._plan is None


async def test_small_viewport_and_scanner_unavailable_block_submission(tmp_path: Path) -> None:
    investigation, remediation = await _artifacts(tmp_path)
    backend = FixtureBackend(investigation, remediation, scanner="unavailable")
    app = WatchdogTuiApp(backend)

    async with app.run_test(size=(59, 19)) as pilot:
        await pilot.pause(0.1)
        assert app.query_one("#submit").disabled
        assert "60 columns by 20 rows" in str(app.query_one("#viewport-warning").render())
        await pilot.resize_terminal(100, 30)
        await pilot.pause(0.1)
        assert app.query_one("#submit").disabled
        assert backend.investigation_calls == 0


async def test_focus_order_form_rejection_and_plain_global_bindings(tmp_path: Path) -> None:
    investigation, remediation = await _artifacts(tmp_path)
    backend = FixtureBackend(investigation, remediation)
    app = WatchdogTuiApp(backend)

    binding_keys = [
        binding.key if isinstance(binding, Binding) else binding[0] for binding in app.BINDINGS
    ]
    assert all(len(key) != 1 for key in binding_keys)
    async with app.run_test(size=(100, 30)) as pilot:
        assert app.focused is not None and app.focused.id == "advisory"
        await pilot.press("tab")
        assert app.focused is not None and app.focused.id == "repository"
        await pilot.press("tab")
        assert app.focused is not None and app.focused.id == "repository-ref"
        await pilot.press("shift+tab")
        assert app.focused is not None and app.focused.id == "repository"

        app.query_one("#advisory").value = "CVE-2026-12345\x1b"  # type: ignore[attr-defined]
        app.query_one("#repository").value = (  # type: ignore[attr-defined]
            "https://github.com/octocat/Hello-World"
        )
        await pilot.click("#submit")
        assert backend.investigation_calls == 0
        assert "Input rejected" in str(app.query_one("#status").render())


async def test_no_color_mode_keeps_redundant_status_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    investigation, remediation = await _artifacts(tmp_path)
    app = WatchdogTuiApp(FixtureBackend(investigation, remediation))

    assert app.no_color
    async with app.run_test(size=(100, 30)):
        readiness = str(app.query_one("#readiness").render())
        assert "Scanner: ready" in readiness
        assert "AI: off" in readiness


class CancellingBackend(FixtureBackend):
    def __init__(
        self,
        investigation: InvestigationArtifact,
        remediation: RemediationArtifact,
    ) -> None:
        super().__init__(investigation, remediation)
        self.started = asyncio.Event()
        self.cancel_received = asyncio.Event()
        self.cleanup_release = asyncio.Event()
        self.cleanup_verified = False

    async def investigate(
        self,
        _request: InvestigationWorkflowRequest,
        *,
        observer: WorkflowObserver,
    ) -> InvestigationArtifact:
        observer(WorkflowStage.SNAPSHOT_ACQUISITION)
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError as exc:
            self.cancel_received.set()
            await self.cleanup_release.wait()
            self.cleanup_verified = True
            raise WorkflowCancelledError("cancelled after cleanup") from exc
        raise RuntimeError("synthetic cancellation barrier ended unexpectedly")


async def test_ctrl_c_waits_for_cleanup_before_cancelled_state(tmp_path: Path) -> None:
    investigation, remediation = await _artifacts(tmp_path)
    backend = CancellingBackend(investigation, remediation)
    app = WatchdogTuiApp(backend)

    async with app.run_test(size=(100, 30)) as pilot:
        app.query_one("#advisory").value = "CVE-2026-12345"  # type: ignore[attr-defined]
        app.query_one("#repository").value = (  # type: ignore[attr-defined]
            "https://github.com/octocat/Hello-World"
        )
        await pilot.click("#submit")
        await backend.started.wait()
        cancellation = asyncio.create_task(pilot.press("ctrl+c"))
        await backend.cancel_received.wait()
        assert app.state is TuiState.CANCELLING
        assert "waiting for cleanup" in str(app.query_one("#stage").render())
        backend.cleanup_release.set()
        await cancellation
        await _wait_for_state(app, TuiState.READY)

        assert backend.cleanup_verified
        assert "Cancelled after cleanup verification" in str(app.query_one("#status").render())


class CleanupFailingBackend(FixtureBackend):
    async def investigate(
        self,
        _request: InvestigationWorkflowRequest,
        *,
        observer: WorkflowObserver,
    ) -> InvestigationArtifact:
        observer(WorkflowStage.CLEANUP_VERIFICATION)
        raise WorkflowCleanupError("SENSITIVE CLEANUP DETAIL")


async def test_cleanup_failure_enters_fixed_fatal_state_and_releases_buffers(
    tmp_path: Path,
) -> None:
    investigation, remediation = await _artifacts(tmp_path)
    app = WatchdogTuiApp(CleanupFailingBackend(investigation, remediation))

    async with app.run_test(size=(100, 30)) as pilot:
        app.query_one("#advisory").value = "CVE-2026-12345"  # type: ignore[attr-defined]
        app.query_one("#repository").value = (  # type: ignore[attr-defined]
            "https://github.com/octocat/Hello-World"
        )
        await pilot.click("#submit")
        await _wait_for_state(app, TuiState.FATAL)

        message = str(app.query_one("#fatal-message").render())
        assert message == "Cleanup verification failed. No result was retained."
        assert "SENSITIVE" not in message
        assert app._canonical_bytes == b""
        assert app._report is None
        assert app._plan is None
