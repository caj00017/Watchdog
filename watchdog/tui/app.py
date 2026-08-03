from __future__ import annotations

import asyncio
import signal
import time
from contextlib import suppress
from enum import StrEnum

from pydantic import ValidationError
from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, VerticalScroll
from textual.content import Content
from textual.driver import Driver
from textual.message import Message
from textual.widgets import Button, Input, Select, Static, TabbedContent, TabPane

from watchdog.domain.remediation import RemediationPlan, RemediationWorkflowRequest
from watchdog.domain.reports import InvestigationReport, InvestigationWorkflowRequest
from watchdog.tui.backend import (
    InvestigationArtifact,
    RemediationArtifact,
    TuiBackend,
    investigation_request,
    remediation_request,
)
from watchdog.tui.display import MAX_CANONICAL_DISPLAY_CODEPOINTS, display_bytes, display_text
from watchdog.tui.projection import (
    evidence_detail,
    evidence_index,
    remediation_summary,
    report_summary,
)
from watchdog.workflow.errors import WorkflowCancelledError, WorkflowCleanupError
from watchdog.workflow.observer import WorkflowStage

MINIMUM_WIDTH = 60
MINIMUM_HEIGHT = 20
MAXIMUM_LAYOUT_WIDTH = 240
MAXIMUM_LAYOUT_HEIGHT = 80


class TuiState(StrEnum):
    READY = "ready"
    RUNNING_INVESTIGATION = "running_investigation"
    SHOWING_REPORT = "showing_report"
    RUNNING_REMEDIATION = "running_remediation"
    SHOWING_PLAN = "showing_plan"
    CANCELLING = "cancelling"
    FATAL = "fatal"


class StageChanged(Message):
    def __init__(self, stage: WorkflowStage) -> None:
        super().__init__()
        self.stage = stage


class WatchdogTuiApp(App[int]):
    """A capability-narrow, history-free projection over canonical artifacts."""

    TITLE = ""
    SUB_TITLE = ""
    ENABLE_COMMAND_PALETTE = False
    ALLOW_SELECT = True
    AUTO_FOCUS = "#advisory"
    BINDINGS = [
        Binding("ctrl+c", "cancel_or_exit", "Cancel / Exit", show=False, priority=True),
        Binding("ctrl+q", "request_exit", "Clean exit", show=False, priority=True),
        Binding("escape", "close_detail", "Close detail", show=False),
    ]
    CSS = """
    Screen {
        layout: vertical;
        padding: 1 2;
    }
    #title {
        height: 2;
        text-style: bold;
        border-bottom: solid;
    }
    #viewport-warning {
        height: auto;
        border: heavy;
        padding: 0 1;
    }
    #start, #running, #result, #fatal {
        height: 1fr;
    }
    .hidden {
        display: none;
    }
    .field-label {
        margin-top: 1;
        height: 1;
    }
    Input {
        height: 3;
    }
    #start-actions, #running-actions, #result-actions {
        height: 3;
        margin-top: 1;
    }
    Button {
        margin-right: 1;
        min-width: 18;
    }
    #readiness, #boundary, #status, #fatal-message, #keyboard-help {
        height: auto;
    }
    #stage {
        margin-top: 2;
        height: auto;
        text-style: bold;
    }
    TabbedContent {
        height: 1fr;
    }
    TabPane, VerticalScroll {
        height: 1fr;
    }
    #summary, #evidence-detail, #remediation, #canonical {
        width: 1fr;
        height: auto;
    }
    #evidence-select {
        height: 3;
        margin-bottom: 1;
    }
    #keyboard-help {
        border-top: solid;
        padding-top: 1;
    }
    """

    def __init__(
        self,
        backend: TuiBackend,
        *,
        driver_class: type[Driver] | None = None,
    ) -> None:
        super().__init__(driver_class=driver_class)
        self._backend = backend
        self.state = TuiState.READY
        self._active_task: asyncio.Task[None] | None = None
        self._request: InvestigationWorkflowRequest | None = None
        self._report: InvestigationReport | None = None
        self._plan: RemediationPlan | None = None
        self._canonical_bytes = b""
        self._started_at: float | None = None
        self._exit_requested = False
        self._viewport_supported = True
        self._resize_pending = False
        self._installed_signals: set[signal.Signals] = set()
        self._ui_mounted = False

    def compose(self) -> ComposeResult:
        readiness = self._backend.readiness
        yield Static("NEXURA WATCHDOG — LOCAL EVIDENCE-BOUND TUI", id="title", markup=False)
        yield Static("", id="viewport-warning", classes="hidden", markup=False)
        with Container(id="start"):
            yield Static(
                " | ".join(
                    (
                        f"Scanner: {readiness.scanner}",
                        f"AI: {readiness.ai}",
                        f"Remediation: {readiness.remediation}",
                        f"Previews: {readiness.previews}",
                    )
                ),
                id="readiness",
                markup=False,
            )
            yield Static("Advisory ID", classes="field-label", markup=False)
            yield Input(placeholder="CVE, GHSA, or OSV ID", max_length=128, id="advisory")
            yield Static("Public GitHub repository URL", classes="field-label", markup=False)
            yield Input(
                placeholder="https://github.com/owner/repository",
                max_length=2_048,
                id="repository",
            )
            yield Static("Optional ref", classes="field-label", markup=False)
            yield Input(placeholder="branch, tag, or commit", max_length=255, id="repository-ref")
            with Horizontal(id="start-actions"):
                yield Button("Start investigation", id="submit", variant="primary")
            yield Static("", id="status", markup=False)
        with Container(id="running", classes="hidden"):
            yield Static(
                "Only validated targets and data-free workflow stages are displayed. "
                "Repository work remains inside the cleanup-verified lease.",
                id="boundary",
                markup=False,
            )
            yield Static("Stage: preparing", id="stage", markup=False)
            yield Static("Elapsed: 0.0s", id="elapsed", markup=False)
            with Horizontal(id="running-actions"):
                yield Button("Cancel and verify cleanup", id="cancel", variant="warning")
        with Container(id="result", classes="hidden"):
            with Horizontal(id="result-actions"):
                yield Button("New investigation", id="new-investigation")
                yield Button("Plan remediation", id="plan-remediation")
            with TabbedContent(initial="summary-tab"):
                with TabPane("Summary", id="summary-tab"), VerticalScroll():
                    yield Static("", id="summary", markup=False)
                with TabPane("Evidence", id="evidence-tab"):
                    yield Select([], prompt="Select canonical evidence ID", id="evidence-select")
                    with VerticalScroll():
                        yield Static("No evidence selected.", id="evidence-detail", markup=False)
                with TabPane("Remediation", id="remediation-tab"), VerticalScroll():
                    yield Static(
                        "Remediation planning has not been run for this target.",
                        id="remediation",
                        markup=False,
                    )
                with TabPane("Canonical JSON", id="canonical-tab"), VerticalScroll():
                    yield Static("", id="canonical", markup=False)
        with Container(id="fatal", classes="hidden"):
            yield Static(
                "The TUI stopped safely without displaying exception details.",
                id="fatal-message",
                markup=False,
            )
            yield Button("Exit", id="fatal-exit")
        yield Static(
            "Tab/Shift-Tab: focus  Enter: activate  Esc: close detail  "
            "Ctrl+C: cancel/exit  Ctrl+Q: clean exit",
            id="keyboard-help",
            markup=False,
        )

    async def on_mount(self) -> None:
        self._ui_mounted = True
        self.set_interval(0.25, self._update_elapsed)
        self._apply_viewport()
        self._update_submission()
        if not self.is_headless:
            loop = asyncio.get_running_loop()
            for watched in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(watched, self._post_signal_exit)
                except (NotImplementedError, RuntimeError, ValueError):
                    continue
                self._installed_signals.add(watched)

    async def on_unmount(self) -> None:
        self._ui_mounted = False
        await self._cancel_active()
        if self._installed_signals:
            loop = asyncio.get_running_loop()
            for watched in self._installed_signals:
                loop.remove_signal_handler(watched)
            self._installed_signals.clear()
        self._release_artifacts()

    def _post_signal_exit(self) -> None:
        self.call_later(self.action_request_exit)

    def on_resize(self, _event: events.Resize) -> None:
        if not self._resize_pending:
            self._resize_pending = True
            self.set_timer(0.05, self._coalesced_resize)

    def _coalesced_resize(self) -> None:
        self._resize_pending = False
        self._apply_viewport()

    def _apply_viewport(self) -> None:
        width = min(max(self.size.width, 0), MAXIMUM_LAYOUT_WIDTH)
        height = min(max(self.size.height, 0), MAXIMUM_LAYOUT_HEIGHT)
        self._viewport_supported = width >= MINIMUM_WIDTH and height >= MINIMUM_HEIGHT
        warning = self.query_one("#viewport-warning", Static)
        warning.set_class(self._viewport_supported, "hidden")
        if not self._viewport_supported:
            warning.update("Terminal must be at least 60 columns by 20 rows. Resize to continue.")
        self._update_submission()

    def _update_submission(self) -> None:
        if not self._ui_mounted:
            return
        ready = self._backend.readiness.scanner == "ready" and self._viewport_supported
        self.query_one("#submit", Button).disabled = not ready or self.state is not TuiState.READY
        remediation = self.query_one("#plan-remediation", Button)
        remediation.disabled = (
            not self._viewport_supported
            or self.state is not TuiState.SHOWING_REPORT
            or self._request is None
        )

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            await self._submit()
        elif event.button.id == "cancel":
            await self.action_cancel_or_exit()
        elif event.button.id == "new-investigation":
            self._new_investigation()
        elif event.button.id == "plan-remediation":
            await self._start_remediation()
        elif event.button.id == "fatal-exit":
            self.exit(1)

    async def _submit(self) -> None:
        if self.state is not TuiState.READY or not self._viewport_supported:
            return
        if self._backend.readiness.scanner != "ready":
            self.query_one("#status", Static).update(
                "Scanner unavailable; investigation not started."
            )
            return
        advisory = self.query_one("#advisory", Input).value
        repository = self.query_one("#repository", Input).value
        ref_value = self.query_one("#repository-ref", Input).value
        try:
            request = investigation_request(advisory, repository, ref_value or None)
        except (ValidationError, ValueError):
            self.query_one("#status", Static).update(
                "Input rejected. Use a valid advisory ID, public GitHub URL, and optional ref."
            )
            return
        self._release_artifacts()
        self._request = request
        self._show_running(TuiState.RUNNING_INVESTIGATION, "advisory resolution")
        self._active_task = asyncio.create_task(
            self._run_investigation(request), name="watchdog-tui-investigation"
        )

    async def _start_remediation(self) -> None:
        if self.state is not TuiState.SHOWING_REPORT or self._request is None:
            return
        request = remediation_request(self._request)
        self._show_running(TuiState.RUNNING_REMEDIATION, "advisory resolution")
        self._active_task = asyncio.create_task(
            self._run_remediation(request), name="watchdog-tui-remediation"
        )

    def _show_running(self, state: TuiState, stage: str) -> None:
        self.state = state
        self._started_at = time.monotonic()
        self.query_one("#start", Container).add_class("hidden")
        self.query_one("#result", Container).add_class("hidden")
        self.query_one("#fatal", Container).add_class("hidden")
        self.query_one("#running", Container).remove_class("hidden")
        self.query_one("#stage", Static).update(f"Stage: {stage}")
        self.query_one("#elapsed", Static).update("Elapsed: 0.0s")
        self._update_submission()

    async def _run_investigation(self, request: InvestigationWorkflowRequest) -> None:
        try:
            artifact = await self._backend.investigate(request, observer=self._observe)
            self._show_report(artifact)
        except (WorkflowCancelledError, asyncio.CancelledError):
            self._show_cancelled()
        except WorkflowCleanupError:
            self._show_fatal("Cleanup verification failed. No result was retained.")
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            self._show_fatal("Investigation failed safely. No report was produced.")
        finally:
            self._finish_task()

    async def _run_remediation(self, request: RemediationWorkflowRequest) -> None:
        try:
            artifact = await self._backend.remediate(request, observer=self._observe)
            self._show_plan(artifact)
        except (WorkflowCancelledError, asyncio.CancelledError):
            self._show_cancelled()
        except WorkflowCleanupError:
            self._show_fatal("Cleanup verification failed. No result was retained.")
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            self._show_fatal("Remediation planning failed safely. No plan was produced.")
        finally:
            self._finish_task()

    def _observe(self, stage: WorkflowStage) -> None:
        self.post_message(StageChanged(stage))

    def on_stage_changed(self, message: StageChanged) -> None:
        label = message.stage.value.replace("_", " ")
        self.query_one("#stage", Static).update(f"Stage: {label}")

    def _show_report(self, artifact: InvestigationArtifact) -> None:
        self._report = artifact.report
        self._plan = None
        self._canonical_bytes = artifact.canonical_json
        self.state = TuiState.SHOWING_REPORT
        self.query_one("#summary", Static).update(report_summary(artifact.report))
        selector: Select[str] = self.query_one("#evidence-select", Select)
        selector.set_options(
            (Content(label), value) for label, value in evidence_index(artifact.report)
        )
        selector.clear()
        self.query_one("#evidence-detail", Static).update("No evidence selected.")
        self.query_one("#remediation", Static).update(
            "Remediation planning has not been run for this target. "
            "Use Plan remediation to run a separate workflow."
        )
        self._show_canonical(artifact.report.id, artifact.canonical_json)
        self._show_result()

    def _show_plan(self, artifact: RemediationArtifact) -> None:
        self._plan = artifact.plan
        self._canonical_bytes = artifact.canonical_json
        self.state = TuiState.SHOWING_PLAN
        self.query_one("#remediation", Static).update(remediation_summary(artifact.plan))
        self._show_canonical(artifact.plan.id, artifact.canonical_json)
        self._show_result()
        self.query_one(TabbedContent).active = "remediation-tab"

    def _show_canonical(self, artifact_id: str, body: bytes) -> None:
        rendered = display_bytes(body, max_codepoints=MAX_CANONICAL_DISPLAY_CODEPOINTS)
        metadata = (
            "Display-safe canonical JSON representation\n"
            f"Artifact ID: {display_text(artifact_id).text}\n"
            f"Original frozen bytes retained in memory: {len(body)}\n"
            f"Display policy: {rendered.policy_version}; escaped code points: "
            f"{rendered.escaped_codepoints}; omitted code points: {rendered.omitted_codepoints}\n\n"
        )
        self.query_one("#canonical", Static).update(metadata + rendered.text)

    def _show_result(self) -> None:
        self._started_at = None
        self.query_one("#running", Container).add_class("hidden")
        self.query_one("#start", Container).add_class("hidden")
        self.query_one("#fatal", Container).add_class("hidden")
        self.query_one("#result", Container).remove_class("hidden")
        self._update_submission()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "evidence-select" or self._report is None:
            return
        selected = event.value
        item = next((value for value in self._report.evidence if value.id == selected), None)
        self.query_one("#evidence-detail", Static).update(
            "No evidence selected." if item is None else evidence_detail(item)
        )

    def _show_cancelled(self) -> None:
        self._started_at = None
        self.state = TuiState.READY
        if not self._ui_mounted:
            return
        self.query_one("#running", Container).add_class("hidden")
        self.query_one("#result", Container).add_class("hidden")
        self.query_one("#start", Container).remove_class("hidden")
        self.query_one("#status", Static).update("Cancelled after cleanup verification.")
        self._update_submission()

    def _show_fatal(self, message: str) -> None:
        self._started_at = None
        self.state = TuiState.FATAL
        self._release_artifacts()
        if not self._ui_mounted:
            return
        self.query_one("#running", Container).add_class("hidden")
        self.query_one("#result", Container).add_class("hidden")
        self.query_one("#start", Container).add_class("hidden")
        self.query_one("#fatal", Container).remove_class("hidden")
        self.query_one("#fatal-message", Static).update(message)

    def _new_investigation(self) -> None:
        if self._active_task is not None:
            return
        self._release_artifacts()
        self._request = None
        self.state = TuiState.READY
        self.query_one("#result", Container).add_class("hidden")
        self.query_one("#start", Container).remove_class("hidden")
        self.query_one("#status", Static).update("")
        self._update_submission()
        self.query_one("#advisory", Input).focus()

    def _update_elapsed(self) -> None:
        if self._started_at is None or not self._ui_mounted:
            return
        elapsed = min(max(time.monotonic() - self._started_at, 0.0), 999.9)
        self.query_one("#elapsed", Static).update(f"Elapsed: {elapsed:.1f}s")

    async def _cancel_active(self) -> None:
        task = self._active_task
        if task is None:
            return
        self.state = TuiState.CANCELLING
        if self._ui_mounted:
            self.query_one("#stage", Static).update(
                "Stage: cancelling; waiting for cleanup verification"
            )
        if not task.done():
            task.cancel()
        with suppress(asyncio.CancelledError, WorkflowCancelledError):
            await task

    async def action_cancel_or_exit(self) -> None:
        if self._active_task is not None:
            await self._cancel_active()
            return
        self._release_artifacts()
        self.exit(0)

    async def action_request_exit(self) -> None:
        self._exit_requested = True
        if self._active_task is not None:
            await self._cancel_active()
        self._release_artifacts()
        self.exit(0)

    def action_close_detail(self) -> None:
        if self._ui_mounted:
            self.query_one("#evidence-select", Select).clear()
            self.query_one("#evidence-detail", Static).update("No evidence selected.")

    def _finish_task(self) -> None:
        if self._active_task is asyncio.current_task():
            self._active_task = None
        if self._exit_requested:
            self._release_artifacts()
            self.exit(0)

    def _release_artifacts(self) -> None:
        self._report = None
        self._plan = None
        self._canonical_bytes = b""
        if not self._ui_mounted:
            return
        for selector in ("#summary", "#evidence-detail", "#remediation", "#canonical"):
            self.query_one(selector, Static).update("")
        self.query_one("#evidence-select", Select).clear()
