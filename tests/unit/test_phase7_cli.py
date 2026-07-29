from __future__ import annotations

import io
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import cast

from apps.cli import __main__ as cli
from tests.report_fixtures import build_report
from watchdog.reporting.renderers import ReportRenderer
from watchdog.workflow.runtime import WorkflowRuntime
from watchdog.workflow.service import InvestigationWorkflowService


class BinaryStdout:
    def __init__(self) -> None:
        self.buffer = io.BytesIO()


class FakeWorkflow:
    def __init__(self, report: object) -> None:
        self.report = report

    async def run(self, _request):  # type: ignore[no-untyped-def]
        return self.report

    async def run_rendered(self, request, renderer):  # type: ignore[no-untyped-def]
        return renderer.render(self.report, view=request.view, format=request.format)


async def test_cli_writes_only_report_to_stdout(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    report, reporting, _investigation = await build_report(tmp_path)
    runtime = WorkflowRuntime(
        workflow=cast(InvestigationWorkflowService, FakeWorkflow(report)),
        renderer=ReportRenderer(reporting),
    )

    @asynccontextmanager
    async def fake_runtime(_settings) -> AsyncIterator[WorkflowRuntime]:  # type: ignore[no-untyped-def]
        yield runtime

    stdout = BinaryStdout()
    stderr = io.StringIO()
    monkeypatch.setattr(cli, "workflow_runtime", fake_runtime)
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)

    exit_code = await cli._async_main(
        [
            "investigate",
            "--advisory",
            "CVE-2026-12345",
            "--repository",
            "https://github.com/octocat/Hello-World",
            "--format",
            "markdown",
        ]
    )

    assert exit_code == 0
    assert stdout.buffer.getvalue().startswith(b"This is an evidence-bound investigation")
    assert stderr.getvalue() == ""


async def test_cli_argument_errors_do_not_echo_hostile_values(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    stdout = BinaryStdout()
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)

    exit_code = await cli._async_main(["investigate", "--unknown", "\x1b[31mhostile"])

    assert exit_code == 2
    assert stdout.buffer.getvalue() == b""
    assert "\x1b" not in stderr.getvalue()
    assert stderr.getvalue() == "invalid_arguments: The command arguments are invalid.\n"
