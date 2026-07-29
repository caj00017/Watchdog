from __future__ import annotations

import io
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import cast

from apps.cli import __main__ as cli
from tests.integration.test_workflow_service import reporting_configuration
from tests.remediation_fixtures import remediation_configuration
from tests.security.test_remediation_interface import _plan
from watchdog.remediation.renderers import RemediationRenderer
from watchdog.reporting.renderers import ReportRenderer
from watchdog.workflow.runtime import WorkflowRuntime
from watchdog.workflow.service import InvestigationWorkflowService, RemediationWorkflowService


class BinaryStdout:
    def __init__(self) -> None:
        self.buffer = io.BytesIO()


class FakeInvestigationWorkflow:
    pass


class FakeRemediationWorkflow:
    def __init__(self, plan) -> None:  # type: ignore[no-untyped-def]
        self.plan = plan

    async def run_rendered(self, request, renderer):  # type: ignore[no-untyped-def]
        return renderer.render(self.plan, view=request.view, format=request.format)


async def test_remediation_cli_writes_one_buffered_plan(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    configuration = remediation_configuration(enabled=True)
    runtime = WorkflowRuntime(
        workflow=cast(InvestigationWorkflowService, FakeInvestigationWorkflow()),
        renderer=ReportRenderer(reporting_configuration()),
        remediation_workflow=cast(
            RemediationWorkflowService,
            FakeRemediationWorkflow(_plan(configuration.id)),
        ),
        remediation_renderer=RemediationRenderer(configuration),
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
            "remediate",
            "--advisory",
            "CVE-2026-12345",
            "--repository",
            "https://github.com/octocat/Hello-World",
        ]
    )

    assert exit_code == 4
    assert stdout.buffer.getvalue().startswith(b'{"advisory_id"')
    assert stderr.getvalue() == ""


async def test_remediation_cli_has_no_apply_command_or_output_options(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    stdout = BinaryStdout()
    stderr = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", stderr)

    for option in ("--apply", "--output", "--command", "--path"):
        exit_code = await cli._async_main(
            [
                "remediate",
                "--advisory",
                "CVE-2026-12345",
                "--repository",
                "https://github.com/octocat/Hello-World",
                option,
                "hostile-value",
            ]
        )
        assert exit_code == 2

    assert stdout.buffer.getvalue() == b""
    assert "hostile-value" not in stderr.getvalue()
