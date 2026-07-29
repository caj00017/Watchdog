from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from tests.report_fixtures import build_report
from watchdog.domain.reports import (
    InvestigationReport,
    ReportCategory,
    ReportEntry,
    ReportFormat,
    ReportView,
)
from watchdog.reporting.identifiers import investigation_report_id
from watchdog.reporting.limits import ReportingConfiguration, ReportingLimits
from watchdog.reporting.renderers import ReportRenderer
from watchdog.reporting.report_json import ReportRenderError


async def test_report_identity_and_rendering_are_deterministic(tmp_path: Path) -> None:
    report, configuration, _investigation = await build_report(tmp_path)
    renderer = ReportRenderer(configuration)

    assert report.id == investigation_report_id(report)
    assert InvestigationReport.model_validate(report.model_dump(mode="python")) == report
    for view in ReportView:
        first = renderer.render(report, view=view, format=ReportFormat.JSON)
        second = renderer.render(report, view=view, format=ReportFormat.JSON)
        assert first == second
        payload = json.loads(first.body)
        assert payload["id"] == report.id
        assert payload["status"] == report.status.value
        assert payload["coverage"] == report.coverage.model_dump(mode="json")
        assert payload["scanner"] == report.scanner.model_dump(mode="json")
    assert (
        b'"evidence"'
        not in renderer.render(report, view=ReportView.SUMMARY, format=ReportFormat.JSON).body
    )
    assert (
        b'"evidence"'
        in renderer.render(report, view=ReportView.TECHNICAL, format=ReportFormat.JSON).body
    )


async def test_markdown_escapes_hostile_content_and_starts_with_boundary(
    tmp_path: Path,
) -> None:
    report, configuration, _investigation = await build_report(tmp_path)
    hostile = "<script>alert(1)</script> **bold** \x1b[31m \u202e danger\nnext"
    entry = ReportEntry(
        category=ReportCategory.COVERAGE_GAP,
        code="hostile_value",
        text=hostile,
    )
    payload = report.model_dump(mode="json", exclude={"id"})
    payload["summary"] = (*payload["summary"], entry.model_dump(mode="json"))
    payload["technical"] = (*payload["technical"], entry.model_dump(mode="json"))
    changed = InvestigationReport(id=investigation_report_id(payload), **payload)

    body = (
        ReportRenderer(configuration)
        .render(changed, view=ReportView.SUMMARY, format=ReportFormat.MARKDOWN)
        .body.decode()
    )

    assert body.startswith("This is an evidence-bound investigation")
    assert "Scanner version:" in body
    assert "<script>" not in body
    assert "\\<script\\>" in body
    assert "\x1b" not in body
    assert "U+001B" in body
    assert "\u202e" not in body
    assert "U+202E" in body


async def test_strict_report_validation_rejects_broken_identity_and_links(
    tmp_path: Path,
) -> None:
    report, _configuration, _investigation = await build_report(tmp_path)
    with pytest.raises(ValidationError, match="identity"):
        InvestigationReport.model_validate(
            {**report.model_dump(mode="python"), "id": "report:sha256:" + "0" * 64}
        )

    payload = report.model_dump(mode="json", exclude={"id"})
    entry = ReportEntry(
        category=ReportCategory.DETERMINISTIC_FACT,
        code="fabricated_link",
        text="Unsupported finding.",
        support_ids=("evidence:sha256:" + "0" * 64,),
    )
    payload["summary"] = (*payload["summary"], entry.model_dump(mode="json"))
    with pytest.raises(ValidationError, match="broken support"):
        InvestigationReport(id=investigation_report_id(payload), **payload)


async def test_renderer_fails_before_partial_output_on_overflow(tmp_path: Path) -> None:
    report, configuration, _investigation = await build_report(tmp_path)
    limits = configuration.limits.model_copy(
        update={"max_json_bytes": 64, "max_markdown_bytes": 64}
    )
    limited = ReportingConfiguration(limits=ReportingLimits.model_validate(limits))
    renderer = ReportRenderer(limited)

    with pytest.raises(ReportRenderError, match="byte limit"):
        renderer.render(report, view=ReportView.SUMMARY, format=ReportFormat.JSON)
    with pytest.raises(ReportRenderError, match="byte limit"):
        renderer.render(report, view=ReportView.SUMMARY, format=ReportFormat.MARKDOWN)
