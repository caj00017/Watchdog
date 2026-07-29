from __future__ import annotations

from watchdog.domain.reports import (
    InvestigationReport,
    RenderedReport,
    ReportFormat,
    ReportView,
)
from watchdog.reporting.limits import ReportingConfiguration
from watchdog.reporting.report_json import render_report_json
from watchdog.reporting.report_markdown import render_report_markdown


class ReportRenderer:
    def __init__(self, configuration: ReportingConfiguration) -> None:
        self._configuration = ReportingConfiguration.model_validate(
            configuration.model_dump(mode="python")
        )

    def render(
        self,
        report: InvestigationReport,
        *,
        view: ReportView,
        format: ReportFormat,
    ) -> RenderedReport:
        validated = InvestigationReport.model_validate(report.model_dump(mode="python"))
        if format is ReportFormat.JSON:
            body = render_report_json(validated, view, self._configuration.limits)
            media_type = "application/json"
        else:
            body = render_report_markdown(validated, view, self._configuration.limits)
            media_type = "text/markdown"
        return RenderedReport(
            body=body,
            media_type=media_type,
            report_id=validated.id,
            status=validated.status,
        )
