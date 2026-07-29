from __future__ import annotations

from watchdog.domain.remediation import RemediationPlan, RenderedRemediationPlan
from watchdog.domain.reports import ReportFormat, ReportView
from watchdog.remediation.limits import RemediationConfiguration
from watchdog.remediation.report_json import render_remediation_json
from watchdog.remediation.report_markdown import render_remediation_markdown


class RemediationRenderer:
    def __init__(self, configuration: RemediationConfiguration) -> None:
        self._configuration = RemediationConfiguration.model_validate(
            configuration.model_dump(mode="python")
        )

    def render(
        self,
        plan: RemediationPlan,
        *,
        view: ReportView,
        format: ReportFormat,
    ) -> RenderedRemediationPlan:
        validated = RemediationPlan.model_validate(plan.model_dump(mode="python"))
        if format is ReportFormat.JSON:
            body = render_remediation_json(validated, view, self._configuration.limits)
            media_type = "application/json"
        else:
            body = render_remediation_markdown(validated, view, self._configuration.limits)
            media_type = "text/markdown"
        return RenderedRemediationPlan(
            body=body,
            media_type=media_type,
            plan_id=validated.id,
            status=validated.status,
        )
