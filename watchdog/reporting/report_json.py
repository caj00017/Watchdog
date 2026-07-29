from __future__ import annotations

import json

from watchdog.domain.reports import InvestigationReport, ReportView
from watchdog.reporting.limits import ReportingLimits


class ReportRenderError(ValueError):
    code = "report_render_failed"


def json_projection(report: InvestigationReport, view: ReportView) -> dict[str, object]:
    common: dict[str, object] = {
        "view": view.value,
        "id": report.id,
        "producer": report.producer.model_dump(mode="json"),
        "configuration_sha256": report.configuration_sha256,
        "status": report.status.value,
        "advisory": report.advisory.model_dump(mode="json"),
        "repository": report.repository.model_dump(mode="json"),
        "scanner": report.scanner.model_dump(mode="json"),
        "investigation": report.investigation.model_dump(mode="json"),
        "coverage": report.coverage.model_dump(mode="json"),
        "entries": [
            item.model_dump(mode="json")
            for item in (report.summary if view is ReportView.SUMMARY else report.technical)
        ],
    }
    if view is ReportView.TECHNICAL:
        common.update(
            {
                "inventory_configuration_sha256": report.inventory_configuration_sha256,
                "evidence_bundle_id": report.evidence_bundle_id,
                "evidence_configuration_sha256": report.evidence_configuration_sha256,
                "context_bundle_id": report.context_bundle_id,
                "context_configuration_sha256": report.context_configuration_sha256,
                "matches": [item.model_dump(mode="json") for item in report.matches],
                "evidence": [item.model_dump(mode="json") for item in report.evidence],
                "observations": [item.model_dump(mode="json") for item in report.observations],
                "signals": [item.model_dump(mode="json") for item in report.signals],
                "diagnostics": [item.model_dump(mode="json") for item in report.diagnostics],
            }
        )
    return common


def render_report_json(
    report: InvestigationReport,
    view: ReportView,
    limits: ReportingLimits,
) -> bytes:
    try:
        body = json.dumps(
            json_projection(report, view),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReportRenderError("report was not canonical JSON") from exc
    if len(body) > limits.max_json_bytes:
        raise ReportRenderError("canonical JSON report exceeded its byte limit")
    return body
