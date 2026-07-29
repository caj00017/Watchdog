from __future__ import annotations

import json

from watchdog.domain.remediation import RemediationPlan
from watchdog.domain.reports import ReportView
from watchdog.remediation.limits import RemediationLimits


class RemediationRenderError(ValueError):
    code = "remediation_render_failed"


def json_projection(plan: RemediationPlan, view: ReportView) -> dict[str, object]:
    candidates: list[dict[str, object]]
    previews: list[dict[str, object]]
    if view is ReportView.TECHNICAL:
        candidates = [item.model_dump(mode="json") for item in plan.candidates]
        previews = [item.model_dump(mode="json") for item in plan.previews]
    else:
        candidates = [
            {
                "id": item.id,
                "current_coordinate": item.current_coordinate.model_dump(mode="json"),
                "raw_source_reported_target": item.raw_source_reported_target,
                "match_state": item.match_state.value,
                "selection": item.selection.value,
                "classifications": [value.value for value in item.classifications],
                "limitations": [value.value for value in item.limitations],
                "advisory_fact_support_ids": [value.id for value in item.advisory_fact_supports],
                "dependency_evidence_ids": list(item.dependency_evidence_ids),
            }
            for item in plan.candidates
        ]
        previews = [
            {
                "id": item.id,
                "candidate_id": item.candidate_id,
                "status": item.status.value,
                "source_reference": item.source_reference.model_dump(mode="json"),
                "replacement": item.replacement.model_dump(mode="json"),
                "redacted_zero_context_diff": item.redacted_zero_context_diff,
                "limitations": [value.value for value in item.limitations],
            }
            for item in plan.previews
        ]
    return {
        "view": view.value,
        "id": plan.id,
        "producer": plan.producer.model_dump(mode="json"),
        "configuration_id": plan.configuration_id,
        "phase7_report_id": plan.phase7_report_id,
        "advisory_id": plan.advisory_id,
        "snapshot": plan.snapshot.model_dump(mode="json"),
        "status": plan.status.value,
        "no_change_statement": plan.no_change_statement,
        "candidates": candidates,
        "previews": previews,
        "validation_actions": [item.value for item in plan.validation_actions],
        "conflicts": [item.value for item in plan.conflicts],
        "warnings": [item.value for item in plan.warnings],
        "coverage": plan.coverage.model_dump(mode="json"),
        "partial": plan.partial,
    }


def render_remediation_json(
    plan: RemediationPlan,
    view: ReportView,
    limits: RemediationLimits,
) -> bytes:
    try:
        body = json.dumps(
            json_projection(plan, view),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RemediationRenderError("remediation plan was not canonical JSON") from exc
    if len(body) > limits.max_json_bytes:
        raise RemediationRenderError("remediation JSON exceeded its byte limit")
    return body
