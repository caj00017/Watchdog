from __future__ import annotations

from collections.abc import Iterable

from watchdog.domain.remediation import RemediationPlan
from watchdog.domain.reports import InvestigationReport, ReportCategory, ReportEvidence
from watchdog.tui.display import display_text


def _safe(value: object) -> str:
    return display_text(str(value)).text


def _lines(title: str, values: Iterable[object]) -> list[str]:
    items = tuple(values)
    return [title, *(f"- {_safe(item)}" for item in items)] if items else [title, "- None"]


def report_summary(report: InvestigationReport) -> str:
    sections: list[str] = [
        "Evidence-bound investigation (not affected/not-affected or runtime exposure)",
        f"Status: {_safe(report.status.value)}",
        f"Report ID: {_safe(report.id)}",
        f"Advisory: {_safe(report.advisory.primary_id)}",
        f"Exact commit: {_safe(report.repository.commit_sha)}",
        f"Dependency matches: {len(report.matches)}",
        "",
    ]
    labels = (
        (ReportCategory.DETERMINISTIC_FACT, "Deterministic facts"),
        (ReportCategory.MODEL_INFERENCE, "Model inference"),
        (ReportCategory.ASSUMPTION, "Assumptions"),
        (ReportCategory.COVERAGE_GAP, "Coverage gaps and limitations"),
        (ReportCategory.VALIDATION_ACTION, "Human validation actions"),
    )
    for category, title in labels:
        sections.extend(
            _lines(title, (entry.text for entry in report.summary if entry.category is category))
        )
        sections.append("")
    coverage = report.coverage.model_dump(mode="json")
    sections.extend(
        _lines("Coverage fields", (f"{key}: {value}" for key, value in coverage.items()))
    )
    return "\n".join(sections)


def evidence_index(report: InvestigationReport) -> tuple[tuple[str, str], ...]:
    return tuple((_safe(item.id), item.id) for item in report.evidence)


def evidence_detail(item: ReportEvidence) -> str:
    location = _safe(item.path)
    if item.start_line is not None:
        location += f":{item.start_line}"
        if item.end_line is not None and item.end_line != item.start_line:
            location += f"-{item.end_line}"
    content = (
        "Content omitted by source evidence policy."
        if item.content is None
        else _safe(item.content)
    )
    return "\n".join(
        (
            f"Evidence ID: {_safe(item.id)}",
            "Phase / kind / status: "
            f"{_safe(item.phase)} / {_safe(item.kind)} / {_safe(item.status)}",
            f"Source location (display only): {location}",
            "Source redaction: content below is already-redacted canonical report data.",
            content,
            *_lines("Limitations", item.limitation_codes),
        )
    )


def remediation_summary(plan: RemediationPlan) -> str:
    lines = [
        "Candidate planning only; no change was applied.",
        f"Status: {_safe(plan.status.value)}",
        f"Plan ID: {_safe(plan.id)}",
        f"Phase 7 report ID: {_safe(plan.phase7_report_id)}",
        f"Candidates: {len(plan.candidates)}",
        f"Previews: {len(plan.previews)}",
        "",
    ]
    for candidate in plan.candidates:
        lines.extend(
            (
                f"Candidate: {_safe(candidate.id)}",
                "  Current: "
                f"{_safe(candidate.current_coordinate.ecosystem)}/"
                f"{_safe(candidate.current_coordinate.name)}@"
                f"{_safe(candidate.current_coordinate.version)}",
                f"  Source-reported target: {_safe(candidate.raw_source_reported_target)}",
                f"  Selection: {_safe(candidate.selection.value)}",
                "  Evidence: "
                + ", ".join(_safe(value) for value in candidate.dependency_evidence_ids),
            )
        )
    lines.extend(("", *_lines("Controlled validation actions", plan.validation_actions)))
    lines.extend(("", *_lines("Coverage limitations", plan.coverage.limitations)))
    lines.extend(("", *_lines("Conflicts", plan.conflicts)))
    lines.extend(("", *_lines("Warnings", plan.warnings)))
    if plan.previews:
        lines.append("")
        lines.append("Opt-in, display-safe previews")
        for preview in plan.previews:
            lines.append(f"Preview: {_safe(preview.id)} ({_safe(preview.status.value)})")
            if preview.redacted_zero_context_diff is not None:
                lines.append(_safe(preview.redacted_zero_context_diff))
    lines.extend(("", _safe(plan.no_change_statement)))
    return "\n".join(lines)
