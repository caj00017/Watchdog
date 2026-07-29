from __future__ import annotations

import unicodedata

from watchdog.domain.reports import InvestigationReport, ReportCategory, ReportEntry, ReportView
from watchdog.reporting.limits import ReportingLimits
from watchdog.reporting.report_json import ReportRenderError

_BIDI_CONTROLS = {
    "\u061c",
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}
_MARKDOWN = "\\`*_{}[]<>()#+-.!|~>"
_HEADINGS = {
    ReportCategory.TARGET_METADATA: "Target metadata",
    ReportCategory.DETERMINISTIC_FACT: "Deterministic findings",
    ReportCategory.MODEL_INFERENCE: "Model inference",
    ReportCategory.ASSUMPTION: "Assumptions",
    ReportCategory.COVERAGE_GAP: "Coverage and limitations",
    ReportCategory.VALIDATION_ACTION: "Validation actions",
}


def escape_report_text(value: str) -> str:
    output: list[str] = []
    for character in value:
        codepoint = ord(character)
        if character in _BIDI_CONTROLS:
            output.append(f"U+{codepoint:04X}")
        elif character in {"\n", "\r", "\t"}:
            output.append(" ")
        elif codepoint < 32 or codepoint == 127 or unicodedata.category(character) == "Cc":
            output.append(f"U+{codepoint:04X}")
        elif character == "&":
            output.append("&amp;")
        elif character in _MARKDOWN:
            output.append(f"\\{character}")
        else:
            output.append(character)
    return "".join(output)


def _entry_lines(entries: tuple[ReportEntry, ...]) -> list[str]:
    lines: list[str] = []
    for category in ReportCategory:
        selected = [item for item in entries if item.category is category]
        if not selected:
            continue
        lines.extend((f"## {_HEADINGS[category]}", ""))
        for item in selected:
            lines.append(f"- {escape_report_text(item.text)}")
            if item.support_ids:
                citations = ", ".join(escape_report_text(value) for value in item.support_ids)
                lines.append(f"  - Evidence links: {citations}")
        lines.append("")
    return lines


def render_report_markdown(
    report: InvestigationReport,
    view: ReportView,
    limits: ReportingLimits,
) -> bytes:
    entries = report.summary if view is ReportView.SUMMARY else report.technical
    lines = [
        "This is an evidence-bound investigation, not an affected/not-affected or "
        "runtime-exposure determination.",
        "",
        "# Nexura Watchdog investigation report",
        "",
        f"Report ID: {escape_report_text(report.id)}",
        "",
        f"Report status: {escape_report_text(report.status.value)}",
        "",
        f"Advisory: {escape_report_text(report.advisory.primary_id)}",
        "",
        f"Repository: {escape_report_text(report.repository.canonical_url)}",
        "",
        f"Exact commit: {escape_report_text(report.repository.commit_sha)}",
        "",
        f"Report producer version: {escape_report_text(report.producer.version)}",
        "",
        f"Scanner version: {escape_report_text(report.scanner.tool_version or 'unavailable')}",
        "",
        f"Model inference status: {escape_report_text(report.investigation.status.value)}",
        "",
        *_entry_lines(entries),
    ]
    if view is ReportView.TECHNICAL:
        lines.extend(
            (
                "## Technical identities",
                "",
                f"- Evidence bundle: {escape_report_text(report.evidence_bundle_id)}",
                f"- Context bundle: {escape_report_text(report.context_bundle_id)}",
                f"- Investigation result: {escape_report_text(report.investigation.result_id)}",
                "- Scanner version: "
                f"{escape_report_text(report.scanner.tool_version or 'unavailable')}",
                "",
            )
        )
    body = ("\n".join(lines).rstrip() + "\n").encode("utf-8")
    if len(body) > limits.max_markdown_bytes:
        raise ReportRenderError("Markdown report exceeded its byte limit")
    return body
