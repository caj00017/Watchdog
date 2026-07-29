from __future__ import annotations

from watchdog.domain.remediation import RemediationPlan
from watchdog.domain.reports import ReportView
from watchdog.remediation.limits import RemediationLimits
from watchdog.remediation.report_json import RemediationRenderError
from watchdog.reporting.report_markdown import escape_report_text

_ACTION_TEXT = {
    "review_advisory_fixed_version_provenance": (
        "Review the cited advisory fixed-version provenance."
    ),
    "assess_target_compatibility_and_release_notes_independently": (
        "Assess target-version compatibility and release notes independently."
    ),
    "review_cited_declaration_and_preview": "Review the cited declaration and preview.",
    "update_generated_artifacts_in_trusted_workflow": (
        "Update generated lock or checksum artifacts using the maintainer's trusted workflow."
    ),
    "run_project_tests_outside_watchdog": "Run the project's trusted tests outside Watchdog.",
    "confirm_deployment_and_conditional_applicability": (
        "Confirm deployment and conditional dependency applicability."
    ),
    "rerun_watchdog_against_separately_acquired_new_commit": (
        "Rerun Watchdog against a separately acquired new commit."
    ),
}


def render_remediation_markdown(
    plan: RemediationPlan,
    view: ReportView,
    limits: RemediationLimits,
) -> bytes:
    lines = [
        plan.no_change_statement,
        "",
        "# Nexura Watchdog remediation plan",
        "",
        f"Plan ID: {escape_report_text(plan.id)}",
        "",
        f"Plan status: {escape_report_text(plan.status.value)}",
        "",
        f"Phase 7 report: {escape_report_text(plan.phase7_report_id)}",
        "",
        f"Advisory: {escape_report_text(plan.advisory_id)}",
        "",
        f"Repository: {escape_report_text(plan.snapshot.repository_url)}",
        "",
        f"Exact commit: {escape_report_text(plan.snapshot.commit_sha)}",
        "",
        "## Source-reported candidates",
        "",
    ]
    if not plan.candidates:
        lines.extend(("- No provenance-complete candidate is available within coverage.", ""))
    for candidate in plan.candidates:
        coordinate = candidate.current_coordinate
        lines.extend(
            (
                "- "
                f"{escape_report_text(coordinate.ecosystem.value)} "
                f"{escape_report_text(coordinate.name)} "
                f"{escape_report_text(coordinate.version)} → "
                f"{escape_report_text(candidate.raw_source_reported_target)}",
                f"  - Candidate ID: {escape_report_text(candidate.id)}",
                f"  - Selection: {escape_report_text(candidate.selection.value)}",
                "  - Advisory fact support: "
                + ", ".join(
                    escape_report_text(item.id) for item in candidate.advisory_fact_supports
                ),
                "  - Dependency evidence: "
                + ", ".join(escape_report_text(item) for item in candidate.dependency_evidence_ids),
            )
        )
        if candidate.limitations:
            lines.append(
                "  - Limitations: "
                + ", ".join(escape_report_text(item.value) for item in candidate.limitations)
            )
        lines.append("")
    lines.extend(("## In-memory previews", ""))
    if not plan.previews:
        lines.extend(("- No validated preview is available.", ""))
    for preview in plan.previews:
        lines.extend(
            (
                f"- Preview ID: {escape_report_text(preview.id)}",
                f"  - Candidate: {escape_report_text(preview.candidate_id)}",
                f"  - Source: {escape_report_text(preview.source_reference.path)}",
                f"  - Status: {escape_report_text(preview.status.value)}",
                "  - Structured replacement: byte offset "
                f"{preview.replacement.offset}; "
                f"{escape_report_text(preview.replacement.original_token)} → "
                f"{escape_report_text(preview.replacement.replacement_token)}",
            )
        )
        if preview.redacted_zero_context_diff is not None:
            lines.append(
                "  - Redacted zero-context diff: "
                + escape_report_text(preview.redacted_zero_context_diff)
            )
        if preview.limitations:
            lines.append(
                "  - Limitations: "
                + ", ".join(escape_report_text(item.value) for item in preview.limitations)
            )
        lines.append("")
    lines.extend(("## Human validation actions", ""))
    lines.extend(
        f"- {escape_report_text(_ACTION_TEXT[action.value])}" for action in plan.validation_actions
    )
    lines.extend(("", "## Coverage and limitations", ""))
    lines.append(f"- Coverage: {escape_report_text(plan.coverage.state.value)}")
    lines.append(f"- Partial: {'yes' if plan.partial else 'no'}")
    for limitation in plan.coverage.limitations:
        lines.append(f"- {escape_report_text(limitation.value)}")
    if view is ReportView.TECHNICAL:
        lines.extend(
            (
                "",
                "## Technical identities",
                "",
                f"- Configuration: {escape_report_text(plan.configuration_id)}",
                f"- Tree: {escape_report_text(plan.snapshot.tree_sha)}",
                f"- Archive: {escape_report_text(plan.snapshot.archive_sha256)}",
            )
        )
    body = ("\n".join(lines).rstrip() + "\n").encode("utf-8")
    if len(body) > limits.max_markdown_bytes:
        raise RemediationRenderError("remediation Markdown exceeded its byte limit")
    return body
