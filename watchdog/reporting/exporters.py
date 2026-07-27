import html
import json
from collections.abc import Iterable

from watchdog.domain.advisories import AdvisoryRecord, VersionEvent


def advisory_to_json(advisory: AdvisoryRecord) -> str:
    """Serialize the validated domain record without losing provenance."""

    return json.dumps(advisory.model_dump(mode="json"), indent=2, sort_keys=True)


def _escape_markdown(value: str) -> str:
    escaped = html.escape(value, quote=False).replace("\\", "\\\\")
    for character in ("`", "*", "_", "[", "]", "#", "|"):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped


def _quote_block(value: str) -> str:
    return "\n".join(f"> {_escape_markdown(line)}" if line else ">" for line in value.splitlines())


def _event_text(event: VersionEvent) -> str:
    for name in ("introduced", "fixed", "last_affected", "limit"):
        value = getattr(event, name)
        if value is not None:
            return f"{name.replace('_', ' ')} {value}"
    raise AssertionError("validated events always contain one value")


def _bullet_lines(values: Iterable[str], *, empty: str = "None reported.") -> list[str]:
    result = [f"- {value}" for value in values]
    return result or [empty]


def advisory_to_markdown(advisory: AdvisoryRecord) -> str:
    """Render an auditable Markdown advisory without embedding raw HTML."""

    lines = [f"# Advisory {_escape_markdown(advisory.primary_id)}", ""]
    if advisory.summary:
        lines.extend([f"## {_escape_markdown(advisory.summary)}", ""])

    lines.extend(["## Identifiers", ""])
    lines.extend(_bullet_lines([_escape_markdown(alias) for alias in advisory.aliases]))

    lines.extend(["", "## Details", ""])
    lines.append(_quote_block(advisory.details) if advisory.details else "No details reported.")

    lines.extend(["", "## Severity", ""])
    lines.extend(
        _bullet_lines(
            f"{_escape_markdown(item.type)}: `{_escape_markdown(item.score)}`"
            for item in advisory.severity
        )
    )

    lines.extend(["", "## Affected packages", ""])
    package_lines: list[str] = []
    for package in advisory.affected_packages:
        if package.ecosystem and package.name:
            identity = f"{package.ecosystem} / {package.name}"
        else:
            identity = next(
                (
                    affected_range.repository
                    for affected_range in package.ranges
                    if affected_range.repository
                ),
                "Unpackaged component",
            )
        package_lines.append(f"- **{_escape_markdown(identity)}**")
        for affected_range in package.ranges:
            events = ", ".join(_event_text(event) for event in affected_range.events)
            suffix = f": {_escape_markdown(events)}" if events else ""
            package_lines.append(f"  - {_escape_markdown(affected_range.type)}{suffix}")
    lines.extend(package_lines or ["None reported."])

    lines.extend(["", "## CWEs", ""])
    lines.extend(_bullet_lines(_escape_markdown(cwe) for cwe in advisory.cwes))

    lines.extend(["", "## Remediation", ""])
    lines.extend(_bullet_lines(_escape_markdown(item.description) for item in advisory.remediation))

    lines.extend(["", "## References", ""])
    reference_lines = []
    for reference in advisory.references:
        label = _escape_markdown(reference.type or "Reference")
        reference_lines.append(f"- {label}: {_escape_markdown(reference.url)}")
    lines.extend(reference_lines or ["None reported."])

    lines.extend(["", "## Sources and provenance", ""])
    for source in advisory.sources:
        lines.append(
            f"- {_escape_markdown(source.source)} record "
            f"`{_escape_markdown(source.record_id)}`, retrieved "
            f"{source.retrieved_at.isoformat()}"
        )
    lines.append("")
    lines.append(
        f"Field-level provenance is retained for {len(advisory.field_provenance)} normalized paths."
    )

    if advisory.conflicts:
        lines.extend(["", "## Conflicting source values", ""])
        for conflict in advisory.conflicts:
            lines.append(
                f"- `{_escape_markdown(conflict.field)}`: {_escape_markdown(conflict.description)}"
            )

    if advisory.partial or advisory.warnings:
        lines.extend(["", "## Limitations", ""])
        if advisory.partial:
            lines.append("- This is a partial result.")
        lines.extend(f"- {_escape_markdown(warning)}" for warning in advisory.warnings)

    return "\n".join(lines).rstrip() + "\n"
