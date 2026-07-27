import json

from watchdog.reporting.exporters import advisory_to_json, advisory_to_markdown

from ..factories import make_advisory


def test_json_export_includes_provenance() -> None:
    exported = json.loads(advisory_to_json(make_advisory()))

    assert exported["primary_id"] == "CVE-2026-12345"
    assert exported["field_provenance"]["/summary"][0]["source"] == "test-source"


def test_markdown_export_escapes_untrusted_markup() -> None:
    exported = advisory_to_markdown(make_advisory(summary="<script>*unsafe*</script>"))

    assert "<script>" not in exported
    assert "&lt;script&gt;" in exported
    assert "\\*unsafe\\*" in exported
    assert "Sources and provenance" in exported
