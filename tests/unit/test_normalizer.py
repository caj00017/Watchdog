from watchdog.vulnerability_sources.normalizer import merge_advisory_records

from ..factories import make_advisory


def test_merge_preserves_conflicting_scalar_values_and_provenance() -> None:
    osv = make_advisory(summary="OSV summary", source="osv")
    second = make_advisory(
        primary_id="GHSA-2345-6789-CFGH",
        aliases=("CVE-2026-12345",),
        summary="Different source summary",
        source="second-source",
    )

    merged = merge_advisory_records((osv, second))

    assert merged.summary == "OSV summary"
    assert merged.aliases == ("GHSA-2345-6789-CFGH",)
    summary_conflict = next(item for item in merged.conflicts if item.field == "/summary")
    assert {value.value for value in summary_conflict.values} == {
        "OSV summary",
        "Different source summary",
    }
    assert {value.provenance[0].source for value in summary_conflict.values} == {
        "osv",
        "second-source",
    }
    assert {item.source for item in merged.field_provenance["/aliases/0"]} == {
        "osv",
        "second-source",
    }


def test_merge_rejects_unrelated_records() -> None:
    first = make_advisory()
    second = make_advisory(primary_id="CVE-2026-99999", aliases=())

    try:
        merge_advisory_records((first, second))
    except ValueError as exc:
        assert "shared identifier" in str(exc)
    else:
        raise AssertionError("unrelated records must not be merged")
