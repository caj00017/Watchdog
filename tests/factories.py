from datetime import UTC, datetime

from watchdog.domain.advisories import AdvisoryRecord, FieldProvenance, SourceRecord


def make_advisory(
    *,
    primary_id: str = "CVE-2026-12345",
    aliases: tuple[str, ...] = ("GHSA-2345-6789-CFGH",),
    summary: str = "Example advisory",
    source: str = "test-source",
) -> AdvisoryRecord:
    retrieved_at = datetime(2026, 1, 2, tzinfo=UTC)
    source_url = f"https://example.test/{primary_id}"
    primary_provenance = FieldProvenance(
        source=source,
        record_id=primary_id,
        source_url=source_url,
        retrieved_at=retrieved_at,
        path="$.id",
    )
    summary_provenance = FieldProvenance(
        source=source,
        record_id=primary_id,
        source_url=source_url,
        retrieved_at=retrieved_at,
        path="$.summary",
    )
    aliases_provenance = FieldProvenance(
        source=source,
        record_id=primary_id,
        source_url=source_url,
        retrieved_at=retrieved_at,
        path="$.aliases",
    )
    modified_provenance = FieldProvenance(
        source=source,
        record_id=primary_id,
        source_url=source_url,
        retrieved_at=retrieved_at,
        path="$.modified",
    )
    return AdvisoryRecord(
        primary_id=primary_id,
        aliases=aliases,
        summary=summary,
        modified=datetime(2026, 1, 1, tzinfo=UTC),
        sources=(
            SourceRecord(
                source=source,
                record_id=primary_id,
                source_url=source_url,
                retrieved_at=retrieved_at,
                raw={"id": primary_id, "aliases": list(aliases), "summary": summary},
            ),
        ),
        field_provenance={
            "/primary_id": (primary_provenance,),
            "/aliases": (aliases_provenance,),
            **{
                f"/aliases/{index}": (
                    aliases_provenance.model_copy(update={"path": f"$.aliases[{index}]"}),
                )
                for index in range(len(aliases))
            },
            "/summary": (summary_provenance,),
            "/modified": (modified_provenance,),
        },
    )
