from __future__ import annotations

from watchdog.config import Settings
from watchdog.domain.advisories import (
    AdvisoryRecord,
    AffectedPackage,
    AffectedRange,
    FieldProvenance,
    VersionEvent,
)
from watchdog.remediation.limits import RemediationConfiguration

from .factories import make_advisory


def remediation_configuration(
    *,
    enabled: bool = True,
    preview_enabled: bool = False,
    **overrides: object,
) -> RemediationConfiguration:
    values: dict[str, object] = {
        "remediation_enabled": enabled,
        "remediation_preview_enabled": preview_enabled,
    }
    values.update(overrides)
    return RemediationConfiguration.from_settings(Settings.model_validate(values))


def remediation_advisory(
    ecosystem: str,
    name: str,
    target: str,
    *,
    conditional_second_target: str | None = None,
) -> AdvisoryRecord:
    advisory = make_advisory()
    provenance = FieldProvenance(
        source="test-source",
        record_id=advisory.primary_id,
        source_url=f"https://example.test/{advisory.primary_id}",
        retrieved_at=advisory.sources[0].retrieved_at,
        path="$.affected[0].ranges[0].events[1].fixed",
    )
    events = [VersionEvent(introduced="0"), VersionEvent(fixed=target)]
    if conditional_second_target is not None:
        events.append(VersionEvent(fixed=conditional_second_target))
    affected = AffectedPackage(
        ecosystem=ecosystem,
        name=name,
        ranges=(AffectedRange(type="ECOSYSTEM", events=tuple(events)),),
    )
    field_provenance = dict(advisory.field_provenance)
    field_provenance.update(
        {
            "/affected_packages/0": (provenance.model_copy(update={"path": "$.affected[0]"}),),
            "/affected_packages/0/ecosystem": (
                provenance.model_copy(update={"path": "$.affected[0].package.ecosystem"}),
            ),
            "/affected_packages/0/name": (
                provenance.model_copy(update={"path": "$.affected[0].package.name"}),
            ),
            "/affected_packages/0/ranges/0/events/1/fixed": (provenance,),
        }
    )
    if conditional_second_target is not None:
        field_provenance["/affected_packages/0/ranges/0/events/2/fixed"] = (
            provenance.model_copy(update={"path": "$.affected[0].ranges[0].events[2].fixed"}),
        )
    return advisory.model_copy(
        update={
            "affected_packages": (affected,),
            "field_provenance": field_provenance,
        }
    )
