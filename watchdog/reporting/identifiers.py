from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel

from watchdog.investigation.identifiers import canonical_sha256


def reporting_configuration_sha256(value: object) -> str:
    return canonical_sha256(value)


def investigation_report_id(value: object) -> str:
    if isinstance(value, BaseModel):
        payload: object = value.model_dump(mode="json", exclude={"id"})
    elif isinstance(value, Mapping):
        payload = {key: item for key, item in value.items() if str(key) != "id"}
    else:
        payload = value
    return f"report:sha256:{canonical_sha256(payload)}"
