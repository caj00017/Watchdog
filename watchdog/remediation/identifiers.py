from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel

from watchdog.investigation.identifiers import canonical_sha256


def _identity(prefix: str, value: object) -> str:
    if isinstance(value, BaseModel):
        payload: object = value.model_dump(mode="json", exclude={"id"})
    elif isinstance(value, Mapping):
        payload = {key: item for key, item in value.items() if str(key) != "id"}
    else:
        payload = value
    return f"{prefix}:sha256:{canonical_sha256(payload)}"


def remediation_support_id(value: object) -> str:
    return _identity("remediation-support", value)


def remediation_candidate_id(value: object) -> str:
    return _identity("remediation-candidate", value)


def remediation_preview_id(value: object) -> str:
    return _identity("remediation-preview", value)


def remediation_configuration_id(value: object) -> str:
    return _identity("remediation-config", value)


def remediation_plan_id(value: object) -> str:
    return _identity("remediation-plan", value)
