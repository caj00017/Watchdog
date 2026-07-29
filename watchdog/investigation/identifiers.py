from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import Enum

from pydantic import BaseModel


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return _json_value(value.model_dump(mode="json"))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    return value


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        _json_value(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def investigation_configuration_sha256(value: object) -> str:
    return canonical_sha256(value)


def advisory_provenance_id(value: object) -> str:
    digest = hashlib.sha256(canonical_json_bytes(_without_top_level_id(value))).hexdigest()
    return f"advisory-provenance:sha256:{digest}"


def investigation_envelope_id(value: object) -> str:
    digest = hashlib.sha256(canonical_json_bytes(_without_top_level_id(value))).hexdigest()
    return f"investigation-envelope:sha256:{digest}"


def investigation_result_id(value: object) -> str:
    digest = hashlib.sha256(canonical_json_bytes(_without_top_level_id(value))).hexdigest()
    return f"investigation-result:sha256:{digest}"


def _without_top_level_id(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude={"id"})
    if isinstance(value, Mapping):
        return {key: item for key, item in value.items() if str(key) != "id"}
    return value
