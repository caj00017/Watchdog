from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from enum import Enum
from typing import Any

from pydantic import BaseModel

_ID_FIELDS = {"id"}


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        _canonical_value(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def context_target_id(value: object) -> str:
    return _identity("context-target", value)


def context_evidence_id(value: object) -> str:
    return _identity("context-evidence", value)


def context_observation_id(value: object) -> str:
    return _identity("context-observation", value)


def context_node_id(value: object) -> str:
    return _identity("context-node", value)


def context_edge_id(value: object) -> str:
    return _identity("context-edge", value)


def context_signal_id(value: object) -> str:
    return _identity("context-signal", value)


def context_bundle_id(value: object) -> str:
    return _identity("context-bundle", value)


def context_configuration_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def catalog_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _identity(prefix: str, value: object) -> str:
    payload = _without_identity(value)
    return f"{prefix}:sha256:{hashlib.sha256(canonical_json_bytes(payload)).hexdigest()}"


def _without_identity(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(exclude=_ID_FIELDS, mode="json")
    if isinstance(value, Mapping):
        return {key: item for key, item in value.items() if key != "id"}
    return value


def _canonical_value(value: object) -> Any:
    if isinstance(value, BaseModel):
        return _canonical_value(value.model_dump(mode="json"))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError("context canonical JSON received an unsupported value")
