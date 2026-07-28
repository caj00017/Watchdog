from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from enum import Enum

from pydantic import BaseModel


def _json_value(value: object, *, exclude: set[str] | None = None) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude=exclude)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {
            str(key): _json_value(item)
            for key, item in value.items()
            if exclude is None or str(key) not in exclude
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    return value


def canonical_json_bytes(value: object, *, exclude: set[str] | None = None) -> bytes:
    return json.dumps(
        _json_value(value, exclude=exclude),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_json_sha256(value: object, *, exclude: set[str] | None = None) -> str:
    return hashlib.sha256(canonical_json_bytes(value, exclude=exclude)).hexdigest()


def evidence_configuration_sha256(configuration: object) -> str:
    return canonical_json_sha256(configuration)


def evidence_item_id(item: object) -> str:
    return f"evidence:sha256:{canonical_json_sha256(item, exclude={'id'})}"


def evidence_bundle_id(bundle: object) -> str:
    return f"bundle:sha256:{canonical_json_sha256(bundle, exclude={'id'})}"


# Concise public aliases for callers constructing canonical models.
configuration_sha256 = evidence_configuration_sha256
evidence_id = evidence_item_id
bundle_id = evidence_bundle_id
