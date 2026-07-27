from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

from packaging.utils import canonicalize_name

from watchdog.domain.inventory import Applicability, Ecosystem, SourceReference

_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")


def normalize_package_name(ecosystem: Ecosystem, name: str) -> str:
    stripped = name.strip()
    if not stripped:
        raise ValueError("package name must not be empty")
    if ecosystem == Ecosystem.PYPI:
        return canonicalize_name(stripped)
    if ecosystem == Ecosystem.NPM:
        normalized = stripped.lower()
        if not _NPM_NAME.fullmatch(normalized):
            raise ValueError("invalid npm package name")
        return normalized
    return stripped


def canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def deterministic_id(prefix: str, value: Mapping[str, object]) -> str:
    return f"{prefix}_{hashlib.sha256(canonical_json(value)).hexdigest()}"


def applicability_identity(applicability: Applicability) -> object:
    return applicability.model_dump(mode="json")


def source_identity(source: SourceReference) -> object:
    return {
        "path": source.path,
        "selector": source.selector.model_dump(mode="json"),
        "sha256": source.file_sha256,
    }


def project_id(*, commit_sha: str, root: str, ecosystem: Ecosystem) -> str:
    return deterministic_id(
        "project",
        {"commit": commit_sha, "root": root, "ecosystem": ecosystem.value},
    )


def component_id(
    *,
    commit_sha: str,
    project_root: str,
    ecosystem: Ecosystem,
    normalized_name: str,
    version: str | None,
    applicability: Applicability,
    source: SourceReference,
) -> str:
    return deterministic_id(
        "component",
        {
            "commit": commit_sha,
            "project_root": project_root,
            "ecosystem": ecosystem.value,
            "name": normalized_name,
            "version": version,
            "condition": applicability_identity(applicability),
            "source": source_identity(source),
        },
    )


def edge_id(
    *,
    commit_sha: str,
    project_root: str,
    ecosystem: Ecosystem,
    from_component_id: str | None,
    to_component_id: str,
    relationship: str,
    applicability: Applicability,
    source: SourceReference,
) -> str:
    return deterministic_id(
        "edge",
        {
            "commit": commit_sha,
            "project_root": project_root,
            "ecosystem": ecosystem.value,
            "from": from_component_id,
            "to": to_component_id,
            "relationship": relationship,
            "condition": applicability_identity(applicability),
            "source": source_identity(source),
        },
    )
