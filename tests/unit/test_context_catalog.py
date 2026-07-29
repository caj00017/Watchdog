from __future__ import annotations

import pytest
from pydantic import ValidationError

from watchdog.context.catalog import DEFAULT_CONTEXT_CATALOG, catalog_metadata
from watchdog.context.identifiers import catalog_sha256
from watchdog.domain.context import (
    ContextRuleCatalog,
    MemberRule,
    ObservationKind,
    PackageMappingRule,
)


def test_default_catalog_is_canonical_and_digest_bound() -> None:
    first = catalog_metadata()
    second = catalog_metadata(DEFAULT_CONTEXT_CATALOG)

    assert first == second
    assert first.sha256 == catalog_sha256(DEFAULT_CONTEXT_CATALOG)
    assert first.sha256 == "5141a20d849b9506cc36ec4e711f36169b0d7d3d3780d6e166071a970dcdd51f"
    changed = DEFAULT_CONTEXT_CATALOG.model_copy(update={"version": "2"})
    assert catalog_sha256(changed) != first.sha256


def test_catalog_rejects_extra_fields_duplicates_conflicts_and_unsorted_values() -> None:
    mapping = PackageMappingRule(
        id="mapping-a",
        ecosystem="PyPI",
        package_name="distribution",
        import_roots=("distribution",),
        review_reference="https://example.invalid/review",
    )
    with pytest.raises(ValidationError, match="globally unique"):
        ContextRuleCatalog(version="1", package_mappings=(mapping, mapping))

    conflicting = mapping.model_copy(update={"id": "mapping-b", "import_roots": ("other",)})
    with pytest.raises(ValidationError, match="must not conflict"):
        ContextRuleCatalog(version="1", package_mappings=(mapping, conflicting))

    with pytest.raises(ValidationError, match="unique and sorted"):
        PackageMappingRule(
            id="mapping-a",
            ecosystem="PyPI",
            package_name="distribution",
            import_roots=("z", "a"),
            review_reference="https://example.invalid/review",
        )

    overlapping = PackageMappingRule(
        id="mapping-c",
        ecosystem="PyPI",
        package_name="other",
        import_roots=("distribution.child",),
        review_reference="https://example.invalid/review",
    )
    with pytest.raises(ValidationError, match="overlap"):
        ContextRuleCatalog(version="1", package_mappings=(mapping, overlapping))

    with pytest.raises(ValidationError, match="normalized name"):
        PackageMappingRule(
            id="mapping-invalid",
            ecosystem="PyPI",
            package_name="Not_Normalized",
            import_roots=("valid",),
            review_reference="https://example.invalid/review",
        )

    with pytest.raises(ValidationError, match="reference or call"):
        MemberRule(
            id="member-invalid",
            ecosystem="PyPI",
            package_name="distribution",
            member_path=("value",),
            observation_kind=ObservationKind.TARGET_CONFIGURATION,
            review_reference="https://example.invalid/review",
        )

    values = DEFAULT_CONTEXT_CATALOG.model_dump()
    values["caller_regex"] = ".*"
    with pytest.raises(ValidationError):
        ContextRuleCatalog.model_validate(values)
