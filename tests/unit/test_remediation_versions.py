from __future__ import annotations

import pytest

from watchdog.domain.inventory import Ecosystem
from watchdog.remediation.versions import (
    UnsupportedVersion,
    compare_versions,
    parse_go_version,
    parse_npm_semver,
)


@pytest.mark.parametrize(
    ("current", "target", "greater"),
    [
        ("1.0.0", "1.0.1", True),
        ("1.0.0-alpha", "1.0.0", True),
        ("1.0.0+one", "1.0.0+two", False),
        ("2.0.0", "1.9.9", False),
        ("1.0.0-alpha.2", "1.0.0-alpha.10", True),
    ],
)
def test_npm_strict_semver_precedence(current: str, target: str, greater: bool) -> None:
    result = compare_versions(Ecosystem.NPM, current, target)
    assert result.supported
    assert result.greater is greater


@pytest.mark.parametrize(
    "value",
    [
        "v1.2.3",
        "v1.2.3-rc.1",
        "v2.0.0+incompatible",
        "v0.0.0-20260729123456-abcdef123456",
        "v1.2.4-0.20260729123456-abcdef123456",
        "v1.2.3-pre.0.20260729123456-abcdef123456",
    ],
)
def test_go_canonical_versions(value: str) -> None:
    parse_go_version(value)


@pytest.mark.parametrize(
    "value",
    [
        "1.2.3",
        "v01.2.3",
        "v1.2.3+metadata",
        "v1.2.4-0.20261301120000-abcdef123456",
        "v1.2.4-0.20260729123456-ABCDEF123456",
        "v1.2.3\n",
        "v1.2.3‮",
        "v" + "1" * 129,
    ],
)
def test_go_unsupported_versions_fail_closed(value: str) -> None:
    with pytest.raises(UnsupportedVersion):
        parse_go_version(value)


@pytest.mark.parametrize(
    "value", ["^1.2.3", "~1.2.3", "latest", "npm:alias@1.0.0", "v1.2.3", "1.02.3", "1.2"]
)
def test_npm_ranges_aliases_tags_and_noncanonical_values_fail_closed(value: str) -> None:
    with pytest.raises(UnsupportedVersion):
        parse_npm_semver(value)


def test_pypi_comparison_rejects_invalid_and_orders_prereleases() -> None:
    assert compare_versions(Ecosystem.PYPI, "1.0rc1", "1.0").greater
    invalid = compare_versions(Ecosystem.PYPI, "not a version", "2.0")
    assert not invalid.supported
    assert not invalid.greater
