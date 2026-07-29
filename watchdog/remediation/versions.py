from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from functools import total_ordering

from packaging.version import InvalidVersion, Version

from watchdog.domain.inventory import Ecosystem

_MAX_VERSION_BYTES = 128
_SEMVER = re.compile(
    r"(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)
_GO_PSEUDO = (
    re.compile(
        r"v(?P<major>[0-9]+)\.0\.0-(?P<timestamp>[0-9]{14})-"
        r"(?P<hash>[0-9a-f]{12})(?:\+incompatible)?"
    ),
    re.compile(
        r"v(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)"
        r"-0\.(?P<timestamp>[0-9]{14})-(?P<hash>[0-9a-f]{12})(?:\+incompatible)?"
    ),
    re.compile(
        r"v(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)"
        r"-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)\.0\."
        r"(?P<timestamp>[0-9]{14})-(?P<hash>[0-9a-f]{12})(?:\+incompatible)?"
    ),
)


class UnsupportedVersion(ValueError):
    """A hostile or unsupported version is visible but cannot authorize selection."""


@dataclass(frozen=True, slots=True)
class VersionComparison:
    supported: bool
    greater: bool


def _bounded_ascii(value: str) -> None:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise UnsupportedVersion("version is outside the supported ASCII grammar") from exc
    if not encoded or len(encoded) > _MAX_VERSION_BYTES:
        raise UnsupportedVersion("version exceeds the comparator bound")
    if value != value.strip() or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise UnsupportedVersion("version contains whitespace or controls")


@total_ordering
@dataclass(frozen=True, slots=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()
    build: tuple[str, ...] = ()

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        core = (self.major, self.minor, self.patch)
        other_core = (other.major, other.minor, other.patch)
        if core != other_core:
            return core < other_core
        if not self.prerelease:
            return False
        if not other.prerelease:
            return True
        for left, right in zip(self.prerelease, other.prerelease, strict=False):
            if left == right:
                continue
            left_numeric = left.isdigit()
            right_numeric = right.isdigit()
            if left_numeric and right_numeric:
                return int(left) < int(right)
            if left_numeric != right_numeric:
                return left_numeric
            return left < right
        return len(self.prerelease) < len(other.prerelease)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return False
        return (
            self.major,
            self.minor,
            self.patch,
            self.prerelease,
        ) == (
            other.major,
            other.minor,
            other.patch,
            other.prerelease,
        )


def _parse_semver(value: str) -> SemVer:
    _bounded_ascii(value)
    match = _SEMVER.fullmatch(value)
    if match is None:
        raise UnsupportedVersion("version is not strict SemVer 2.0.0")
    prerelease = (
        tuple((match.group("prerelease") or "").split(".")) if match.group("prerelease") else ()
    )
    if any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in prerelease):
        raise UnsupportedVersion("numeric prerelease identifiers cannot contain leading zeroes")
    build = tuple((match.group("build") or "").split(".")) if match.group("build") else ()
    return SemVer(
        major=int(match.group("major")),
        minor=int(match.group("minor")),
        patch=int(match.group("patch")),
        prerelease=prerelease,
        build=build,
    )


def parse_npm_semver(value: str) -> SemVer:
    """Parse one exact, prefix-free npm SemVer 2.0.0 value."""

    return _parse_semver(value)


def parse_go_version(value: str) -> SemVer:
    """Parse one canonical Go module semantic or pseudo-version."""

    _bounded_ascii(value)
    if not value.startswith("v"):
        raise UnsupportedVersion("Go module versions require a canonical v prefix")
    parsed = _parse_semver(value[1:])
    if parsed.build and parsed.build != ("incompatible",):
        raise UnsupportedVersion("Go module build metadata is limited to +incompatible")
    timestamp_like = bool(re.search(r"(?:^|\.)[0-9]{14}(?:-|\.)", value))
    pseudo_match = next(
        (match for pattern in _GO_PSEUDO if (match := pattern.fullmatch(value))), None
    )
    if timestamp_like and pseudo_match is None:
        raise UnsupportedVersion("Go pseudo-version is not canonical")
    if pseudo_match is not None:
        try:
            datetime.strptime(pseudo_match.group("timestamp"), "%Y%m%d%H%M%S")
        except ValueError as exc:
            raise UnsupportedVersion("Go pseudo-version timestamp is invalid") from exc
    return parsed


def compare_versions(ecosystem: Ecosystem, current: str, target: str) -> VersionComparison:
    try:
        if ecosystem is Ecosystem.PYPI:
            _bounded_ascii(current)
            _bounded_ascii(target)
            return VersionComparison(supported=True, greater=Version(target) > Version(current))
        if ecosystem is Ecosystem.NPM:
            return VersionComparison(
                supported=True,
                greater=parse_npm_semver(target) > parse_npm_semver(current),
            )
        return VersionComparison(
            supported=True,
            greater=parse_go_version(target) > parse_go_version(current),
        )
    except (InvalidVersion, UnsupportedVersion):
        return VersionComparison(supported=False, greater=False)
