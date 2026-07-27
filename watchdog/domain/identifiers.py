import re
from dataclasses import dataclass
from enum import StrEnum

from watchdog.domain.errors import InvalidIdentifierError

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,19}", re.IGNORECASE)
_GHSA_PATTERN = re.compile(
    r"GHSA-[23456789CFGHJMPQRVWX]{4}-[23456789CFGHJMPQRVWX]{4}-"
    r"[23456789CFGHJMPQRVWX]{4}",
    re.IGNORECASE,
)
_OSV_DATABASE_PATTERN = re.compile(
    r"[A-Z][A-Z0-9]{1,31}-\d{4}-[A-Z0-9][A-Z0-9._-]{0,127}",
    re.IGNORECASE,
)


class IdentifierKind(StrEnum):
    CVE = "cve"
    GHSA = "ghsa"
    OSV = "osv"


@dataclass(frozen=True, slots=True)
class AdvisoryIdentifier:
    value: str
    kind: IdentifierKind


def parse_advisory_identifier(raw_identifier: str) -> AdvisoryIdentifier:
    """Validate and canonicalize an identifier before it reaches an adapter."""

    identifier = raw_identifier.strip()
    if _CVE_PATTERN.fullmatch(identifier):
        return AdvisoryIdentifier(identifier.upper(), IdentifierKind.CVE)
    if _GHSA_PATTERN.fullmatch(identifier):
        prefix, *parts = identifier.split("-")
        canonical = "-".join((prefix.upper(), *(part.lower() for part in parts)))
        return AdvisoryIdentifier(canonical, IdentifierKind.GHSA)
    if _OSV_DATABASE_PATTERN.fullmatch(identifier):
        return AdvisoryIdentifier(identifier.upper(), IdentifierKind.OSV)
    raise InvalidIdentifierError(raw_identifier)
