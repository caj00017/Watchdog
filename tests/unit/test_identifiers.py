import pytest

from watchdog.domain.errors import InvalidIdentifierError
from watchdog.domain.identifiers import IdentifierKind, parse_advisory_identifier


@pytest.mark.parametrize(
    ("raw", "canonical", "kind"),
    [
        ("cve-2026-12345", "CVE-2026-12345", IdentifierKind.CVE),
        ("GHSA-2345-6789-CFGH", "GHSA-2345-6789-cfgh", IdentifierKind.GHSA),
        ("OSV-2020-1113", "OSV-2020-1113", IdentifierKind.OSV),
        ("PYSEC-2024-12", "PYSEC-2024-12", IdentifierKind.OSV),
    ],
)
def test_parse_supported_identifier(
    raw: str,
    canonical: str,
    kind: IdentifierKind,
) -> None:
    parsed = parse_advisory_identifier(raw)

    assert parsed.value == canonical
    assert parsed.kind is kind


@pytest.mark.parametrize(
    "raw",
    ["", "CVE-26-1", "GHSA-aaaa-aaaa-aaaa", "https://example.com/CVE-2026-12345", "../../x"],
)
def test_reject_unsupported_or_unsafe_identifier(raw: str) -> None:
    with pytest.raises(InvalidIdentifierError):
        parse_advisory_identifier(raw)
