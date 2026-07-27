from typing import Any

import httpx
import pytest

from watchdog.domain.errors import (
    AdvisoryNotFoundError,
    MalformedSourceResponseError,
    SourceUnavailableError,
)
from watchdog.domain.identifiers import parse_advisory_identifier
from watchdog.vulnerability_sources.osv import OsvSource

OSV_PAYLOAD: dict[str, Any] = {
    "id": "GHSA-2345-6789-CFGH",
    "aliases": ["CVE-2026-12345"],
    "modified": "2026-01-03T12:00:00Z",
    "published": "2026-01-02T12:00:00Z",
    "summary": "Unsafe parsing in example-package",
    "details": "A parser accepted untrusted input.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
    "affected": [
        {
            "package": {
                "ecosystem": "PyPI",
                "name": "example-package",
                "purl": "pkg:pypi/example-package",
            },
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.0.1"}],
                }
            ],
            "versions": ["2.0.0"],
        }
    ],
    "references": [{"type": "ADVISORY", "url": "https://example.test/advisory"}],
    "database_specific": {"cwe_ids": ["CWE-20"]},
}


async def test_osv_source_normalizes_aliases_provenance_and_raw_record() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/vulns/CVE-2026-12345"
        return httpx.Response(200, json=OSV_PAYLOAD)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await OsvSource(client).get_advisory(parse_advisory_identifier("CVE-2026-12345"))

    assert result.primary_id == "GHSA-2345-6789-cfgh"
    assert result.aliases == ("CVE-2026-12345",)
    assert result.affected_packages[0].name == "example-package"
    assert result.remediation[0].fixed_version == "2.0.1"
    assert result.cwes == ("CWE-20",)
    assert result.sources[0].raw["id"] == "GHSA-2345-6789-CFGH"
    assert result.field_provenance["/summary"][0].path == "$.summary"
    assert result.field_provenance["/affected_packages/0/name"][0].source == "osv"
    assert result.field_provenance["/affected_packages/0/ranges/0/events/1/fixed"][0].path.endswith(
        ".events[1].fixed"
    )
    assert result.field_provenance["/affected_packages/0/versions/0"][0].path.endswith(
        ".versions[0]"
    )
    assert result.field_provenance["/remediation/0/description"][0].path.endswith(
        ".events[1].fixed"
    )


async def test_osv_source_preserves_git_only_affected_component() -> None:
    payload: dict[str, Any] = {
        "id": "CVE-2026-12345",
        "modified": "2026-01-03T12:00:00Z",
        "affected": [
            {
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://example.test/source.git",
                        "events": [{"introduced": "0"}, {"fixed": "abc123"}],
                    }
                ]
            }
        ],
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await OsvSource(client).get_advisory(parse_advisory_identifier("CVE-2026-12345"))

    component = result.affected_packages[0]
    assert component.name is None
    assert component.ecosystem is None
    assert component.ranges[0].repository == "https://example.test/source.git"
    assert result.remediation[0].fixed_version == "abc123"


async def test_osv_source_uses_canonical_lowercase_ghsa_path() -> None:
    payload = {
        "id": "GHSA-2345-6789-cfgh",
        "modified": "2026-01-03T12:00:00Z",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/vulns/GHSA-2345-6789-cfgh"
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await OsvSource(client).get_advisory(
            parse_advisory_identifier("GHSA-2345-6789-CFGH")
        )

    assert result.primary_id == "GHSA-2345-6789-cfgh"


@pytest.mark.parametrize(
    ("status_code", "error_type"),
    [(404, AdvisoryNotFoundError), (503, SourceUnavailableError)],
)
async def test_osv_source_maps_upstream_statuses(
    status_code: int,
    error_type: type[Exception],
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(error_type):
            await OsvSource(client).get_advisory(parse_advisory_identifier("CVE-2026-12345"))


async def test_osv_source_rejects_malformed_response() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "CVE-2026-12345", "modified": 42})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(MalformedSourceResponseError):
            await OsvSource(client).get_advisory(parse_advisory_identifier("CVE-2026-12345"))


async def test_osv_source_maps_normalization_failure_to_malformed_response() -> None:
    payload = {
        "id": "CVE-2026-12345",
        "modified": "2026-01-03T12:00:00Z",
        "affected": [{"ranges": [{"type": "ECOSYSTEM"}]}],
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(MalformedSourceResponseError):
            await OsvSource(client).get_advisory(parse_advisory_identifier("CVE-2026-12345"))


async def test_osv_source_exposes_timeouts_as_source_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(SourceUnavailableError):
            await OsvSource(client).get_advisory(parse_advisory_identifier("CVE-2026-12345"))
