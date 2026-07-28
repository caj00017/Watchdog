from fastapi.testclient import TestClient

from apps.api.dependencies.advisories import get_advisory_service
from apps.api.main import create_app
from watchdog.advisory_service import AdvisoryService
from watchdog.domain.advisories import AdvisoryRecord
from watchdog.domain.identifiers import AdvisoryIdentifier

from ..factories import make_advisory


class FakeSource:
    name = "fake"

    def __init__(self, advisory: AdvisoryRecord) -> None:
        self._advisory = advisory

    async def get_advisory(self, _identifier: AdvisoryIdentifier) -> AdvisoryRecord:
        return self._advisory


def create_test_client() -> TestClient:
    application = create_app()
    service = AdvisoryService(FakeSource(make_advisory()))
    application.dependency_overrides[get_advisory_service] = lambda: service
    return TestClient(application)


def test_health_endpoint() -> None:
    with create_test_client() as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.1.0"}


def test_advisory_endpoint_returns_validated_json() -> None:
    with create_test_client() as client:
        response = client.get("/api/v1/advisories/CVE-2026-12345")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert payload["primary_id"] == "CVE-2026-12345"
    assert payload["field_provenance"]["/primary_id"][0]["source"] == "test-source"


def test_advisory_endpoint_supports_markdown_query_and_accept_header() -> None:
    with create_test_client() as client:
        query_response = client.get(
            "/api/v1/advisories/CVE-2026-12345", params={"format": "markdown"}
        )
        accept_response = client.get(
            "/api/v1/advisories/CVE-2026-12345", headers={"Accept": "text/markdown"}
        )

    assert query_response.status_code == 200
    assert query_response.headers["content-type"].startswith("text/markdown")
    assert query_response.text == accept_response.text
    assert query_response.text.startswith("# Advisory CVE-2026-12345")


def test_advisory_endpoint_rejects_invalid_identifier() -> None:
    with create_test_client() as client:
        response = client.get("/api/v1/advisories/not-an-id")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_identifier"


def test_phase4_does_not_expand_openapi_routes() -> None:
    assert set(create_app().openapi()["paths"]) == {
        "/health",
        "/api/v1/advisories/{identifier}",
    }
