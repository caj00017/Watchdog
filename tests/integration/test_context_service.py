from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import pytest
from pydantic import ValidationError

from tests.repository_fixtures import FakeRepositorySource, TarEntry, build_tar
from watchdog.advisory_match_service import AdvisoryMatchService
from watchdog.context.catalog import catalog_metadata
from watchdog.context.identifiers import (
    canonical_json_bytes,
    context_bundle_id,
    context_edge_id,
    context_observation_id,
)
from watchdog.context.limits import ContextConfiguration, ContextLimits
from watchdog.context.service import ContextService
from watchdog.domain.advisories import AdvisoryRecord, AffectedPackage
from watchdog.domain.context import (
    ContextBundle,
    ContextLimitation,
    ContextSignalKind,
    GraphEdgeKind,
    ObservationKind,
)
from watchdog.domain.evidence import EvidenceStatus
from watchdog.domain.repositories import RepositoryRequest
from watchdog.evidence.redaction import RedactionResult, Redactor
from watchdog.evidence.service import EvidenceService
from watchdog.inventory.service import DependencyInventoryService
from watchdog.repository.intake import RepositoryIntakeService

from ..factories import make_advisory
from ..unit.test_matching import FakeScanner
from .test_evidence_service import configuration as evidence_configuration
from .test_phase3_pipeline import inventory_limits, repository_limits


def context_limits(**overrides: object) -> ContextLimits:
    values: dict[str, object] = {
        "deadline_seconds": 10,
        "max_directories": 100,
        "max_candidate_paths": 200,
        "max_directory_depth": 10,
        "max_path_bytes": 512,
        "max_source_files": 50,
        "max_bytes_per_source_file": 1024 * 1024,
        "max_total_source_bytes": 2 * 1024 * 1024,
        "max_tokens_per_file": 10_000,
        "max_total_tokens": 100_000,
        "max_nesting_depth": 64,
        "max_observations": 1_000,
        "max_graph_nodes": 1_000,
        "max_graph_edges": 2_000,
        "max_evidence_items": 1_000,
        "max_line_span": 50,
        "max_display_bytes_per_item": 4096,
        "max_bundle_display_bytes": 64 * 1024,
        "max_redactions_per_item": 20,
        "max_warnings": 100,
    }
    values.update(overrides)
    return ContextLimits.model_validate(values)


def request() -> RepositoryRequest:
    return RepositoryRequest(
        repository_url="https://github.com/octocat/Hello-World",
        ref="main",
    )


def advisory(package: str, ecosystem: str = "PyPI") -> AdvisoryRecord:
    return make_advisory().model_copy(
        update={"affected_packages": (AffectedPackage(ecosystem=ecosystem, name=package),)}
    )


async def test_context_bundle_is_deterministic_linked_and_lease_scoped(tmp_path: Path) -> None:
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=b"requests==2.32.3\n"),
            TarEntry(
                "root/src/app.py",
                content=(
                    b"import requests as client\n"
                    b'client.get("https://example.invalid", verify=False)\n'
                ),
            ),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())

    async with lease as acquired:
        workspace = acquired.root.parent
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(FakeScanner()).match(advisory("requests"), inventory)
        phase4 = await EvidenceService(evidence_configuration()).collect(
            acquired, inventory, report
        )
        service = ContextService(context_limits())
        first = await service.collect(acquired, inventory, report, phase4)
        second = await service.collect(acquired, inventory, report, phase4)

        assert first == second
        assert canonical_json_bytes(first) == canonical_json_bytes(second)
        assert first.snapshot == inventory.snapshot
        assert first.match_links[0].dependency_evidence_ids == phase4.match_links[0].evidence_ids
        assert all(signal.dependency_evidence_ids for signal in first.signals)
        assert first.match_links[0].context_evidence_ids
        assert all(item.dependency_evidence_ids for item in first.evidence)
        assert all(
            item.source.file_sha256 == first.file_outcomes[0].file_sha256 for item in first.evidence
        )
        assert {item.kind for item in first.observations} >= {
            ObservationKind.IMPORT_DECLARATION,
            ObservationKind.TARGET_REFERENCE,
            ObservationKind.EXPLICIT_CALL,
            ObservationKind.TARGET_CONFIGURATION,
        }
        assert ContextSignalKind.EXPLICIT_TARGET_CALL_OBSERVED in {
            item.kind for item in first.signals
        }
        assert ContextSignalKind.CONTEXT_INCOMPLETE in {item.kind for item in first.signals}
        assert first.partial

        invalid = first.model_dump()
        edge = invalid["graph_edges"][0]
        edge["kind"] = GraphEdgeKind.DECLARED_NEAR_ENDPOINT
        edge["id"] = context_edge_id(edge)
        invalid["graph_edges"] = tuple(sorted(invalid["graph_edges"], key=lambda item: item["id"]))
        invalid["id"] = context_bundle_id(invalid)
        with pytest.raises(ValidationError, match="invalid lexical relationship"):
            ContextBundle.model_validate(invalid)

        mismatched = first.model_dump(mode="json")
        observation = next(item for item in mismatched["observations"] if item["rule_id"] is None)
        observation["rule_id"] = "synthetic-rule"
        observation["id"] = context_observation_id(observation)
        mismatched["observations"] = sorted(mismatched["observations"], key=lambda item: item["id"])
        with pytest.raises(ValidationError, match="broken evidence or target link"):
            ContextBundle.model_validate(mismatched)

    assert lease.cleanup_result.verified
    assert not workspace.exists()


def test_context_service_rejects_spoofed_producer_configuration() -> None:
    metadata = catalog_metadata()
    configuration = ContextConfiguration(
        limits=context_limits(),
        producer_version="spoofed",
        catalog_version=metadata.version,
        catalog_sha256=metadata.sha256,
    )

    with pytest.raises(ValueError, match="versions are fixed"):
        ContextService(configuration)


async def test_complete_mapping_can_emit_only_guarded_static_non_observation(
    tmp_path: Path,
) -> None:
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=b"pyyaml==6.0.2\n"),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())

    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(FakeScanner()).match(advisory("pyyaml"), inventory)
        phase4 = await EvidenceService(evidence_configuration()).collect(
            acquired, inventory, report
        )
        bundle = await ContextService(context_limits()).collect(acquired, inventory, report, phase4)

        assert [signal.kind for signal in bundle.signals] == [
            ContextSignalKind.TARGET_USAGE_NOT_OBSERVED_WITHIN_COVERAGE
        ]
        assert bundle.signals[0].limitation_codes == (
            ContextLimitation.STATIC_NON_OBSERVATION_LIMITATION,
        )
        assert not bundle.partial

    assert lease.cleanup_result.verified


@pytest.mark.parametrize(
    ("manifest_path", "manifest", "source_path", "source", "package", "ecosystem"),
    [
        (
            "package.json",
            b'{"dependencies":{"jsonwebtoken":"9.0.2"}}',
            "src/app.js",
            b'const jwt = require("jsonwebtoken");\njwt.verify(token);\n',
            "jsonwebtoken",
            "npm",
        ),
        (
            "go.mod",
            b"module example.com/app\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.10.0\n",
            "cmd/app/main.go",
            b'package main\nimport web "github.com/gin-gonic/gin"\nfunc main() { web.Default() }\n',
            "github.com/gin-gonic/gin",
            "Go",
        ),
    ],
)
async def test_javascript_and_go_pipeline_slices_link_phase3_through_phase5(
    tmp_path: Path,
    manifest_path: str,
    manifest: bytes,
    source_path: str,
    source: bytes,
    package: str,
    ecosystem: str,
) -> None:
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry(f"root/{manifest_path}", content=manifest),
            TarEntry(f"root/{source_path}", content=source),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())

    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(FakeScanner()).match(
            advisory(package, ecosystem), inventory
        )
        phase4 = await EvidenceService(evidence_configuration()).collect(
            acquired, inventory, report
        )
        bundle = await ContextService(context_limits()).collect(acquired, inventory, report, phase4)

        assert bundle.match_links[0].dependency_evidence_ids == phase4.match_links[0].evidence_ids
        assert any(item.kind == ObservationKind.EXPLICIT_CALL for item in bundle.observations)
        assert ContextSignalKind.EXPLICIT_TARGET_CALL_OBSERVED in {
            signal.kind for signal in bundle.signals
        }
        assert ContextSignalKind.TARGET_USAGE_NOT_OBSERVED_WITHIN_COVERAGE not in {
            signal.kind for signal in bundle.signals
        }
        assert {GraphEdgeKind.BINDS, GraphEdgeKind.REFERENCES, GraphEdgeKind.CALLS} <= {
            edge.kind for edge in bundle.graph_edges
        }

    assert lease.cleanup_result.verified


async def test_malformed_deadline_and_exclusion_paths_stay_incomplete(tmp_path: Path) -> None:
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=b"pyyaml==6.0.2\n"),
            TarEntry("root/app.py", content=b"import yaml\nyaml.load(\n"),
            TarEntry("root/vendor/ignored.py", content=b"import yaml\nyaml.load(data)\n"),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())

    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(FakeScanner()).match(advisory("pyyaml"), inventory)
        phase4 = await EvidenceService(evidence_configuration()).collect(
            acquired, inventory, report
        )
        malformed = await ContextService(context_limits()).collect(
            acquired, inventory, report, phase4
        )
        deadline = await ContextService(context_limits(deadline_seconds=1e-9)).collect(
            acquired, inventory, report, phase4
        )
        overflow = await ContextService(context_limits(max_candidate_paths=1)).collect(
            acquired, inventory, report, phase4
        )

        for bundle in (malformed, deadline, overflow):
            assert bundle.partial
            assert ContextSignalKind.CONTEXT_INCOMPLETE in {
                signal.kind for signal in bundle.signals
            }
            assert ContextSignalKind.TARGET_USAGE_NOT_OBSERVED_WITHIN_COVERAGE not in {
                signal.kind for signal in bundle.signals
            }
        assert ContextLimitation.MALFORMED_SYNTAX in malformed.coverage.limitation_codes
        assert ContextLimitation.DIRECTORY_EXCLUDED in malformed.coverage.limitation_codes
        assert ContextLimitation.CONTEXT_DEADLINE_EXCEEDED in deadline.coverage.limitation_codes
        assert ContextLimitation.CANDIDATE_PATH_LIMIT_EXCEEDED in overflow.coverage.limitation_codes

    assert lease.cleanup_result.verified


class _BlockingRedaction:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()


async def test_cancellation_waits_for_context_worker_before_lease_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=b"requests==2.32.3\n"),
            TarEntry("root/app.py", content=b"import requests\nrequests.get()\n"),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())
    blocker = _BlockingRedaction()
    original_redact = Redactor.redact

    def blocking_redact(redactor: Redactor, text: str, *, max_redactions: int) -> RedactionResult:
        blocker.started.set()
        blocker.release.wait(timeout=5)
        return original_redact(redactor, text, max_redactions=max_redactions)

    monkeypatch.setattr(Redactor, "redact", blocking_redact)

    async with lease as acquired:
        workspace = acquired.root.parent
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(FakeScanner()).match(advisory("requests"), inventory)
        phase4 = await EvidenceService(evidence_configuration()).collect(
            acquired, inventory, report
        )
        task = asyncio.create_task(
            ContextService(context_limits()).collect(acquired, inventory, report, phase4)
        )
        await asyncio.to_thread(blocker.started.wait, 2)
        task.cancel()
        await asyncio.sleep(0)
        assert workspace.exists()
        blocker.release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert lease.cleanup_result.verified
    assert not workspace.exists()


async def test_redaction_failure_never_exposes_repository_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    synthetic = "SYNTHETIC_CONTEXT_PIPELINE_SECRET"
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=b"requests==2.32.3\n"),
            TarEntry(
                "root/app.py",
                content=(f'import requests\nrequests.get(password="{synthetic}")\n'.encode()),
            ),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())

    def raising_redact(_redactor: Redactor, text: str, *, max_redactions: int) -> RedactionResult:
        del max_redactions
        raise RuntimeError(f"synthetic redaction failure contains {text}")

    monkeypatch.setattr(Redactor, "redact", raising_redact)

    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(FakeScanner()).match(advisory("requests"), inventory)
        phase4 = await EvidenceService(evidence_configuration()).collect(
            acquired, inventory, report
        )
        bundle = await ContextService(context_limits()).collect(acquired, inventory, report, phase4)

        assert all(item.status == EvidenceStatus.CONTENT_OMITTED for item in bundle.evidence)
        assert synthetic not in canonical_json_bytes(bundle).decode()
        assert synthetic not in repr(bundle)
        assert ContextLimitation.REDACTION_FAILED in bundle.coverage.limitation_codes

    assert lease.cleanup_result.verified
