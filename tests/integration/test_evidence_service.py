from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from pathlib import Path

import pytest

from tests.repository_fixtures import FakeRepositorySource, TarEntry, build_tar
from watchdog.advisory_match_service import AdvisoryMatchService
from watchdog.domain.advisories import AdvisoryRecord, AffectedPackage
from watchdog.domain.evidence import EvidenceStatus
from watchdog.domain.inventory import SelectorKind, SourceReference, SourceSelector
from watchdog.domain.repositories import RepositoryRequest
from watchdog.evidence.identifiers import canonical_json_bytes
from watchdog.evidence.limits import EvidenceConfiguration, EvidenceLimits
from watchdog.evidence.redaction import RedactionResult, Redactor
from watchdog.evidence.service import EvidenceService
from watchdog.inventory.service import DependencyInventoryService
from watchdog.repository.intake import RepositoryIntakeService

from ..factories import make_advisory
from ..unit.test_matching import FakeScanner
from .test_phase3_pipeline import inventory_limits, repository_limits


def evidence_limits(**overrides: object) -> EvidenceLimits:
    values: dict[str, object] = {
        "deadline_seconds": 10,
        "max_source_files": 20,
        "max_bytes_per_source_file": 1024 * 1024,
        "max_total_source_bytes": 2 * 1024 * 1024,
        "max_evidence_items": 100,
        "max_line_span": 50,
        "max_display_bytes_per_item": 4096,
        "max_bundle_display_bytes": 8192,
        "max_redactions_per_item": 20,
        "max_warnings": 100,
    }
    values.update(overrides)
    return EvidenceLimits.model_validate(values)


def configuration(**overrides: object) -> EvidenceConfiguration:
    return EvidenceConfiguration(limits=evidence_limits(**overrides))


def request() -> RepositoryRequest:
    return RepositoryRequest(repository_url="https://github.com/octocat/Hello-World", ref="main")


def advisory(name: str) -> AdvisoryRecord:
    return make_advisory().model_copy(
        update={"affected_packages": (AffectedPackage(ecosystem="PyPI", name=name),)}
    )


async def test_redacted_bundle_is_deterministic_and_lease_scoped(tmp_path: Path) -> None:
    synthetic = "synthetic-user:synthetic-password"
    manifest = f"fixture @ https://{synthetic}@example.invalid/archive.whl\n".encode()
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=manifest),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())

    async with lease as acquired:
        workspace = acquired.root.parent
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(FakeScanner()).match(advisory("fixture"), inventory)
        service = EvidenceService(configuration())
        first = await service.collect(acquired, inventory, report)
        second = await service.collect(acquired, inventory, report)

        assert first == second
        assert canonical_json_bytes(first) == canonical_json_bytes(second)
        assert first.items[0].status == EvidenceStatus.REDACTED
        assert first.items[0].content is not None
        assert synthetic not in first.items[0].content.text
        assert synthetic not in canonical_json_bytes(first).decode()
        assert first.match_links[0].match_state == report.matches[0].state
        assert first.match_links[0].match_coverage_limitations == (
            report.matches[0].coverage_limitations
        )

    assert lease.cleanup_result.verified
    assert not workspace.exists()


async def test_digest_mismatch_is_omitted_and_never_becomes_negative(
    tmp_path: Path,
) -> None:
    original = b"requests==2.32.3\n"
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=original),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())

    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(FakeScanner()).match(advisory("requests"), inventory)
        (acquired.root / "requirements.txt").write_bytes(b"requests==9.9.9\n")

        bundle = await EvidenceService(configuration()).collect(acquired, inventory, report)

        assert bundle.partial
        assert bundle.items[0].status == EvidenceStatus.CONTENT_OMITTED
        assert bundle.items[0].limitation_codes == ("source_digest_mismatch",)
        assert bundle.match_links[0].match_state == report.matches[0].state
        assert bundle.match_links[0].source_outcomes[0].evidence_id == bundle.items[0].id

    assert lease.cleanup_result.verified


async def test_item_overflow_remains_visible_in_match_source_outcomes(tmp_path: Path) -> None:
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements-a.txt", content=b"requests==2.32.3\n"),
            TarEntry("root/requirements-b.txt", content=b"requests==2.32.3\n"),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())

    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(FakeScanner()).match(advisory("requests"), inventory)
        bundle = await EvidenceService(configuration(max_evidence_items=1)).collect(
            acquired, inventory, report
        )

        assert len(bundle.items) == 1
        assert len(bundle.match_links) == 2
        outcomes = [link.source_outcomes[0] for link in bundle.match_links]
        assert sum(outcome.evidence_id is None for outcome in outcomes) == 1
        assert any(outcome.limitation_codes == ("item_limit_exceeded",) for outcome in outcomes)
        assert bundle.coverage.overflow_outcomes == 1
        assert bundle.partial

        warning_limited = await EvidenceService(
            configuration(max_evidence_items=1, max_warnings=1)
        ).collect(acquired, inventory, report)
        assert [warning.code for warning in warning_limited.warnings] == ["warning_limit_exceeded"]
        assert "warning_limit_exceeded" in warning_limited.coverage.limitation_codes

    assert lease.cleanup_result.verified


async def test_file_input_display_and_deadline_limits_are_explicit(tmp_path: Path) -> None:
    manifest = b"requests==2.32.3\n"
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements-a.txt", content=manifest),
            TarEntry("root/requirements-b.txt", content=manifest),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())

    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(FakeScanner()).match(advisory("requests"), inventory)

        file_limited = await EvidenceService(configuration(max_source_files=1)).collect(
            acquired, inventory, report
        )
        assert "source_file_limit_exceeded" in file_limited.coverage.limitation_codes

        total_limited = await EvidenceService(
            configuration(
                max_bytes_per_source_file=len(manifest),
                max_total_source_bytes=len(manifest),
            )
        ).collect(acquired, inventory, report)
        assert "source_total_bytes_limit_exceeded" in total_limited.coverage.limitation_codes

        per_file_limited = await EvidenceService(
            configuration(
                max_bytes_per_source_file=len(manifest) - 1,
                max_total_source_bytes=len(manifest) * 2,
            )
        ).collect(acquired, inventory, report)
        assert per_file_limited.coverage.omitted_items == 2
        assert "source_file_bytes_limit_exceeded" in (per_file_limited.coverage.limitation_codes)

        display_limited = await EvidenceService(
            configuration(
                max_display_bytes_per_item=5,
                max_bundle_display_bytes=10,
            )
        ).collect(acquired, inventory, report)
        assert all(
            item.content is not None and item.content.truncated for item in display_limited.items
        )
        assert "display_item_bytes_limit_exceeded" in (display_limited.coverage.limitation_codes)

        bundle_limited = await EvidenceService(
            configuration(
                max_display_bytes_per_item=len(manifest),
                max_bundle_display_bytes=len(manifest),
            )
        ).collect(acquired, inventory, report)
        assert "bundle_display_bytes_limit_exceeded" in (bundle_limited.coverage.limitation_codes)

        deadline_limited = await EvidenceService(configuration(deadline_seconds=1e-9)).collect(
            acquired, inventory, report
        )
        assert deadline_limited.partial
        assert "evidence_deadline_exceeded" in deadline_limited.coverage.limitation_codes

    assert lease.cleanup_result.verified


async def test_same_path_digest_conflict_omits_every_conflicting_reference(
    tmp_path: Path,
) -> None:
    manifest = b"requests==2.32.3\n"
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=manifest),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())

    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(FakeScanner()).match(advisory("requests"), inventory)
        match = report.matches[0]
        assert match.component_id is not None
        original = match.source_references[0]
        conflict = original.model_copy(update={"file_sha256": "f" * 64})
        changed_components = tuple(
            component.model_copy(update={"source_references": (original, conflict)})
            if component.id == match.component_id
            else component
            for component in inventory.components
        )
        changed_inventory = inventory.model_copy(update={"components": changed_components})
        changed_match = match.model_copy(update={"source_references": (original, conflict)})
        changed_report = report.model_copy(update={"matches": (changed_match, *report.matches[1:])})

        bundle = await EvidenceService(configuration()).collect(
            acquired, changed_inventory, changed_report
        )

        assert bundle.coverage.files_read == 0
        assert bundle.coverage.omitted_items == 2
        assert all(item.limitation_codes == ("source_digest_conflict",) for item in bundle.items)

    assert lease.cleanup_result.verified


class _BlockingRedactor(Redactor):
    def __init__(self) -> None:
        super().__init__(("credential_assignment",))
        self.started = threading.Event()
        self.release = threading.Event()

    def redact(self, text: str, *, max_redactions: int) -> RedactionResult:
        self.started.set()
        self.release.wait(timeout=5)
        return super().redact(text, max_redactions=max_redactions)


class _RaisingRedactor(Redactor):
    def __init__(self) -> None:
        super().__init__(("credential_assignment",))

    def redact(self, text: str, *, max_redactions: int) -> RedactionResult:
        del max_redactions
        raise RuntimeError(f"synthetic detector failure: {text}")


async def test_cancellation_waits_for_worker_before_lease_cleanup(tmp_path: Path) -> None:
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=b"requests==2.32.3\n"),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())
    blocker = _BlockingRedactor()

    async with lease as acquired:
        workspace = acquired.root.parent
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(FakeScanner()).match(advisory("requests"), inventory)
        task = asyncio.create_task(
            EvidenceService(configuration(), redactor=blocker).collect(acquired, inventory, report)
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


async def test_detector_failure_omits_content_without_secret_diagnostics(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "synthetic-user:synthetic-password"
    manifest = f"fixture @ https://{secret}@example.invalid/archive.whl\n".encode()
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=manifest),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())
    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(FakeScanner()).match(advisory("fixture"), inventory)

        bundle = await EvidenceService(configuration(), redactor=_RaisingRedactor()).collect(
            acquired, inventory, report
        )

        rendered = canonical_json_bytes(bundle).decode()
        assert bundle.items[0].limitation_codes == ("redaction_failed",)
        assert secret not in rendered
        assert secret not in caplog.text

    assert lease.cleanup_result.verified


async def test_bundle_contains_no_operational_paths_or_timestamps(tmp_path: Path) -> None:
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=b"requests==2.32.3\n"),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())
    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(FakeScanner()).match(advisory("requests"), inventory)
        bundle = await EvidenceService(configuration()).collect(acquired, inventory, report)
        rendered = json.dumps(bundle.model_dump(mode="json"), sort_keys=True)
        assert str(acquired.root) not in rendered
        assert "generated_at" not in rendered
        assert "completed_at" not in rendered
        assert "retrieved_at" not in rendered

    assert lease.cleanup_result.verified


async def test_report_cannot_introduce_a_caller_selected_path(tmp_path: Path) -> None:
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry("root/requirements.txt", content=b"requests==2.32.3\n"),
            TarEntry("root/unrelated.txt", content=b"unrelated repository data\n"),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())
    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(FakeScanner()).match(advisory("requests"), inventory)
        injected = SourceReference(
            path="unrelated.txt",
            selector=SourceSelector(kind=SelectorKind.LINE, value="line:1"),
            file_sha256=hashlib.sha256(b"unrelated repository data\n").hexdigest(),
        )
        changed_match = report.matches[0].model_copy(update={"source_references": (injected,)})
        changed_report = report.model_copy(update={"matches": (changed_match,)})

        with pytest.raises(ValueError, match="not generated by the inventory"):
            await EvidenceService(configuration()).collect(acquired, inventory, changed_report)

    assert lease.cleanup_result.verified
