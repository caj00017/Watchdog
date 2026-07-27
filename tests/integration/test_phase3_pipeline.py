from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from tests.repository_fixtures import FakeRepositorySource, TarEntry, build_tar
from watchdog.advisory_match_service import AdvisoryMatchService
from watchdog.domain.advisories import AdvisoryRecord, AffectedPackage
from watchdog.domain.matching import MatchState
from watchdog.domain.repositories import RepositoryRequest
from watchdog.inventory.limits import InventoryLimits
from watchdog.inventory.service import DependencyInventoryService
from watchdog.repository.intake import RepositoryIntakeService
from watchdog.repository.limits import RepositoryLimits
from watchdog.scanners.limits import ScannerLimits
from watchdog.scanners.osv_scanner import OsvScanner

from ..factories import make_advisory
from ..unit.test_matching import FakeScanner


def repository_limits(workspace_root: Path) -> RepositoryLimits:
    return RepositoryLimits(
        network_timeout_seconds=5,
        max_duration_seconds=10,
        max_archive_bytes=1024 * 1024,
        max_extracted_bytes=1024 * 1024,
        max_files=100,
        max_path_length=256,
        max_concurrent_intakes=1,
        workspace_root=workspace_root,
    )


def inventory_limits() -> InventoryLimits:
    return InventoryLimits(
        deadline_seconds=10,
        max_manifest_files=20,
        max_bytes_per_manifest=1024 * 1024,
        max_total_parsed_bytes=2 * 1024 * 1024,
        max_components=100,
        max_edges=200,
        max_parser_nesting_depth=32,
        max_requirements_include_depth=5,
        max_warnings=100,
    )


def request() -> RepositoryRequest:
    return RepositoryRequest(
        repository_url="https://github.com/octocat/Hello-World",
        ref="main",
    )


def advisory(ecosystem: str, name: str) -> AdvisoryRecord:
    return make_advisory(primary_id="GO-2021-0053", aliases=("CVE-2021-3121",)).model_copy(
        update={"affected_packages": (AffectedPackage(ecosystem=ecosystem, name=name),)}
    )


async def directory_entries(path: Path) -> list[Path]:
    return await asyncio.to_thread(lambda: list(path.iterdir()))


async def test_inventory_and_matching_run_only_inside_lease_and_cleanup(tmp_path: Path) -> None:
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry(
                "root/go.mod",
                content=b"module example.com/app\nrequire github.com/gogo/protobuf v1.3.1\n",
            ),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())
    scanner = FakeScanner()

    async with lease as acquired:
        workspace = acquired.root.parent
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(scanner).match(
            advisory("Go", "github.com/gogo/protobuf"), inventory
        )
        assert scanner.coordinates[0].version == "1.3.1"
        assert report.matches[0].state == MatchState.NOT_REPORTED_AFFECTED

    assert lease.cleanup_result.verified
    assert not await asyncio.to_thread(workspace.exists)


@pytest.mark.parametrize(
    ("manifest_name", "manifest_content", "scanner_incomplete"),
    [
        ("package.json", b"{", False),
        ("requirements.txt", b"requests==2.32.3\n", True),
    ],
    ids=["parser-failure", "scanner-failure"],
)
async def test_parser_and_scanner_failures_preserve_verified_cleanup(
    tmp_path: Path,
    manifest_name: str,
    manifest_content: bytes,
    scanner_incomplete: bool,
) -> None:
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry(f"root/{manifest_name}", content=manifest_content),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())

    async with lease as acquired:
        workspace = acquired.root.parent
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        if scanner_incomplete:
            report = await AdvisoryMatchService(FakeScanner(incomplete=True)).match(
                make_advisory().model_copy(
                    update={
                        "affected_packages": (AffectedPackage(ecosystem="PyPI", name="requests"),)
                    }
                ),
                inventory,
            )
            assert report.matches[0].state == MatchState.SCANNER_INCOMPLETE
        else:
            assert inventory.partial

    assert lease.cleanup_result.verified
    assert not await asyncio.to_thread(workspace.exists)


@pytest.mark.skipif(
    os.environ.get("WATCHDOG_RUN_LIVE_SCANNER_TEST") != "1",
    reason="bounded live OSV contract test is opt-in",
)
async def test_live_osv_contract_gogo_protobuf(tmp_path: Path) -> None:
    scanner_path = Path(os.environ.get("WATCHDOG_OSV_SCANNER_PATH", "/usr/local/bin/osv-scanner"))
    scanner = OsvScanner(
        scanner_path,
        ScannerLimits(
            timeout_seconds=120,
            max_input_bytes=5 * 1024 * 1024,
            max_stdout_bytes=25 * 1024 * 1024,
            max_stderr_bytes=1024 * 1024,
        ),
    )
    archive = build_tar(
        [
            TarEntry("root/", kind="dir"),
            TarEntry(
                "root/go.mod",
                content=b"module example.com/app\nrequire github.com/gogo/protobuf v1.3.1\n",
            ),
        ]
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(request())

    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        report = await AdvisoryMatchService(scanner).match(
            advisory("Go", "github.com/gogo/protobuf"), inventory
        )
        assert report.matches[0].state == MatchState.AFFECTED

    assert lease.cleanup_result.verified
    assert await directory_entries(tmp_path) == []
