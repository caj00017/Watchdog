from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from watchdog.advisory_match_service import AdvisoryMatchService
from watchdog.domain.advisories import AdvisoryRecord, AffectedPackage, AffectedRange
from watchdog.domain.matching import (
    ExactPackageCoordinate,
    MatchState,
    ScannerPackageResult,
    ScannerRunEvidence,
    ScannerRunResult,
    ScannerRunStatus,
    ScannerVulnerability,
)

from ..factories import make_advisory
from .test_inventory import build_inventory


class FakeScanner:
    def __init__(
        self,
        vulnerabilities: dict[ExactPackageCoordinate, tuple[ScannerVulnerability, ...]]
        | None = None,
        *,
        incomplete: bool = False,
    ) -> None:
        self.vulnerabilities = vulnerabilities or {}
        self.incomplete = incomplete
        self.coordinates: tuple[ExactPackageCoordinate, ...] = ()

    async def scan(
        self,
        coordinates: tuple[ExactPackageCoordinate, ...],
    ) -> ScannerRunResult:
        self.coordinates = coordinates
        moment = datetime(2026, 7, 27, tzinfo=UTC)
        evidence = ScannerRunEvidence(
            tool="fake-scanner",
            tool_version="2.4.0",
            arguments=("fake-scanner",),
            started_at=moment,
            completed_at=moment,
        )
        if self.incomplete:
            return ScannerRunResult(
                status=ScannerRunStatus.INCOMPLETE,
                evidence=evidence,
                warning_code="scanner_timeout",
            )
        return ScannerRunResult(
            status=ScannerRunStatus.SUCCESS,
            packages=tuple(
                ScannerPackageResult(
                    coordinate=coordinate,
                    vulnerabilities=self.vulnerabilities.get(coordinate, ()),
                )
                for coordinate in coordinates
            ),
            evidence=evidence,
        )


def affected_advisory(ecosystem: str | None, name: str | None) -> AdvisoryRecord:
    advisory = make_advisory(primary_id="CVE-2026-12345", aliases=("GHSA-TEST-ALIAS",))
    if ecosystem is None or name is None:
        affected = AffectedPackage(
            ranges=(
                AffectedRange(
                    type="GIT",
                    repository="https://github.com/example/package-less",
                ),
            ),
        )
    else:
        affected = AffectedPackage(ecosystem=ecosystem, name=name)
    return advisory.model_copy(update={"affected_packages": (affected,)})


async def test_alias_match_maps_every_occurrence_and_preserves_condition(tmp_path: Path) -> None:
    inventory = await build_inventory(
        tmp_path,
        {
            "pyproject.toml": """
[project]
dependencies = ["requests==2.32.3; sys_platform == 'linux'"]
"""
        },
    )
    coordinate = ExactPackageCoordinate(
        ecosystem="PyPI",
        name="requests",
        version="2.32.3",
    )
    scanner = FakeScanner(
        {coordinate: (ScannerVulnerability(id="OSV-OTHER", aliases=("GHSA-TEST-ALIAS",)),)}
    )

    report = await AdvisoryMatchService(scanner).match(
        affected_advisory("PyPI", "Requests"), inventory
    )

    assert scanner.coordinates == (coordinate,)
    assert report.matches[0].state == MatchState.AFFECTED_CONDITIONAL
    assert report.matches[0].matched_vulnerability_ids == ("OSV-OTHER", "GHSA-TEST-ALIAS")
    assert report.matches[0].source_references
    assert not report.partial


async def test_successful_exact_negative_is_narrowly_labeled(tmp_path: Path) -> None:
    inventory = await build_inventory(tmp_path, {"requirements.txt": "requests==2.32.3\n"})

    report = await AdvisoryMatchService(FakeScanner()).match(
        affected_advisory("PyPI", "requests"), inventory
    )

    assert report.matches[0].state == MatchState.NOT_REPORTED_AFFECTED
    assert "not a repository-level" in report.matches[0].coverage_limitations[0]
    assert any("reachability" in item for item in report.coverage_limitations)
    assert not report.partial


async def test_constraints_are_version_unknown_and_never_sent_to_scanner(tmp_path: Path) -> None:
    inventory = await build_inventory(
        tmp_path, {"pyproject.toml": "[project]\ndependencies=['flask>=3']\n"}
    )
    scanner = FakeScanner()

    report = await AdvisoryMatchService(scanner).match(
        affected_advisory("PyPI", "flask"), inventory
    )

    assert report.matches[0].state == MatchState.VERSION_UNKNOWN
    assert scanner.coordinates == ()
    assert report.partial


async def test_scanner_failure_never_becomes_negative(tmp_path: Path) -> None:
    inventory = await build_inventory(tmp_path, {"requirements.txt": "requests==2.32.3\n"})

    report = await AdvisoryMatchService(FakeScanner(incomplete=True)).match(
        affected_advisory("PyPI", "requests"), inventory
    )

    assert report.matches[0].state == MatchState.SCANNER_INCOMPLETE
    assert all(item.state != MatchState.NOT_REPORTED_AFFECTED for item in report.matches)
    assert report.partial
    assert report.warnings[0].code == "scanner_timeout"


async def test_unsupported_ecosystem_has_explicit_advisory_result(tmp_path: Path) -> None:
    inventory = await build_inventory(tmp_path, {"package.json": "{}"})

    report = await AdvisoryMatchService(FakeScanner()).match(
        affected_advisory("Maven", "example"), inventory
    )

    assert report.matches[0].state == MatchState.UNSUPPORTED_ADVISORY_COMPONENT
    assert report.partial


async def test_package_less_git_advisory_is_explicitly_unsupported(tmp_path: Path) -> None:
    inventory = await build_inventory(tmp_path, {"package.json": "{}"})

    report = await AdvisoryMatchService(FakeScanner()).match(
        affected_advisory(None, None), inventory
    )

    assert report.matches[0].state == MatchState.UNSUPPORTED_ADVISORY_COMPONENT
    assert "package-less Git" in report.matches[0].coverage_limitations[0]
