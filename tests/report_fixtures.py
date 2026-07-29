from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from tests.investigation_fixtures import build_investigation_inputs
from tests.unit.test_investigation_configuration import investigation_configuration
from watchdog.config import Settings
from watchdog.domain.reports import InvestigationReport
from watchdog.domain.repositories import GitHubRepository, RepositorySnapshot
from watchdog.investigation.limits import InvestigationConfiguration
from watchdog.investigation.service import InvestigationService
from watchdog.reporting.assembler import ReportAssembler
from watchdog.reporting.limits import ReportingConfiguration


async def build_report(
    workspace_root: Path,
) -> tuple[InvestigationReport, ReportingConfiguration, InvestigationConfiguration]:
    advisory, inventory, matches, evidence, context = await build_investigation_inputs(
        workspace_root
    )
    investigation_config = investigation_configuration(enabled=False, model=None)
    result = await InvestigationService(investigation_config).investigate(
        advisory, inventory, matches, evidence, context
    )
    snapshot = RepositorySnapshot(
        repository=GitHubRepository(
            owner="octocat",
            name="Hello-World",
            canonical_url=inventory.snapshot.repository_url,
        ),
        requested_ref="main",
        resolved_ref="main",
        commit_sha=inventory.snapshot.commit_sha,
        tree_sha=inventory.snapshot.tree_sha,
        retrieved_at=datetime(2026, 1, 1, tzinfo=UTC),
        archive_sha256=inventory.snapshot.archive_sha256,
        archive_bytes=1,
        extracted_bytes=1,
        file_count=2,
        symlink_count=0,
    )
    reporting_config = ReportingConfiguration.from_settings(Settings())
    report = ReportAssembler(reporting_config, investigation_config).assemble(
        advisory,
        snapshot,
        inventory,
        matches,
        evidence,
        context,
        result,
    )
    return report, reporting_config, investigation_config
