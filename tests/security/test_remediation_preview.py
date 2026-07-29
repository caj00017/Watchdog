from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.integration.test_evidence_service import configuration as evidence_configuration
from tests.integration.test_phase3_pipeline import inventory_limits, repository_limits
from tests.remediation_fixtures import remediation_advisory, remediation_configuration
from tests.repository_fixtures import FakeRepositorySource, TarEntry, build_tar
from tests.unit.test_matching import FakeScanner
from watchdog.advisory_match_service import AdvisoryMatchService
from watchdog.domain.matching import ExactPackageCoordinate, ScannerVulnerability
from watchdog.domain.remediation import CandidateClassification, PreviewStatus
from watchdog.domain.repositories import RepositoryRequest
from watchdog.evidence.service import EvidenceService
from watchdog.inventory.service import DependencyInventoryService
from watchdog.remediation.candidates import derive_candidates
from watchdog.remediation.preview import PreviewCollector
from watchdog.repository.intake import RepositoryIntakeService


def _case(kind: str) -> tuple[list[TarEntry], str, str, str, str, str]:
    if kind == "requirements":
        return (
            [TarEntry("root/requirements.txt", content=b"requests==2.32.3\n")],
            "PyPI",
            "requests",
            "2.32.3",
            "2.32.4",
            "requirements.txt",
        )
    if kind == "pyproject":
        return (
            [
                TarEntry(
                    "root/pyproject.toml",
                    content=b'[project]\nname = "demo"\ndependencies = ["requests==2.32.3"]\n',
                )
            ],
            "PyPI",
            "requests",
            "2.32.3",
            "2.32.4",
            "pyproject.toml",
        )
    if kind == "npm":
        package = json.dumps(
            {"name": "demo", "version": "1.0.0", "dependencies": {"lodash": "1.0.0"}}
        ).encode()
        lock = json.dumps(
            {
                "name": "demo",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo", "version": "1.0.0", "dependencies": {"lodash": "1.0.0"}},
                    "node_modules/lodash": {"version": "1.0.0"},
                },
            }
        ).encode()
        return (
            [
                TarEntry("root/package.json", content=package),
                TarEntry("root/package-lock.json", content=lock),
            ],
            "npm",
            "lodash",
            "1.0.0",
            "1.0.1",
            "package.json",
        )
    return (
        [
            TarEntry(
                "root/go.mod",
                content=(b"module example.test/demo\n\nrequire github.com/gogo/protobuf v1.3.1\n"),
            )
        ],
        "Go",
        "github.com/gogo/protobuf",
        "1.3.1",
        "v1.3.2",
        "go.mod",
    )


@pytest.mark.parametrize("kind", ["requirements", "pyproject", "npm", "go"])
async def test_preview_formats_change_one_token_only_in_memory(tmp_path: Path, kind: str) -> None:
    entries, ecosystem, package, scanner_version, target, preview_path = _case(kind)
    archive = build_tar([TarEntry("root/", kind="dir"), *entries])
    advisory = remediation_advisory(ecosystem, package, target)
    coordinate = ExactPackageCoordinate(ecosystem=ecosystem, name=package, version=scanner_version)
    scanner = FakeScanner(
        {coordinate: (ScannerVulnerability(id=advisory.primary_id, aliases=advisory.aliases),)}
    )
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(
        RepositoryRequest(repository_url="https://github.com/octocat/Hello-World", ref="main")
    )
    configuration = remediation_configuration(preview_enabled=True)
    evidence_config = evidence_configuration()
    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        matches = await AdvisoryMatchService(scanner).match(advisory, inventory)
        evidence = await EvidenceService(evidence_config).collect(acquired, inventory, matches)
        derivation = derive_candidates(advisory, inventory, matches, evidence, configuration)
        path = acquired.root / preview_path
        original = path.read_bytes()
        collected = await PreviewCollector(
            configuration,
            inventory_limits=inventory_limits(),
            evidence_configuration=evidence_config,
        ).collect(acquired, inventory, matches, derivation.candidates)

        assert path.read_bytes() == original
        assert len(collected.previews) == 1
        preview = collected.previews[0]
        assert preview.source_reference.path == preview_path
        assert preview.replacement.original_token in {scanner_version, "v" + scanner_version}
        assert preview.replacement.replacement_token == target
        assert preview.redacted_zero_context_diff is not None
        assert preview.hypothetical_sha256 != preview.original_sha256
        if kind == "npm":
            assert '"version": "1.0.0"' in preview.redacted_zero_context_diff
            assert '"lodash": "1.0.1"' in preview.redacted_zero_context_diff

    assert lease.cleanup_result.verified
    assert not acquired.root.parent.exists()


async def test_preview_digest_drift_is_explicit_and_never_writes(tmp_path: Path) -> None:
    entries, ecosystem, package, scanner_version, target, preview_path = _case("requirements")
    archive = build_tar([TarEntry("root/", kind="dir"), *entries])
    advisory = remediation_advisory(ecosystem, package, target)
    coordinate = ExactPackageCoordinate(ecosystem=ecosystem, name=package, version=scanner_version)
    scanner = FakeScanner({coordinate: (ScannerVulnerability(id=advisory.primary_id),)})
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(RepositoryRequest(repository_url="https://github.com/octocat/Hello-World"))
    configuration = remediation_configuration(preview_enabled=True)
    evidence_config = evidence_configuration()
    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        matches = await AdvisoryMatchService(scanner).match(advisory, inventory)
        evidence = await EvidenceService(evidence_config).collect(acquired, inventory, matches)
        derivation = derive_candidates(advisory, inventory, matches, evidence, configuration)
        changed = b"requests==2.32.3\n# concurrent change\n"
        (acquired.root / preview_path).write_bytes(changed)
        collected = await PreviewCollector(
            configuration,
            inventory_limits=inventory_limits(),
            evidence_configuration=evidence_config,
        ).collect(acquired, inventory, matches, derivation.candidates)

        assert not collected.previews
        assert (acquired.root / preview_path).read_bytes() == changed
        assert "preview_source_digest_mismatch" in {item.value for item in collected.limitations}


async def test_duplicate_manifest_tokens_fail_closed(tmp_path: Path) -> None:
    manifest = (
        b'[project]\nname = "demo"\ndependencies = ["requests==2.32.3", "requests==2.32.3"]\n'
    )
    entries = [TarEntry("root/pyproject.toml", content=manifest)]
    archive = build_tar([TarEntry("root/", kind="dir"), *entries])
    advisory = remediation_advisory("PyPI", "requests", "2.32.4")
    coordinate = ExactPackageCoordinate(ecosystem="PyPI", name="requests", version="2.32.3")
    scanner = FakeScanner({coordinate: (ScannerVulnerability(id=advisory.primary_id),)})
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(RepositoryRequest(repository_url="https://github.com/octocat/Hello-World"))
    configuration = remediation_configuration(preview_enabled=True)
    evidence_config = evidence_configuration()
    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        matches = await AdvisoryMatchService(scanner).match(advisory, inventory)
        evidence = await EvidenceService(evidence_config).collect(acquired, inventory, matches)
        derivation = derive_candidates(advisory, inventory, matches, evidence, configuration)
        collected = await PreviewCollector(
            configuration,
            inventory_limits=inventory_limits(),
            evidence_configuration=evidence_config,
        ).collect(acquired, inventory, matches, derivation.candidates)

        assert not collected.previews
        assert "preview_token_ambiguous" in {item.value for item in collected.limitations}
        assert (acquired.root / "pyproject.toml").read_bytes() == manifest


async def test_preview_redaction_exhaustion_omits_diff_and_never_writes(tmp_path: Path) -> None:
    tokens = " ".join(f"ghp_{index:036d}" for index in range(11))
    manifest = f"requests==2.32.3  # {tokens}\n".encode()
    archive = build_tar(
        [TarEntry("root/", kind="dir"), TarEntry("root/requirements.txt", content=manifest)]
    )
    advisory = remediation_advisory("PyPI", "requests", "2.32.4")
    coordinate = ExactPackageCoordinate(ecosystem="PyPI", name="requests", version="2.32.3")
    scanner = FakeScanner({coordinate: (ScannerVulnerability(id=advisory.primary_id),)})
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(RepositoryRequest(repository_url="https://github.com/octocat/Hello-World"))
    configuration = remediation_configuration(preview_enabled=True)
    evidence_config = evidence_configuration()

    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        matches = await AdvisoryMatchService(scanner).match(advisory, inventory)
        evidence = await EvidenceService(evidence_config).collect(acquired, inventory, matches)
        derivation = derive_candidates(advisory, inventory, matches, evidence, configuration)
        collected = await PreviewCollector(
            configuration,
            inventory_limits=inventory_limits(),
            evidence_configuration=evidence_config,
        ).collect(acquired, inventory, matches, derivation.candidates)

        assert len(collected.previews) == 1
        preview = collected.previews[0]
        assert preview.status is PreviewStatus.DIFF_OMITTED
        assert preview.redacted_zero_context_diff is None
        assert collected.omitted == 1
        assert (
            CandidateClassification.PREVIEW_UNAVAILABLE in collected.candidates[0].classifications
        )
        assert (
            CandidateClassification.PREVIEW_ELIGIBLE not in collected.candidates[0].classifications
        )
        assert (acquired.root / "requirements.txt").read_bytes() == manifest


@pytest.mark.parametrize(
    ("declaration_path", "declaration", "expected_limitation"),
    [
        (None, None, "direct_declaration_unavailable"),
        (
            "root/package.json",
            {"name": "demo", "dependencies": {"lodash": "^1.0.0"}},
            "direct_declaration_unsupported",
        ),
        (
            "root/package.json",
            {"name": "demo", "dependencies": {"lodash": "npm:other@1.0.0"}},
            "direct_declaration_unsupported",
        ),
        (
            "root/package.json",
            {"name": "demo", "dependencies": {"lodash": "1.0.1"}},
            "direct_declaration_version_mismatch",
        ),
        (
            "root/package.json",
            {
                "name": "demo",
                "dependencies": {"lodash": "1.0.0"},
                "devDependencies": {"lodash": "1.0.0"},
            },
            "direct_declaration_ambiguous",
        ),
        (
            "root/other/package.json",
            {"name": "other", "dependencies": {"lodash": "1.0.0"}},
            "direct_declaration_unavailable",
        ),
    ],
    ids=["lock-only", "range", "alias", "mismatch", "duplicate", "cross-root"],
)
async def test_npm_bridge_rejects_non_unique_same_root_exact_declarations(
    tmp_path: Path,
    declaration_path: str | None,
    declaration: dict[str, object] | None,
    expected_limitation: str,
) -> None:
    lock = {
        "name": "demo",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo", "dependencies": {"lodash": "1.0.0"}},
            "node_modules/lodash": {"version": "1.0.0"},
        },
    }
    entries = [
        TarEntry("root/", kind="dir"),
        TarEntry("root/package-lock.json", content=json.dumps(lock).encode()),
    ]
    if declaration_path is not None and declaration is not None:
        if declaration_path.startswith("root/other/"):
            entries.append(TarEntry("root/other/", kind="dir"))
        entries.append(TarEntry(declaration_path, content=json.dumps(declaration).encode()))
    archive = build_tar(entries)
    advisory = remediation_advisory("npm", "lodash", "1.0.1")
    coordinate = ExactPackageCoordinate(ecosystem="npm", name="lodash", version="1.0.0")
    scanner = FakeScanner({coordinate: (ScannerVulnerability(id=advisory.primary_id),)})
    lease = RepositoryIntakeService(
        FakeRepositorySource(archive), repository_limits(tmp_path)
    ).acquire(RepositoryRequest(repository_url="https://github.com/octocat/Hello-World"))
    configuration = remediation_configuration(preview_enabled=True)
    evidence_config = evidence_configuration()

    async with lease as acquired:
        inventory = await DependencyInventoryService(inventory_limits()).build(acquired)
        matches = await AdvisoryMatchService(scanner).match(advisory, inventory)
        evidence = await EvidenceService(evidence_config).collect(acquired, inventory, matches)
        derivation = derive_candidates(advisory, inventory, matches, evidence, configuration)
        collected = await PreviewCollector(
            configuration,
            inventory_limits=inventory_limits(),
            evidence_configuration=evidence_config,
        ).collect(acquired, inventory, matches, derivation.candidates)

        assert not collected.previews
        assert expected_limitation in {item.value for item in collected.limitations}
        assert (acquired.root / "package-lock.json").read_bytes() == json.dumps(lock).encode()
