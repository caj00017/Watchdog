from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from watchdog.domain.inventory import (
    ApplicabilityKind,
    CoverageKind,
    DependencyInventory,
    DependencyRelationship,
    DependencyScope,
    Ecosystem,
    VersionKind,
)
from watchdog.domain.repositories import (
    AcquiredRepository,
    GitHubRepository,
    RepositorySnapshot,
)
from watchdog.inventory.identifiers import normalize_package_name
from watchdog.inventory.limits import InventoryLimits
from watchdog.inventory.service import DependencyInventoryService


def inventory_limits(**overrides: object) -> InventoryLimits:
    values: dict[str, object] = {
        "deadline_seconds": 10.0,
        "max_manifest_files": 200,
        "max_bytes_per_manifest": 5 * 1024 * 1024,
        "max_total_parsed_bytes": 25 * 1024 * 1024,
        "max_components": 50_000,
        "max_edges": 200_000,
        "max_parser_nesting_depth": 64,
        "max_requirements_include_depth": 10,
        "max_warnings": 1_000,
    }
    values.update(overrides)
    return InventoryLimits.model_validate(values)


def acquired_repository(tmp_path: Path, files: dict[str, str]) -> AcquiredRepository:
    root = tmp_path / "source"
    root.mkdir(parents=True)
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return AcquiredRepository(
        root=root,
        snapshot=RepositorySnapshot(
            repository=GitHubRepository(
                owner="example",
                name="fixture",
                canonical_url="https://github.com/example/fixture",
            ),
            requested_ref="main",
            resolved_ref="main",
            commit_sha="a" * 40,
            tree_sha="b" * 40,
            retrieved_at=datetime(2026, 7, 27, tzinfo=UTC),
            archive_sha256="c" * 64,
            archive_bytes=100,
            extracted_bytes=100,
            file_count=len(files),
            symlink_count=0,
        ),
    )


def repository_with_requirements_symlink(tmp_path: Path) -> AcquiredRepository:
    repository = acquired_repository(
        tmp_path,
        {
            "requirements.txt": "-r linked.txt\nroot-package==1.0.0\n",
            "target.txt": "followed-package==9.9.9\n",
        },
    )
    os.symlink(repository.root / "target.txt", repository.root / "linked.txt")
    return repository


async def build_inventory(
    tmp_path: Path,
    files: dict[str, str],
    limits: InventoryLimits | None = None,
) -> DependencyInventory:
    repository = acquired_repository(tmp_path, files)
    return await DependencyInventoryService(limits or inventory_limits()).build(repository)


def test_name_normalization_is_ecosystem_specific() -> None:
    assert normalize_package_name(Ecosystem.PYPI, "Requests_Tool.Belt") == "requests-tool-belt"
    assert normalize_package_name(Ecosystem.NPM, "@Scope/Package") == "@scope/package"
    assert normalize_package_name(Ecosystem.GO, "Example.COM/Upper/Module") == (
        "Example.COM/Upper/Module"
    )


async def test_inventory_ids_are_deterministic_for_the_same_snapshot(tmp_path: Path) -> None:
    first = await build_inventory(tmp_path / "first", {"requirements.txt": "requests==2.32.3\n"})
    second = await build_inventory(tmp_path / "second", {"requirements.txt": "requests==2.32.3\n"})

    assert [item.id for item in first.projects] == [item.id for item in second.projects]
    assert [item.id for item in first.components] == [item.id for item in second.components]
    assert [item.id for item in first.edges] == [item.id for item in second.edges]


async def test_pyproject_preserves_exact_pins_markers_and_scopes(tmp_path: Path) -> None:
    inventory = await build_inventory(
        tmp_path,
        {
            "pyproject.toml": """
[project]
name = "demo"
version = "1.0"
dependencies = ["Requests==2.32.3; python_version < '3.13'", "flask>=3"]

[project.optional-dependencies]
docs = ["sphinx===8.0.0"]

[dependency-groups]
dev = ["pytest==8.3.4"]
"""
        },
    )

    by_name = {component.normalized_name: component for component in inventory.components}
    requests = by_name["requests"]
    assert requests.version == "2.32.3"
    assert requests.version_kind == VersionKind.EXACT
    assert requests.scanner_eligible
    assert requests.relationship == DependencyRelationship.DIRECT
    assert requests.applicability.kind == ApplicabilityKind.CONDITIONAL
    assert requests.applicability.marker == 'python_version < "3.13"'
    assert by_name["flask"].version_kind == VersionKind.CONSTRAINT
    assert not by_name["flask"].scanner_eligible
    assert by_name["sphinx"].scopes == (DependencyScope.OPTIONAL,)
    assert by_name["pytest"].scopes == (DependencyScope.DEVELOPMENT,)
    assert inventory.coverage.kind == CoverageKind.COMPLETE
    assert all(
        reference.file_sha256
        for item in inventory.components
        for reference in item.source_references
    )


async def test_requirements_includes_constraints_cycles_and_escape_are_visible(
    tmp_path: Path,
) -> None:
    inventory = await build_inventory(
        tmp_path,
        {
            "requirements.txt": """
-r requirements/runtime.in
-c constraints.txt
-r ../outside.txt
urllib3==2.2.3
""",
            "requirements/runtime.in": "requests==2.32.3\n-r runtime.in\n",
            "constraints.txt": "urllib3==1.0\n",
        },
    )

    coordinates = {(item.normalized_name, item.version) for item in inventory.components}
    assert coordinates == {("requests", "2.32.3"), ("urllib3", "2.2.3")}
    assert all(item.relationship == DependencyRelationship.UNKNOWN for item in inventory.components)
    codes = {warning.code for warning in inventory.warnings}
    assert "requirements_include_cycle" in codes
    assert "requirements_include_escape" in codes
    assert inventory.partial


async def test_requirements_continuations_hashes_and_inline_comments(tmp_path: Path) -> None:
    inventory = await build_inventory(
        tmp_path,
        {
            "requirements-prod.txt": """
requests==2.32.3 \\
  --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \\
  --hash sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
urllib3==2.2.3  # pinned runtime
"""
        },
    )

    assert {(item.normalized_name, item.version) for item in inventory.components} == {
        ("requests", "2.32.3"),
        ("urllib3", "2.2.3"),
    }
    assert all(item.scanner_eligible for item in inventory.components)


async def test_requirements_include_does_not_follow_symlinks(tmp_path: Path) -> None:
    repository = repository_with_requirements_symlink(tmp_path)

    inventory = await DependencyInventoryService(inventory_limits()).build(repository)

    assert {item.normalized_name for item in inventory.components} == {"root-package"}
    assert "requirements_include_symlink" in {warning.code for warning in inventory.warnings}
    assert inventory.partial


async def test_uv_lock_maps_registry_packages_workspace_and_edges(tmp_path: Path) -> None:
    inventory = await build_inventory(
        tmp_path,
        {
            "uv.lock": """
version = 1

[[package]]
name = "workspace-app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "httpx", version = "0.27.2", marker = "sys_platform == 'linux'" }]

[[package]]
name = "httpx"
version = "0.27.2"
source = { registry = "https://pypi.org/simple" }
resolution-markers = ["python_full_version >= '3.12'"]
"""
        },
    )

    components = {item.normalized_name: item for item in inventory.components}
    assert not components["workspace-app"].scanner_eligible
    assert components["httpx"].scanner_eligible
    assert components["httpx"].relationship == DependencyRelationship.DIRECT
    assert components["httpx"].applicability.kind == ApplicabilityKind.CONDITIONAL
    assert len(inventory.edges) == 1
    assert inventory.edges[0].relationship == DependencyRelationship.DIRECT


async def test_unknown_uv_schema_infers_nothing_and_marks_partial(tmp_path: Path) -> None:
    inventory = await build_inventory(tmp_path, {"uv.lock": "version = 2\npackage = []\n"})

    assert not inventory.components
    assert inventory.partial
    assert inventory.scanned_files[0].status.value == "unsupported"
    assert {warning.code for warning in inventory.warnings} >= {"uv_lock_schema_unsupported"}


async def test_npm_lock_builds_exact_nested_graph_and_conditions(tmp_path: Path) -> None:
    inventory = await build_inventory(
        tmp_path,
        {
            "package.json": '{"name":"app","dependencies":{"a":"^1"}}',
            "package-lock.json": """
{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name":"app","dependencies":{"a":"^1"}},
    "node_modules/a": {"name":"a","version":"1.0.0","dependencies":{"b":"2"}},
    "node_modules/a/node_modules/b": {
      "name":"b","version":"2.0.0","os":["linux"],"cpu":["x64"]
    }
  }
}
""",
        },
    )

    exact = [item for item in inventory.components if item.version_kind == VersionKind.EXACT]
    by_name = {item.normalized_name: item for item in exact}
    assert by_name["a"].relationship == DependencyRelationship.DIRECT
    assert by_name["b"].relationship == DependencyRelationship.TRANSITIVE
    assert by_name["b"].applicability.os == ("linux",)
    assert by_name["b"].applicability.cpu == ("x64",)
    assert len([edge for edge in inventory.edges if edge.from_component_id]) == 1


async def test_npm_workspaces_are_separate_projects_and_competing_lock_warns(
    tmp_path: Path,
) -> None:
    inventory = await build_inventory(
        tmp_path,
        {
            "package-lock.json": """
{"lockfileVersion":2,"packages":{
  "":{"name":"root","workspaces":["packages/a"]},
  "packages/a":{"name":"workspace-a","version":"1.0.0","dependencies":{"left-pad":"1"}},
  "node_modules/left-pad":{"version":"1.3.0"}
}}
""",
            "yarn.lock": "# unsupported competing lock\n",
        },
    )

    roots = {project.root for project in inventory.projects}
    assert roots == {".", "packages/a"}
    assert "npm_competing_lockfiles" in {warning.code for warning in inventory.warnings}
    assert inventory.partial


async def test_go_mod_preserves_relationships_replacements_exclusions_and_tools(
    tmp_path: Path,
) -> None:
    inventory = await build_inventory(
        tmp_path,
        {
            "go.mod": """
module example.com/app
go 1.24
require (
  github.com/gogo/protobuf v1.3.1
  example.com/indirect v2.0.0 // indirect
  example.com/local v1.0.0
)
replace github.com/gogo/protobuf => example.com/fork v1.3.2
replace example.com/local => ../local
exclude github.com/gogo/protobuf v1.3.1
tool example.com/tool/cmd
""",
            "go.sum": "github.com/gogo/protobuf v1.3.1 h1:fixture\n",
        },
    )

    by_name = {item.name: item for item in inventory.components}
    replaced = by_name["github.com/gogo/protobuf"]
    assert replaced.version == "v1.3.2"
    assert replaced.resolved_name == "example.com/fork"
    assert by_name["example.com/indirect"].relationship == DependencyRelationship.TRANSITIVE
    assert by_name["example.com/local"].version_kind == VersionKind.UNKNOWN
    assert not by_name["example.com/local"].scanner_eligible
    assert by_name["example.com/tool/cmd"].scopes == (DependencyScope.TOOL,)
    assert {warning.code for warning in inventory.warnings} >= {
        "go_local_replacement",
        "go_required_version_excluded",
    }


async def test_discovery_skips_symlinks_vendor_and_reports_coverage(tmp_path: Path) -> None:
    repository = acquired_repository(
        tmp_path, {"vendor/package.json": '{"dependencies":{"x":"1"}}'}
    )
    outside = tmp_path / "outside-package.json"
    outside.write_text('{"dependencies":{"secret":"1"}}', encoding="utf-8")
    os.symlink(outside, repository.root / "package.json")

    inventory = await DependencyInventoryService(inventory_limits()).build(repository)

    assert not inventory.components
    codes = {warning.code for warning in inventory.warnings}
    assert "excluded_dependency_tree" in codes
    assert "symlinked_manifest_skipped" in codes
    assert inventory.coverage.kind == CoverageKind.NO_SUPPORTED_MANIFEST


async def test_empty_malformed_unsupported_and_component_limit_states(tmp_path: Path) -> None:
    empty = await build_inventory(tmp_path / "empty", {"package.json": "{}"})
    assert empty.coverage.kind == CoverageKind.EMPTY_SUPPORTED_MANIFEST
    assert not empty.partial

    malformed = await build_inventory(tmp_path / "malformed", {"package.json": "{"})
    assert malformed.coverage.kind == CoverageKind.ALL_SUPPORTED_MANIFESTS_MALFORMED
    assert malformed.partial

    unsupported = await build_inventory(tmp_path / "unsupported", {"go.work": "go 1.24\n"})
    assert unsupported.coverage.kind == CoverageKind.UNSUPPORTED_MANIFESTS_ONLY
    assert unsupported.partial

    limited = await build_inventory(
        tmp_path / "limited",
        {"requirements.txt": "a==1\nb==2\n"},
        inventory_limits(max_components=1),
    )
    assert len(limited.components) == 1
    assert "component_limit_exceeded" in {warning.code for warning in limited.warnings}
    assert limited.partial
