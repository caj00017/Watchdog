from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any

from watchdog.domain.inventory import (
    Applicability,
    ApplicabilityKind,
    DependencyComponent,
    DependencyRelationship,
    DependencyScope,
    Ecosystem,
    InventoryProject,
    SelectorKind,
    VersionKind,
)
from watchdog.inventory.common import (
    InventoryBuilder,
    ParseFailure,
    project_root_for,
    validate_nesting,
)
from watchdog.inventory.identifiers import normalize_package_name


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def load_json(builder: InventoryBuilder, data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8"),
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
        validate_nesting(value, builder.limits.max_parser_nesting_depth)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, ParseFailure) as exc:
        raise ParseFailure(str(exc)) from exc
    if not isinstance(value, dict):
        raise ParseFailure("JSON manifest root must be an object")
    return value


def _pointer_part(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _condition(entry: dict[str, Any]) -> Applicability:
    os_values = entry.get("os", [])
    cpu_values = entry.get("cpu", [])
    if not isinstance(os_values, list) or not all(isinstance(item, str) for item in os_values):
        raise ParseFailure("npm os restrictions must be arrays of strings")
    if not isinstance(cpu_values, list) or not all(isinstance(item, str) for item in cpu_values):
        raise ParseFailure("npm cpu restrictions must be arrays of strings")
    if os_values or cpu_values:
        return Applicability(
            kind=ApplicabilityKind.CONDITIONAL,
            os=tuple(os_values),
            cpu=tuple(cpu_values),
        )
    return Applicability()


def _lock_scopes(entry: dict[str, Any]) -> tuple[DependencyScope, ...]:
    scopes: list[DependencyScope] = []
    boolean_scopes = (
        ("dev", DependencyScope.DEVELOPMENT),
        ("optional", DependencyScope.OPTIONAL),
        ("peer", DependencyScope.PEER),
    )
    for field, scope in boolean_scopes:
        value = entry.get(field, False)
        if not isinstance(value, bool):
            raise ParseFailure(f"npm package {field} flag must be a boolean")
        if value:
            scopes.append(scope)
    return tuple(scopes) or (DependencyScope.RUNTIME,)


_DECLARATION_SCOPES = (
    ("dependencies", DependencyScope.RUNTIME),
    ("devDependencies", DependencyScope.DEVELOPMENT),
    ("optionalDependencies", DependencyScope.OPTIONAL),
    ("peerDependencies", DependencyScope.PEER),
)


def _declarations(entry: dict[str, Any]) -> list[tuple[str, str, DependencyScope, str]]:
    result: list[tuple[str, str, DependencyScope, str]] = []
    for field, scope in _DECLARATION_SCOPES:
        values = entry.get(field, {})
        if not isinstance(values, dict):
            raise ParseFailure(f"npm {field} must be an object")
        for name in sorted(values):
            version = values[name]
            if not isinstance(name, str) or not isinstance(version, str):
                raise ParseFailure(f"npm {field} entries must map strings to strings")
            result.append((name, version, scope, field))
    bundled = entry.get("bundleDependencies", entry.get("bundledDependencies", []))
    if isinstance(bundled, bool):
        bundled = []
    if not isinstance(bundled, list) or not all(isinstance(item, str) for item in bundled):
        raise ParseFailure("npm bundled dependencies must be an array of strings")
    known = {name for name, _version, _scope, _field in result}
    for name in bundled:
        if name not in known:
            result.append((name, "", DependencyScope.RUNTIME, "bundledDependencies"))
    return result


def parse_package_json(
    builder: InventoryBuilder,
    relative: str,
    data: bytes,
    digest: str,
) -> int:
    document = load_json(builder, data)
    name = document.get("name")
    version = document.get("version")
    if name is not None and not isinstance(name, str):
        raise ParseFailure("package.json name must be a string")
    if version is not None and not isinstance(version, str):
        raise ParseFailure("package.json version must be a string")
    source = builder.source(relative, digest, SelectorKind.JSON_POINTER, "")
    project = builder.add_project(
        root=project_root_for(relative),
        ecosystem=Ecosystem.NPM,
        source=source,
        name=name,
        version=version,
    )
    applicability = _condition(document)
    added = 0
    for dependency_name, constraint, scope, field in _declarations(document):
        selector = f"/{field}/{_pointer_part(dependency_name)}"
        dependency_source = builder.source(relative, digest, SelectorKind.JSON_POINTER, selector)
        normalized = normalize_package_name(Ecosystem.NPM, dependency_name)
        component = builder.add_component(
            project=project,
            name=dependency_name,
            normalized_name=normalized,
            version=constraint or None,
            version_kind=VersionKind.CONSTRAINT if constraint else VersionKind.UNKNOWN,
            relationship=DependencyRelationship.DIRECT,
            scopes=(scope,),
            applicability=applicability,
            source=dependency_source,
            scanner_eligible=False,
            source_type="declaration",
        )
        builder.add_edge(
            project=project,
            parent=None,
            child=component,
            relationship=DependencyRelationship.DIRECT,
            scopes=(scope,),
            applicability=applicability,
            source=dependency_source,
        )
        added += 1
    return added


def _package_name(location: str, entry: dict[str, Any]) -> str | None:
    explicit = entry.get("name")
    if explicit is not None:
        if not isinstance(explicit, str) or not explicit:
            raise ParseFailure("npm package name must be a non-empty string")
        return explicit
    marker = "node_modules/"
    if marker not in location:
        return None
    suffix = location.rsplit(marker, 1)[1]
    parts = PurePosixPath(suffix).parts
    if not parts:
        return None
    if parts[0].startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def _resolve_location(
    packages: dict[str, Any],
    from_location: str,
    dependency_name: str,
    local_names: dict[str, str],
) -> str | None:
    current = PurePosixPath(from_location) if from_location else PurePosixPath(".")
    while True:
        prefix = "" if current.as_posix() == "." else f"{current.as_posix()}/"
        candidate = f"{prefix}node_modules/{dependency_name}"
        if candidate in packages:
            link_entry = packages[candidate]
            if isinstance(link_entry, dict) and link_entry.get("link") is True:
                return local_names.get(dependency_name, candidate)
            return candidate
        if current.as_posix() == ".":
            break
        current = current.parent
    return local_names.get(dependency_name)


def parse_package_lock(
    builder: InventoryBuilder,
    relative: str,
    data: bytes,
    digest: str,
) -> int:
    document = load_json(builder, data)
    lock_version = document.get("lockfileVersion")
    if not isinstance(lock_version, int):
        raise ParseFailure("package-lock lockfileVersion must be an integer")
    if lock_version not in {2, 3}:
        builder.warning(
            "npm_lock_version_unsupported",
            f"package-lock version {lock_version} is unsupported; no exact graph was inferred.",
            path=relative,
        )
        return -1
    packages = document.get("packages")
    if not isinstance(packages, dict) or not all(
        isinstance(location, str) and isinstance(entry, dict)
        for location, entry in packages.items()
    ):
        raise ParseFailure("package-lock packages must be an object of package records")
    lock_root = project_root_for(relative)
    local_locations = sorted(
        location for location in packages if "node_modules" not in PurePosixPath(location).parts
    )
    projects: dict[str, InventoryProject] = {}
    local_names: dict[str, str] = {}
    for location in local_locations:
        entry = packages[location]
        assert isinstance(entry, dict)
        project_path = PurePosixPath(lock_root)
        if location:
            project_path = project_path / PurePosixPath(location)
        project_root = project_path.as_posix()
        if project_root == ".":
            project_root = "."
        selector = f"/packages/{_pointer_part(location)}"
        source = builder.source(relative, digest, SelectorKind.JSON_POINTER, selector)
        project_name = entry.get("name")
        project_version = entry.get("version")
        if project_name is not None and not isinstance(project_name, str):
            raise ParseFailure("package-lock project name must be a string")
        if project_version is not None and not isinstance(project_version, str):
            raise ParseFailure("package-lock project version must be a string")
        projects[location] = builder.add_project(
            root=project_root,
            ecosystem=Ecosystem.NPM,
            source=source,
            name=project_name,
            version=project_version,
        )
        if project_name:
            local_names[normalize_package_name(Ecosystem.NPM, project_name)] = location
    if "" not in projects:
        source = builder.source(relative, digest, SelectorKind.JSON_POINTER, "/packages")
        projects[""] = builder.add_project(
            root=lock_root,
            ecosystem=Ecosystem.NPM,
            source=source,
        )

    nodes: dict[str, DependencyComponent] = {}
    added = 0
    root_project = projects[""]
    for location in sorted(packages):
        entry = packages[location]
        assert isinstance(entry, dict)
        package_name = _package_name(location, entry)
        if package_name is None:
            continue
        normalized = normalize_package_name(Ecosystem.NPM, package_name)
        version = entry.get("version")
        if version is not None and not isinstance(version, str):
            raise ParseFailure("npm package version must be a string")
        selector = f"/packages/{_pointer_part(location)}"
        source = builder.source(relative, digest, SelectorKind.JSON_POINTER, selector)
        application = _condition(entry)
        link = entry.get("link") is True
        if not version:
            builder.warning(
                "npm_package_version_unknown",
                "A package-lock package had no exact version and is scanner-ineligible.",
                path=relative,
                selector=source.selector,
            )
        local_package = location in projects
        component = builder.add_component(
            project=projects.get(location, root_project),
            name=package_name,
            normalized_name=normalized,
            version=version or None,
            version_kind=VersionKind.EXACT if version else VersionKind.UNKNOWN,
            relationship=DependencyRelationship.TRANSITIVE,
            scopes=_lock_scopes(entry),
            applicability=application,
            source=source,
            scanner_eligible=bool(version and not link and not local_package),
            source_type=(
                "workspace-link" if link else "workspace" if local_package else "registry"
            ),
        )
        nodes[location] = component
        added += 1

    for location in sorted(packages):
        entry = packages[location]
        assert isinstance(entry, dict)
        parent = None if location in projects else nodes.get(location)
        project = projects.get(location, root_project)
        for dependency_name, _constraint, scope, field in _declarations(entry):
            normalized_dependency = normalize_package_name(Ecosystem.NPM, dependency_name)
            resolved = _resolve_location(packages, location, normalized_dependency, local_names)
            child = nodes.get(resolved) if resolved is not None else None
            selector = (
                f"/packages/{_pointer_part(location)}/{field}/{_pointer_part(dependency_name)}"
            )
            source = builder.source(relative, digest, SelectorKind.JSON_POINTER, selector)
            if child is None:
                builder.warning(
                    "npm_dependency_unresolved",
                    "An npm dependency edge could not be resolved with ancestor "
                    "node_modules lookup.",
                    path=relative,
                    selector=source.selector,
                )
                continue
            relationship = (
                DependencyRelationship.DIRECT
                if location in projects
                else DependencyRelationship.TRANSITIVE
            )
            if (
                relationship == DependencyRelationship.DIRECT
                and child.relationship != relationship
                and resolved is not None
            ):
                child = child.model_copy(
                    update={
                        "relationship": DependencyRelationship.DIRECT,
                        "scopes": tuple(dict.fromkeys((*child.scopes, scope))),
                    }
                )
                nodes[resolved] = child
                builder.components[child.id] = child
            builder.add_edge(
                project=project,
                parent=parent,
                child=child,
                relationship=relationship,
                scopes=(scope,),
                applicability=child.applicability,
                source=source,
            )
    return added
