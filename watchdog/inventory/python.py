from __future__ import annotations

import re
import tomllib
from pathlib import Path, PurePosixPath

from packaging.requirements import InvalidRequirement, Requirement

from watchdog.domain.inventory import (
    Applicability,
    ApplicabilityKind,
    DependencyComponent,
    DependencyRelationship,
    DependencyScope,
    Ecosystem,
    InventoryProject,
    ScannedFileStatus,
    SelectorKind,
    VersionKind,
)
from watchdog.inventory.common import (
    InventoryBuilder,
    ParseFailure,
    project_root_for,
    repository_path,
    validate_nesting,
)
from watchdog.inventory.identifiers import normalize_package_name

_INCLUDE = re.compile(r"^(?:-r|--requirement)(?:\s+|=)(.+)$")
_CONSTRAINT = re.compile(r"^(?:-c|--constraint)(?:\s+|=)(.+)$")
_HASH_OPTION = re.compile(r"\s+--hash(?:=|\s+)\S+")


def _requirement_version(requirement: Requirement) -> tuple[str | None, VersionKind]:
    specifiers = tuple(requirement.specifier)
    if (
        len(specifiers) == 1
        and specifiers[0].operator in {"==", "==="}
        and "*" not in specifiers[0].version
    ):
        return specifiers[0].version, VersionKind.EXACT
    if specifiers or requirement.url:
        return str(requirement.specifier) or requirement.url, VersionKind.CONSTRAINT
    return None, VersionKind.UNKNOWN


def _add_requirement(
    builder: InventoryBuilder,
    *,
    raw: str,
    path: str,
    digest: str,
    selector_kind: SelectorKind,
    selector: str,
    project_root: str,
    relationship: DependencyRelationship,
    scope: DependencyScope,
    editable: bool = False,
) -> bool:
    try:
        requirement = Requirement(raw)
    except InvalidRequirement:
        builder.warning(
            "python_requirement_malformed",
            "A Python requirement could not be parsed and was skipped.",
            path=path,
            selector=builder.source(path, digest, selector_kind, selector).selector,
        )
        return False
    applicability = (
        Applicability(kind=ApplicabilityKind.CONDITIONAL, marker=str(requirement.marker))
        if requirement.marker is not None
        else Applicability()
    )
    version, version_kind = _requirement_version(requirement)
    source = builder.source(path, digest, selector_kind, selector)
    project = builder.add_project(root=project_root, ecosystem=Ecosystem.PYPI, source=source)
    normalized = normalize_package_name(Ecosystem.PYPI, requirement.name)
    scanner_eligible = version_kind == VersionKind.EXACT and not requirement.url and not editable
    component = builder.add_component(
        project=project,
        name=requirement.name,
        normalized_name=normalized,
        version=version,
        version_kind=version_kind,
        relationship=relationship,
        scopes=(scope,),
        applicability=applicability,
        source=source,
        scanner_eligible=scanner_eligible,
        source_type="editable" if editable else ("url" if requirement.url else "registry"),
    )
    builder.add_edge(
        project=project,
        parent=None,
        child=component,
        relationship=relationship,
        scopes=(scope,),
        applicability=applicability,
        source=source,
    )
    return True


def parse_pyproject(
    builder: InventoryBuilder,
    path: Path,
    relative: str,
    data: bytes,
    digest: str,
) -> int:
    try:
        document = tomllib.loads(data.decode("utf-8"))
        validate_nesting(document, builder.limits.max_parser_nesting_depth)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ParseFailure) as exc:
        raise ParseFailure(str(exc)) from exc
    project_table = document.get("project", {})
    if not isinstance(project_table, dict):
        raise ParseFailure("project must be a TOML table")
    root = project_root_for(relative)
    source = builder.source(relative, digest, SelectorKind.TOML, "project")
    project_name = project_table.get("name")
    project_version = project_table.get("version")
    if project_name is not None and not isinstance(project_name, str):
        raise ParseFailure("project.name must be a string")
    if project_version is not None and not isinstance(project_version, str):
        raise ParseFailure("project.version must be a string")
    builder.add_project(
        root=root,
        ecosystem=Ecosystem.PYPI,
        source=source,
        name=project_name,
        version=project_version,
    )
    added = 0
    dependencies = project_table.get("dependencies", [])
    if not isinstance(dependencies, list) or not all(
        isinstance(item, str) for item in dependencies
    ):
        raise ParseFailure("project.dependencies must be an array of strings")
    for index, requirement in enumerate(dependencies):
        builder.check_active()
        added += _add_requirement(
            builder,
            raw=requirement,
            path=relative,
            digest=digest,
            selector_kind=SelectorKind.TOML,
            selector=f"project.dependencies[{index}]",
            project_root=root,
            relationship=DependencyRelationship.DIRECT,
            scope=DependencyScope.RUNTIME,
        )
    optional = project_table.get("optional-dependencies", {})
    if not isinstance(optional, dict):
        raise ParseFailure("project.optional-dependencies must be a table")
    for group in sorted(optional):
        values = optional[group]
        if (
            not isinstance(group, str)
            or not isinstance(values, list)
            or not all(isinstance(item, str) for item in values)
        ):
            raise ParseFailure("optional dependency groups must contain arrays of strings")
        for index, requirement in enumerate(values):
            added += _add_requirement(
                builder,
                raw=requirement,
                path=relative,
                digest=digest,
                selector_kind=SelectorKind.TOML,
                selector=f"project.optional-dependencies.{group}[{index}]",
                project_root=root,
                relationship=DependencyRelationship.DIRECT,
                scope=DependencyScope.OPTIONAL,
            )
    groups = document.get("dependency-groups", {})
    if not isinstance(groups, dict):
        raise ParseFailure("dependency-groups must be a table")
    for group in sorted(groups):
        values = groups[group]
        if not isinstance(group, str) or not isinstance(values, list):
            raise ParseFailure("dependency groups must be arrays")
        for index, entry in enumerate(values):
            if isinstance(entry, str):
                added += _add_requirement(
                    builder,
                    raw=entry,
                    path=relative,
                    digest=digest,
                    selector_kind=SelectorKind.TOML,
                    selector=f"dependency-groups.{group}[{index}]",
                    project_root=root,
                    relationship=DependencyRelationship.DIRECT,
                    scope=DependencyScope.DEVELOPMENT,
                )
            elif not (
                isinstance(entry, dict)
                and set(entry) == {"include-group"}
                and isinstance(entry["include-group"], str)
            ):
                builder.warning(
                    "python_dependency_group_entry_unsupported",
                    "An unsupported dependency-group entry was not inferred.",
                    path=relative,
                    selector=builder.source(
                        relative,
                        digest,
                        SelectorKind.TOML,
                        f"dependency-groups.{group}[{index}]",
                    ).selector,
                )
    return added


def _requirements_target(
    builder: InventoryBuilder,
    *,
    including: Path,
    raw_target: str,
    relative: str,
    line_number: int,
) -> Path | None:
    value = raw_target.strip()
    selector = builder.source(relative, "0" * 64, SelectorKind.LINE, f"line:{line_number}").selector
    if (
        not value
        or "://" in value
        or "\\" in value
        or value.startswith("/")
        or re.match(r"^[A-Za-z]:", value)
    ):
        builder.warning(
            "requirements_include_rejected",
            "A requirements include was absolute, a URL, or empty and was rejected.",
            path=relative,
            selector=selector,
        )
        return None
    candidate = including.parent.joinpath(*PurePosixPath(value).parts)
    try:
        candidate.relative_to(builder.root)
    except ValueError:
        builder.warning(
            "requirements_include_escape",
            "A requirements include escaped the acquired repository root and was rejected.",
            path=relative,
            selector=selector,
        )
        return None
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(builder.root.resolve())
    except ValueError:
        builder.warning(
            "requirements_include_escape",
            "A requirements include escaped the acquired repository root and was rejected.",
            path=relative,
            selector=selector,
        )
        return None
    current = candidate
    while current != builder.root:
        if current.is_symlink():
            builder.warning(
                "requirements_include_symlink",
                "A requirements include containing a symlink was rejected.",
                path=relative,
                selector=selector,
            )
            return None
        current = current.parent
    return resolved


def _logical_requirement_lines(text: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    pending = ""
    start_line = 1
    for line_number, original in enumerate(text.splitlines(), start=1):
        stripped = original.rstrip()
        if not pending:
            start_line = line_number
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        result.append((start_line, pending + stripped))
        pending = ""
    if pending:
        result.append((start_line, pending))
    return result


def parse_requirements_tree(
    builder: InventoryBuilder,
    path: Path,
    *,
    depth: int = 0,
    constraints: bool = False,
    stack: tuple[Path, ...] = (),
) -> int:
    builder.check_active()
    relative = repository_path(builder.root, path)
    if depth > builder.limits.max_requirements_include_depth:
        builder.warning(
            "requirements_include_depth_exceeded",
            "The requirements include-depth limit was exceeded.",
            path=relative,
        )
        return 0
    if path in stack:
        builder.warning(
            "requirements_include_cycle",
            "A cyclic requirements include was rejected.",
            path=relative,
        )
        return 0
    if not path.exists():
        builder.warning(
            "requirements_include_missing",
            "A local requirements include did not exist.",
            path=relative,
        )
        return 0
    read = builder.read_file(path, relative)
    if read is None:
        return 0
    data, digest = read
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        builder.malformed_manifests += 1
        builder.add_scanned_file(
            path=relative,
            digest=digest,
            byte_count=len(data),
            kind="requirements",
            status=ScannedFileStatus.MALFORMED,
            parser="python-requirements",
        )
        builder.warning(
            "manifest_invalid_utf8",
            "A requirements file was not valid UTF-8 and was skipped.",
            path=relative,
        )
        return 0
    added = 0
    project_root = project_root_for(relative)
    for line_number, original in _logical_requirement_lines(text):
        builder.check_active()
        line = original.strip()
        if not line or line.startswith("#"):
            continue
        include = _INCLUDE.match(line)
        constraint = _CONSTRAINT.match(line)
        if include or constraint:
            match = include or constraint
            assert match is not None
            target = _requirements_target(
                builder,
                including=path,
                raw_target=match.group(1),
                relative=relative,
                line_number=line_number,
            )
            if target is not None:
                added += parse_requirements_tree(
                    builder,
                    target,
                    depth=depth + 1,
                    constraints=constraints or constraint is not None,
                    stack=(*stack, path),
                )
            continue
        if constraints:
            continue
        editable = False
        if line.startswith("-e ") or line.startswith("--editable "):
            editable = True
            line = line.split(maxsplit=1)[1]
        if line.startswith("-"):
            builder.warning(
                "requirements_option_unsupported",
                "A requirements option was preserved only as a coverage warning.",
                path=relative,
                selector=builder.source(
                    relative, digest, SelectorKind.LINE, f"line:{line_number}"
                ).selector,
            )
            continue
        line = _HASH_OPTION.sub("", line).strip()
        line = re.split(r"\s+#", line, maxsplit=1)[0].rstrip()
        if not line:
            continue
        added += _add_requirement(
            builder,
            raw=line,
            path=relative,
            digest=digest,
            selector_kind=SelectorKind.LINE,
            selector=f"line:{line_number}",
            project_root=project_root,
            relationship=DependencyRelationship.UNKNOWN,
            scope=DependencyScope.RUNTIME,
            editable=editable,
        )
    builder.add_scanned_file(
        path=relative,
        digest=digest,
        byte_count=len(data),
        kind="requirements-constraint" if constraints else "requirements",
        status=ScannedFileStatus.VALID if added else ScannedFileStatus.EMPTY,
        parser="python-requirements",
    )
    return added


def _uv_source_type(source: object) -> tuple[str, bool]:
    if not isinstance(source, dict):
        raise ParseFailure("uv package source must be a table")
    known = ("registry", "editable", "virtual", "directory", "git", "url", "path")
    present = [key for key in known if key in source]
    if len(present) != 1 or not isinstance(source[present[0]], str):
        raise ParseFailure("uv package source must contain one known string source")
    source_type = present[0]
    return source_type, source_type == "registry"


def parse_uv_lock(
    builder: InventoryBuilder,
    relative: str,
    data: bytes,
    digest: str,
) -> int:
    try:
        document = tomllib.loads(data.decode("utf-8"))
        validate_nesting(document, builder.limits.max_parser_nesting_depth)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ParseFailure) as exc:
        raise ParseFailure(str(exc)) from exc
    schema_version = document.get("version")
    if not isinstance(schema_version, int):
        raise ParseFailure("uv.lock version must be an integer")
    if schema_version != 1:
        builder.warning(
            "uv_lock_schema_unsupported",
            f"uv.lock schema version {schema_version} is unsupported; no components were inferred.",
            path=relative,
        )
        return -1
    packages = document.get("package", [])
    if not isinstance(packages, list):
        raise ParseFailure("uv.lock package must be an array of tables")
    lock_root = project_root_for(relative)
    package_components: dict[tuple[str, str | None], list[DependencyComponent]] = {}
    package_rows: list[tuple[dict[str, object], InventoryProject, DependencyComponent]] = []
    added = 0
    for index, raw_package in enumerate(packages):
        builder.check_active()
        if not isinstance(raw_package, dict):
            raise ParseFailure("uv package entries must be tables")
        name = raw_package.get("name")
        version = raw_package.get("version")
        if not isinstance(name, str) or not name:
            raise ParseFailure("uv package name must be a non-empty string")
        if version is not None and (not isinstance(version, str) or not version):
            raise ParseFailure("uv package version must be a non-empty string when present")
        source_type, registry = _uv_source_type(raw_package.get("source"))
        marker = raw_package.get("resolution-markers", raw_package.get("marker"))
        marker_expressions: tuple[str, ...] = ()
        if marker is not None:
            if isinstance(marker, str):
                marker_expressions = (marker,)
            elif isinstance(marker, list) and all(isinstance(item, str) for item in marker):
                marker_expressions = tuple(marker)
            else:
                raise ParseFailure("uv resolution markers must be strings")
        applicability = (
            Applicability(
                kind=ApplicabilityKind.CONDITIONAL,
                expressions=marker_expressions,
            )
            if marker_expressions
            else Applicability()
        )
        selector = f"package[name={name!r},version={version!r},index={index}]"
        source = builder.source(relative, digest, SelectorKind.TOML, selector)
        project_root = lock_root
        source_value = raw_package.get("source")
        assert isinstance(source_value, dict)
        editable = source_value.get("editable")
        if source_type == "editable" and isinstance(editable, str):
            candidate_root = PurePosixPath(lock_root) / editable
            project_root = candidate_root.as_posix()
            if project_root in {"", "./"}:
                project_root = "."
        project = builder.add_project(
            root=project_root,
            ecosystem=Ecosystem.PYPI,
            source=source,
            name=name if source_type in {"editable", "virtual", "directory", "path"} else None,
            version=version
            if source_type in {"editable", "virtual", "directory", "path"}
            else None,
        )
        normalized = normalize_package_name(Ecosystem.PYPI, name)
        component = builder.add_component(
            project=project,
            name=name,
            normalized_name=normalized,
            version=version,
            version_kind=VersionKind.EXACT if version else VersionKind.UNKNOWN,
            relationship=DependencyRelationship.UNKNOWN,
            scopes=(DependencyScope.UNKNOWN,),
            applicability=applicability,
            source=source,
            scanner_eligible=bool(registry and version),
            source_type=source_type,
        )
        package_components.setdefault((normalized, version), []).append(component)
        package_rows.append((raw_package, project, component))
        added += 1
    for raw_package, project_value, parent_value in package_rows:
        dependencies = raw_package.get("dependencies", [])
        if not isinstance(dependencies, list):
            raise ParseFailure("uv package dependencies must be an array")
        for dependency_index, dependency in enumerate(dependencies):
            if isinstance(dependency, str):
                dependency_name = dependency
                dependency_version = None
                dependency_marker = None
            elif isinstance(dependency, dict):
                raw_dependency_name = dependency.get("name")
                raw_dependency_version = dependency.get("version")
                raw_dependency_marker = dependency.get("marker")
                if not isinstance(raw_dependency_name, str):
                    raise ParseFailure("uv dependency name must be a string")
                if raw_dependency_version is not None and not isinstance(
                    raw_dependency_version, str
                ):
                    raise ParseFailure("uv dependency version must be a string")
                if raw_dependency_marker is not None and not isinstance(raw_dependency_marker, str):
                    raise ParseFailure("uv dependency marker must be a string")
                dependency_name = raw_dependency_name
                dependency_version = raw_dependency_version
                dependency_marker = raw_dependency_marker
            else:
                raise ParseFailure("uv dependency must be a string or table")
            normalized_dependency = normalize_package_name(Ecosystem.PYPI, dependency_name)
            possible = package_components.get((normalized_dependency, dependency_version), [])
            if dependency_version is None:
                possible = [
                    item
                    for (candidate_name, _candidate_version), values in package_components.items()
                    if candidate_name == normalized_dependency
                    for item in values
                ]
            if len(possible) != 1:
                builder.warning(
                    "uv_dependency_unresolved",
                    "A uv dependency edge could not be resolved to one package variant.",
                    path=relative,
                    selector=builder.source(
                        relative,
                        digest,
                        SelectorKind.TOML,
                        f"{parent_value.source_references[0].selector.value}.dependencies[{dependency_index}]",
                    ).selector,
                )
                continue
            child = possible[0]
            applicability = (
                Applicability(kind=ApplicabilityKind.CONDITIONAL, marker=dependency_marker)
                if dependency_marker
                else child.applicability
            )
            edge_source = builder.source(
                relative,
                digest,
                SelectorKind.TOML,
                f"{parent_value.source_references[0].selector.value}.dependencies[{dependency_index}]",
            )
            relationship = (
                DependencyRelationship.DIRECT
                if parent_value.source_type in {"editable", "virtual", "directory", "path"}
                else DependencyRelationship.TRANSITIVE
            )
            if child.relationship == DependencyRelationship.UNKNOWN or (
                relationship == DependencyRelationship.DIRECT
                and child.relationship == DependencyRelationship.TRANSITIVE
            ):
                child = child.model_copy(update={"relationship": relationship})
                builder.components[child.id] = child
            builder.add_edge(
                project=project_value,
                parent=parent_value,
                child=child,
                relationship=relationship,
                scopes=(DependencyScope.RUNTIME,),
                applicability=applicability,
                source=edge_source,
            )
    return added
