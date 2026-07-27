from __future__ import annotations

from dataclasses import dataclass

from watchdog.domain.inventory import (
    Applicability,
    DependencyRelationship,
    DependencyScope,
    Ecosystem,
    SelectorKind,
    VersionKind,
)
from watchdog.inventory.common import InventoryBuilder
from watchdog.inventory.identifiers import normalize_package_name


@dataclass(frozen=True, slots=True)
class _GoRequirement:
    name: str
    version: str
    indirect: bool
    line: int


@dataclass(frozen=True, slots=True)
class _GoReplacement:
    old_name: str
    old_version: str | None
    new_name: str
    new_version: str | None
    line: int


def _split_comment(line: str) -> tuple[str, str]:
    before, separator, after = line.partition("//")
    return before.strip(), after.strip() if separator else ""


def _warn_malformed(builder: InventoryBuilder, relative: str, line: int, directive: str) -> None:
    builder.warning(
        "go_directive_malformed",
        f"A malformed Go {directive} directive was skipped.",
        path=relative,
        selector=builder.source(relative, "0" * 64, SelectorKind.LINE, f"line:{line}").selector,
    )


def parse_go_mod(
    builder: InventoryBuilder,
    relative: str,
    data: bytes,
    digest: str,
) -> int:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("go.mod was not valid UTF-8") from None
    module_name: str | None = None
    module_line = 1
    requirements: list[_GoRequirement] = []
    replacements: list[_GoReplacement] = []
    excludes: set[tuple[str, str]] = set()
    tools: list[tuple[str, int]] = []
    block: str | None = None

    for line_number, original in enumerate(text.splitlines(), start=1):
        builder.check_active()
        content, comment = _split_comment(original.strip())
        if not content:
            continue
        if content == ")":
            if block is None:
                _warn_malformed(builder, relative, line_number, "block")
            block = None
            continue
        directive = block
        payload = content
        if block is None:
            parts = content.split(maxsplit=1)
            directive = parts[0]
            payload = parts[1] if len(parts) == 2 else ""
            if payload == "(" and directive in {"require", "replace", "exclude", "tool"}:
                block = directive
                continue
        assert directive is not None
        tokens = payload.split()
        if directive == "module":
            if len(tokens) != 1:
                _warn_malformed(builder, relative, line_number, directive)
            else:
                module_name = tokens[0]
                module_line = line_number
        elif directive in {"go", "toolchain"}:
            if len(tokens) != 1:
                _warn_malformed(builder, relative, line_number, directive)
        elif directive == "require":
            if len(tokens) != 2:
                _warn_malformed(builder, relative, line_number, directive)
            else:
                requirements.append(
                    _GoRequirement(
                        name=tokens[0],
                        version=tokens[1],
                        indirect=comment == "indirect",
                        line=line_number,
                    )
                )
        elif directive == "replace":
            if "=>" not in tokens or tokens.count("=>") != 1:
                _warn_malformed(builder, relative, line_number, directive)
                continue
            split = tokens.index("=>")
            old, new = tokens[:split], tokens[split + 1 :]
            if len(old) not in {1, 2} or len(new) not in {1, 2}:
                _warn_malformed(builder, relative, line_number, directive)
            else:
                replacements.append(
                    _GoReplacement(
                        old_name=old[0],
                        old_version=old[1] if len(old) == 2 else None,
                        new_name=new[0],
                        new_version=new[1] if len(new) == 2 else None,
                        line=line_number,
                    )
                )
        elif directive == "exclude":
            if len(tokens) != 2:
                _warn_malformed(builder, relative, line_number, directive)
            else:
                excludes.add((tokens[0], tokens[1]))
        elif directive == "tool":
            if len(tokens) != 1:
                _warn_malformed(builder, relative, line_number, directive)
            else:
                tools.append((tokens[0], line_number))
        elif block is None:
            builder.warning(
                "go_directive_unsupported",
                "An unknown top-level go.mod directive was not interpreted.",
                path=relative,
                selector=builder.source(
                    relative, digest, SelectorKind.LINE, f"line:{line_number}"
                ).selector,
            )
    if block is not None:
        builder.warning(
            "go_block_unterminated",
            "An unterminated go.mod directive block limited coverage.",
            path=relative,
        )

    root = "." if "/" not in relative else relative.rsplit("/", 1)[0]
    project_source = builder.source(relative, digest, SelectorKind.LINE, f"line:{module_line}")
    project = builder.add_project(
        root=root,
        ecosystem=Ecosystem.GO,
        source=project_source,
        name=module_name,
    )
    added = 0
    for requirement in requirements:
        source = builder.source(relative, digest, SelectorKind.LINE, f"line:{requirement.line}")
        relationship = (
            DependencyRelationship.TRANSITIVE
            if requirement.indirect
            else DependencyRelationship.DIRECT
        )
        version: str | None = requirement.version
        version_kind = VersionKind.EXACT
        scanner_eligible = True
        resolved_name: str | None = None
        source_type = "registry"
        for replacement in replacements:
            if replacement.old_name != requirement.name or (
                replacement.old_version is not None
                and replacement.old_version != requirement.version
            ):
                continue
            if replacement.new_version is None:
                version = None
                version_kind = VersionKind.UNKNOWN
                scanner_eligible = False
                source_type = "local-replacement"
                builder.warning(
                    "go_local_replacement",
                    "A local-path Go replacement is visible but scanner-ineligible.",
                    path=relative,
                    selector=builder.source(
                        relative,
                        digest,
                        SelectorKind.LINE,
                        f"line:{replacement.line}",
                    ).selector,
                )
            else:
                version = replacement.new_version
                resolved_name = replacement.new_name
                source_type = "module-replacement"
            break
        if (requirement.name, requirement.version) in excludes:
            builder.warning(
                "go_required_version_excluded",
                "A required Go module version was also excluded.",
                path=relative,
                selector=source.selector,
            )
        normalized = normalize_package_name(Ecosystem.GO, requirement.name)
        component = builder.add_component(
            project=project,
            name=requirement.name,
            normalized_name=normalized,
            version=version,
            version_kind=version_kind,
            relationship=relationship,
            scopes=(DependencyScope.RUNTIME,),
            applicability=Applicability(),
            source=source,
            scanner_eligible=scanner_eligible,
            resolved_name=resolved_name,
            source_type=source_type,
        )
        builder.add_edge(
            project=project,
            parent=None,
            child=component,
            relationship=relationship,
            scopes=(DependencyScope.RUNTIME,),
            applicability=Applicability(),
            source=source,
        )
        added += 1
    for tool_name, line_number in tools:
        source = builder.source(relative, digest, SelectorKind.LINE, f"line:{line_number}")
        component = builder.add_component(
            project=project,
            name=tool_name,
            normalized_name=normalize_package_name(Ecosystem.GO, tool_name),
            version=None,
            version_kind=VersionKind.UNKNOWN,
            relationship=DependencyRelationship.DIRECT,
            scopes=(DependencyScope.TOOL,),
            applicability=Applicability(),
            source=source,
            scanner_eligible=False,
            source_type="tool-directive",
        )
        builder.add_edge(
            project=project,
            parent=None,
            child=component,
            relationship=DependencyRelationship.DIRECT,
            scopes=(DependencyScope.TOOL,),
            applicability=Applicability(),
            source=source,
        )
        added += 1
    return added
