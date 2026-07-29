from __future__ import annotations

import asyncio
import hashlib
import json
import re
import threading
import time
import tomllib
from contextlib import suppress
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from watchdog.domain.inventory import (
    ApplicabilityKind,
    DependencyComponent,
    DependencyInventory,
    DependencyRelationship,
    Ecosystem,
    SelectorKind,
    SourceReference,
)
from watchdog.domain.matching import DependencyMatchReport
from watchdog.domain.remediation import (
    ByteTokenReplacement,
    CandidateClassification,
    CandidateSelectionOutcome,
    PatchPreview,
    PreviewStatus,
    RemediationCandidate,
    RemediationLimitation,
    RemediationWarning,
    SemanticReparseStatus,
)
from watchdog.domain.repositories import AcquiredRepository
from watchdog.evidence.limits import EvidenceConfiguration, EvidenceLimits
from watchdog.evidence.reader import (
    DescriptorRepositoryReader,
    EvidenceCancelled,
    EvidenceDeadlineExceeded,
)
from watchdog.evidence.redaction import Redactor
from watchdog.inventory.identifiers import normalize_package_name
from watchdog.inventory.limits import InventoryLimits
from watchdog.remediation.identifiers import remediation_candidate_id, remediation_preview_id
from watchdog.remediation.limits import RemediationConfiguration
from watchdog.remediation.versions import UnsupportedVersion, parse_npm_semver


class PreviewCollectionError(ValueError):
    code = "remediation_preview_collection_failed"


class _PreviewUnavailable(Exception):
    def __init__(self, limitation: RemediationLimitation) -> None:
        self.limitation = limitation


@dataclass(frozen=True, slots=True)
class PreviewCollection:
    candidates: tuple[RemediationCandidate, ...]
    previews: tuple[PatchPreview, ...]
    warnings: tuple[RemediationWarning, ...]
    limitations: tuple[RemediationLimitation, ...]
    attempted: int
    omitted: int


@dataclass(frozen=True, slots=True)
class _TokenLocation:
    offset: int
    line_number: int
    original_line: str


@dataclass(frozen=True, slots=True)
class _DependencyFact:
    selector: str
    name: str
    version: str


def _strict_json(data: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise ValueError("duplicate JSON key")
            output[key] = value
        return output

    def reject(_value: str) -> None:
        raise ValueError("non-finite JSON value")

    value = json.loads(data.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject)
    if not isinstance(value, dict):
        raise ValueError("manifest root is not an object")
    return value


def _requirement_fact(raw: str, selector: str) -> _DependencyFact:
    try:
        requirement = Requirement(raw)
    except InvalidRequirement as exc:
        raise ValueError("dependency declaration is malformed") from exc
    if requirement.url is not None or requirement.marker is not None:
        raise ValueError("dependency declaration is not unconditional registry data")
    specifiers = tuple(requirement.specifier)
    if len(specifiers) != 1 or specifiers[0].operator != "==" or "*" in specifiers[0].version:
        raise ValueError("dependency declaration is not one exact version")
    return _DependencyFact(
        selector=selector,
        name=normalize_package_name(Ecosystem.PYPI, requirement.name),
        version=specifiers[0].version,
    )


def _requirements_facts(data: bytes) -> tuple[_DependencyFact, ...]:
    text = data.decode("utf-8")
    facts: list[_DependencyFact] = []
    for line_number, original in enumerate(text.splitlines(), start=1):
        line = re.split(r"\s+#", original.strip(), maxsplit=1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\") or line.startswith("-") or " --hash" in line:
            raise ValueError("requirements syntax is outside the preview grammar")
        facts.append(_requirement_fact(line, f"line:{line_number}"))
    return tuple(facts)


def _pyproject_facts(data: bytes) -> tuple[_DependencyFact, ...]:
    document = tomllib.loads(data.decode("utf-8"))
    project = document.get("project", {})
    if not isinstance(project, dict):
        raise ValueError("project table is malformed")
    facts: list[_DependencyFact] = []
    dependencies = project.get("dependencies", [])
    if not isinstance(dependencies, list) or not all(
        isinstance(item, str) for item in dependencies
    ):
        raise ValueError("project dependencies are malformed")
    for index, value in enumerate(dependencies):
        facts.append(_requirement_fact(value, f"project.dependencies[{index}]"))
    optional = project.get("optional-dependencies", {})
    if not isinstance(optional, dict):
        raise ValueError("optional dependencies are malformed")
    for group in sorted(optional):
        values = optional[group]
        if (
            not isinstance(group, str)
            or not isinstance(values, list)
            or not all(isinstance(item, str) for item in values)
        ):
            raise ValueError("optional dependencies are malformed")
        for index, value in enumerate(values):
            facts.append(
                _requirement_fact(value, f"project.optional-dependencies.{group}[{index}]")
            )
    return tuple(facts)


_NPM_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def _npm_facts(data: bytes) -> tuple[_DependencyFact, ...]:
    document = _strict_json(data)
    facts: list[_DependencyFact] = []
    for field in _NPM_FIELDS:
        values = document.get(field, {})
        if not isinstance(values, dict):
            raise ValueError("npm dependency declarations are malformed")
        for name in sorted(values):
            version = values[name]
            if not isinstance(name, str) or not isinstance(version, str):
                raise ValueError("npm dependency declarations are malformed")
            parse_npm_semver(version)
            pointer_name = name.replace("~", "~0").replace("/", "~1")
            facts.append(
                _DependencyFact(
                    selector=f"/{field}/{pointer_name}",
                    name=normalize_package_name(Ecosystem.NPM, name),
                    version=version,
                )
            )
    return tuple(facts)


def _go_facts(data: bytes) -> tuple[_DependencyFact, ...]:
    text = data.decode("utf-8")
    facts: list[_DependencyFact] = []
    block: str | None = None
    for line_number, original in enumerate(text.splitlines(), start=1):
        content = original.split("//", 1)[0].strip()
        if not content:
            continue
        if content == ")":
            if block is None:
                raise ValueError("unexpected go.mod block terminator")
            block = None
            continue
        directive = block
        payload = content
        if directive is None:
            pieces = content.split(maxsplit=1)
            directive = pieces[0]
            payload = pieces[1] if len(pieces) == 2 else ""
            if payload == "(" and directive in {"require", "replace", "exclude", "tool"}:
                block = directive
                continue
        if directive == "require":
            tokens = payload.split()
            if len(tokens) != 2:
                raise ValueError("go.mod require directive is malformed")
            facts.append(
                _DependencyFact(
                    selector=f"line:{line_number}",
                    name=normalize_package_name(Ecosystem.GO, tokens[0]),
                    version=tokens[1],
                )
            )
        elif directive == "replace":
            raise ValueError("go.mod replacements are outside the preview grammar")
        elif directive not in {"module", "go", "toolchain", "exclude", "tool"}:
            raise ValueError("go.mod directive is outside the preview grammar")
    if block is not None:
        raise ValueError("go.mod block is unterminated")
    return tuple(facts)


def _facts(path: str, data: bytes) -> tuple[_DependencyFact, ...]:
    name = PurePosixPath(path).name
    if name.startswith("requirements") and name.endswith(".txt"):
        return _requirements_facts(data)
    if name == "pyproject.toml":
        return _pyproject_facts(data)
    if name == "package.json":
        return _npm_facts(data)
    if name == "go.mod":
        return _go_facts(data)
    raise ValueError("manifest format is not previewable")


def _line_location(data: bytes, line_number: int, current: str) -> _TokenLocation:
    lines = data.splitlines(keepends=True)
    if line_number < 1 or line_number > len(lines):
        raise _PreviewUnavailable(RemediationLimitation.TOKEN_AMBIGUOUS)
    line = lines[line_number - 1]
    token = current.encode("utf-8")
    matches = tuple(
        re.finditer(rb"(?<![0-9A-Za-z.+_-])" + re.escape(token) + rb"(?![0-9A-Za-z.+_-])", line)
    )
    if len(matches) != 1:
        raise _PreviewUnavailable(RemediationLimitation.TOKEN_AMBIGUOUS)
    offset = sum(len(item) for item in lines[: line_number - 1]) + matches[0].start()
    try:
        display = line.rstrip(b"\r\n").decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNSUPPORTED) from exc
    return _TokenLocation(offset=offset, line_number=line_number, original_line=display)


def _location(
    source: SourceReference,
    data: bytes,
    *,
    normalized_name: str,
    current: str,
) -> _TokenLocation:
    name = PurePosixPath(source.path).name
    selector = source.selector.value
    if name.startswith("requirements") and name.endswith(".txt"):
        if source.selector.kind is not SelectorKind.LINE or not selector.startswith("line:"):
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNSUPPORTED)
        try:
            line_number = int(selector.split(":", 1)[1])
            fact = next(item for item in _requirements_facts(data) if item.selector == selector)
        except (ValueError, StopIteration) as exc:
            raise _PreviewUnavailable(RemediationLimitation.SEMANTIC_REPARSE_FAILED) from exc
        if fact.name != normalized_name or fact.version != current:
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_MISMATCH)
        return _line_location(data, line_number, current)
    if name == "go.mod":
        if source.selector.kind is not SelectorKind.LINE or not selector.startswith("line:"):
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNSUPPORTED)
        try:
            line_number = int(selector.split(":", 1)[1])
            fact = next(item for item in _go_facts(data) if item.selector == selector)
        except (ValueError, StopIteration) as exc:
            raise _PreviewUnavailable(RemediationLimitation.SEMANTIC_REPARSE_FAILED) from exc
        if fact.name != normalized_name or fact.version != current:
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_MISMATCH)
        return _line_location(data, line_number, current)
    if name == "pyproject.toml":
        if source.selector.kind is not SelectorKind.TOML or not selector.startswith(
            "project.dependencies["
        ):
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNSUPPORTED)
        try:
            fact = next(item for item in _pyproject_facts(data) if item.selector == selector)
            document = tomllib.loads(data.decode("utf-8"))
            index = int(selector.removeprefix("project.dependencies[").removesuffix("]"))
            raw = document["project"]["dependencies"][index]
        except (
            KeyError,
            IndexError,
            TypeError,
            ValueError,
            StopIteration,
            UnicodeDecodeError,
            tomllib.TOMLDecodeError,
        ) as exc:
            raise _PreviewUnavailable(RemediationLimitation.SEMANTIC_REPARSE_FAILED) from exc
        if fact.name != normalized_name or fact.version != current or not isinstance(raw, str):
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_MISMATCH)
        if any(character in raw for character in "'\"\\\r\n") or not raw.isascii():
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNSUPPORTED)
        toml_locations: list[int] = []
        for quote in (b'"', b"'"):
            literal = quote + raw.encode("ascii") + quote
            start = 0
            while (found := data.find(literal, start)) >= 0:
                toml_locations.append(found + 1 + raw.index(current))
                start = found + len(literal)
        if len(toml_locations) != 1 or raw.count(current) != 1:
            raise _PreviewUnavailable(RemediationLimitation.TOKEN_AMBIGUOUS)
        prefix = data[: toml_locations[0]]
        line_number = prefix.count(b"\n") + 1
        original_line = data.splitlines()[line_number - 1].decode("utf-8")
        return _TokenLocation(toml_locations[0], line_number, original_line)
    if name == "package.json":
        if source.selector.kind is not SelectorKind.JSON_POINTER:
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNSUPPORTED)
        try:
            fact = next(item for item in _npm_facts(data) if item.selector == selector)
        except (ValueError, UnsupportedVersion, StopIteration) as exc:
            raise _PreviewUnavailable(RemediationLimitation.SEMANTIC_REPARSE_FAILED) from exc
        if fact.name != normalized_name or fact.version != current:
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_MISMATCH)
        pointer_parts = selector.split("/")
        if len(pointer_parts) != 3 or pointer_parts[1] not in _NPM_FIELDS:
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNSUPPORTED)
        dependency_name = pointer_parts[2].replace("~1", "/").replace("~0", "~")
        key = json.dumps(dependency_name, ensure_ascii=False).encode("utf-8")
        value = json.dumps(current, ensure_ascii=False).encode("utf-8")
        pattern = re.compile(re.escape(key) + rb"\s*:\s*" + re.escape(value))
        json_locations: list[int] = []
        for json_match in pattern.finditer(data):
            value_start = json_match.end() - len(value)
            json_locations.append(value_start + 1)
        if len(json_locations) != 1:
            raise _PreviewUnavailable(RemediationLimitation.TOKEN_AMBIGUOUS)
        line_number = data[: json_locations[0]].count(b"\n") + 1
        original_line = data.splitlines()[line_number - 1].decode("utf-8")
        return _TokenLocation(json_locations[0], line_number, original_line)
    raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNSUPPORTED)


def _validate_semantics(
    path: str,
    original: bytes,
    hypothetical: bytes,
    *,
    selector: str,
    normalized_name: str,
    current: str,
    target: str,
) -> None:
    try:
        before = _facts(path, original)
        after = _facts(path, hypothetical)
    except (ValueError, UnicodeDecodeError, tomllib.TOMLDecodeError, json.JSONDecodeError) as exc:
        raise _PreviewUnavailable(RemediationLimitation.SEMANTIC_REPARSE_FAILED) from exc
    if len(before) != len(after):
        raise _PreviewUnavailable(RemediationLimitation.SEMANTIC_REPARSE_FAILED)
    changes = [(left, right) for left, right in zip(before, after, strict=True) if left != right]
    if len(changes) != 1:
        raise _PreviewUnavailable(RemediationLimitation.SEMANTIC_REPARSE_FAILED)
    left, right = changes[0]
    if not (
        left.selector == right.selector == selector
        and left.name == right.name == normalized_name
        and left.version == current
        and right.version == target
    ):
        raise _PreviewUnavailable(RemediationLimitation.SEMANTIC_REPARSE_FAILED)


def _candidate_source(
    candidate: RemediationCandidate,
    inventory: DependencyInventory,
) -> SourceReference:
    components = {component.id: component for component in inventory.components}
    component = components.get(candidate.component_id)
    if component is None:
        raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNAVAILABLE)
    current = candidate.current_coordinate.version
    eligible: list[SourceReference] = []
    if component.ecosystem is Ecosystem.NPM:
        try:
            parse_npm_semver(current)
        except UnsupportedVersion as exc:
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNSUPPORTED) from exc
        declarations: list[tuple[DependencyComponent, SourceReference]] = []
        for declaration in inventory.components:
            if (
                declaration.project_id == component.project_id
                and declaration.ecosystem is Ecosystem.NPM
                and declaration.normalized_name == component.normalized_name
                and declaration.relationship is DependencyRelationship.DIRECT
                and declaration.source_type == "declaration"
            ):
                declarations.extend(
                    (declaration, reference)
                    for reference in declaration.source_references
                    if PurePosixPath(reference.path).name == "package.json"
                )
        unique_declarations = {
            (
                reference.path,
                reference.selector.kind.value,
                reference.selector.value,
                reference.file_sha256,
            ): (declaration, reference)
            for declaration, reference in declarations
        }
        if not unique_declarations:
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNAVAILABLE)
        if len(unique_declarations) != 1:
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_AMBIGUOUS)
        declaration, source = next(iter(unique_declarations.values()))
        if declaration.applicability.kind is not ApplicabilityKind.UNCONDITIONAL:
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNSUPPORTED)
        if declaration.version is None:
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNSUPPORTED)
        try:
            parse_npm_semver(declaration.version)
        except UnsupportedVersion as exc:
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNSUPPORTED) from exc
        if declaration.version != current:
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_MISMATCH)
        if any(warning.path == source.path for warning in inventory.warnings):
            raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNSUPPORTED)
        return source
    else:
        for reference in component.source_references:
            filename = PurePosixPath(reference.path).name
            registry_unconditional = (
                component.source_type == "registry"
                and component.applicability.kind is ApplicabilityKind.UNCONDITIONAL
            )
            requirements_supported = (
                component.ecosystem is Ecosystem.PYPI
                and registry_unconditional
                and filename.startswith("requirements")
                and filename.endswith(".txt")
            )
            python_supported = component.ecosystem is Ecosystem.PYPI and (
                requirements_supported
                or (
                    registry_unconditional
                    and component.relationship is DependencyRelationship.DIRECT
                    and filename == "pyproject.toml"
                )
            )
            go_supported = (
                component.ecosystem is Ecosystem.GO
                and filename == "go.mod"
                and registry_unconditional
                and component.relationship is DependencyRelationship.DIRECT
            )
            if python_supported or go_supported:
                eligible.append(reference)
    unique = {
        (item.path, item.selector.kind.value, item.selector.value, item.file_sha256): item
        for item in eligible
    }
    if not unique:
        raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNAVAILABLE)
    if len(unique) != 1:
        raise _PreviewUnavailable(RemediationLimitation.DECLARATION_AMBIGUOUS)
    source = next(iter(unique.values()))
    if any(warning.path == source.path for warning in inventory.warnings):
        raise _PreviewUnavailable(RemediationLimitation.DECLARATION_UNSUPPORTED)
    return source


def mark_preview_unavailable(
    candidate: RemediationCandidate,
    limitation: RemediationLimitation,
) -> RemediationCandidate:
    if candidate.selection is not CandidateSelectionOutcome.SELECTED:
        return candidate
    classifications = set(candidate.classifications)
    classifications.discard(CandidateClassification.PREVIEW_ELIGIBLE)
    classifications.add(CandidateClassification.PREVIEW_UNAVAILABLE)
    draft = candidate.model_copy(
        update={
            "classifications": tuple(sorted(classifications, key=lambda item: item.value)),
            "limitations": tuple(
                sorted({*candidate.limitations, limitation}, key=lambda item: item.value)
            ),
        }
    )
    payload = draft.model_dump(mode="python", exclude={"id"})
    return RemediationCandidate(id=remediation_candidate_id(draft), **payload)


class PreviewCollector:
    def __init__(
        self,
        configuration: RemediationConfiguration,
        *,
        inventory_limits: InventoryLimits,
        evidence_configuration: EvidenceConfiguration,
    ) -> None:
        self._configuration = RemediationConfiguration.model_validate(
            configuration.model_dump(mode="python")
        )
        phase8 = configuration.limits
        evidence = evidence_configuration.limits
        self._reader_limits = EvidenceLimits(
            deadline_seconds=min(phase8.deadline_seconds, evidence.deadline_seconds),
            max_source_files=min(
                phase8.max_preview_source_files,
                evidence.max_source_files,
                inventory_limits.max_manifest_files,
            ),
            max_bytes_per_source_file=min(
                phase8.max_bytes_per_preview_source_file,
                evidence.max_bytes_per_source_file,
                inventory_limits.max_bytes_per_manifest,
            ),
            max_total_source_bytes=min(
                phase8.max_total_preview_source_bytes,
                evidence.max_total_source_bytes,
                inventory_limits.max_total_parsed_bytes,
            ),
            max_evidence_items=1,
            max_line_span=1,
            max_display_bytes_per_item=min(phase8.max_diff_bytes_per_preview, 5 * 1024 * 1024),
            max_bundle_display_bytes=min(phase8.max_total_preview_display_bytes, 5 * 1024 * 1024),
            max_redactions_per_item=evidence.max_redactions_per_item,
            max_warnings=min(phase8.max_warnings, evidence.max_warnings),
        )
        self._redactor = Redactor(evidence_configuration.enabled_detectors)

    async def collect(
        self,
        repository: AcquiredRepository,
        inventory: DependencyInventory,
        matches: DependencyMatchReport,
        candidates: tuple[RemediationCandidate, ...],
    ) -> PreviewCollection:
        if not self._configuration.preview_enabled:
            raise PreviewCollectionError("preview collection was called while disabled")
        validated_inventory = DependencyInventory.model_validate(
            inventory.model_dump(mode="python")
        )
        validated_matches = DependencyMatchReport.model_validate(matches.model_dump(mode="python"))
        if validated_inventory.snapshot != validated_matches.snapshot:
            raise PreviewCollectionError("preview inputs do not identify one snapshot")
        if (
            repository.snapshot.commit_sha != inventory.snapshot.commit_sha
            or repository.snapshot.tree_sha != inventory.snapshot.tree_sha
            or repository.snapshot.archive_sha256 != inventory.snapshot.archive_sha256
        ):
            raise PreviewCollectionError("repository lease does not match preview snapshot")
        cancel_event = threading.Event()
        deadline = time.monotonic() + self._reader_limits.deadline_seconds
        task = asyncio.create_task(
            asyncio.to_thread(
                self._collect_sync,
                repository,
                validated_inventory,
                candidates,
                deadline,
                cancel_event,
            )
        )
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            cancel_event.set()
            with suppress(Exception, asyncio.CancelledError):
                await task
            raise

    def _collect_sync(
        self,
        repository: AcquiredRepository,
        inventory: DependencyInventory,
        candidates: tuple[RemediationCandidate, ...],
        deadline: float,
        cancel_event: threading.Event,
    ) -> PreviewCollection:
        updated: list[RemediationCandidate] = []
        previews: list[PatchPreview] = []
        warnings: set[RemediationWarning] = set()
        limitations: set[RemediationLimitation] = set()
        attempted = 0
        omitted = 0
        display_bytes = 0
        with DescriptorRepositoryReader(
            repository.root,
            self._reader_limits,
            deadline=deadline,
            cancel_event=cancel_event,
        ) as reader:
            for candidate in candidates:
                if candidate.selection is not CandidateSelectionOutcome.SELECTED:
                    updated.append(candidate)
                    continue
                if len(previews) >= self._configuration.limits.max_previews:
                    limitation = RemediationLimitation.PREVIEW_LIMIT_EXCEEDED
                    updated.append(mark_preview_unavailable(candidate, limitation))
                    limitations.add(limitation)
                    warnings.add(RemediationWarning.PREVIEW_LIMIT_EXCEEDED)
                    omitted += 1
                    continue
                attempted += 1
                try:
                    source = _candidate_source(candidate, inventory)
                    read = reader.read(source.path, source.file_sha256)
                    if read.data is None:
                        raise _PreviewUnavailable(self._read_limitation(read.limitation_code))
                    preview = self._preview(candidate, source, read.data)
                    display_size = len((preview.redacted_zero_context_diff or "").encode("utf-8"))
                    if (
                        display_bytes + display_size
                        > self._configuration.limits.max_total_preview_display_bytes
                    ):
                        raise _PreviewUnavailable(RemediationLimitation.DIFF_LIMIT_EXCEEDED)
                    display_bytes += display_size
                    if preview.status is PreviewStatus.COMPLETE:
                        updated.append(candidate)
                    else:
                        limitation = preview.limitations[0]
                        updated.append(mark_preview_unavailable(candidate, limitation))
                        limitations.add(limitation)
                        warnings.add(RemediationWarning.PREVIEW_OMITTED)
                        omitted += 1
                    previews.append(preview)
                except _PreviewUnavailable as exc:
                    updated.append(mark_preview_unavailable(candidate, exc.limitation))
                    limitations.add(exc.limitation)
                    warnings.add(RemediationWarning.PREVIEW_OMITTED)
                    omitted += 1
                except (EvidenceDeadlineExceeded, EvidenceCancelled):
                    raise
        updated.sort(key=lambda item: item.id)
        previews.sort(key=lambda item: item.id)
        return PreviewCollection(
            candidates=tuple(updated),
            previews=tuple(previews),
            warnings=tuple(sorted(warnings, key=lambda item: item.value)),
            limitations=tuple(sorted(limitations, key=lambda item: item.value)),
            attempted=attempted,
            omitted=omitted,
        )

    def _preview(
        self,
        candidate: RemediationCandidate,
        source: SourceReference,
        original: bytes,
    ) -> PatchPreview:
        current = candidate.current_coordinate.version
        target = candidate.raw_source_reported_target
        normalized_name = normalize_package_name(
            candidate.current_coordinate.ecosystem, candidate.current_coordinate.name
        )
        location = _location(
            source,
            original,
            normalized_name=normalized_name,
            current=current,
        )
        old = current.encode("utf-8")
        new = target.encode("utf-8")
        if original[location.offset : location.offset + len(old)] != old:
            raise _PreviewUnavailable(RemediationLimitation.TOKEN_BOUNDARY_INVALID)
        prefix = original[: location.offset]
        suffix = original[location.offset + len(old) :]
        hypothetical = prefix + new + suffix
        if not hypothetical.startswith(prefix) or not hypothetical.endswith(suffix):
            raise _PreviewUnavailable(RemediationLimitation.TOKEN_BOUNDARY_INVALID)
        _validate_semantics(
            source.path,
            original,
            hypothetical,
            selector=source.selector.value,
            normalized_name=normalized_name,
            current=current,
            target=target,
        )
        line_start = original.rfind(b"\n", 0, location.offset) + 1
        line_end = original.find(b"\n", location.offset)
        if line_end < 0:
            line_end = len(original)
        line_bytes = original[line_start:line_end].removesuffix(b"\r")
        if not (line_start <= location.offset <= line_end - len(old)):
            raise _PreviewUnavailable(RemediationLimitation.TOKEN_BOUNDARY_INVALID)
        token_column = location.offset - line_start
        new_line_bytes = line_bytes[:token_column] + new + line_bytes[token_column + len(old) :]
        try:
            original_line = line_bytes.decode("utf-8")
            new_line = new_line_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _PreviewUnavailable(RemediationLimitation.TOKEN_BOUNDARY_INVALID) from exc
        if original_line != location.original_line:
            raise _PreviewUnavailable(RemediationLimitation.TOKEN_BOUNDARY_INVALID)
        raw_diff = (
            f"--- {source.path}\n+++ {source.path}\n"
            f"@@ -{location.line_number} +{location.line_number} @@\n"
            f"-{original_line}\n+{new_line}\n"
        )
        redaction = self._redactor.redact(
            raw_diff, max_redactions=self._reader_limits.max_redactions_per_item
        )
        limitations: tuple[RemediationLimitation, ...] = ()
        display = redaction.text
        status = PreviewStatus.COMPLETE
        if display is None:
            display = None
            status = PreviewStatus.DIFF_OMITTED
            limitations = (RemediationLimitation.REDACTION_FAILED,)
        elif len(display.encode("utf-8")) > self._configuration.limits.max_diff_bytes_per_preview:
            display = None
            status = PreviewStatus.DIFF_OMITTED
            limitations = (RemediationLimitation.DIFF_LIMIT_EXCEEDED,)
        replacement = ByteTokenReplacement(
            offset=location.offset,
            original_byte_count=len(old),
            original_sha256=hashlib.sha256(old).hexdigest(),
            original_token=current,
            replacement_token=target,
        )
        payload: dict[str, object] = {
            "candidate_id": candidate.id,
            "source_reference": source,
            "original_sha256": hashlib.sha256(original).hexdigest(),
            "hypothetical_sha256": hashlib.sha256(hypothetical).hexdigest(),
            "replacement": replacement,
            "redacted_zero_context_diff": display,
            "status": status,
            "semantic_reparse_status": SemanticReparseStatus.VALIDATED_SINGLE_VERSION_CHANGE,
            "dependency_evidence_ids": candidate.dependency_evidence_ids,
            "limitations": limitations,
        }
        return PatchPreview(id=remediation_preview_id(payload), **payload)

    @staticmethod
    def _read_limitation(code: str | None) -> RemediationLimitation:
        if code == "source_digest_mismatch":
            return RemediationLimitation.SOURCE_DIGEST_MISMATCH
        if code == "source_changed_during_read":
            return RemediationLimitation.SOURCE_CHANGED
        if code in {
            "source_file_limit_exceeded",
            "source_file_bytes_limit_exceeded",
            "source_total_bytes_limit_exceeded",
        }:
            return RemediationLimitation.SOURCE_LIMIT_EXCEEDED
        return RemediationLimitation.SOURCE_UNSAFE
