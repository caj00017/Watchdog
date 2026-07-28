from __future__ import annotations

import ast
import json
import re
import tomllib
from dataclasses import dataclass, field

from packaging.requirements import InvalidRequirement, Requirement

from watchdog.domain.evidence import SourceLineRange
from watchdog.domain.inventory import (
    DependencyComponent,
    Ecosystem,
    SelectorKind,
    SourceSelector,
    VersionKind,
)
from watchdog.inventory.identifiers import normalize_package_name


class SelectorResolutionError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class Selection:
    text: str
    line_range: SourceLineRange
    value: object = None
    key: str | None = None


def resolve_selector(
    data: bytes,
    selector: SourceSelector,
    *,
    max_line_span: int,
    component: DependencyComponent | None = None,
) -> Selection:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SelectorResolutionError("source_invalid_utf8") from exc
    try:
        if selector.kind == SelectorKind.LINE:
            selection = _resolve_line(text, selector.value)
        elif selector.kind == SelectorKind.JSON_POINTER:
            selection = _resolve_json_pointer(text, selector.value)
        elif selector.kind == SelectorKind.TOML:
            selection = _resolve_toml(text, selector.value)
        else:
            raise SelectorResolutionError("selector_kind_unsupported")
    except SelectorResolutionError:
        raise
    except Exception as exc:
        raise SelectorResolutionError("selector_unsupported_or_ambiguous") from exc
    span = selection.line_range.end - selection.line_range.start + 1
    if span > max_line_span:
        raise SelectorResolutionError("source_line_span_limit_exceeded")
    if component is not None and not selection_supports_component(selection, selector, component):
        raise SelectorResolutionError("selector_stale")
    return selection


def _line_range(text: str, start: int, end: int) -> SourceLineRange:
    first = text.count("\n", 0, start) + 1
    selected = text[start:end]
    last = first + selected.count("\n")
    if selected.endswith("\n"):
        last = max(first, last - 1)
    return SourceLineRange(start=first, end=last)


def _normalize_display_newlines(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _resolve_line(text: str, raw_selector: str) -> Selection:
    match = re.fullmatch(r"line:([1-9][0-9]*)", raw_selector)
    if match is None:
        raise SelectorResolutionError("selector_invalid")
    requested = int(match.group(1))
    lines = text.splitlines(keepends=True)
    if requested > len(lines):
        raise SelectorResolutionError("selector_stale")
    start_index = requested - 1
    end_index = start_index
    while _without_line_ending(lines[end_index]).rstrip().endswith("\\"):
        end_index += 1
        if end_index >= len(lines):
            raise SelectorResolutionError("selector_unsupported_or_ambiguous")
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    start = offsets[start_index]
    end = offsets[end_index + 1]
    selected = text[start:end].rstrip("\r\n")
    if not selected.strip():
        raise SelectorResolutionError("selector_stale")
    return Selection(
        text=_normalize_display_newlines(selected),
        line_range=SourceLineRange(start=requested, end=end_index + 1),
        value=selected,
    )


def _without_line_ending(value: str) -> str:
    return (
        value[:-2]
        if value.endswith("\r\n")
        else value[:-1]
        if value.endswith(("\r", "\n"))
        else value
    )


@dataclass(slots=True)
class _JsonNode:
    value: object
    start: int
    end: int
    members: dict[str, tuple[_JsonNode, int, int]] = field(default_factory=dict)
    elements: list[_JsonNode] = field(default_factory=list)


class _JsonParser:
    def __init__(self, text: str, maximum_depth: int = 128) -> None:
        self.text = text
        self.length = len(text)
        self.maximum_depth = maximum_depth
        self.decoder = json.JSONDecoder(parse_constant=self._reject_constant)

    def parse(self) -> _JsonNode:
        index = self._space(0)
        node, index = self._value(index, 1)
        if self._space(index) != self.length:
            raise SelectorResolutionError("selector_unsupported_or_ambiguous")
        return node

    def _value(self, index: int, depth: int) -> tuple[_JsonNode, int]:
        if depth > self.maximum_depth or index >= self.length:
            raise SelectorResolutionError("selector_unsupported_or_ambiguous")
        character = self.text[index]
        if character == "{":
            return self._object(index, depth)
        if character == "[":
            return self._array(index, depth)
        if character == '"':
            value, end = self._string(index)
            return _JsonNode(value=value, start=index, end=end), end
        try:
            value, end = self.decoder.raw_decode(self.text, index)
        except (json.JSONDecodeError, ValueError) as exc:
            raise SelectorResolutionError("selector_unsupported_or_ambiguous") from exc
        if isinstance(value, (dict, list, str)):
            raise SelectorResolutionError("selector_unsupported_or_ambiguous")
        return _JsonNode(value=value, start=index, end=end), end

    def _object(self, start: int, depth: int) -> tuple[_JsonNode, int]:
        index = self._space(start + 1)
        members: dict[str, tuple[_JsonNode, int, int]] = {}
        values: dict[str, object] = {}
        if index < self.length and self.text[index] == "}":
            return _JsonNode(values, start, index + 1, members=members), index + 1
        while True:
            member_start = index
            if index >= self.length or self.text[index] != '"':
                raise SelectorResolutionError("selector_unsupported_or_ambiguous")
            key, index = self._string(index)
            if key in members:
                raise SelectorResolutionError("selector_ambiguous")
            index = self._space(index)
            if index >= self.length or self.text[index] != ":":
                raise SelectorResolutionError("selector_unsupported_or_ambiguous")
            index = self._space(index + 1)
            value, index = self._value(index, depth + 1)
            members[key] = (value, member_start, value.end)
            values[key] = value.value
            index = self._space(index)
            if index >= self.length:
                raise SelectorResolutionError("selector_unsupported_or_ambiguous")
            if self.text[index] == "}":
                end = index + 1
                return _JsonNode(values, start, end, members=members), end
            if self.text[index] != ",":
                raise SelectorResolutionError("selector_unsupported_or_ambiguous")
            index = self._space(index + 1)

    def _array(self, start: int, depth: int) -> tuple[_JsonNode, int]:
        index = self._space(start + 1)
        elements: list[_JsonNode] = []
        if index < self.length and self.text[index] == "]":
            return _JsonNode([], start, index + 1, elements=elements), index + 1
        while True:
            value, index = self._value(index, depth + 1)
            elements.append(value)
            index = self._space(index)
            if index >= self.length:
                raise SelectorResolutionError("selector_unsupported_or_ambiguous")
            if self.text[index] == "]":
                end = index + 1
                return _JsonNode(
                    [item.value for item in elements], start, end, elements=elements
                ), end
            if self.text[index] != ",":
                raise SelectorResolutionError("selector_unsupported_or_ambiguous")
            index = self._space(index + 1)

    def _string(self, start: int) -> tuple[str, int]:
        index = start + 1
        while index < self.length:
            character = self.text[index]
            if character == "\\":
                index += 2
                continue
            if character == '"':
                end = index + 1
                try:
                    value = json.loads(self.text[start:end])
                except (json.JSONDecodeError, ValueError) as exc:
                    raise SelectorResolutionError("selector_unsupported_or_ambiguous") from exc
                if not isinstance(value, str):
                    raise SelectorResolutionError("selector_unsupported_or_ambiguous")
                return value, end
            if ord(character) < 32:
                raise SelectorResolutionError("selector_unsupported_or_ambiguous")
            index += 1
        raise SelectorResolutionError("selector_unsupported_or_ambiguous")

    def _space(self, index: int) -> int:
        while index < self.length and self.text[index] in " \t\r\n":
            index += 1
        return index

    def _reject_constant(self, _value: str) -> None:
        raise ValueError("invalid JSON constant")


def _pointer_tokens(pointer: str) -> tuple[str, ...]:
    if pointer == "":
        return ()
    if not pointer.startswith("/"):
        raise SelectorResolutionError("selector_invalid")
    result: list[str] = []
    for raw in pointer[1:].split("/"):
        if re.search(r"~(?![01])", raw):
            raise SelectorResolutionError("selector_invalid")
        result.append(raw.replace("~1", "/").replace("~0", "~"))
    return tuple(result)


def _resolve_json_pointer(text: str, pointer: str) -> Selection:
    node = _JsonParser(text).parse()
    selected_start, selected_end = node.start, node.end
    key: str | None = None
    previous_token: str | None = None
    for token in _pointer_tokens(pointer):
        if isinstance(node.value, dict):
            member = node.members.get(token)
            if member is None and token == "bundledDependencies":
                member = node.members.get("bundleDependencies")
            if member is None:
                raise SelectorResolutionError("selector_stale")
            node, selected_start, selected_end = member
            key = token
        elif isinstance(node.value, list):
            if re.fullmatch(r"0|[1-9][0-9]*", token):
                index = int(token)
            elif previous_token == "bundledDependencies":
                matches = [
                    index for index, element in enumerate(node.elements) if element.value == token
                ]
                if len(matches) != 1:
                    raise SelectorResolutionError(
                        "selector_ambiguous" if matches else "selector_stale"
                    )
                index = matches[0]
                key = token
            else:
                raise SelectorResolutionError("selector_invalid")
            if index >= len(node.elements):
                raise SelectorResolutionError("selector_stale")
            node = node.elements[index]
            selected_start, selected_end = node.start, node.end
            if previous_token != "bundledDependencies":
                key = None
        else:
            raise SelectorResolutionError("selector_stale")
        previous_token = token
    selected = text[selected_start:selected_end]
    return Selection(
        text=_normalize_display_newlines(selected),
        line_range=_line_range(text, selected_start, selected_end),
        value=node.value,
        key=key,
    )


@dataclass(frozen=True, slots=True)
class _TomlAssignment:
    path: tuple[str, ...]
    value_start: int
    value_end: int
    section_path: tuple[str, ...]
    section_index: int | None


@dataclass(slots=True)
class _TomlSection:
    path: tuple[str, ...]
    index: int | None
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class _TomlDocument:
    value: dict[str, object]
    assignments: tuple[_TomlAssignment, ...]
    sections: tuple[_TomlSection, ...]


def _scan_toml(text: str) -> _TomlDocument:
    try:
        value = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        raise SelectorResolutionError("selector_unsupported_or_ambiguous") from exc
    assignments: list[_TomlAssignment] = []
    sections: list[_TomlSection] = []
    array_counts: dict[tuple[str, ...], int] = {}
    section_path: tuple[str, ...] = ()
    section_index: int | None = None
    index = 0
    while index < len(text):
        line_end = text.find("\n", index)
        line_end = len(text) if line_end < 0 else line_end
        first = index
        while first < line_end and text[first] in " \t\r":
            first += 1
        if first >= line_end or text[first] == "#":
            index = min(len(text), line_end + 1)
            continue
        if text[first] == "[":
            raw_line = _toml_without_comment(text[first:line_end]).strip()
            array_table = raw_line.startswith("[[") and raw_line.endswith("]]")
            if array_table:
                inner = raw_line[2:-2].strip()
            elif raw_line.endswith("]"):
                inner = raw_line[1:-1].strip()
            else:
                raise SelectorResolutionError("selector_unsupported_or_ambiguous")
            section_path = _toml_key_path(inner)
            if array_table:
                section_index = array_counts.get(section_path, 0)
                array_counts[section_path] = section_index + 1
            else:
                section_index = None
            sections.append(_TomlSection(section_path, section_index, first, line_end))
            index = min(len(text), line_end + 1)
            continue
        statement_end = _toml_statement_end(text, first)
        equals = _toml_top_level_equals(text, first, statement_end)
        if equals is None:
            raise SelectorResolutionError("selector_unsupported_or_ambiguous")
        key_path = _toml_key_path(text[first:equals].strip())
        value_start = equals + 1
        while value_start < statement_end and text[value_start] in " \t\r\n":
            value_start += 1
        value_end = statement_end
        while value_end > value_start and text[value_end - 1] in " \t\r\n":
            value_end -= 1
        assignments.append(
            _TomlAssignment(
                path=(*section_path, *key_path),
                value_start=value_start,
                value_end=value_end,
                section_path=section_path,
                section_index=section_index,
            )
        )
        if sections:
            sections[-1].end = value_end
        index = statement_end
        while index < len(text) and text[index] in "\r\n":
            index += 1
    return _TomlDocument(value, tuple(assignments), tuple(sections))


def _toml_without_comment(raw: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(raw):
        if quote is not None:
            if quote == '"' and character == "\\" and not escaped:
                escaped = True
                continue
            if character == quote and not escaped:
                quote = None
            escaped = False
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "#":
            return raw[:index]
    return raw


def _toml_key_path(raw: str) -> tuple[str, ...]:
    parts: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    for index, character in enumerate(raw):
        if quote is not None:
            if quote == '"' and character == "\\" and not escaped:
                escaped = True
                continue
            if character == quote and not escaped:
                quote = None
            escaped = False
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == ".":
            parts.append(_toml_key_part(raw[start:index]))
            start = index + 1
    if quote is not None:
        raise SelectorResolutionError("selector_unsupported_or_ambiguous")
    parts.append(_toml_key_part(raw[start:]))
    if any(not part for part in parts):
        raise SelectorResolutionError("selector_unsupported_or_ambiguous")
    return tuple(parts)


def _toml_key_part(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if value[0] in {'"', "'"}:
        try:
            parsed = tomllib.loads(f"key = {value}")["key"]
        except (tomllib.TOMLDecodeError, KeyError) as exc:
            raise SelectorResolutionError("selector_unsupported_or_ambiguous") from exc
        if not isinstance(parsed, str):
            raise SelectorResolutionError("selector_unsupported_or_ambiguous")
        return parsed
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise SelectorResolutionError("selector_unsupported_or_ambiguous")
    return value


def _toml_statement_end(text: str, start: int) -> int:
    square = curly = 0
    quote: str | None = None
    triple = False
    escaped = False
    index = start
    while index < len(text):
        character = text[index]
        if quote is not None:
            if triple and text.startswith(quote * 3, index):
                quote = None
                triple = False
                index += 3
                continue
            if not triple and quote == '"' and character == "\\" and not escaped:
                escaped = True
                index += 1
                continue
            if not triple and character == quote and not escaped:
                quote = None
            escaped = False
            index += 1
            continue
        if character in {'"', "'"}:
            quote = character
            triple = text.startswith(character * 3, index)
            index += 3 if triple else 1
            continue
        if character == "#":
            comment_end = text.find("\n", index)
            if square == 0 and curly == 0:
                return index
            index = len(text) if comment_end < 0 else comment_end
            continue
        if character == "[":
            square += 1
        elif character == "]":
            square -= 1
        elif character == "{":
            curly += 1
        elif character == "}":
            curly -= 1
        elif character == "\n" and square == 0 and curly == 0:
            return index
        if square < 0 or curly < 0:
            raise SelectorResolutionError("selector_unsupported_or_ambiguous")
        index += 1
    if quote is not None or square or curly:
        raise SelectorResolutionError("selector_unsupported_or_ambiguous")
    return len(text)


def _toml_top_level_equals(text: str, start: int, end: int) -> int | None:
    quote: str | None = None
    escaped = False
    for index in range(start, end):
        character = text[index]
        if quote is not None:
            if quote == '"' and character == "\\" and not escaped:
                escaped = True
                continue
            if character == quote and not escaped:
                quote = None
            escaped = False
        elif character in {'"', "'"}:
            quote = character
        elif character == "=":
            return index
    return None


def _array_element_spans(text: str, start: int, end: int) -> tuple[tuple[int, int], ...]:
    if start >= end or text[start] != "[":
        raise SelectorResolutionError("selector_stale")
    result: list[tuple[int, int]] = []
    square = 1
    curly = 0
    quote: str | None = None
    triple = False
    escaped = False
    element_start = start + 1
    index = start + 1
    while index < end:
        character = text[index]
        if quote is not None:
            if triple and text.startswith(quote * 3, index):
                quote = None
                triple = False
                index += 3
                continue
            if not triple and quote == '"' and character == "\\" and not escaped:
                escaped = True
                index += 1
                continue
            if not triple and character == quote and not escaped:
                quote = None
            escaped = False
            index += 1
            continue
        if character in {'"', "'"}:
            quote = character
            triple = text.startswith(character * 3, index)
            index += 3 if triple else 1
            continue
        if character == "#":
            newline = text.find("\n", index, end)
            index = end if newline < 0 else newline
            continue
        if character == "[":
            square += 1
        elif character == "]":
            square -= 1
            if square == 0:
                _append_trimmed_span(result, text, element_start, index)
                return tuple(result)
        elif character == "{":
            curly += 1
        elif character == "}":
            curly -= 1
        elif character == "," and square == 1 and curly == 0:
            _append_trimmed_span(result, text, element_start, index)
            element_start = index + 1
        index += 1
    raise SelectorResolutionError("selector_unsupported_or_ambiguous")


def _append_trimmed_span(result: list[tuple[int, int]], text: str, start: int, end: int) -> None:
    while start < end and text[start] in " \t\r\n":
        start += 1
    while end > start and text[end - 1] in " \t\r\n":
        end -= 1
    if start < end:
        result.append((start, end))


def _parse_uv_selector(selector: str) -> tuple[str, str | None, int, int | None] | None:
    dependency_index: int | None = None
    base = selector
    suffix = re.search(r"\.dependencies\[([0-9]+)\]$", selector)
    if suffix is not None:
        dependency_index = int(suffix.group(1))
        base = selector[: suffix.start()]
    if not base.startswith("package[") or not base.endswith("]"):
        return None
    expression = f"dict({base[len('package[') : -1]})"
    try:
        parsed = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise SelectorResolutionError("selector_invalid") from exc
    call = parsed.body
    if (
        not isinstance(call, ast.Call)
        or call.args
        or not isinstance(call.func, ast.Name)
        or call.func.id != "dict"
    ):
        raise SelectorResolutionError("selector_invalid")
    values: dict[str, object] = {}
    for keyword in call.keywords:
        if keyword.arg is None or keyword.arg in values:
            raise SelectorResolutionError("selector_invalid")
        try:
            values[keyword.arg] = ast.literal_eval(keyword.value)
        except (ValueError, TypeError) as exc:
            raise SelectorResolutionError("selector_invalid") from exc
    if set(values) != {"name", "version", "index"}:
        raise SelectorResolutionError("selector_invalid")
    name, version, index = values["name"], values["version"], values["index"]
    if not isinstance(name, str) or not isinstance(index, int) or isinstance(index, bool):
        raise SelectorResolutionError("selector_invalid")
    if version is not None and not isinstance(version, str):
        raise SelectorResolutionError("selector_invalid")
    return name, version, index, dependency_index


def _resolve_toml(text: str, selector: str) -> Selection:
    document = _scan_toml(text)
    uv = _parse_uv_selector(selector)
    if uv is not None:
        return _resolve_uv_toml(text, document, uv)
    if selector == "project":
        sections = [section for section in document.sections if section.path == ("project",)]
        if len(sections) != 1:
            raise SelectorResolutionError("selector_stale")
        return _toml_span_selection(
            text, sections[0].start, sections[0].end, document.value.get("project")
        )
    match = re.fullmatch(r"(.+)\[([0-9]+)\]", selector)
    if match is None:
        raise SelectorResolutionError("selector_invalid")
    path_text, index_text = match.groups()
    candidates = [
        assignment for assignment in document.assignments if ".".join(assignment.path) == path_text
    ]
    if len(candidates) != 1:
        raise SelectorResolutionError("selector_ambiguous" if candidates else "selector_stale")
    spans = _array_element_spans(text, candidates[0].value_start, candidates[0].value_end)
    element_index = int(index_text)
    if element_index >= len(spans):
        raise SelectorResolutionError("selector_stale")
    start, end = spans[element_index]
    value = _toml_semantic_value(document.value, candidates[0].path, element_index)
    return _toml_span_selection(text, start, end, value)


def _resolve_uv_toml(
    text: str,
    document: _TomlDocument,
    uv: tuple[str, str | None, int, int | None],
) -> Selection:
    name, version, package_index, dependency_index = uv
    packages = document.value.get("package")
    if not isinstance(packages, list) or package_index >= len(packages):
        raise SelectorResolutionError("selector_stale")
    package = packages[package_index]
    if (
        not isinstance(package, dict)
        or package.get("name") != name
        or package.get("version") != version
    ):
        raise SelectorResolutionError("selector_stale")
    sections = [
        section
        for section in document.sections
        if section.path == ("package",) and section.index == package_index
    ]
    if len(sections) != 1:
        raise SelectorResolutionError("selector_ambiguous")
    if dependency_index is None:
        section = sections[0]
        return _toml_span_selection(text, section.start, section.end, package)
    assignments = [
        assignment
        for assignment in document.assignments
        if assignment.section_path == ("package",)
        and assignment.section_index == package_index
        and assignment.path == ("package", "dependencies")
    ]
    if len(assignments) != 1:
        raise SelectorResolutionError("selector_stale")
    spans = _array_element_spans(text, assignments[0].value_start, assignments[0].value_end)
    dependencies = package.get("dependencies")
    if (
        not isinstance(dependencies, list)
        or dependency_index >= len(dependencies)
        or dependency_index >= len(spans)
    ):
        raise SelectorResolutionError("selector_stale")
    start, end = spans[dependency_index]
    return _toml_span_selection(text, start, end, dependencies[dependency_index])


def _toml_semantic_value(
    document: dict[str, object], path: tuple[str, ...], element_index: int
) -> object:
    current: object = document
    for part in path:
        if not isinstance(current, dict) or part not in current:
            raise SelectorResolutionError("selector_stale")
        current = current[part]
    if not isinstance(current, list) or element_index >= len(current):
        raise SelectorResolutionError("selector_stale")
    return current[element_index]


def _toml_span_selection(text: str, start: int, end: int, value: object) -> Selection:
    while start < end and text[start] in " \t\r\n":
        start += 1
    while end > start and text[end - 1] in " \t\r\n":
        end -= 1
    if start >= end:
        raise SelectorResolutionError("selector_stale")
    return Selection(
        text=_normalize_display_newlines(text[start:end]),
        line_range=_line_range(text, start, end),
        value=value,
    )


def selection_supports_component(
    selection: Selection,
    selector: SourceSelector,
    component: DependencyComponent,
) -> bool:
    try:
        if selector.kind == SelectorKind.JSON_POINTER:
            return _json_supports_component(selection, component)
        if selector.kind == SelectorKind.TOML:
            return _toml_supports_component(selection, component)
        if selector.kind == SelectorKind.LINE:
            return _line_supports_component(selection.text, component)
    except (InvalidRequirement, ValueError, TypeError):
        return False


def _json_supports_component(selection: Selection, component: DependencyComponent) -> bool:
    if isinstance(selection.value, str) and selection.key is not None:
        return normalize_package_name(
            Ecosystem.NPM, selection.key
        ) == component.normalized_name and (
            component.version is None or selection.value == component.version
        )
    if isinstance(selection.value, dict):
        raw_name = selection.value.get("name")
        if raw_name is None and selection.key is not None and "node_modules/" in selection.key:
            suffix = selection.key.rsplit("node_modules/", 1)[1]
            parts = suffix.split("/")
            raw_name = (
                f"{parts[0]}/{parts[1]}"
                if parts[0].startswith("@") and len(parts) > 1
                else parts[0]
            )
        if not isinstance(raw_name, str):
            return False
        version = selection.value.get("version")
        return normalize_package_name(Ecosystem.NPM, raw_name) == component.normalized_name and (
            component.version is None or version == component.version
        )
    return False


def _toml_supports_component(selection: Selection, component: DependencyComponent) -> bool:
    if isinstance(selection.value, str):
        requirement = Requirement(selection.value)
        if normalize_package_name(Ecosystem.PYPI, requirement.name) != component.normalized_name:
            return False
        return _requirement_supports_version(requirement, component)
    if isinstance(selection.value, dict):
        name = selection.value.get("name")
        version = selection.value.get("version")
        return (
            isinstance(name, str)
            and normalize_package_name(Ecosystem.PYPI, name) == component.normalized_name
            and (component.version is None or version == component.version)
        )
    return False


def _line_supports_component(text: str, component: DependencyComponent) -> bool:
    logical = re.sub(r"\\\s*\n", " ", text).strip()
    if component.ecosystem == Ecosystem.PYPI:
        if logical.startswith(("-e ", "--editable ")):
            logical = logical.split(maxsplit=1)[1]
        logical = re.sub(r"\s+--hash(?:=|\s+)\S+", "", logical)
        logical = re.split(r"\s+#", logical, maxsplit=1)[0].rstrip()
        requirement = Requirement(logical)
        if normalize_package_name(Ecosystem.PYPI, requirement.name) != component.normalized_name:
            return False
        return _requirement_supports_version(requirement, component)
    if component.ecosystem == Ecosystem.GO:
        tokens = logical.split("//", 1)[0].split()
        return component.name in tokens
    return False


def _requirement_supports_version(requirement: Requirement, component: DependencyComponent) -> bool:
    if component.version is None:
        return not requirement.specifier and requirement.url is None
    if component.version_kind == VersionKind.EXACT:
        specifiers = tuple(requirement.specifier)
        return (
            len(specifiers) == 1
            and specifiers[0].operator in {"==", "==="}
            and specifiers[0].version == component.version
        )
    rendered_version = str(requirement.specifier) or requirement.url
    return rendered_version == component.version
