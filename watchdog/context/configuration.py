from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass

from watchdog.context._recognition import (
    RecognitionBudget,
    RecognitionLimitExceeded,
    RecognitionResult,
    RecognizedFact,
    finish_result,
)
from watchdog.context.discovery import DiscoveredSource
from watchdog.domain.context import (
    ContextAnchor,
    ContextLimitation,
    ContextRuleCatalog,
    ContextTarget,
    ObservationKind,
    SourceLanguage,
)


class _DuplicateKey(Exception):
    pass


@dataclass(frozen=True, slots=True)
class _KeyAnchor:
    key: str
    anchor: ContextAnchor


def recognize_configuration(
    source: DiscoveredSource,
    targets: tuple[ContextTarget, ...],
    catalog: ContextRuleCatalog,
    budget: RecognitionBudget,
) -> RecognitionResult:
    facts: list[RecognizedFact] = []
    try:
        text = source.content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        budget.limitations.add(ContextLimitation.INVALID_UTF8)
        return finish_result(source, facts, budget)
    try:
        if source.language == SourceLanguage.JSON:
            anchors = _json_keys(text, budget)
        elif source.language == SourceLanguage.TOML:
            anchors = _toml_keys(text, budget)
        else:
            budget.limitations.add(ContextLimitation.UNSUPPORTED_SYNTAX)
            return finish_result(source, facts, budget)
    except RecognitionLimitExceeded:
        return finish_result(source, facts, budget)
    except (_DuplicateKey, RecursionError, json.JSONDecodeError, tomllib.TOMLDecodeError):
        budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
        return finish_result(source, facts, budget)

    for target in targets:
        rules = [
            rule
            for rule in catalog.configuration_rules
            if rule.id in target.configuration_rule_ids and source.path in rule.normalized_paths
        ]
        for key_anchor in anchors:
            for rule in rules:
                budget.check()
                if key_anchor.key not in rule.keys:
                    continue
                _append_fact(
                    facts,
                    RecognizedFact(
                        kind=ObservationKind.TARGET_CONFIGURATION,
                        match_ordinal=target.match_ordinal,
                        target_id=target.id,
                        path=source.path,
                        anchor=key_anchor.anchor,
                        rule_id=rule.id,
                    ),
                    budget,
                )
    return finish_result(source, facts, budget)


def _json_keys(text: str, budget: RecognitionBudget) -> tuple[_KeyAnchor, ...]:
    _validate_json_depth(text, budget)

    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise _DuplicateKey
            result[key] = value
        return result

    json.loads(
        text,
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(_DuplicateKey()),
    )
    anchors: list[_KeyAnchor] = []
    index = 0
    line = 1
    column = 0
    while index < len(text):
        budget.check()
        character = text[index]
        if character in "\r\n":
            index, line, column = _advance(text, index, line, column)
            continue
        if character != '"':
            if not character.isspace():
                budget.token()
            index += 1
            column += 1
            continue
        budget.token()
        start_index = index
        start_line, start_column = line, column
        index += 1
        column += 1
        escaped = False
        while index < len(text):
            if text[index] == "\\":
                escaped = True
                index += 2
                column += 2
                continue
            if text[index] == '"':
                index += 1
                column += 1
                break
            index, line, column = _advance(text, index, line, column)
        cursor = index
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor >= len(text) or text[cursor] != ":":
            continue
        try:
            key = json.loads(text[start_index:index])
        except json.JSONDecodeError:
            continue
        if not isinstance(key, str):
            continue
        if escaped:
            budget.limitations.add(ContextLimitation.UNSUPPORTED_SYNTAX)
        anchors.append(
            _KeyAnchor(
                key=key,
                anchor=ContextAnchor(
                    start_line=start_line,
                    start_column=start_column,
                    end_line=line,
                    end_column=column,
                ),
            )
        )
    return tuple(anchors)


def _validate_json_depth(text: str, budget: RecognitionBudget) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        budget.check()
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "{[":
            depth += 1
            if depth > budget.limits.max_nesting_depth:
                budget.limitations.add(ContextLimitation.NESTING_DEPTH_EXCEEDED)
                raise RecognitionLimitExceeded
        elif character in "}]":
            depth -= 1
            if depth < 0:
                return


def _toml_keys(text: str, budget: RecognitionBudget) -> tuple[_KeyAnchor, ...]:
    tomllib.loads(text)
    anchors: list[_KeyAnchor] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        budget.check()
        separator = _toml_assignment_separator(line)
        if separator is None:
            continue
        budget.token()
        raw_key = line[:separator].strip()
        if not raw_key or raw_key.startswith("["):
            continue
        segment = raw_key.rsplit(".", 1)[-1].strip()
        if not segment or not all(
            character.isascii() and (character.isalnum() or character in "_-")
            for character in segment
        ):
            budget.limitations.add(ContextLimitation.UNSUPPORTED_SYNTAX)
            continue
        start_column = line.find(segment)
        anchors.append(
            _KeyAnchor(
                key=segment,
                anchor=ContextAnchor(
                    start_line=line_number,
                    start_column=start_column,
                    end_line=line_number,
                    end_column=start_column + len(segment),
                ),
            )
        )
    return tuple(anchors)


def _toml_assignment_separator(line: str) -> int | None:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(line):
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\" and quote == '"':
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "#":
            return None
        elif character == "=":
            return index
    return None


def _advance(text: str, index: int, line: int, column: int) -> tuple[int, int, int]:
    if text[index] == "\r":
        if index + 1 < len(text) and text[index + 1] == "\n":
            index += 1
        return index + 1, line + 1, 0
    if text[index] == "\n":
        return index + 1, line + 1, 0
    return index + 1, line, column + 1


def _append_fact(
    facts: list[RecognizedFact], fact: RecognizedFact, budget: RecognitionBudget
) -> None:
    if len(facts) >= budget.limits.max_observations:
        budget.limitations.add(ContextLimitation.OBSERVATION_LIMIT_EXCEEDED)
        return
    facts.append(fact)
