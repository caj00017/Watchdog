from __future__ import annotations

from dataclasses import dataclass, field

from watchdog.context._recognition import (
    RecognitionBudget,
    RecognitionLimitExceeded,
    RecognitionResult,
    RecognizedFact,
    finish_result,
    target_matches_import,
)
from watchdog.context.discovery import DiscoveredSource
from watchdog.domain.context import (
    ContextAnchor,
    ContextLimitation,
    ContextRuleCatalog,
    ContextTarget,
    ObservationKind,
)


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    line: int
    column: int
    end_line: int
    end_column: int
    value: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class _Binding:
    name: str
    target: ContextTarget


def recognize_go(
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
    lines = text.splitlines()
    if any(
        line.lstrip().startswith("// Code generated") and "DO NOT EDIT." in line
        for line in lines[:20]
    ):
        budget.limitations.add(ContextLimitation.GENERATED_FILE_OMITTED)
        return finish_result(source, facts, budget)
    if any(line.startswith("//go:build") or line.startswith("// +build") for line in lines[:20]):
        budget.limitations.add(ContextLimitation.BUILD_CONSTRAINT_UNEVALUATED)
    try:
        tokens, malformed = _lex(text, budget)
    except RecognitionLimitExceeded:
        return finish_result(source, facts, budget)
    if malformed or _invalid_delimiters(tokens, budget):
        budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
        return finish_result(source, facts, budget)
    if any(item.value in {"interface", "reflect"} for item in tokens):
        budget.limitations.add(ContextLimitation.DYNAMIC_DISPATCH_UNRESOLVED)

    bindings: dict[str, list[_Binding]] = {}
    import_indices: set[int] = set()
    _collect_imports(
        source,
        tokens,
        targets,
        bindings,
        import_indices,
        facts,
        budget,
    )
    shadowed = _shadowed_bindings(tokens, bindings, import_indices)
    if shadowed:
        budget.limitations.add(ContextLimitation.AMBIGUOUS_BINDING)
    for index, item in enumerate(tokens):
        budget.check()
        if (
            index in import_indices
            or item.kind != "identifier"
            or item.value not in bindings
            or item.value in shadowed
        ):
            continue
        if index > 0 and tokens[index - 1].value == ".":
            continue
        members, last = _member_chain(tokens, index)
        if not members:
            continue
        next_index = last + 1 if last + 1 < len(tokens) else None
        call_end = (
            _call_end(tokens, next_index, budget)
            if next_index is not None and tokens[next_index].value == "("
            else None
        )
        for binding in bindings[item.value]:
            reference_anchor = _anchor(item, tokens[last])
            _append_fact(
                facts,
                RecognizedFact(
                    kind=ObservationKind.TARGET_REFERENCE,
                    match_ordinal=binding.target.match_ordinal,
                    target_id=binding.target.id,
                    path=source.path,
                    anchor=reference_anchor,
                    binding=binding.name,
                    member_path=members,
                ),
                budget,
            )
            if call_end is None:
                continue
            call_anchor = _anchor(item, tokens[call_end])
            if _line_span(call_anchor) > budget.limits.max_line_span:
                budget.limitations.add(ContextLimitation.LINE_SPAN_LIMIT_EXCEEDED)
                continue
            _append_fact(
                facts,
                RecognizedFact(
                    kind=ObservationKind.EXPLICIT_CALL,
                    match_ordinal=binding.target.match_ordinal,
                    target_id=binding.target.id,
                    path=source.path,
                    anchor=call_anchor,
                    binding=binding.name,
                    member_path=members,
                    rule_id=_member_rule_id(members, binding.target, catalog),
                ),
                budget,
            )
            endpoint_rule = _endpoint_rule_id(members, binding.target, catalog)
            if endpoint_rule is not None:
                _append_fact(
                    facts,
                    RecognizedFact(
                        kind=ObservationKind.ENDPOINT_DECLARATION,
                        match_ordinal=binding.target.match_ordinal,
                        target_id=binding.target.id,
                        path=source.path,
                        anchor=call_anchor,
                        binding=binding.name,
                        member_path=members,
                        rule_id=endpoint_rule,
                    ),
                    budget,
                )
    return finish_result(source, facts, budget)


def _lex(text: str, budget: RecognitionBudget) -> tuple[list[_Token], bool]:
    tokens: list[_Token] = []
    index = 0
    line = 1
    column = 0
    malformed = False
    while index < len(text):
        budget.check()
        character = text[index]
        if character in " \t\f\v":
            index += 1
            column += 1
            continue
        if character in "\r\n":
            start_line, start_column = line, column
            if character == "\r" and index + 1 < len(text) and text[index + 1] == "\n":
                index += 1
            index += 1
            line += 1
            column = 0
            _emit(tokens, budget, "newline", "\n", start_line, start_column, line, column)
            continue
        if text.startswith("//", index):
            while index < len(text) and text[index] not in "\r\n":
                index += 1
                column += 1
            continue
        if text.startswith("/*", index):
            index += 2
            column += 2
            closed = False
            while index < len(text):
                if text.startswith("*/", index):
                    index += 2
                    column += 2
                    closed = True
                    break
                index, line, column = _advance(text, index, line, column)
            if not closed:
                malformed = True
                break
            continue
        if character == '"':
            start_line, start_column = line, column
            index += 1
            column += 1
            string_value: list[str] = []
            escaped = False
            closed = False
            while index < len(text):
                current = text[index]
                if current in "\r\n":
                    break
                if current == "\\":
                    escaped = True
                    index += 1
                    column += 1
                    if index < len(text):
                        string_value.append(text[index])
                        index += 1
                        column += 1
                    continue
                if current == '"':
                    index += 1
                    column += 1
                    closed = True
                    break
                string_value.append(current)
                index += 1
                column += 1
            if not closed:
                malformed = True
                break
            _emit(
                tokens,
                budget,
                "ambiguous_string" if escaped else "string",
                "".join(string_value),
                start_line,
                start_column,
                line,
                column,
            )
            continue
        if character == "`":
            start_line, start_column = line, column
            index += 1
            column += 1
            raw_value: list[str] = []
            closed = False
            while index < len(text):
                if text[index] == "`":
                    index += 1
                    column += 1
                    closed = True
                    break
                raw_value.append(text[index])
                index, line, column = _advance(text, index, line, column)
            if not closed:
                malformed = True
                break
            _emit(
                tokens,
                budget,
                "string",
                "".join(raw_value),
                start_line,
                start_column,
                line,
                column,
            )
            continue
        if character == "'":
            start_line, start_column = line, column
            index += 1
            column += 1
            closed = False
            while index < len(text) and text[index] not in "\r\n":
                if text[index] == "\\":
                    index += 1
                    column += 1
                elif text[index] == "'":
                    index += 1
                    column += 1
                    closed = True
                    break
                else:
                    index += 1
                    column += 1
            if not closed:
                malformed = True
                break
            _emit(tokens, budget, "rune", "", start_line, start_column, line, column)
            continue
        if _identifier_start(character):
            start = index
            start_column = column
            while index < len(text) and _identifier_continue(text[index]):
                index += 1
                column += 1
            value = text[start:index]
            if not value.isascii():
                budget.limitations.add(ContextLimitation.UNSUPPORTED_SYNTAX)
            _emit(tokens, budget, "identifier", value, line, start_column, line, column)
            continue
        start_column = column
        punctuator = next(
            (
                value
                for value in (":=", "...", "==", "!=", "&&", "||", "<-", "++", "--")
                if text.startswith(value, index)
            ),
            character,
        )
        index += len(punctuator)
        column += len(punctuator)
        _emit(tokens, budget, "punctuator", punctuator, line, start_column, line, column)
    return tokens, malformed


def _collect_imports(
    source: DiscoveredSource,
    tokens: list[_Token],
    targets: tuple[ContextTarget, ...],
    bindings: dict[str, list[_Binding]],
    import_indices: set[int],
    facts: list[RecognizedFact],
    budget: RecognitionBudget,
) -> None:
    for index, item in enumerate(tokens):
        if item.value != "import":
            continue
        end = _declaration_end(tokens, index)
        import_indices.update(range(index, end))
        cursor = index + 1
        if cursor < end and tokens[cursor].value == "(":
            cursor += 1
            closing = end - 1
        else:
            closing = end
        while cursor < closing:
            budget.check()
            if tokens[cursor].value in {"\n", ";", ")"}:
                cursor += 1
                continue
            alias: str | None = None
            if tokens[cursor].kind == "identifier" or tokens[cursor].value == ".":
                alias = tokens[cursor].value
                cursor += 1
            if cursor >= closing or tokens[cursor].kind not in {"string", "ambiguous_string"}:
                budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
                return
            path_token = tokens[cursor]
            cursor += 1
            if path_token.kind != "string":
                budget.limitations.add(ContextLimitation.UNSUPPORTED_SYNTAX)
                continue
            if path_token.value == "C":
                budget.limitations.add(ContextLimitation.CGO_UNSUPPORTED)
                continue
            imported = path_token.value
            for target in targets:
                if not target_matches_import(target, imported):
                    continue
                if alias == ".":
                    _append_import_fact(source, target, item, path_token, None, facts, budget)
                    budget.limitations.add(ContextLimitation.DOT_IMPORT_UNSUPPORTED)
                    continue
                if alias == "_":
                    _append_import_fact(source, target, item, path_token, None, facts, budget)
                    budget.limitations.add(ContextLimitation.BLANK_IMPORT_UNSUPPORTED)
                    continue
                if alias is None:
                    _append_import_fact(source, target, item, path_token, None, facts, budget)
                    # A Go import path does not prove the imported package's declared
                    # identifier. Without an explicit alias, selector binding is
                    # therefore ambiguous and must not produce reference/call facts.
                    budget.limitations.add(ContextLimitation.AMBIGUOUS_BINDING)
                    continue
                binding = alias
                if not _valid_identifier(binding):
                    budget.limitations.add(ContextLimitation.AMBIGUOUS_BINDING)
                    continue
                _append_import_fact(source, target, item, path_token, binding, facts, budget)
                bindings.setdefault(binding, []).append(_Binding(name=binding, target=target))


def _append_import_fact(
    source: DiscoveredSource,
    target: ContextTarget,
    start: _Token,
    end: _Token,
    binding: str | None,
    facts: list[RecognizedFact],
    budget: RecognitionBudget,
) -> None:
    _append_fact(
        facts,
        RecognizedFact(
            kind=ObservationKind.IMPORT_DECLARATION,
            match_ordinal=target.match_ordinal,
            target_id=target.id,
            path=source.path,
            anchor=_anchor(start, end),
            binding=binding,
        ),
        budget,
    )


def _declaration_end(tokens: list[_Token], start: int) -> int:
    if start + 1 < len(tokens) and tokens[start + 1].value == "(":
        depth = 0
        for index in range(start + 1, len(tokens)):
            if tokens[index].value == "(":
                depth += 1
            elif tokens[index].value == ")":
                depth -= 1
                if depth == 0:
                    return index + 1
        return len(tokens)
    for index in range(start + 1, len(tokens)):
        if tokens[index].value in {"\n", ";"}:
            return index + 1
    return len(tokens)


def _shadowed_bindings(
    tokens: list[_Token], bindings: dict[str, list[_Binding]], import_indices: set[int]
) -> set[str]:
    shadowed = {
        name
        for name, values in bindings.items()
        if len(values) != len({value.target.id for value in values})
    }
    for index, item in enumerate(tokens):
        if index in import_indices or item.kind != "identifier" or item.value not in bindings:
            continue
        previous = tokens[index - 1].value if index > 0 else None
        if (
            previous in {"const", "type", "var"}
            or (index + 1 < len(tokens) and tokens[index + 1].value in {"=", ":="})
            or _is_parameter_binding(tokens, index)
        ):
            shadowed.add(item.value)
    return shadowed


def _is_parameter_binding(tokens: list[_Token], index: int) -> bool:
    depth = 0
    opening: int | None = None
    for candidate in range(index - 1, -1, -1):
        value = tokens[candidate].value
        if value == ")":
            depth += 1
        elif value == "(":
            if depth == 0:
                opening = candidate
                break
            depth -= 1
        elif depth == 0 and value in {"\n", ";", "{", "}"}:
            break
    if opening is None:
        return False
    for candidate in range(opening - 1, -1, -1):
        value = tokens[candidate].value
        if value in {"\n", ";", "{", "}"}:
            return False
        if value == "func":
            return True
    return False


def _member_chain(tokens: list[_Token], start: int) -> tuple[tuple[str, ...], int]:
    members: list[str] = []
    last = start
    index = start + 1
    while (
        index + 1 < len(tokens)
        and tokens[index].value == "."
        and tokens[index + 1].kind == "identifier"
    ):
        members.append(tokens[index + 1].value)
        last = index + 1
        index += 2
    return tuple(members), last


def _call_end(tokens: list[_Token], opening: int | None, budget: RecognitionBudget) -> int | None:
    if opening is None or opening >= len(tokens) or tokens[opening].value != "(":
        return None
    depth = 0
    for index in range(opening, len(tokens)):
        budget.check()
        if tokens[index].value == "(":
            depth += 1
        elif tokens[index].value == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _member_rule_id(
    members: tuple[str, ...], target: ContextTarget, catalog: ContextRuleCatalog
) -> str | None:
    for rule in catalog.member_rules:
        if rule.id in target.member_rule_ids and members == rule.member_path:
            return rule.id
    return None


def _endpoint_rule_id(
    members: tuple[str, ...], target: ContextTarget, catalog: ContextRuleCatalog
) -> str | None:
    for rule in catalog.endpoint_rules:
        if rule.id in target.endpoint_rule_ids and any(
            len(members) >= len(path) and members[-len(path) :] == path
            for path in rule.member_paths
        ):
            return rule.id
    return None


def _invalid_delimiters(tokens: list[_Token], budget: RecognitionBudget) -> bool:
    stack: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for item in tokens:
        if item.value in {"(", "[", "{"}:
            stack.append(item.value)
            if len(stack) > budget.limits.max_nesting_depth:
                budget.limitations.add(ContextLimitation.NESTING_DEPTH_EXCEEDED)
                return True
        elif item.value in pairs and (not stack or stack.pop() != pairs[item.value]):
            return True
    return bool(stack)


def _emit(
    tokens: list[_Token],
    budget: RecognitionBudget,
    kind: str,
    value: str,
    line: int,
    column: int,
    end_line: int,
    end_column: int,
) -> None:
    budget.token()
    tokens.append(
        _Token(
            kind=kind,
            value=value,
            line=line,
            column=column,
            end_line=end_line,
            end_column=end_column,
        )
    )


def _advance(text: str, index: int, line: int, column: int) -> tuple[int, int, int]:
    if text[index] == "\r":
        if index + 1 < len(text) and text[index + 1] == "\n":
            index += 1
        return index + 1, line + 1, 0
    if text[index] == "\n":
        return index + 1, line + 1, 0
    return index + 1, line, column + 1


def _identifier_start(value: str) -> bool:
    return value == "_" or value.isalpha()


def _identifier_continue(value: str) -> bool:
    return _identifier_start(value) or value.isdigit()


def _valid_identifier(value: str) -> bool:
    return (
        bool(value)
        and value.isascii()
        and _identifier_start(value[0])
        and all(_identifier_continue(character) for character in value[1:])
    )


def _anchor(start: _Token, end: _Token) -> ContextAnchor:
    return ContextAnchor(
        start_line=start.line,
        start_column=start.column,
        end_line=end.end_line,
        end_column=end.end_column,
    )


def _line_span(anchor: ContextAnchor) -> int:
    return anchor.end_line - anchor.start_line + 1


def _append_fact(
    facts: list[RecognizedFact], fact: RecognizedFact, budget: RecognitionBudget
) -> None:
    if len(facts) >= budget.limits.max_observations:
        budget.limitations.add(ContextLimitation.OBSERVATION_LIMIT_EXCEEDED)
        return
    facts.append(fact)
