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
    imported_members: tuple[str, ...]
    target: ContextTarget


def recognize_javascript(
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
        tokens, malformed = _lex(text, budget)
    except RecognitionLimitExceeded:
        return finish_result(source, facts, budget)
    if malformed or _invalid_delimiters(tokens, budget):
        budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
        return finish_result(source, facts, budget)
    if any(item.value in {"interface", "namespace", "type"} for item in tokens):
        budget.limitations.add(ContextLimitation.UNSUPPORTED_SYNTAX)
    if any(item.value in {"<", ">"} for item in tokens):
        budget.limitations.add(ContextLimitation.UNSUPPORTED_SYNTAX)

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
        if index > 0 and tokens[index - 1].value in {".", "?."}:
            continue
        if index + 1 < len(tokens) and tokens[index + 1].value == "[":
            budget.limitations.add(ContextLimitation.COMPUTED_MEMBER_UNSUPPORTED)
            continue
        members, last_index = _member_chain(tokens, index, budget)
        next_index = last_index + 1 if last_index + 1 < len(tokens) else None
        call_end = (
            _call_end(tokens, next_index, budget)
            if next_index is not None and tokens[next_index].value == "("
            else None
        )
        for binding in bindings[item.value]:
            full_members = (*binding.imported_members, *members)
            reference_anchor = _anchor(item, tokens[last_index])
            _append_fact(
                facts,
                RecognizedFact(
                    kind=ObservationKind.TARGET_REFERENCE,
                    match_ordinal=binding.target.match_ordinal,
                    target_id=binding.target.id,
                    path=source.path,
                    anchor=reference_anchor,
                    binding=binding.name,
                    member_path=full_members,
                ),
                budget,
            )
            if call_end is None:
                configuration = _configuration_assignment(
                    tokens,
                    last_index,
                    full_members,
                    binding.target,
                    catalog,
                    budget,
                )
                if configuration is not None:
                    rule_id, value_end = configuration
                    _append_fact(
                        facts,
                        RecognizedFact(
                            kind=ObservationKind.TARGET_CONFIGURATION,
                            match_ordinal=binding.target.match_ordinal,
                            target_id=binding.target.id,
                            path=source.path,
                            anchor=_anchor(item, tokens[value_end]),
                            binding=binding.name,
                            member_path=full_members,
                            rule_id=rule_id,
                        ),
                        budget,
                    )
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
                    member_path=full_members,
                    rule_id=_member_rule_id(full_members, binding.target, catalog),
                ),
                budget,
            )
            endpoint_rule = _endpoint_rule_id(full_members, binding.target, catalog)
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
                        member_path=full_members,
                        rule_id=endpoint_rule,
                    ),
                    budget,
                )
            assert next_index is not None
            for rule_id, key in _configuration_properties(
                tokens,
                next_index,
                call_end,
                binding.target,
                catalog,
                budget,
            ):
                _append_fact(
                    facts,
                    RecognizedFact(
                        kind=ObservationKind.TARGET_CONFIGURATION,
                        match_ordinal=binding.target.match_ordinal,
                        target_id=binding.target.id,
                        path=source.path,
                        anchor=call_anchor,
                        binding=binding.name,
                        member_path=(*full_members, key),
                        rule_id=rule_id,
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
        if character == "/":
            # Regular-expression literals require grammar context to distinguish
            # them from division. Omit the remainder of the statement instead of
            # interpreting hostile regex contents as identifiers or calls.
            budget.limitations.add(ContextLimitation.UNSUPPORTED_SYNTAX)
            while index < len(text) and text[index] not in "\r\n;":
                index += 1
                column += 1
            continue
        if character in {'"', "'"}:
            start_line, start_column = line, column
            quote = character
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
                if current == quote:
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
            interpolated = False
            closed = False
            while index < len(text):
                if text.startswith("${", index):
                    interpolated = True
                if text[index] == "\\":
                    index += 1
                    column += 1
                    if index < len(text):
                        index, line, column = _advance(text, index, line, column)
                    continue
                if text[index] == "`":
                    index += 1
                    column += 1
                    closed = True
                    break
                index, line, column = _advance(text, index, line, column)
            if not closed:
                malformed = True
                break
            if interpolated:
                budget.limitations.add(ContextLimitation.TEMPLATE_INTERPOLATION_UNSUPPORTED)
            _emit(
                tokens,
                budget,
                "template",
                "",
                start_line,
                start_column,
                line,
                column,
            )
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
                for value in ("?.", "=>", "===", "!==", "==", "!=", "&&", "||")
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
        budget.check()
        if item.value == "export":
            end = _statement_end(tokens, index)
            if any(token.value == "from" for token in tokens[index:end]):
                budget.limitations.add(ContextLimitation.REEXPORT_UNSUPPORTED)
                import_indices.update(range(index, end))
            continue
        if item.value == "import":
            if index > 0 and tokens[index - 1].value in {".", "?.", "export"}:
                continue
            if index + 1 < len(tokens) and tokens[index + 1].value == "(":
                _call_import(
                    source,
                    tokens,
                    index,
                    "import",
                    targets,
                    bindings,
                    import_indices,
                    facts,
                    budget,
                )
            else:
                _static_import(
                    source,
                    tokens,
                    index,
                    targets,
                    bindings,
                    import_indices,
                    facts,
                    budget,
                )
        elif (
            item.value == "require"
            and (index == 0 or tokens[index - 1].value not in {".", "?."})
            and index + 1 < len(tokens)
            and tokens[index + 1].value == "("
        ):
            if _global_name_is_shadowed(tokens, "require"):
                budget.limitations.add(ContextLimitation.AMBIGUOUS_BINDING)
                continue
            _call_import(
                source,
                tokens,
                index,
                "require",
                targets,
                bindings,
                import_indices,
                facts,
                budget,
            )


def _static_import(
    source: DiscoveredSource,
    tokens: list[_Token],
    start: int,
    targets: tuple[ContextTarget, ...],
    bindings: dict[str, list[_Binding]],
    import_indices: set[int],
    facts: list[RecognizedFact],
    budget: RecognitionBudget,
) -> None:
    end = _statement_end(tokens, start)
    import_indices.update(range(start, end))
    string_index = next(
        (
            index
            for index in range(start + 1, end)
            if tokens[index].kind in {"string", "ambiguous_string"}
        ),
        None,
    )
    if string_index is None or tokens[string_index].kind != "string":
        budget.limitations.add(ContextLimitation.DYNAMIC_IMPORT_UNSUPPORTED)
        return
    imported = tokens[string_index].value
    imported_bindings = _static_import_bindings(tokens, start, string_index, end)
    if imported_bindings is None:
        budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
        return
    _record_import(
        source,
        imported,
        imported_bindings,
        targets,
        bindings,
        tokens[start],
        tokens[string_index],
        facts,
        budget,
    )


def _static_import_bindings(
    tokens: list[_Token], start: int, string_index: int, end: int
) -> list[tuple[str, tuple[str, ...]]] | None:
    trailing = [item for item in tokens[string_index + 1 : end] if item.value not in {";", "\n"}]
    if trailing:
        return None
    prefix = [item for item in tokens[start + 1 : string_index] if item.value != "\n"]
    if not prefix:
        return []
    if prefix[-1].value != "from":
        return None
    clause = prefix[:-1]
    if not clause:
        return None
    bindings: list[tuple[str, tuple[str, ...]]] = []
    index = 0
    if clause[index].kind == "identifier":
        bindings.append((clause[index].value, ()))
        index += 1
        if index == len(clause):
            return bindings
        if clause[index].value != ",":
            return None
        index += 1
    if index >= len(clause):
        return None
    if clause[index].value == "*":
        if (
            index + 2 != len(clause) - 1
            or clause[index + 1].value != "as"
            or clause[index + 2].kind != "identifier"
        ):
            return None
        bindings.append((clause[index + 2].value, ()))
        return bindings
    if clause[index].value != "{" or clause[-1].value != "}":
        return None
    index += 1
    while index < len(clause) - 1:
        if clause[index].value == ",":
            index += 1
            continue
        if clause[index].kind != "identifier":
            return None
        member = clause[index].value
        alias = member
        index += 1
        if index < len(clause) - 1 and clause[index].value == "as":
            if index + 1 >= len(clause) - 1 or clause[index + 1].kind != "identifier":
                return None
            alias = clause[index + 1].value
            index += 2
        if index < len(clause) - 1 and clause[index].value != ",":
            return None
        bindings.append((alias, (member,)))
    return bindings


def _call_import(
    source: DiscoveredSource,
    tokens: list[_Token],
    start: int,
    form: str,
    targets: tuple[ContextTarget, ...],
    bindings: dict[str, list[_Binding]],
    import_indices: set[int],
    facts: list[RecognizedFact],
    budget: RecognitionBudget,
) -> None:
    close = _call_end(tokens, start + 1, budget)
    if close is None:
        budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
        return
    end = _statement_end(tokens, start)
    import_indices.update(range(max(0, _statement_start(tokens, start)), end))
    if close != start + 3 or tokens[start + 2].kind != "string":
        budget.limitations.add(ContextLimitation.DYNAMIC_IMPORT_UNSUPPORTED)
        return
    binding: str | None = None
    previous = start - 1
    if (
        previous >= 1
        and tokens[previous].value == "="
        and tokens[previous - 1].kind == "identifier"
    ):
        binding = tokens[previous - 1].value
    elif (
        previous >= 2
        and tokens[previous].value == "await"
        and tokens[previous - 1].value == "="
        and tokens[previous - 2].kind == "identifier"
    ):
        binding = tokens[previous - 2].value
    imported_bindings: list[tuple[str, tuple[str, ...]]] = (
        [(binding, ())] if binding is not None else []
    )
    _record_import(
        source,
        tokens[start + 2].value,
        imported_bindings,
        targets,
        bindings,
        tokens[start],
        tokens[close],
        facts,
        budget,
    )
    if form == "import" and binding is None:
        budget.limitations.add(ContextLimitation.DYNAMIC_IMPORT_UNSUPPORTED)


def _record_import(
    source: DiscoveredSource,
    imported: str,
    imported_bindings: list[tuple[str, tuple[str, ...]]],
    targets: tuple[ContextTarget, ...],
    bindings: dict[str, list[_Binding]],
    start: _Token,
    end: _Token,
    facts: list[RecognizedFact],
    budget: RecognitionBudget,
) -> None:
    for target in targets:
        if not target_matches_import(target, imported):
            continue
        bindings_to_record: tuple[tuple[str | None, tuple[str, ...]], ...] = (
            tuple(imported_bindings) if imported_bindings else ((None, ()),)
        )
        for name, members in bindings_to_record:
            _append_fact(
                facts,
                RecognizedFact(
                    kind=ObservationKind.IMPORT_DECLARATION,
                    match_ordinal=target.match_ordinal,
                    target_id=target.id,
                    path=source.path,
                    anchor=_anchor(start, end),
                    binding=name,
                    member_path=members,
                ),
                budget,
            )
            if name is None:
                continue
            bindings.setdefault(name, []).append(
                _Binding(name=name, imported_members=members, target=target)
            )


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
            previous in {"const", "let", "var", "function", "class", "catch"}
            or (index + 1 < len(tokens) and tokens[index + 1].value in {"=", "=>"})
            or _is_parameter_binding(tokens, index)
        ):
            shadowed.add(item.value)
    return shadowed


def _global_name_is_shadowed(tokens: list[_Token], name: str) -> bool:
    for index, item in enumerate(tokens):
        if item.kind != "identifier" or item.value != name:
            continue
        previous = tokens[index - 1].value if index > 0 else None
        if (
            previous in {"catch", "class", "const", "function", "let", "var"}
            or index + 1 < len(tokens)
            and tokens[index + 1].value in {"=", "=>"}
            or _is_parameter_binding(tokens, index)
        ):
            return True
    return False


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
        elif depth == 0 and value in {";", "{", "}"}:
            break
    if opening is None:
        return False
    depth = 0
    closing: int | None = None
    for candidate in range(opening, len(tokens)):
        value = tokens[candidate].value
        if value == "(":
            depth += 1
        elif value == ")":
            depth -= 1
            if depth == 0:
                closing = candidate
                break
    if closing is None or index >= closing:
        return False
    prefix = {item.value for item in tokens[max(0, opening - 3) : opening]}
    return bool(prefix & {"function", "catch"}) or (
        closing + 1 < len(tokens) and tokens[closing + 1].value == "=>"
    )


def _member_chain(
    tokens: list[_Token], start: int, budget: RecognitionBudget
) -> tuple[tuple[str, ...], int]:
    members: list[str] = []
    last = start
    index = start + 1
    while index < len(tokens) and tokens[index].value in {".", "?."}:
        if tokens[index].value == "?.":
            budget.limitations.add(ContextLimitation.UNSUPPORTED_SYNTAX)
        if index + 1 >= len(tokens) or tokens[index + 1].kind != "identifier":
            break
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


def _configuration_properties(
    tokens: list[_Token],
    opening: int,
    closing: int,
    target: ContextTarget,
    catalog: ContextRuleCatalog,
    budget: RecognitionBudget,
) -> tuple[tuple[str, str], ...]:
    rules = [
        rule for rule in catalog.configuration_rules if rule.id in target.configuration_rule_ids
    ]
    found: set[tuple[str, str]] = set()
    for index in range(opening + 1, closing - 1):
        if (
            tokens[index].kind not in {"identifier", "string"}
            or tokens[index + 1].value != ":"
            or tokens[index - 1].value not in {",", "{"}
        ):
            continue
        for rule in rules:
            if tokens[index].value in rule.keys:
                value_index = index + 2
                value_end = _literal_end(tokens, value_index, stop=closing)
                next_value = (
                    tokens[value_end + 1].value
                    if value_end is not None and value_end + 1 <= closing
                    else None
                )
                if value_end is not None and next_value in {",", ")", "]", "}"}:
                    found.add((rule.id, tokens[index].value))
                else:
                    budget.limitations.add(ContextLimitation.UNSUPPORTED_SYNTAX)
    return tuple(sorted(found))


def _configuration_assignment(
    tokens: list[_Token],
    last: int,
    members: tuple[str, ...],
    target: ContextTarget,
    catalog: ContextRuleCatalog,
    budget: RecognitionBudget,
) -> tuple[str, int] | None:
    rule_id = _configuration_rule_id(members, target, catalog)
    if last + 1 >= len(tokens) or tokens[last + 1].value != "=" or rule_id is None:
        return None
    statement_end = _statement_end(tokens, last + 2)
    value_end = _literal_end(tokens, last + 2, stop=statement_end)
    if value_end is None or any(
        item.value not in {";", "\n"} for item in tokens[value_end + 1 : statement_end]
    ):
        budget.limitations.add(ContextLimitation.UNSUPPORTED_SYNTAX)
        return None
    return rule_id, value_end


def _literal_end(tokens: list[_Token], start: int, *, stop: int) -> int | None:
    if start >= stop:
        return None
    item = tokens[start]
    if (
        item.kind == "string"
        or item.kind == "identifier"
        and item.value
        in {
            "false",
            "null",
            "true",
        }
    ):
        return start
    if item.value in {"+", "-"}:
        number_end = _number_end(tokens, start + 1, stop=stop)
        return number_end
    number_end = _number_end(tokens, start, stop=stop)
    if number_end is not None:
        return number_end
    pairs = {"[": "]", "{": "}"}
    closing = pairs.get(item.value)
    if closing is None:
        return None
    index = start + 1
    if index < stop and tokens[index].value == closing:
        return index
    while index < stop:
        if item.value == "{":
            if tokens[index].kind not in {"identifier", "string"}:
                return None
            index += 1
            if index >= stop or tokens[index].value != ":":
                return None
            index += 1
        value_end = _literal_end(tokens, index, stop=stop)
        if value_end is None:
            return None
        index = value_end + 1
        if index >= stop:
            return None
        if tokens[index].value == closing:
            return index
        if tokens[index].value != ",":
            return None
        index += 1
        if index < stop and tokens[index].value == closing:
            return index
    return None


def _number_end(tokens: list[_Token], start: int, *, stop: int) -> int | None:
    if start >= stop or tokens[start].value not in set("0123456789"):
        return None
    index = start
    seen_dot = False
    while index + 1 < stop:
        value = tokens[index + 1].value
        if value in set("0123456789"):
            index += 1
            continue
        if value == "." and not seen_dot:
            seen_dot = True
            index += 1
            continue
        break
    return index


def _configuration_rule_id(
    members: tuple[str, ...], target: ContextTarget, catalog: ContextRuleCatalog
) -> str | None:
    if not members:
        return None
    for rule in catalog.configuration_rules:
        if rule.id in target.configuration_rule_ids and members[-1] in rule.keys:
            return rule.id
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


def _statement_start(tokens: list[_Token], index: int) -> int:
    while index > 0 and tokens[index - 1].value not in {";", "\n"}:
        index -= 1
    return index


def _statement_end(tokens: list[_Token], index: int) -> int:
    depth = 0
    while index < len(tokens):
        if tokens[index].value in {"(", "[", "{"}:
            depth += 1
        elif tokens[index].value in {")", "]", "}"}:
            depth -= 1
        elif depth == 0 and tokens[index].value in {";", "\n"}:
            return index + 1
        index += 1
    return len(tokens)


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
    return value == "_" or value == "$" or value.isalpha()


def _identifier_continue(value: str) -> bool:
    return _identifier_start(value) or value.isdigit()


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
