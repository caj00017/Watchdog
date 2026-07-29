from __future__ import annotations

import io
import token
import tokenize
from dataclasses import dataclass

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
class _Binding:
    name: str
    imported_members: tuple[str, ...]
    target: ContextTarget


def recognize_python(
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
        tokens = _tokens(text, budget)
    except RecognitionLimitExceeded:
        return finish_result(source, facts, budget)
    except (IndentationError, SyntaxError, tokenize.TokenError, UnicodeError):
        budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
        return finish_result(source, facts, budget)

    if any(
        (item.type == tokenize.ERRORTOKEN and not item.string.isspace())
        or (item.type == tokenize.OP and item.string not in token.EXACT_TOKEN_TYPES)
        for item in tokens
    ):
        budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
        return finish_result(source, facts, budget)
    if any(token.tok_name.get(item.type, "").startswith("FSTRING") for item in tokens):
        budget.limitations.add(ContextLimitation.UNSUPPORTED_SYNTAX)
    if _invalid_delimiters(tokens, budget):
        return finish_result(source, facts, budget)

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
    if any(
        item.type == tokenize.NAME
        and item.string in {"__import__", "import_module"}
        and _next_index(tokens, index + 1) is not None
        and tokens[_next_index(tokens, index + 1) or 0].string == "("
        for index, item in enumerate(tokens)
    ):
        budget.limitations.add(ContextLimitation.DYNAMIC_IMPORT_UNSUPPORTED)

    shadowed = _shadowed_bindings(tokens, bindings, import_indices)
    if shadowed:
        budget.limitations.add(ContextLimitation.AMBIGUOUS_BINDING)
    for index, item in enumerate(tokens):
        budget.check()
        if (
            index in import_indices
            or item.type != tokenize.NAME
            or item.string not in bindings
            or item.string in shadowed
        ):
            continue
        previous = _previous_index(tokens, index - 1)
        if previous is not None and tokens[previous].string == ".":
            continue
        member_path, last_index = _member_chain(tokens, index)
        next_index = _next_index(tokens, last_index + 1)
        call_end = (
            _call_end(tokens, next_index, budget)
            if next_index is not None and tokens[next_index].string == "("
            else None
        )
        for binding in bindings[item.string]:
            full_members = (*binding.imported_members, *member_path)
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
            member_rule = _member_rule_id(full_members, binding.target, catalog)
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
                    rule_id=member_rule,
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
            for rule_id, key in _configuration_keywords(
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


def _tokens(text: str, budget: RecognitionBudget) -> list[tokenize.TokenInfo]:
    result: list[tokenize.TokenInfo] = []
    for item in tokenize.generate_tokens(io.StringIO(text).readline):
        budget.token()
        if item.type not in {tokenize.ENCODING, tokenize.COMMENT, tokenize.INDENT, tokenize.DEDENT}:
            result.append(item)
    return result


def _invalid_delimiters(tokens: list[tokenize.TokenInfo], budget: RecognitionBudget) -> bool:
    stack: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for item in tokens:
        if item.type != tokenize.OP:
            continue
        if item.string in {"(", "[", "{"}:
            stack.append(item.string)
            if len(stack) > budget.limits.max_nesting_depth:
                budget.limitations.add(ContextLimitation.NESTING_DEPTH_EXCEEDED)
                return True
        elif item.string in pairs and (not stack or stack.pop() != pairs[item.string]):
            budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
            return True
    if stack:
        budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
        return True
    return False


def _collect_imports(
    source: DiscoveredSource,
    tokens: list[tokenize.TokenInfo],
    targets: tuple[ContextTarget, ...],
    bindings: dict[str, list[_Binding]],
    import_indices: set[int],
    facts: list[RecognizedFact],
    budget: RecognitionBudget,
) -> None:
    index = 0
    while index < len(tokens):
        budget.check()
        item = tokens[index]
        if item.type == tokenize.NAME and item.string == "from":
            index = _from_import(
                source, tokens, index, targets, bindings, import_indices, facts, budget
            )
            continue
        if item.type == tokenize.NAME and item.string == "import":
            previous = _previous_index(tokens, index - 1)
            if previous is None or tokens[previous].string != "from":
                index = _direct_import(
                    source, tokens, index, targets, bindings, import_indices, facts, budget
                )
                continue
        index += 1


def _direct_import(
    source: DiscoveredSource,
    tokens: list[tokenize.TokenInfo],
    start: int,
    targets: tuple[ContextTarget, ...],
    bindings: dict[str, list[_Binding]],
    import_indices: set[int],
    facts: list[RecognizedFact],
    budget: RecognitionBudget,
) -> int:
    end = _statement_end(tokens, start)
    import_indices.update(range(start, end))
    index = _next_index(tokens, start + 1, stop=end)
    while index is not None and index < end:
        if tokens[index].type != tokenize.NAME:
            index = _next_index(tokens, index + 1, stop=end)
            continue
        module_parts = [tokens[index].string]
        last = index
        cursor = _next_index(tokens, index + 1, stop=end)
        while cursor is not None and tokens[cursor].string == ".":
            name_index = _next_index(tokens, cursor + 1, stop=end)
            if name_index is None or tokens[name_index].type != tokenize.NAME:
                budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
                return end
            module_parts.append(tokens[name_index].string)
            last = name_index
            cursor = _next_index(tokens, name_index + 1, stop=end)
        alias: str | None = None
        if cursor is not None and tokens[cursor].string == "as":
            alias_index = _next_index(tokens, cursor + 1, stop=end)
            if alias_index is None or tokens[alias_index].type != tokenize.NAME:
                budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
                return end
            alias = tokens[alias_index].string
            last = alias_index
            cursor = _next_index(tokens, alias_index + 1, stop=end)
        imported = ".".join(module_parts)
        binding_name = alias or module_parts[0]
        _record_import(
            source,
            imported,
            binding_name,
            tuple(module_parts[1:]) if alias else (),
            targets,
            bindings,
            tokens[start],
            tokens[last],
            facts,
            budget,
        )
        if cursor is None or tokens[cursor].string != ",":
            break
        index = _next_index(tokens, cursor + 1, stop=end)
    return end


def _from_import(
    source: DiscoveredSource,
    tokens: list[tokenize.TokenInfo],
    start: int,
    targets: tuple[ContextTarget, ...],
    bindings: dict[str, list[_Binding]],
    import_indices: set[int],
    facts: list[RecognizedFact],
    budget: RecognitionBudget,
) -> int:
    end = _statement_end(tokens, start)
    import_indices.update(range(start, end))
    index = _next_index(tokens, start + 1, stop=end)
    if index is None:
        budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
        return end
    if tokens[index].string == ".":
        budget.limitations.add(ContextLimitation.RELATIVE_IMPORT_UNSUPPORTED)
        return end
    module_parts: list[str] = []
    while index < end and tokens[index].string != "import":
        if tokens[index].type == tokenize.NAME:
            module_parts.append(tokens[index].string)
        elif tokens[index].string != "." and tokens[index].type not in {tokenize.NL}:
            budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
            return end
        next_index = _next_index(tokens, index + 1, stop=end)
        if next_index is None:
            budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
            return end
        index = next_index
    if not module_parts or tokens[index].string != "import":
        budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
        return end
    imported = ".".join(module_parts)
    cursor = _next_index(tokens, index + 1, stop=end)
    while cursor is not None and cursor < end:
        if tokens[cursor].string in {"(", ")", ","}:
            cursor = _next_index(tokens, cursor + 1, stop=end)
            continue
        if tokens[cursor].string == "*":
            budget.limitations.add(ContextLimitation.STAR_IMPORT_UNSUPPORTED)
            return end
        if tokens[cursor].type != tokenize.NAME:
            budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
            return end
        member = tokens[cursor].string
        last = cursor
        alias = member
        next_index = _next_index(tokens, cursor + 1, stop=end)
        if next_index is not None and tokens[next_index].string == "as":
            alias_index = _next_index(tokens, next_index + 1, stop=end)
            if alias_index is None or tokens[alias_index].type != tokenize.NAME:
                budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
                return end
            alias = tokens[alias_index].string
            last = alias_index
            next_index = _next_index(tokens, alias_index + 1, stop=end)
        _record_import(
            source,
            imported,
            alias,
            (member,),
            targets,
            bindings,
            tokens[start],
            tokens[last],
            facts,
            budget,
        )
        cursor = next_index
    return end


def _record_import(
    source: DiscoveredSource,
    imported: str,
    binding_name: str,
    imported_members: tuple[str, ...],
    targets: tuple[ContextTarget, ...],
    bindings: dict[str, list[_Binding]],
    start: tokenize.TokenInfo,
    end: tokenize.TokenInfo,
    facts: list[RecognizedFact],
    budget: RecognitionBudget,
) -> None:
    for target in targets:
        if not target_matches_import(target, imported):
            continue
        bindings.setdefault(binding_name, []).append(
            _Binding(name=binding_name, imported_members=imported_members, target=target)
        )
        _append_fact(
            facts,
            RecognizedFact(
                kind=ObservationKind.IMPORT_DECLARATION,
                match_ordinal=target.match_ordinal,
                target_id=target.id,
                path=source.path,
                anchor=_anchor(start, end),
                binding=binding_name,
                member_path=imported_members,
            ),
            budget,
        )


def _shadowed_bindings(
    tokens: list[tokenize.TokenInfo],
    bindings: dict[str, list[_Binding]],
    import_indices: set[int],
) -> set[str]:
    shadowed = {
        name
        for name, values in bindings.items()
        if len(values) != len({value.target.id for value in values})
    }
    for index, item in enumerate(tokens):
        if index in import_indices or item.type != tokenize.NAME or item.string not in bindings:
            continue
        next_index = _next_index(tokens, index + 1)
        previous = _previous_index(tokens, index - 1)
        if (
            next_index is not None
            and tokens[next_index].string in {"=", ":="}
            or previous is not None
            and tokens[previous].string in {"as", "class", "def", "for", "lambda"}
            or _is_parameter_binding(tokens, index)
        ):
            shadowed.add(item.string)
    return shadowed


def _is_parameter_binding(tokens: list[tokenize.TokenInfo], index: int) -> bool:
    depth = 0
    opening: int | None = None
    for candidate in range(index - 1, -1, -1):
        value = tokens[candidate].string
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
    prefix: set[str] = set()
    for candidate in range(opening - 1, -1, -1):
        item = tokens[candidate]
        if item.type == tokenize.NEWLINE or item.string in {";", "{", "}"}:
            break
        if item.type != tokenize.NL:
            prefix.add(item.string)
    return bool(prefix & {"def", "lambda"})


def _member_chain(tokens: list[tokenize.TokenInfo], start: int) -> tuple[tuple[str, ...], int]:
    members: list[str] = []
    last = start
    cursor = _next_index(tokens, start + 1)
    while cursor is not None and tokens[cursor].string == ".":
        name_index = _next_index(tokens, cursor + 1)
        if name_index is None or tokens[name_index].type != tokenize.NAME:
            break
        members.append(tokens[name_index].string)
        last = name_index
        cursor = _next_index(tokens, name_index + 1)
    return tuple(members), last


def _call_end(
    tokens: list[tokenize.TokenInfo], opening: int | None, budget: RecognitionBudget
) -> int | None:
    if opening is None or tokens[opening].string != "(":
        return None
    depth = 0
    for index in range(opening, len(tokens)):
        budget.check()
        if tokens[index].string == "(":
            depth += 1
        elif tokens[index].string == ")":
            depth -= 1
            if depth == 0:
                return index
    budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
    return None


def _configuration_keywords(
    tokens: list[tokenize.TokenInfo],
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
    depth = 0
    for index in range(opening + 1, closing):
        value = tokens[index].string
        if value in {"(", "[", "{"}:
            depth += 1
        elif value in {")", "]", "}"}:
            depth -= 1
        elif depth == 0 and tokens[index].type == tokenize.NAME:
            next_index = _next_index(tokens, index + 1, stop=closing)
            if next_index is not None and tokens[next_index].string == "=":
                for rule in rules:
                    if value in rule.keys:
                        value_index = _next_index(tokens, next_index + 1, stop=closing)
                        value_end = (
                            _literal_end(tokens, value_index, stop=closing)
                            if value_index is not None
                            else None
                        )
                        separator = (
                            _next_index(tokens, value_end + 1, stop=closing)
                            if value_end is not None
                            else None
                        )
                        if value_end is not None and (
                            separator is None or tokens[separator].string == ","
                        ):
                            found.add((rule.id, value))
                        else:
                            budget.limitations.add(ContextLimitation.UNSUPPORTED_SYNTAX)
    return tuple(sorted(found))


def _configuration_assignment(
    tokens: list[tokenize.TokenInfo],
    last_index: int,
    members: tuple[str, ...],
    target: ContextTarget,
    catalog: ContextRuleCatalog,
    budget: RecognitionBudget,
) -> tuple[str, int] | None:
    next_index = _next_index(tokens, last_index + 1)
    rule_id = _configuration_rule_id(members, target, catalog)
    if next_index is None or tokens[next_index].string not in {"=", ":="} or rule_id is None:
        return None
    value_index = _next_index(tokens, next_index + 1)
    if value_index is None:
        budget.limitations.add(ContextLimitation.MALFORMED_SYNTAX)
        return None
    value_end = _literal_end(tokens, value_index, stop=_statement_end(tokens, value_index))
    if value_end is None:
        budget.limitations.add(ContextLimitation.UNSUPPORTED_SYNTAX)
        return None
    statement_end = _statement_end(tokens, value_index)
    if _next_index(tokens, value_end + 1, stop=statement_end) is not None:
        budget.limitations.add(ContextLimitation.UNSUPPORTED_SYNTAX)
        return None
    return rule_id, value_end


def _literal_end(tokens: list[tokenize.TokenInfo], start: int, *, stop: int) -> int | None:
    if start >= stop:
        return None
    item = tokens[start]
    if item.type in {tokenize.STRING, tokenize.NUMBER} or (
        item.type == tokenize.NAME and item.string in {"False", "None", "True"}
    ):
        return start
    if item.string in {"+", "-"}:
        value_index = _next_index(tokens, start + 1, stop=stop)
        if value_index is not None and tokens[value_index].type == tokenize.NUMBER:
            return value_index
        return None
    pairs = {"[": "]", "(": ")", "{": "}"}
    closing = pairs.get(item.string)
    if closing is None:
        return None
    index = _next_index(tokens, start + 1, stop=stop)
    if index is not None and tokens[index].string == closing:
        return index
    while index is not None and index < stop:
        if item.string == "{" and (
            tokens[index].type in {tokenize.STRING, tokenize.NUMBER}
            or tokens[index].type == tokenize.NAME
            and tokens[index].string in {"False", "None", "True"}
        ):
            separator = _next_index(tokens, index + 1, stop=stop)
            if separator is None or tokens[separator].string != ":":
                return None
            index = _next_index(tokens, separator + 1, stop=stop)
            if index is None:
                return None
        value_end = _literal_end(tokens, index, stop=stop)
        if value_end is None:
            return None
        separator = _next_index(tokens, value_end + 1, stop=stop)
        if separator is None:
            return None
        if tokens[separator].string == closing:
            return separator
        if tokens[separator].string != ",":
            return None
        index = _next_index(tokens, separator + 1, stop=stop)
        if index is not None and tokens[index].string == closing:
            return index
    return None


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
        if rule.id not in target.endpoint_rule_ids:
            continue
        if any(
            len(members) >= len(path) and members[-len(path) :] == path
            for path in rule.member_paths
        ):
            return rule.id
    return None


def _statement_end(tokens: list[tokenize.TokenInfo], start: int) -> int:
    for index in range(start + 1, len(tokens)):
        if (
            tokens[index].type in {tokenize.NEWLINE, tokenize.ENDMARKER}
            or tokens[index].string == ";"
        ):
            return index
    return len(tokens)


def _next_index(
    tokens: list[tokenize.TokenInfo], start: int, *, stop: int | None = None
) -> int | None:
    maximum = len(tokens) if stop is None else min(stop, len(tokens))
    for index in range(start, maximum):
        if tokens[index].type not in {tokenize.NL}:
            return index
    return None


def _previous_index(tokens: list[tokenize.TokenInfo], start: int) -> int | None:
    for index in range(start, -1, -1):
        if tokens[index].type not in {tokenize.NL}:
            return index
    return None


def _anchor(start: tokenize.TokenInfo, end: tokenize.TokenInfo) -> ContextAnchor:
    return ContextAnchor(
        start_line=start.start[0],
        start_column=start.start[1],
        end_line=end.end[0],
        end_column=end.end[1],
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
