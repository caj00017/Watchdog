from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from watchdog.context._recognition import RecognitionResult, RecognizedFact
from watchdog.context.discovery import ContextCancelled
from watchdog.context.identifiers import context_evidence_id, context_observation_id
from watchdog.context.limits import ContextLimits
from watchdog.domain.context import (
    ContextEvidenceItem,
    ContextEvidenceKind,
    ContextLimitation,
    ContextObservation,
    ContextProducer,
    ContextSource,
    ContextTarget,
    ContextWarning,
    SourceFileOutcome,
    SourceFileStatus,
)
from watchdog.domain.evidence import EvidenceStatus
from watchdog.domain.inventory import InventorySnapshot
from watchdog.evidence.redaction import RedactionResult, Redactor, evidence_content


@dataclass(frozen=True, slots=True)
class EvidenceBuildResult:
    evidence: tuple[ContextEvidenceItem, ...]
    observations: tuple[ContextObservation, ...]
    file_outcomes: tuple[SourceFileOutcome, ...]
    warnings: tuple[ContextWarning, ...]
    limitation_codes: tuple[ContextLimitation, ...]


def build_context_evidence(
    results: tuple[RecognitionResult, ...],
    targets: tuple[ContextTarget, ...],
    snapshot: InventorySnapshot,
    producer: ContextProducer,
    limits: ContextLimits,
    redactor: Redactor,
    *,
    deadline: float,
    cancel_event: threading.Event,
) -> EvidenceBuildResult:
    target_by_id = {target.id: target for target in targets}
    evidence_items: list[ContextEvidenceItem] = []
    observations: list[ContextObservation] = []
    warning_candidates: list[ContextWarning] = []
    global_limitations: set[ContextLimitation] = set()
    path_limitations: dict[str, set[ContextLimitation]] = {
        result.source.path: set(result.limitation_codes) for result in results
    }
    path_observations: dict[str, list[str]] = {result.source.path: [] for result in results}
    bundle_display_bytes = 0
    for result in results:
        for code in result.limitation_codes:
            global_limitations.add(code)
            warning_candidates.append(
                ContextWarning(
                    code=code,
                    message="source recognition completed with an explicit limitation",
                    path=result.source.path,
                )
            )
    result_by_path = {result.source.path: result for result in results}
    ordered_facts = (
        fact
        for result in sorted(results, key=lambda item: item.source.path.encode("utf-8"))
        for fact in result.facts
    )
    for fact in ordered_facts:
        _check_cancel(cancel_event)
        if time.monotonic() >= deadline:
            for result in results:
                _limit(
                    global_limitations,
                    path_limitations,
                    warning_candidates,
                    result.source.path,
                    ContextLimitation.CONTEXT_DEADLINE_EXCEEDED,
                    "context evidence deadline was exceeded",
                )
            break
        result = result_by_path[fact.path]
        target = target_by_id[fact.target_id]
        if not target.dependency_evidence_ids:
            _limit(
                global_limitations,
                path_limitations,
                warning_candidates,
                fact.path,
                ContextLimitation.DEPENDENCY_EVIDENCE_INCOMPLETE,
                "context fact had no canonical Phase 4 evidence link",
            )
            continue
        if not _safe_symbols(fact):
            _limit(
                global_limitations,
                path_limitations,
                warning_candidates,
                fact.path,
                ContextLimitation.UNSUPPORTED_SYNTAX,
                "context fact contained an unsupported identifier",
            )
            continue
        if len(observations) >= limits.max_observations:
            for source_result in results:
                _limit(
                    global_limitations,
                    path_limitations,
                    warning_candidates,
                    source_result.source.path,
                    ContextLimitation.OBSERVATION_LIMIT_EXCEEDED,
                    "context observation limit was exceeded",
                )
            break
        if len(evidence_items) >= limits.max_evidence_items:
            for source_result in results:
                _limit(
                    global_limitations,
                    path_limitations,
                    warning_candidates,
                    source_result.source.path,
                    ContextLimitation.EVIDENCE_LIMIT_EXCEEDED,
                    "context evidence-item limit was exceeded",
                )
            break
        if fact.anchor.end_line - fact.anchor.start_line + 1 > limits.max_line_span:
            _limit(
                global_limitations,
                path_limitations,
                warning_candidates,
                fact.path,
                ContextLimitation.LINE_SPAN_LIMIT_EXCEEDED,
                "context syntactic span exceeded the line limit",
            )
            continue
        span = _extract_span(result, fact)
        if span is None:
            _limit(
                global_limitations,
                path_limitations,
                warning_candidates,
                fact.path,
                ContextLimitation.MALFORMED_SYNTAX,
                "context syntactic anchor could not be extracted",
            )
            continue
        try:
            redaction = redactor.redact(span, max_redactions=limits.max_redactions_per_item)
        except Exception:
            redaction = RedactionResult(None, (), "redaction_failed")
        source = ContextSource(
            repository_url=snapshot.repository_url,
            commit_sha=snapshot.commit_sha,
            tree_sha=snapshot.tree_sha,
            path=fact.path,
            file_sha256=result.source.file_sha256,
            anchor=fact.anchor,
        )
        item_limitations: tuple[ContextLimitation, ...] = ()
        content = None
        if redaction.text is None:
            code = _redaction_limitation(redaction.limitation_code)
            item_limitations = (code,)
            status = EvidenceStatus.CONTENT_OMITTED
            _limit(
                global_limitations,
                path_limitations,
                warning_candidates,
                fact.path,
                code,
                "context display was omitted because redaction did not complete",
            )
        else:
            remaining = limits.max_bundle_display_bytes - bundle_display_bytes
            redacted_bytes = len(redaction.text.encode("utf-8"))
            if redacted_bytes > limits.max_display_bytes_per_item:
                code = ContextLimitation.DISPLAY_ITEM_BYTES_LIMIT_EXCEEDED
                item_limitations = (code,)
                status = EvidenceStatus.CONTENT_OMITTED
                _limit(
                    global_limitations,
                    path_limitations,
                    warning_candidates,
                    fact.path,
                    code,
                    "context display was omitted after the item display limit",
                )
            elif redacted_bytes > remaining:
                code = ContextLimitation.BUNDLE_DISPLAY_BYTES_LIMIT_EXCEEDED
                item_limitations = (code,)
                status = EvidenceStatus.CONTENT_OMITTED
                _limit(
                    global_limitations,
                    path_limitations,
                    warning_candidates,
                    fact.path,
                    code,
                    "context display was omitted after the bundle display limit",
                )
            else:
                try:
                    content = evidence_content(
                        redaction,
                        max_display_bytes=limits.max_display_bytes_per_item,
                    )
                except Exception:
                    content = None
                if content is None:
                    code = ContextLimitation.REDACTION_FAILED
                    item_limitations = (code,)
                    status = EvidenceStatus.CONTENT_OMITTED
                    _limit(
                        global_limitations,
                        path_limitations,
                        warning_candidates,
                        fact.path,
                        code,
                        "context display was omitted because content construction failed",
                    )
                else:
                    status = (
                        EvidenceStatus.REDACTED if content.redacted else EvidenceStatus.EXTRACTED
                    )
                    bundle_display_bytes += content.byte_count
        item_payload = {
            "kind": ContextEvidenceKind.LEXICAL_CONTEXT,
            "producer": producer,
            "source": source,
            "match_ordinal": fact.match_ordinal,
            "target_id": fact.target_id,
            "dependency_evidence_ids": target.dependency_evidence_ids,
            "observation_kind": fact.kind,
            "rule_id": fact.rule_id,
            "status": status,
            "content": content,
            "limitation_codes": item_limitations,
        }
        item = ContextEvidenceItem(id=context_evidence_id(item_payload), **item_payload)
        observation_payload = {
            "kind": fact.kind,
            "match_ordinal": fact.match_ordinal,
            "target_id": fact.target_id,
            "evidence_id": item.id,
            "path": fact.path,
            "anchor": fact.anchor,
            "binding": fact.binding,
            "member_path": fact.member_path,
            "rule_id": fact.rule_id,
        }
        observation = ContextObservation(
            id=context_observation_id(observation_payload), **observation_payload
        )
        evidence_items.append(item)
        observations.append(observation)
        path_observations[fact.path].append(observation.id)
    evidence_tuple = tuple(sorted(evidence_items, key=lambda item: item.id))
    observation_tuple = tuple(sorted(observations, key=lambda item: item.id))
    file_outcomes = tuple(
        _file_outcome(
            result, path_observations[result.source.path], path_limitations[result.source.path]
        )
        for result in sorted(results, key=lambda item: item.source.path.encode("utf-8"))
    )
    warnings = _bounded_warnings(warning_candidates, limits.max_warnings)
    if any(item.code == ContextLimitation.WARNING_LIMIT_EXCEEDED for item in warnings):
        global_limitations.add(ContextLimitation.WARNING_LIMIT_EXCEEDED)
    return EvidenceBuildResult(
        evidence=evidence_tuple,
        observations=observation_tuple,
        file_outcomes=file_outcomes,
        warnings=warnings,
        limitation_codes=tuple(sorted(global_limitations)),
    )


def _extract_span(result: RecognitionResult, fact: RecognizedFact) -> str | None:
    try:
        text = result.source.content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    lines = text.splitlines(keepends=True)
    start_line = fact.anchor.start_line - 1
    end_line = fact.anchor.end_line - 1
    if start_line < 0 or end_line >= len(lines):
        return None
    if start_line == end_line:
        value = lines[start_line][fact.anchor.start_column : fact.anchor.end_column]
    else:
        selected = [lines[start_line][fact.anchor.start_column :]]
        selected.extend(lines[start_line + 1 : end_line])
        selected.append(lines[end_line][: fact.anchor.end_column])
        value = "".join(selected)
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _file_outcome(
    result: RecognitionResult,
    observation_ids: list[str],
    limitations: set[ContextLimitation],
) -> SourceFileOutcome:
    status = SourceFileStatus.PARTIAL if limitations else SourceFileStatus.ANALYZED
    return SourceFileOutcome(
        path=result.source.path,
        language=result.source.language,
        status=status,
        file_sha256=result.source.file_sha256,
        byte_count=result.source.byte_count,
        lexical_tokens=result.lexical_tokens,
        observation_ids=tuple(sorted(observation_ids)),
        limitation_codes=tuple(sorted(limitations)),
        test_source=result.source.test_source,
    )


def _redaction_limitation(value: str | None) -> ContextLimitation:
    if value == "redaction_limit_exceeded":
        return ContextLimitation.REDACTION_LIMIT_EXCEEDED
    return ContextLimitation.REDACTION_FAILED


def _limit(
    global_limitations: set[ContextLimitation],
    path_limitations: dict[str, set[ContextLimitation]],
    warnings: list[ContextWarning],
    path: str,
    code: ContextLimitation,
    message: str,
) -> None:
    global_limitations.add(code)
    if code in path_limitations[path]:
        return
    path_limitations[path].add(code)
    warnings.append(ContextWarning(code=code, message=message, path=path))


def _bounded_warnings(candidates: list[ContextWarning], maximum: int) -> tuple[ContextWarning, ...]:
    ordered = tuple(
        sorted(candidates, key=lambda item: (item.code.value, item.path or "", item.message))
    )
    if len(ordered) <= maximum:
        return ordered
    summary = ContextWarning(
        code=ContextLimitation.WARNING_LIMIT_EXCEEDED,
        message="additional context warnings were omitted after the configured limit",
    )
    if maximum == 1:
        return (summary,)
    return tuple(
        sorted(
            (*ordered[: maximum - 1], summary),
            key=lambda item: (item.code.value, item.path or "", item.message),
        )
    )


def _check_cancel(cancel_event: threading.Event) -> None:
    if cancel_event.is_set():
        raise ContextCancelled


def _safe_symbols(fact: RecognizedFact) -> bool:
    values = (*fact.member_path, *((fact.binding,) if fact.binding is not None else ()))
    return all(
        bool(value)
        and len(value) <= 128
        and (value[0].isalpha() or value[0] in "_$")
        and value.isascii()
        and all(character.isalnum() or character in "_$" for character in value[1:])
        for value in values
    )
