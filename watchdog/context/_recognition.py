from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from watchdog.context.discovery import ContextCancelled, DiscoveredSource
from watchdog.context.limits import ContextLimits
from watchdog.domain.context import (
    ContextAnchor,
    ContextLimitation,
    ContextTarget,
    ObservationKind,
)


class RecognitionDeadlineExceeded(Exception):
    pass


@dataclass(frozen=True, slots=True)
class RecognizedFact:
    kind: ObservationKind
    match_ordinal: int
    target_id: str
    path: str
    anchor: ContextAnchor
    binding: str | None = None
    member_path: tuple[str, ...] = ()
    rule_id: str | None = None


@dataclass(frozen=True, slots=True)
class RecognitionResult:
    source: DiscoveredSource
    facts: tuple[RecognizedFact, ...]
    lexical_tokens: int
    limitation_codes: tuple[ContextLimitation, ...]


@dataclass(slots=True)
class RecognitionBudget:
    limits: ContextLimits
    deadline: float
    cancel_event: threading.Event
    lexical_tokens: int = 0
    limitations: set[ContextLimitation] = field(default_factory=set)

    def check(self) -> None:
        if self.cancel_event.is_set():
            raise ContextCancelled
        if time.monotonic() >= self.deadline:
            raise RecognitionDeadlineExceeded

    def token(self) -> None:
        self.check()
        self.lexical_tokens += 1
        if self.lexical_tokens > self.limits.max_tokens_per_file:
            self.limitations.add(ContextLimitation.TOKEN_LIMIT_EXCEEDED)
            raise RecognitionLimitExceeded


class RecognitionLimitExceeded(Exception):
    pass


def fact_key(fact: RecognizedFact) -> tuple[object, ...]:
    return (
        fact.path.encode("utf-8"),
        fact.anchor.start_line,
        fact.anchor.start_column,
        fact.anchor.end_line,
        fact.anchor.end_column,
        fact.match_ordinal,
        fact.kind.value,
        fact.binding or "",
        fact.member_path,
        fact.rule_id or "",
    )


def finish_result(
    source: DiscoveredSource,
    facts: list[RecognizedFact],
    budget: RecognitionBudget,
) -> RecognitionResult:
    unique = {fact_key(fact): fact for fact in facts}
    return RecognitionResult(
        source=source,
        facts=tuple(unique[key] for key in sorted(unique)),
        lexical_tokens=budget.lexical_tokens,
        limitation_codes=tuple(sorted(budget.limitations)),
    )


def target_matches_import(target: ContextTarget, imported: str) -> bool:
    for root in target.import_roots:
        if target.ecosystem.value in {"npm", "Go"}:
            if imported == root or imported.startswith(root + "/"):
                return True
        elif imported == root or imported.startswith(root + "."):
            return True
    return False
