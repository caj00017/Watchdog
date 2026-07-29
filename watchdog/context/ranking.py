from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from watchdog.context.discovery import ContextCancelled
from watchdog.context.identifiers import context_signal_id
from watchdog.domain.context import (
    ContextGraphEdge,
    ContextLimitation,
    ContextObservation,
    ContextSignal,
    ContextSignalKind,
    ContextTarget,
    GraphEdgeKind,
    ObservationKind,
)

_RANK = {
    ContextSignalKind.EXPLICIT_TARGET_CALL_OBSERVED: 1,
    ContextSignalKind.ENDPOINT_PROXIMITY_OBSERVED: 2,
    ContextSignalKind.TARGET_CONFIGURATION_OBSERVED: 3,
    ContextSignalKind.TARGET_REFERENCE_OBSERVED: 4,
    ContextSignalKind.DEPENDENCY_IMPORT_OBSERVED: 5,
    ContextSignalKind.CONTEXT_INCOMPLETE: 900,
    ContextSignalKind.TARGET_USAGE_NOT_OBSERVED_WITHIN_COVERAGE: 950,
    ContextSignalKind.CONTEXT_NOT_APPLICABLE: 1_000,
}


@dataclass(frozen=True, slots=True)
class RankingBuildResult:
    signals: tuple[ContextSignal, ...]
    limitation_codes: tuple[ContextLimitation, ...]


def build_context_signals(
    *,
    match_count: int,
    targets: tuple[ContextTarget, ...],
    observations: tuple[ContextObservation, ...],
    graph_edges: tuple[ContextGraphEdge, ...],
    coverage_limitations: tuple[ContextLimitation, ...],
    deadline: float | None = None,
    cancel_event: threading.Event | None = None,
) -> RankingBuildResult:
    targets_by_match = {target.match_ordinal: target for target in targets}
    observations_by_target: dict[str, list[ContextObservation]] = {}
    for observation in observations:
        observations_by_target.setdefault(observation.target_id, []).append(observation)
    signals: list[ContextSignal] = []
    ranking_limitations: set[ContextLimitation] = set()
    endpoint_evidence = {
        evidence_id
        for edge in graph_edges
        if edge.kind == GraphEdgeKind.DECLARED_NEAR_ENDPOINT
        for evidence_id in edge.evidence_ids
    }
    for ordinal in range(match_count):
        if cancel_event is not None and cancel_event.is_set():
            raise ContextCancelled
        deadline_reached = deadline is not None and time.monotonic() >= deadline
        if deadline_reached:
            ranking_limitations.add(ContextLimitation.CONTEXT_DEADLINE_EXCEEDED)
        target = targets_by_match.get(ordinal)
        if target is None:
            signals.append(
                _signal(
                    ContextSignalKind.CONTEXT_NOT_APPLICABLE,
                    ordinal,
                    target_id=None,
                    dependency_evidence_ids=(),
                )
            )
            continue
        target_observations = tuple(observations_by_target.get(target.id, ()))
        if not deadline_reached:
            _positive_signal(
                signals,
                target,
                target_observations,
                ObservationKind.EXPLICIT_CALL,
                ContextSignalKind.EXPLICIT_TARGET_CALL_OBSERVED,
            )
            _positive_signal(
                signals,
                target,
                target_observations,
                ObservationKind.TARGET_CONFIGURATION,
                ContextSignalKind.TARGET_CONFIGURATION_OBSERVED,
            )
            _positive_signal(
                signals,
                target,
                target_observations,
                ObservationKind.TARGET_REFERENCE,
                ContextSignalKind.TARGET_REFERENCE_OBSERVED,
            )
            _positive_signal(
                signals,
                target,
                target_observations,
                ObservationKind.IMPORT_DECLARATION,
                ContextSignalKind.DEPENDENCY_IMPORT_OBSERVED,
            )
            proximity = tuple(
                sorted(
                    {
                        item.evidence_id
                        for item in target_observations
                        if item.evidence_id in endpoint_evidence
                    }
                )
            )
            if proximity:
                signals.append(
                    _signal(
                        ContextSignalKind.ENDPOINT_PROXIMITY_OBSERVED,
                        ordinal,
                        target_id=target.id,
                        dependency_evidence_ids=target.dependency_evidence_ids,
                        evidence_ids=proximity,
                    )
                )
        limitations = tuple(
            sorted(
                {
                    *coverage_limitations,
                    *target.limitation_codes,
                    *(ranking_limitations if deadline_reached else ()),
                }
            )
        )
        if limitations:
            signals.append(
                _signal(
                    ContextSignalKind.CONTEXT_INCOMPLETE,
                    ordinal,
                    target_id=target.id,
                    dependency_evidence_ids=target.dependency_evidence_ids,
                    limitations=limitations,
                )
            )
        elif not target_observations and target.mapping_complete:
            signals.append(
                _signal(
                    ContextSignalKind.TARGET_USAGE_NOT_OBSERVED_WITHIN_COVERAGE,
                    ordinal,
                    target_id=target.id,
                    dependency_evidence_ids=target.dependency_evidence_ids,
                    limitations=(ContextLimitation.STATIC_NON_OBSERVATION_LIMITATION,),
                )
            )
    if ranking_limitations:
        signals = [
            signal
            for signal in signals
            if signal.kind
            not in {
                ContextSignalKind.CONTEXT_INCOMPLETE,
                ContextSignalKind.TARGET_USAGE_NOT_OBSERVED_WITHIN_COVERAGE,
            }
        ]
        for ordinal in range(match_count):
            if cancel_event is not None and cancel_event.is_set():
                raise ContextCancelled
            target = targets_by_match.get(ordinal)
            if target is None:
                continue
            signals.append(
                _signal(
                    ContextSignalKind.CONTEXT_INCOMPLETE,
                    ordinal,
                    target_id=target.id,
                    dependency_evidence_ids=target.dependency_evidence_ids,
                    limitations=tuple(
                        sorted(
                            {
                                *coverage_limitations,
                                *target.limitation_codes,
                                *ranking_limitations,
                            }
                        )
                    ),
                )
            )
    return RankingBuildResult(
        signals=tuple(sorted(signals, key=lambda item: (item.match_ordinal, item.rank, item.id))),
        limitation_codes=tuple(sorted(ranking_limitations)),
    )


def _positive_signal(
    signals: list[ContextSignal],
    target: ContextTarget,
    observations: tuple[ContextObservation, ...],
    observation_kind: ObservationKind,
    signal_kind: ContextSignalKind,
) -> None:
    evidence_ids = tuple(
        sorted({item.evidence_id for item in observations if item.kind == observation_kind})
    )
    if evidence_ids:
        signals.append(
            _signal(
                signal_kind,
                target.match_ordinal,
                target_id=target.id,
                dependency_evidence_ids=target.dependency_evidence_ids,
                evidence_ids=evidence_ids,
            )
        )


def _signal(
    kind: ContextSignalKind,
    match_ordinal: int,
    *,
    target_id: str | None,
    dependency_evidence_ids: tuple[str, ...],
    evidence_ids: tuple[str, ...] = (),
    limitations: tuple[ContextLimitation, ...] = (),
) -> ContextSignal:
    payload = {
        "kind": kind,
        "match_ordinal": match_ordinal,
        "rank": _RANK[kind],
        "target_id": target_id,
        "dependency_evidence_ids": dependency_evidence_ids,
        "evidence_ids": evidence_ids,
        "limitation_codes": limitations,
    }
    return ContextSignal(id=context_signal_id(payload), **payload)
