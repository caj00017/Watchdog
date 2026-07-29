from __future__ import annotations

import threading
import time

import pytest

from watchdog.context._recognition import RecognitionResult
from watchdog.context.catalog import DEFAULT_CONTEXT_CATALOG
from watchdog.context.discovery import ContextCancelled
from watchdog.context.evidence import EvidenceBuildResult, build_context_evidence
from watchdog.context.graph import GraphDeadlineExceeded, build_observation_graph
from watchdog.context.identifiers import context_target_id
from watchdog.context.ranking import build_context_signals
from watchdog.domain.context import (
    ContextLimitation,
    ContextSignalKind,
    ContextTarget,
    GraphEdgeKind,
    ObservationKind,
)
from watchdog.evidence.redaction import Redactor

from ..security.test_context_discovery import context_limits
from .test_context_evidence import producer, snapshot
from .test_context_javascript import recognize as recognize_javascript
from .test_context_javascript import target as javascript_target
from .test_context_python import recognize as recognize_python
from .test_context_python import target as python_target


def evidence_for(result: RecognitionResult, target: ContextTarget) -> EvidenceBuildResult:
    limits = context_limits()
    return build_context_evidence(
        (result,),
        (target,),
        snapshot(),
        producer(),
        limits,
        Redactor(("credential_assignment",)),
        deadline=time.monotonic() + 10,
        cancel_event=threading.Event(),
    )


def test_graph_contains_only_evidence_linked_lexical_relationships() -> None:
    target = python_target("requests", "requests", complete=False)
    recognized = recognize_python(
        'import requests as client\nclient.get("/", verify=False)\n',
        target,
    )
    evidence = evidence_for(recognized, target)
    graph = build_observation_graph(
        (target,), evidence.observations, DEFAULT_CONTEXT_CATALOG, context_limits()
    )

    kinds = {edge.kind for edge in graph.edges}
    assert GraphEdgeKind.IMPORTS in kinds
    assert GraphEdgeKind.BINDS in kinds
    assert GraphEdgeKind.REFERENCES in kinds
    assert GraphEdgeKind.CALLS in kinds
    assert GraphEdgeKind.CONFIGURES in kinds
    evidence_ids = {item.id for item in evidence.evidence}
    node_ids = {item.id for item in graph.nodes}
    assert all(set(node.evidence_ids) <= evidence_ids for node in graph.nodes)
    assert all(
        edge.from_node_id in node_ids
        and edge.to_node_id in node_ids
        and set(edge.evidence_ids) <= evidence_ids
        for edge in graph.edges
    )


def test_endpoint_proximity_is_bounded_lexical_proximity_not_data_flow() -> None:
    target = javascript_target("express")
    recognized = recognize_javascript(
        'import app from "express";\napp.get("/health", handler);\n',
        target,
    )
    evidence = evidence_for(recognized, target)
    graph = build_observation_graph(
        (target,), evidence.observations, DEFAULT_CONTEXT_CATALOG, context_limits()
    )

    proximity = [edge for edge in graph.edges if edge.kind == GraphEdgeKind.DECLARED_NEAR_ENDPOINT]
    assert proximity
    assert all(edge.evidence_ids for edge in proximity)
    assert GraphEdgeKind.BINDS in {edge.kind for edge in graph.edges}
    assert GraphEdgeKind.REFERENCES in {edge.kind for edge in graph.edges}


def test_graph_limits_drop_broken_edges_and_remain_explicit() -> None:
    target = python_target("requests", "requests", complete=False)
    recognized = recognize_python("import requests\nrequests.get()\n", target)
    evidence = evidence_for(recognized, target)
    graph = build_observation_graph(
        (target,),
        evidence.observations,
        DEFAULT_CONTEXT_CATALOG,
        context_limits(max_graph_nodes=1, max_graph_edges=1),
    )

    assert len(graph.nodes) == 1
    assert graph.edges == ()
    assert graph.limitation_codes == (ContextLimitation.GRAPH_NODE_LIMIT_EXCEEDED,)


def test_positive_signals_are_ranked_and_incomplete_coverage_stays_explicit() -> None:
    target = python_target("requests", "requests", complete=False)
    recognized = recognize_python(
        'import requests\nrequests.get("/", verify=False)\n',
        target,
    )
    evidence = evidence_for(recognized, target)
    graph = build_observation_graph(
        (target,), evidence.observations, DEFAULT_CONTEXT_CATALOG, context_limits()
    )
    signals = build_context_signals(
        match_count=1,
        targets=(target,),
        observations=evidence.observations,
        graph_edges=graph.edges,
        coverage_limitations=evidence.limitation_codes,
    ).signals

    kinds = [signal.kind for signal in signals]
    assert kinds[0] == ContextSignalKind.EXPLICIT_TARGET_CALL_OBSERVED
    assert ContextSignalKind.TARGET_CONFIGURATION_OBSERVED in kinds
    assert ContextSignalKind.TARGET_REFERENCE_OBSERVED in kinds
    assert ContextSignalKind.DEPENDENCY_IMPORT_OBSERVED in kinds
    assert ContextSignalKind.CONTEXT_INCOMPLETE in kinds
    assert ContextSignalKind.TARGET_USAGE_NOT_OBSERVED_WITHIN_COVERAGE not in kinds
    assert all(signal.evidence_ids for signal in signals if signal.rank < 900)


def test_non_observation_requires_complete_mapping_and_coverage() -> None:
    complete = javascript_target("express")
    signals = build_context_signals(
        match_count=1,
        targets=(complete,),
        observations=(),
        graph_edges=(),
        coverage_limitations=(),
    ).signals
    assert [signal.kind for signal in signals] == [
        ContextSignalKind.TARGET_USAGE_NOT_OBSERVED_WITHIN_COVERAGE
    ]
    assert signals[0].limitation_codes == (ContextLimitation.STATIC_NON_OBSERVATION_LIMITATION,)

    incomplete = build_context_signals(
        match_count=1,
        targets=(complete,),
        observations=(),
        graph_edges=(),
        coverage_limitations=(ContextLimitation.INVALID_UTF8,),
    ).signals
    assert [signal.kind for signal in incomplete] == [ContextSignalKind.CONTEXT_INCOMPLETE]


def test_not_applicable_and_vocabulary_cannot_encode_exposure_or_affected_status() -> None:
    signals = build_context_signals(
        match_count=1,
        targets=(),
        observations=(),
        graph_edges=(),
        coverage_limitations=(),
    ).signals
    assert signals[0].kind == ContextSignalKind.CONTEXT_NOT_APPLICABLE
    forbidden = {"affected", "not_affected", "reachable", "unreachable", "exposed", "not_exposed"}
    assert forbidden.isdisjoint({kind.value for kind in ContextSignalKind})
    assert forbidden.isdisjoint({kind.value for kind in ObservationKind})


def test_graph_and_ranking_deadlines_and_cancellation_are_cooperative() -> None:
    target = python_target("requests", "requests", complete=False)
    cancelled = threading.Event()
    cancelled.set()

    with pytest.raises(ContextCancelled):
        build_observation_graph(
            (target,),
            (),
            DEFAULT_CONTEXT_CATALOG,
            context_limits(),
            cancel_event=cancelled,
        )
    with pytest.raises(ContextCancelled):
        build_context_signals(
            match_count=1,
            targets=(target,),
            observations=(),
            graph_edges=(),
            coverage_limitations=(),
            cancel_event=cancelled,
        )

    with pytest.raises(GraphDeadlineExceeded):
        build_observation_graph(
            (target,),
            (),
            DEFAULT_CONTEXT_CATALOG,
            context_limits(),
            deadline=time.monotonic() - 1,
        )
    ranking = build_context_signals(
        match_count=1,
        targets=(target,),
        observations=(),
        graph_edges=(),
        coverage_limitations=(),
        deadline=time.monotonic() - 1,
    )
    assert ranking.limitation_codes == (ContextLimitation.CONTEXT_DEADLINE_EXCEEDED,)
    assert [signal.kind for signal in ranking.signals] == [ContextSignalKind.CONTEXT_INCOMPLETE]


def test_ranking_deadline_invalidates_earlier_static_non_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = javascript_target("express")
    second_payload = first.model_dump(mode="python", exclude={"id"})
    second_payload.update(match_ordinal=1, component_id="component:second")
    second = ContextTarget(id=context_target_id(second_payload), **second_payload)
    timestamps = iter((1.0, 3.0))
    monkeypatch.setattr("watchdog.context.ranking.time.monotonic", lambda: next(timestamps))

    ranking = build_context_signals(
        match_count=2,
        targets=(first, second),
        observations=(),
        graph_edges=(),
        coverage_limitations=(),
        deadline=2.0,
    )

    assert ranking.limitation_codes == (ContextLimitation.CONTEXT_DEADLINE_EXCEEDED,)
    assert [signal.kind for signal in ranking.signals] == [
        ContextSignalKind.CONTEXT_INCOMPLETE,
        ContextSignalKind.CONTEXT_INCOMPLETE,
    ]
    assert all(
        ContextLimitation.CONTEXT_DEADLINE_EXCEEDED in signal.limitation_codes
        for signal in ranking.signals
    )
