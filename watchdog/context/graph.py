from __future__ import annotations

import threading
import time
from bisect import bisect_left, bisect_right
from dataclasses import dataclass

from watchdog.context.discovery import ContextCancelled
from watchdog.context.identifiers import context_edge_id, context_node_id
from watchdog.context.limits import ContextLimits
from watchdog.domain.context import (
    ContextGraphEdge,
    ContextGraphNode,
    ContextLimitation,
    ContextObservation,
    ContextRuleCatalog,
    ContextTarget,
    GraphEdgeKind,
    GraphNodeKind,
    ObservationKind,
)


@dataclass(frozen=True, slots=True)
class GraphBuildResult:
    nodes: tuple[ContextGraphNode, ...]
    edges: tuple[ContextGraphEdge, ...]
    limitation_codes: tuple[ContextLimitation, ...]


class GraphDeadlineExceeded(Exception):
    pass


def build_observation_graph(
    targets: tuple[ContextTarget, ...],
    observations: tuple[ContextObservation, ...],
    catalog: ContextRuleCatalog,
    limits: ContextLimits,
    *,
    deadline: float | None = None,
    cancel_event: threading.Event | None = None,
) -> GraphBuildResult:
    _check(deadline, cancel_event)
    target_by_id = {target.id: target for target in targets}
    node_candidates: dict[tuple[object, ...], ContextGraphNode] = {}
    observation_nodes: dict[str, ContextGraphNode] = {}
    target_nodes: dict[str, ContextGraphNode] = {}
    file_nodes: dict[str, ContextGraphNode] = {}
    binding_nodes: dict[tuple[str, str, str], ContextGraphNode] = {}

    by_target: dict[str, list[ContextObservation]] = {}
    by_path: dict[str, list[ContextObservation]] = {}
    for observation in observations:
        _check(deadline, cancel_event)
        by_target.setdefault(observation.target_id, []).append(observation)
        by_path.setdefault(observation.path, []).append(observation)
    for target_id, values in by_target.items():
        _check(deadline, cancel_event)
        evidence_ids = tuple(sorted({item.evidence_id for item in values}))
        node = _node(
            kind=GraphNodeKind.DEPENDENCY_TARGET,
            target_id=target_id,
            evidence_ids=evidence_ids,
        )
        target_nodes[target_id] = node
        node_candidates[(node.kind.value, target_id)] = node
    for path, values in by_path.items():
        _check(deadline, cancel_event)
        evidence_ids = tuple(sorted({item.evidence_id for item in values}))
        node = _node(
            kind=GraphNodeKind.SOURCE_FILE,
            path=path,
            evidence_ids=evidence_ids,
        )
        file_nodes[path] = node
        node_candidates[(node.kind.value, path)] = node
    for observation in observations:
        _check(deadline, cancel_event)
        node = _node(
            kind=_observation_node_kind(observation.kind),
            target_id=observation.target_id,
            path=observation.path,
            observation_id=observation.id,
            evidence_ids=(observation.evidence_id,),
        )
        observation_nodes[observation.id] = node
        node_candidates[(node.kind.value, observation.id)] = node
        if observation.kind == ObservationKind.IMPORT_DECLARATION and observation.binding:
            key = (observation.target_id, observation.path, observation.binding)
            existing = binding_nodes.get(key)
            evidence_ids = tuple(
                sorted(
                    {
                        observation.evidence_id,
                        *(existing.evidence_ids if existing is not None else ()),
                    }
                )
            )
            binding_node = _node(
                kind=GraphNodeKind.BOUND_IDENTIFIER,
                target_id=observation.target_id,
                path=observation.path,
                observation_id=observation.id,
                evidence_ids=evidence_ids,
            )
            binding_nodes[key] = binding_node
            node_candidates[(binding_node.kind.value, *key)] = binding_node

    limitations: set[ContextLimitation] = set()
    ordered_nodes = tuple(sorted(node_candidates.values(), key=lambda item: item.id))
    if len(ordered_nodes) > limits.max_graph_nodes:
        limitations.add(ContextLimitation.GRAPH_NODE_LIMIT_EXCEEDED)
        ordered_nodes = ordered_nodes[: limits.max_graph_nodes]
    included_ids = {node.id for node in ordered_nodes}

    edge_candidates: dict[str, ContextGraphEdge] = {}
    references = _reference_index(observations)
    for observation in observations:
        _check(deadline, cancel_event)
        observation_node = observation_nodes[observation.id]
        target_node = target_nodes[observation.target_id]
        file_node = file_nodes[observation.path]
        if observation.kind == ObservationKind.IMPORT_DECLARATION:
            _add_edge(
                edge_candidates,
                GraphEdgeKind.IMPORTS,
                file_node,
                target_node,
                (observation.evidence_id,),
                included_ids,
                limits.max_graph_edges,
            )
            if observation.binding:
                binding = binding_nodes[
                    (observation.target_id, observation.path, observation.binding)
                ]
                _add_edge(
                    edge_candidates,
                    GraphEdgeKind.BINDS,
                    observation_node,
                    binding,
                    (observation.evidence_id,),
                    included_ids,
                    limits.max_graph_edges,
                )
        elif observation.kind == ObservationKind.TARGET_REFERENCE:
            referenced_binding = (
                binding_nodes.get((observation.target_id, observation.path, observation.binding))
                if observation.binding
                else None
            )
            if referenced_binding is not None:
                _add_edge(
                    edge_candidates,
                    GraphEdgeKind.REFERENCES,
                    referenced_binding,
                    observation_node,
                    (observation.evidence_id,),
                    included_ids,
                    limits.max_graph_edges,
                )
        elif observation.kind == ObservationKind.EXPLICIT_CALL:
            reference = references.get(_reference_key(observation))
            if reference is not None:
                _add_edge(
                    edge_candidates,
                    GraphEdgeKind.CALLS,
                    observation_nodes[reference.id],
                    observation_node,
                    tuple(sorted((reference.evidence_id, observation.evidence_id))),
                    included_ids,
                    limits.max_graph_edges,
                )
        elif observation.kind == ObservationKind.TARGET_CONFIGURATION:
            _add_edge(
                edge_candidates,
                GraphEdgeKind.CONFIGURES,
                observation_node,
                target_node,
                (observation.evidence_id,),
                included_ids,
                limits.max_graph_edges,
            )

    endpoints_by_location: dict[tuple[str, str], list[ContextObservation]] = {}
    for item in observations:
        if item.kind == ObservationKind.ENDPOINT_DECLARATION:
            endpoints_by_location.setdefault((item.target_id, item.path), []).append(item)
    for values in endpoints_by_location.values():
        values.sort(key=lambda item: (item.anchor.start_line, item.id))
    endpoint_lines = {
        key: tuple(item.anchor.start_line for item in values)
        for key, values in endpoints_by_location.items()
    }
    calls = tuple(
        sorted(
            (item for item in observations if item.kind == ObservationKind.EXPLICIT_CALL),
            key=lambda item: (
                item.path.encode("utf-8"),
                item.anchor.start_line,
                item.anchor.start_column,
                item.id,
            ),
        )
    )
    for call in calls:
        _check(deadline, cancel_event)
        location = (call.target_id, call.path)
        endpoints = endpoints_by_location.get(location, [])
        lines = endpoint_lines.get(location, ())
        proximity = _maximum_proximity(target_by_id[call.target_id], catalog)
        start = bisect_left(lines, call.anchor.start_line - proximity)
        end = bisect_right(lines, call.anchor.start_line + proximity)
        for endpoint in endpoints[start:end]:
            _check(deadline, cancel_event)
            if (
                call.target_id != endpoint.target_id
                or call.path != endpoint.path
                or call.id == endpoint.id
                or not _within_endpoint_rule(call, endpoint, target_by_id[call.target_id], catalog)
            ):
                continue
            _add_edge(
                edge_candidates,
                GraphEdgeKind.DECLARED_NEAR_ENDPOINT,
                observation_nodes[call.id],
                observation_nodes[endpoint.id],
                tuple(sorted((call.evidence_id, endpoint.evidence_id))),
                included_ids,
                limits.max_graph_edges,
            )
            if len(edge_candidates) > limits.max_graph_edges:
                limitations.add(ContextLimitation.GRAPH_EDGE_LIMIT_EXCEEDED)
                break
        if ContextLimitation.GRAPH_EDGE_LIMIT_EXCEEDED in limitations:
            break
    ordered_edges = tuple(sorted(edge_candidates.values(), key=lambda item: item.id))
    if len(ordered_edges) > limits.max_graph_edges:
        limitations.add(ContextLimitation.GRAPH_EDGE_LIMIT_EXCEEDED)
        ordered_edges = ordered_edges[: limits.max_graph_edges]
    return GraphBuildResult(
        nodes=ordered_nodes,
        edges=ordered_edges,
        limitation_codes=tuple(sorted(limitations)),
    )


def _node(
    *,
    kind: GraphNodeKind,
    evidence_ids: tuple[str, ...],
    target_id: str | None = None,
    path: str | None = None,
    observation_id: str | None = None,
) -> ContextGraphNode:
    payload = {
        "kind": kind,
        "target_id": target_id,
        "path": path,
        "observation_id": observation_id,
        "evidence_ids": evidence_ids,
    }
    return ContextGraphNode(id=context_node_id(payload), **payload)


def _add_edge(
    edges: dict[str, ContextGraphEdge],
    kind: GraphEdgeKind,
    from_node: ContextGraphNode,
    to_node: ContextGraphNode,
    evidence_ids: tuple[str, ...],
    included_node_ids: set[str],
    maximum_edges: int,
) -> None:
    if from_node.id not in included_node_ids or to_node.id not in included_node_ids:
        return
    if len(edges) > maximum_edges:
        return
    payload = {
        "kind": kind,
        "from_node_id": from_node.id,
        "to_node_id": to_node.id,
        "evidence_ids": evidence_ids,
    }
    edge = ContextGraphEdge(id=context_edge_id(payload), **payload)
    edges[edge.id] = edge


def _observation_node_kind(kind: ObservationKind) -> GraphNodeKind:
    return {
        ObservationKind.IMPORT_DECLARATION: GraphNodeKind.IMPORT_DECLARATION,
        ObservationKind.TARGET_REFERENCE: GraphNodeKind.EXPLICIT_REFERENCE,
        ObservationKind.EXPLICIT_CALL: GraphNodeKind.EXPLICIT_CALL,
        ObservationKind.TARGET_CONFIGURATION: GraphNodeKind.CONFIGURATION_ENTRY,
        ObservationKind.ENDPOINT_DECLARATION: GraphNodeKind.ENDPOINT_DECLARATION,
    }[kind]


def _reference_index(
    observations: tuple[ContextObservation, ...],
) -> dict[tuple[object, ...], ContextObservation]:
    result: dict[tuple[object, ...], ContextObservation] = {}
    for observation in observations:
        if observation.kind != ObservationKind.TARGET_REFERENCE:
            continue
        key = _reference_key(observation)
        existing = result.get(key)
        if existing is None or observation.id < existing.id:
            result[key] = observation
    return result


def _reference_key(observation: ContextObservation) -> tuple[object, ...]:
    return (
        observation.target_id,
        observation.path,
        observation.binding,
        observation.member_path,
        observation.anchor.start_line,
        observation.anchor.start_column,
    )


def _within_endpoint_rule(
    call: ContextObservation,
    endpoint: ContextObservation,
    target: ContextTarget,
    catalog: ContextRuleCatalog,
) -> bool:
    if endpoint.rule_id is None or endpoint.rule_id not in target.endpoint_rule_ids:
        return False
    rule = next((item for item in catalog.endpoint_rules if item.id == endpoint.rule_id), None)
    return bool(
        rule is not None
        and abs(call.anchor.start_line - endpoint.anchor.start_line) <= rule.proximity_lines
    )


def _maximum_proximity(target: ContextTarget, catalog: ContextRuleCatalog) -> int:
    values = [
        rule.proximity_lines
        for rule in catalog.endpoint_rules
        if rule.id in target.endpoint_rule_ids
    ]
    return max(values, default=0)


def _check(deadline: float | None, cancel_event: threading.Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise ContextCancelled
    if deadline is not None and time.monotonic() >= deadline:
        raise GraphDeadlineExceeded
