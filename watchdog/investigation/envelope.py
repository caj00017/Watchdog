from __future__ import annotations

from pydantic import BaseModel, ValidationError

from watchdog.domain.advisories import (
    AdvisoryRecord,
    AffectedPackage,
    AffectedRange,
    VersionEvent,
)
from watchdog.domain.context import (
    ContextBundle,
    ContextEvidenceItem,
    ContextObservation,
    ContextSignal,
    ContextSignalKind,
)
from watchdog.domain.evidence import EvidenceBundle, EvidenceItem
from watchdog.domain.inventory import DependencyInventory
from watchdog.domain.investigation import (
    AdvisoryProvenanceReference,
    EnvelopeAdvisory,
    EnvelopeAffectedPackage,
    EnvelopeAffectedRange,
    EnvelopeAnchor,
    EnvelopeCoordinate,
    EnvelopeEvidence,
    EnvelopeEvidenceKind,
    EnvelopeGraphEdge,
    EnvelopeGraphNode,
    EnvelopeMatch,
    EnvelopeObservation,
    EnvelopeSeverity,
    EnvelopeSignal,
    EnvelopeVersionEvent,
    InvestigationAssumptionCode,
    InvestigationCoverage,
    InvestigationEnvelope,
    InvestigationLimitationCode,
    InvestigationProducer,
    MissingEvidenceCode,
    ValidationActionCode,
)
from watchdog.domain.matching import DependencyMatchReport, MatchState
from watchdog.investigation.identifiers import (
    advisory_provenance_id,
    canonical_json_bytes,
    investigation_envelope_id,
)
from watchdog.investigation.limits import InvestigationConfiguration
from watchdog.investigation.prompts import (
    MODEL_RESPONSE_SCHEMA_SHA256,
    RESPONSE_SCHEMA_VERSION,
    SYSTEM_INSTRUCTION_SHA256,
    SYSTEM_INSTRUCTION_VERSION,
)


class InvestigationInputError(ValueError):
    """Validated Phase 1–5 inputs disagree at the Phase 6 boundary."""

    code = "invalid_investigation_input"


class InvestigationEnvelopeLimitError(ValueError):
    """Even an evidence-free canonical envelope exceeds its hard byte limit."""

    code = "investigation_envelope_base_too_large"


def investigation_producer(configuration: InvestigationConfiguration) -> InvestigationProducer:
    return InvestigationProducer(
        name=configuration.producer_name,
        version=configuration.producer_version,
        envelope_schema_version=configuration.envelope_schema_version,
        response_schema_version=RESPONSE_SCHEMA_VERSION,
        response_schema_sha256=MODEL_RESPONSE_SCHEMA_SHA256,
        prompt_version=SYSTEM_INSTRUCTION_VERSION,
        prompt_sha256=SYSTEM_INSTRUCTION_SHA256,
        policy_version=configuration.policy_version,
        gateway_protocol_version=configuration.gateway_protocol_version,
    )


def validate_investigation_inputs(
    advisory: AdvisoryRecord,
    inventory: DependencyInventory,
    report: DependencyMatchReport,
    evidence: EvidenceBundle,
    context: ContextBundle,
) -> None:
    try:
        advisory = _revalidate(advisory)
        inventory = _revalidate(inventory)
        report = _revalidate(report)
        evidence = _revalidate(evidence)
        context = _revalidate(context)
    except ValidationError as exc:
        raise InvestigationInputError("an input failed canonical schema validation") from exc
    _validate_boundary_identities(advisory, inventory, report)
    if not (inventory.snapshot == report.snapshot == evidence.snapshot == context.snapshot):
        raise InvestigationInputError("investigation inputs do not describe one exact snapshot")
    if report.advisory_id not in {advisory.primary_id, *advisory.aliases}:
        raise InvestigationInputError("advisory identity disagrees with the match report")
    if len(evidence.match_links) != len(report.matches):
        raise InvestigationInputError("Phase 4 match linkage disagrees with the report")
    if len(context.match_links) != len(report.matches):
        raise InvestigationInputError("Phase 5 match linkage disagrees with the report")
    for ordinal, match in enumerate(report.matches):
        if match.advisory_component_index >= len(advisory.affected_packages):
            raise InvestigationInputError("match cites an unknown advisory component")
        component = advisory.affected_packages[match.advisory_component_index]
        if match.advisory_ecosystem != component.ecosystem or match.advisory_name != component.name:
            raise InvestigationInputError("match package identity disagrees with the advisory")
        phase4_link = evidence.match_links[ordinal]
        if (
            phase4_link.match_ordinal != ordinal
            or phase4_link.advisory_component_index != match.advisory_component_index
            or phase4_link.component_id != match.component_id
            or phase4_link.match_state != match.state
        ):
            raise InvestigationInputError("Phase 4 linkage disagrees with a dependency match")
        phase5_link = context.match_links[ordinal]
        if phase5_link.match_ordinal != ordinal:
            raise InvestigationInputError("Phase 5 linkage disagrees with a dependency match")
        if not set(phase5_link.dependency_evidence_ids).issubset(phase4_link.evidence_ids):
            raise InvestigationInputError("Phase 5 cites unrelated Phase 4 evidence")


def build_investigation_envelope(
    advisory: AdvisoryRecord,
    inventory: DependencyInventory,
    report: DependencyMatchReport,
    evidence_bundle: EvidenceBundle,
    context_bundle: ContextBundle,
    configuration: InvestigationConfiguration,
) -> InvestigationEnvelope:
    validate_investigation_inputs(advisory, inventory, report, evidence_bundle, context_bundle)
    limits = configuration.limits
    selected_match_count = min(len(report.matches), limits.max_matches)
    all_selected_ordinals = set(range(selected_match_count))
    evidence_available = _total_evidence_count(
        evidence_bundle,
        context_bundle,
        all_selected_ordinals,
    )
    advisory_values_omitted = _advisory_omission_count(
        advisory,
        report,
        all_selected_ordinals,
    )
    fixed_limitations = _input_limitations(
        advisory,
        inventory,
        report,
        evidence_bundle,
        context_bundle,
    )
    if selected_match_count < len(report.matches):
        fixed_limitations.add(InvestigationLimitationCode.MATCH_LIMIT_EXCEEDED)
    if advisory_values_omitted:
        fixed_limitations.add(InvestigationLimitationCode.ADVISORY_DATA_LIMIT_EXCEEDED)
    include_optional_advisory = True
    while True:
        selected_ordinals = set(range(selected_match_count))
        provenance = _advisory_provenance(advisory, report, selected_ordinals)
        affected_packages = _affected_packages(advisory, report, selected_ordinals)
        candidates = _evidence_candidates(
            evidence_bundle,
            context_bundle,
            selected_ordinals,
        )
        selected = list(candidates[: limits.max_evidence_items])
        if len(selected) < evidence_available:
            fixed_limitations.add(InvestigationLimitationCode.EVIDENCE_ITEM_LIMIT_EXCEEDED)
        byte_limited = False
        while True:
            limitations = set(fixed_limitations)
            if byte_limited:
                limitations.add(InvestigationLimitationCode.ENVELOPE_BYTE_LIMIT_EXCEEDED)
            envelope = _assemble_envelope(
                advisory,
                inventory,
                report,
                context_bundle,
                configuration,
                provenance,
                affected_packages,
                selected,
                selected_match_count,
                evidence_available,
                advisory_values_omitted,
                include_optional_advisory,
                limitations,
            )
            if len(canonical_json_bytes(envelope)) <= limits.max_input_bytes:
                return envelope
            fixed_limitations.add(InvestigationLimitationCode.ENVELOPE_BYTE_LIMIT_EXCEEDED)
            if selected:
                selected.pop()
                byte_limited = True
                continue
            if selected_match_count:
                selected_match_count -= 1
                fixed_limitations.add(InvestigationLimitationCode.MATCH_LIMIT_EXCEEDED)
                break
            if include_optional_advisory:
                include_optional_advisory = False
                advisory_values_omitted = _all_optional_advisory_value_count(advisory)
                fixed_limitations.add(InvestigationLimitationCode.ADVISORY_DATA_LIMIT_EXCEEDED)
                break
            raise InvestigationEnvelopeLimitError(
                "canonical investigation metadata exceeds the input byte limit"
            )


def _assemble_envelope(
    advisory: AdvisoryRecord,
    inventory: DependencyInventory,
    report: DependencyMatchReport,
    context_bundle: ContextBundle,
    configuration: InvestigationConfiguration,
    provenance: tuple[AdvisoryProvenanceReference, ...],
    affected_packages: tuple[EnvelopeAffectedPackage, ...],
    selected: list[EnvelopeEvidence],
    selected_match_count: int,
    evidence_available: int,
    advisory_values_omitted: int,
    include_optional_advisory: bool,
    limitations: set[InvestigationLimitationCode],
) -> InvestigationEnvelope:
    selected_phase4 = {
        item.id for item in selected if item.kind == EnvelopeEvidenceKind.DEPENDENCY_SOURCE
    }
    selected = [
        item
        for item in selected
        if item.kind == EnvelopeEvidenceKind.DEPENDENCY_SOURCE
        or set(item.dependency_evidence_ids).issubset(selected_phase4)
    ]
    selected_ids = {item.id for item in selected}
    observations = tuple(
        _observation(item)
        for item in context_bundle.observations
        if item.match_ordinal < selected_match_count and item.evidence_id in selected_ids
    )
    observation_ids = {item.id for item in observations}
    graph_nodes = tuple(
        EnvelopeGraphNode(
            id=item.id,
            kind=item.kind.value,
            target_id=item.target_id,
            path=item.path,
            observation_id=item.observation_id,
            evidence_ids=item.evidence_ids,
        )
        for item in context_bundle.graph_nodes
        if set(item.evidence_ids).issubset(selected_ids)
        and (item.observation_id is None or item.observation_id in observation_ids)
    )
    graph_node_ids = {item.id for item in graph_nodes}
    graph_edges = tuple(
        EnvelopeGraphEdge(
            id=item.id,
            kind=item.kind.value,
            from_node_id=item.from_node_id,
            to_node_id=item.to_node_id,
            evidence_ids=item.evidence_ids,
        )
        for item in context_bundle.graph_edges
        if item.from_node_id in graph_node_ids
        and item.to_node_id in graph_node_ids
        and set(item.evidence_ids).issubset(selected_ids)
    )
    signals = tuple(
        _signal(item)
        for item in context_bundle.signals
        if item.match_ordinal < selected_match_count
        and set(item.dependency_evidence_ids).issubset(selected_phase4)
        and set(item.evidence_ids).issubset(selected_ids)
    )
    signal_ids = {item.id for item in signals}
    matches = _matches(
        report,
        context_bundle,
        provenance,
        selected_ids,
        observation_ids,
        signal_ids,
        selected_match_count,
    )
    if any(item.content is None for item in selected):
        limitations.add(InvestigationLimitationCode.DECISIVE_EVIDENCE_OMITTED)
    evidence_omitted = evidence_available - len(selected)
    coverage = InvestigationCoverage(
        input_partial=bool(limitations),
        envelope_truncated=bool(
            {
                InvestigationLimitationCode.MATCH_LIMIT_EXCEEDED,
                InvestigationLimitationCode.EVIDENCE_ITEM_LIMIT_EXCEEDED,
                InvestigationLimitationCode.ENVELOPE_BYTE_LIMIT_EXCEEDED,
            }
            & limitations
        ),
        advisory_values_omitted=advisory_values_omitted,
        matches_available=len(report.matches),
        matches_included=len(matches),
        matches_omitted=len(report.matches) - len(matches),
        evidence_available=evidence_available,
        evidence_included=len(selected),
        evidence_omitted=evidence_omitted,
        limitations=tuple(sorted(limitations)),
    )
    missing_codes = _missing_codes(report, selected, signals, coverage)
    assumption_codes = _assumption_codes(report, observations)
    action_codes = _action_codes(missing_codes, selected, observations)
    advisory_input = EnvelopeAdvisory(
        primary_id=advisory.primary_id,
        aliases=(
            tuple(value for value in sorted(set(advisory.aliases)) if _fits_string(value))[:32]
            if include_optional_advisory
            else ()
        ),
        affected_packages=affected_packages,
        severity=(
            tuple(
                sorted(
                    (
                        EnvelopeSeverity(type=item.type, score=item.score)
                        for item in advisory.severity
                        if _fits_string(item.type) and _fits_string(item.score)
                    ),
                    key=lambda item: (item.type, item.score),
                )
            )[:32]
            if include_optional_advisory
            else ()
        ),
        provenance=provenance if include_optional_advisory else (),
        partial=advisory.partial,
        conflict_count=len(advisory.conflicts),
        warning_count=len(advisory.warnings),
    )
    citations = tuple(
        sorted(
            {
                *(item.id for item in provenance),
                *(item.id for item in selected),
                *(item.id for item in observations),
                *(item.id for item in signals),
            }
        )
    )
    payload = {
        "schema_version": "1",
        "producer": investigation_producer(configuration),
        "advisory": advisory_input,
        "snapshot": inventory.snapshot,
        "matches": matches,
        "evidence": tuple(selected),
        "observations": observations,
        "graph_nodes": graph_nodes,
        "graph_edges": graph_edges,
        "signals": signals,
        "allowed_citation_ids": citations,
        "allowed_assumption_codes": tuple(sorted(assumption_codes)),
        "allowed_missing_evidence_codes": tuple(sorted(missing_codes)),
        "allowed_validation_action_codes": tuple(sorted(action_codes)),
        "coverage": coverage,
    }
    return InvestigationEnvelope(id=investigation_envelope_id(payload), **payload)


def _advisory_provenance(
    advisory: AdvisoryRecord,
    report: DependencyMatchReport,
    selected_ordinals: set[int],
) -> tuple[AdvisoryProvenanceReference, ...]:
    component_indexes = {
        match.advisory_component_index
        for ordinal, match in enumerate(report.matches)
        if ordinal in selected_ordinals
    }
    prefixes = {
        "/primary_id",
        "/aliases",
        "/severity",
        *(f"/affected_packages/{index}" for index in component_indexes),
    }
    references: list[AdvisoryProvenanceReference] = []
    for field, records in sorted(advisory.field_provenance.items()):
        if not any(field == prefix or field.startswith(f"{prefix}/") for prefix in prefixes):
            continue
        for record in records:
            payload = {
                "field": field,
                "source": record.source,
                "record_id": record.record_id,
                "source_url": record.source_url,
                "retrieved_at": record.retrieved_at,
                "path": record.path,
            }
            try:
                references.append(
                    AdvisoryProvenanceReference(
                        id=advisory_provenance_id(payload),
                        **payload,
                    )
                )
            except ValidationError:
                continue
    return tuple(sorted(set(references), key=lambda item: item.id)[:256])


def _affected_packages(
    advisory: AdvisoryRecord,
    report: DependencyMatchReport,
    selected_ordinals: set[int],
) -> tuple[EnvelopeAffectedPackage, ...]:
    indexes = sorted(
        {
            match.advisory_component_index
            for ordinal, match in enumerate(report.matches)
            if ordinal in selected_ordinals
        }
    )
    return tuple(_affected_package(index, advisory.affected_packages[index]) for index in indexes)


def _affected_package(index: int, package: AffectedPackage) -> EnvelopeAffectedPackage:
    ranges: list[EnvelopeAffectedRange] = []
    for item in package.ranges[:32]:
        try:
            ranges.append(_affected_range(item))
        except ValidationError:
            continue
    return EnvelopeAffectedPackage(
        advisory_component_index=index,
        ecosystem=package.ecosystem,
        name=package.name,
        purl=package.purl if package.purl is None or _fits_string(package.purl) else None,
        ranges=tuple(ranges),
        versions=tuple(value for value in sorted(set(package.versions)) if _fits_string(value))[
            :256
        ],
    )


def _affected_range(value: AffectedRange) -> EnvelopeAffectedRange:
    events: list[EnvelopeVersionEvent] = []
    for item in value.events[:64]:
        try:
            events.append(_version_event(item))
        except ValidationError:
            continue
    return EnvelopeAffectedRange(
        type=value.type,
        events=tuple(events),
    )


def _version_event(value: VersionEvent) -> EnvelopeVersionEvent:
    return EnvelopeVersionEvent(
        introduced=value.introduced,
        fixed=value.fixed,
        last_affected=value.last_affected,
        limit=value.limit,
    )


def _evidence_candidates(
    evidence_bundle: EvidenceBundle,
    context_bundle: ContextBundle,
    selected_ordinals: set[int],
) -> tuple[EnvelopeEvidence, ...]:
    phase4_ordinals: dict[str, set[int]] = {}
    for link in evidence_bundle.match_links:
        if link.match_ordinal not in selected_ordinals:
            continue
        for evidence_id in link.evidence_ids:
            phase4_ordinals.setdefault(evidence_id, set()).add(link.match_ordinal)
    signal_ranks: dict[str, int] = {}
    for signal in context_bundle.signals:
        for evidence_id in (*signal.dependency_evidence_ids, *signal.evidence_ids):
            signal_ranks[evidence_id] = min(signal_ranks.get(evidence_id, 1_001), signal.rank)
    candidates: list[tuple[tuple[object, ...], EnvelopeEvidence]] = []
    for phase4_item in evidence_bundle.items:
        ordinals = phase4_ordinals.get(phase4_item.id)
        if not ordinals:
            continue
        envelope_item = _phase4_evidence(phase4_item, tuple(sorted(ordinals)))
        candidates.append(
            (
                _evidence_sort_key(
                    envelope_item,
                    signal_ranks.get(phase4_item.id, 1_001),
                    None,
                ),
                envelope_item,
            )
        )
    for phase5_item in context_bundle.evidence:
        if phase5_item.match_ordinal not in selected_ordinals:
            continue
        envelope_item = _phase5_evidence(phase5_item)
        candidates.append(
            (
                _evidence_sort_key(
                    envelope_item,
                    signal_ranks.get(phase5_item.id, 1_001),
                    phase5_item.rule_id,
                ),
                envelope_item,
            )
        )
    return tuple(item for _, item in sorted(candidates, key=lambda pair: pair[0]))


def _phase4_evidence(item: EvidenceItem, ordinals: tuple[int, ...]) -> EnvelopeEvidence:
    return EnvelopeEvidence(
        id=item.id,
        kind=EnvelopeEvidenceKind.DEPENDENCY_SOURCE,
        match_ordinals=ordinals,
        status=item.status.value,
        path=item.source.path,
        file_sha256=item.source.file_sha256,
        content=item.content.text if item.content else None,
        content_sha256=item.content.sha256 if item.content else None,
        limitations=tuple(sorted(str(code) for code in item.limitation_codes)),
    )


def _phase5_evidence(item: ContextEvidenceItem) -> EnvelopeEvidence:
    return EnvelopeEvidence(
        id=item.id,
        kind=EnvelopeEvidenceKind.LEXICAL_CONTEXT,
        match_ordinals=(item.match_ordinal,),
        status=item.status.value,
        path=item.source.path,
        file_sha256=item.source.file_sha256,
        content=item.content.text if item.content else None,
        content_sha256=item.content.sha256 if item.content else None,
        anchor=EnvelopeAnchor(**item.source.anchor.model_dump()),
        observation_kind=item.observation_kind.value,
        dependency_evidence_ids=item.dependency_evidence_ids,
        limitations=tuple(sorted(code.value for code in item.limitation_codes)),
    )


def _evidence_sort_key(
    item: EnvelopeEvidence,
    rank: int,
    rule_id: str | None,
) -> tuple[object, ...]:
    anchor = item.anchor
    anchor_key = (
        (
            anchor.start_line,
            anchor.start_column,
            anchor.end_line,
            anchor.end_column,
        )
        if anchor
        else (0, 0, 0, 0)
    )
    return (
        min(item.match_ordinals),
        rank,
        item.kind.value,
        item.path.encode("utf-8"),
        anchor_key,
        rule_id or "",
        item.id,
    )


def _observation(item: ContextObservation) -> EnvelopeObservation:
    return EnvelopeObservation(
        id=item.id,
        kind=item.kind.value,
        match_ordinal=item.match_ordinal,
        evidence_id=item.evidence_id,
        path=item.path,
        anchor=EnvelopeAnchor(**item.anchor.model_dump()),
        binding=item.binding,
        member_path=item.member_path,
        rule_id=item.rule_id,
    )


def _signal(item: ContextSignal) -> EnvelopeSignal:
    return EnvelopeSignal(
        id=item.id,
        kind=item.kind.value,
        match_ordinal=item.match_ordinal,
        rank=item.rank,
        dependency_evidence_ids=item.dependency_evidence_ids,
        evidence_ids=item.evidence_ids,
        limitations=tuple(sorted(code.value for code in item.limitation_codes)),
    )


def _matches(
    report: DependencyMatchReport,
    context_bundle: ContextBundle,
    provenance: tuple[AdvisoryProvenanceReference, ...],
    evidence_ids: set[str],
    observation_ids: set[str],
    signal_ids: set[str],
    selected_match_count: int,
) -> tuple[EnvelopeMatch, ...]:
    results: list[EnvelopeMatch] = []
    for ordinal, match in enumerate(report.matches[:selected_match_count]):
        phase5_link = context_bundle.match_links[ordinal]
        component_prefix = f"/affected_packages/{match.advisory_component_index}"
        advisory_ids = tuple(
            sorted(
                item.id
                for item in provenance
                if item.field in {"/primary_id", "/aliases"}
                or item.field.startswith(component_prefix)
            )
        )
        dep_ids = tuple(sorted(set(phase5_link.dependency_evidence_ids) & evidence_ids))
        context_ids = tuple(sorted(set(phase5_link.context_evidence_ids) & evidence_ids))
        observations = tuple(sorted(set(phase5_link.observation_ids) & observation_ids))
        signals = tuple(sorted(set(phase5_link.signal_ids) & signal_ids))
        coordinate = (
            EnvelopeCoordinate(
                ecosystem=match.coordinate.ecosystem.value,
                name=match.coordinate.name,
                version=match.coordinate.version,
            )
            if match.coordinate
            else None
        )
        limitations = tuple(
            sorted(
                {
                    *match.coverage_limitations,
                    *(code.value for code in phase5_link.limitation_codes),
                }
            )
        )
        results.append(
            EnvelopeMatch(
                ordinal=ordinal,
                advisory_component_index=match.advisory_component_index,
                component_id=match.component_id,
                state=match.state.value,
                coordinate=coordinate,
                relationship=match.relationship.value if match.relationship else None,
                scopes=tuple(sorted(scope.value for scope in match.scopes)),
                applicability=match.applicability.kind.value if match.applicability else None,
                advisory_provenance_ids=advisory_ids,
                dependency_evidence_ids=dep_ids,
                context_evidence_ids=context_ids,
                observation_ids=observations,
                signal_ids=signals,
                limitations=limitations,
            )
        )
    return tuple(results)


def _input_limitations(
    advisory: AdvisoryRecord,
    inventory: DependencyInventory,
    report: DependencyMatchReport,
    evidence: EvidenceBundle,
    context: ContextBundle,
) -> set[InvestigationLimitationCode]:
    limitations: set[InvestigationLimitationCode] = set()
    if advisory.partial:
        limitations.add(InvestigationLimitationCode.ADVISORY_PARTIAL)
    if inventory.partial:
        limitations.add(InvestigationLimitationCode.INVENTORY_PARTIAL)
    if report.partial:
        limitations.add(InvestigationLimitationCode.MATCH_REPORT_PARTIAL)
    if evidence.partial:
        limitations.add(InvestigationLimitationCode.PHASE4_EVIDENCE_PARTIAL)
    if context.partial:
        limitations.add(InvestigationLimitationCode.PHASE5_CONTEXT_PARTIAL)
    states = {match.state for match in report.matches}
    if MatchState.SCANNER_INCOMPLETE in states:
        limitations.add(InvestigationLimitationCode.SCANNER_INCOMPLETE)
    if MatchState.VERSION_UNKNOWN in states:
        limitations.add(InvestigationLimitationCode.VERSION_UNKNOWN)
    if MatchState.UNSUPPORTED_ADVISORY_COMPONENT in states:
        limitations.add(InvestigationLimitationCode.UNSUPPORTED_COMPONENT)
    return limitations


def _missing_codes(
    report: DependencyMatchReport,
    evidence: list[EnvelopeEvidence],
    signals: tuple[EnvelopeSignal, ...],
    coverage: InvestigationCoverage,
) -> set[MissingEvidenceCode]:
    codes: set[MissingEvidenceCode] = {
        MissingEvidenceCode.DEPLOYMENT_CONTEXT_ABSENT,
        MissingEvidenceCode.RUNTIME_CONFIGURATION_ABSENT,
    }
    limitations = set(coverage.limitations)
    if InvestigationLimitationCode.INVENTORY_PARTIAL in limitations:
        codes.add(MissingEvidenceCode.INVENTORY_PARTIAL)
    if InvestigationLimitationCode.SCANNER_INCOMPLETE in limitations:
        codes.add(MissingEvidenceCode.SCANNER_INCOMPLETE)
    if InvestigationLimitationCode.VERSION_UNKNOWN in limitations:
        codes.update(
            {
                MissingEvidenceCode.VERSION_UNKNOWN,
                MissingEvidenceCode.LOCKFILE_EVIDENCE_ABSENT,
            }
        )
    if InvestigationLimitationCode.UNSUPPORTED_COMPONENT in limitations:
        codes.add(MissingEvidenceCode.UNSUPPORTED_ADVISORY_COMPONENT)
    if InvestigationLimitationCode.PHASE4_EVIDENCE_PARTIAL in limitations:
        codes.add(MissingEvidenceCode.DEPENDENCY_EVIDENCE_PARTIAL)
    if InvestigationLimitationCode.PHASE5_CONTEXT_PARTIAL in limitations:
        codes.add(MissingEvidenceCode.CONTEXT_EVIDENCE_PARTIAL)
    if coverage.envelope_truncated:
        codes.add(MissingEvidenceCode.ENVELOPE_TRUNCATED)
    if any(item.content is None for item in evidence):
        codes.add(MissingEvidenceCode.REDACTION_OMISSION)
    positive_kinds = {
        ContextSignalKind.EXPLICIT_TARGET_CALL_OBSERVED.value,
        ContextSignalKind.TARGET_REFERENCE_OBSERVED.value,
        ContextSignalKind.DEPENDENCY_IMPORT_OBSERVED.value,
        ContextSignalKind.TARGET_CONFIGURATION_OBSERVED.value,
        ContextSignalKind.ENDPOINT_PROXIMITY_OBSERVED.value,
    }
    if not any(signal.kind in positive_kinds for signal in signals):
        codes.add(MissingEvidenceCode.CONTEXT_NOT_OBSERVED)
    return codes


def _assumption_codes(
    report: DependencyMatchReport,
    observations: tuple[EnvelopeObservation, ...],
) -> set[InvestigationAssumptionCode]:
    codes = {
        InvestigationAssumptionCode.DEPLOYMENT_CONTEXT_UNKNOWN,
        InvestigationAssumptionCode.RUNTIME_CONFIGURATION_UNKNOWN,
    }
    if observations:
        codes.add(InvestigationAssumptionCode.LEXICAL_OBSERVATION_MAY_NOT_EXECUTE)
    conditional = any(
        match.applicability and match.applicability.kind.value != "unconditional"
        for match in report.matches
    )
    if conditional:
        codes.update(
            {
                InvestigationAssumptionCode.ADVISORY_CONDITION_APPLICABILITY_UNKNOWN,
                InvestigationAssumptionCode.DEPENDENCY_APPLICABILITY_PRESERVED,
            }
        )
    return codes


def _action_codes(
    missing: set[MissingEvidenceCode],
    evidence: list[EnvelopeEvidence],
    observations: tuple[EnvelopeObservation, ...],
) -> set[ValidationActionCode]:
    actions = {
        ValidationActionCode.CONFIRM_DEPLOYMENT_CONDITIONS,
        ValidationActionCode.CONFIRM_RUNTIME_CONFIGURATION,
        ValidationActionCode.REVIEW_ADVISORY_CONDITIONS,
    }
    if any(item.kind == EnvelopeEvidenceKind.DEPENDENCY_SOURCE for item in evidence):
        actions.add(ValidationActionCode.REVIEW_CITED_DEPENDENCY_SOURCE)
    if observations:
        actions.add(ValidationActionCode.REVIEW_CITED_CONTEXT_SITE)
    if MissingEvidenceCode.VERSION_UNKNOWN in missing:
        actions.add(ValidationActionCode.OBTAIN_EXACT_VERSION_EVIDENCE)
    if MissingEvidenceCode.INVENTORY_PARTIAL in missing:
        actions.add(ValidationActionCode.OBTAIN_SUPPORTED_MANIFEST_EVIDENCE)
    if MissingEvidenceCode.SCANNER_INCOMPLETE in missing:
        actions.add(ValidationActionCode.RESOLVE_SCANNER_FAILURE)
    return actions


def _total_evidence_count(
    evidence: EvidenceBundle,
    context: ContextBundle,
    selected_ordinals: set[int],
) -> int:
    identifiers = {
        evidence_id
        for link in evidence.match_links
        if link.match_ordinal in selected_ordinals
        for evidence_id in link.evidence_ids
    }
    identifiers.update(
        evidence_id
        for link in context.match_links
        if link.match_ordinal in selected_ordinals
        for evidence_id in link.context_evidence_ids
    )
    return len(identifiers)


def _advisory_omission_count(
    advisory: AdvisoryRecord,
    report: DependencyMatchReport,
    selected_ordinals: set[int],
) -> int:
    valid_aliases = sum(_fits_string(item) for item in set(advisory.aliases))
    valid_severity = sum(
        _fits_string(item.type) and _fits_string(item.score) for item in advisory.severity
    )
    omitted = max(0, valid_aliases - 32) + (len(set(advisory.aliases)) - valid_aliases)
    omitted += max(0, valid_severity - 32) + (len(advisory.severity) - valid_severity)
    component_indexes = {
        match.advisory_component_index
        for ordinal, match in enumerate(report.matches)
        if ordinal in selected_ordinals
    }
    prefixes = {
        "/primary_id",
        "/aliases",
        "/severity",
        *(f"/affected_packages/{index}" for index in component_indexes),
    }
    provenance_records = [
        record
        for field, records in advisory.field_provenance.items()
        if any(field == prefix or field.startswith(f"{prefix}/") for prefix in prefixes)
        for record in records
    ]
    valid_provenance = sum(
        all(
            _fits_string(value)
            for value in (
                record.source,
                record.record_id,
                record.source_url,
                record.path,
            )
        )
        for record in provenance_records
    )
    omitted += max(0, valid_provenance - 256)
    omitted += len(provenance_records) - valid_provenance
    for index in component_indexes:
        package = advisory.affected_packages[index]
        omitted += max(0, len(package.ranges) - 32)
        omitted += max(0, len(set(package.versions)) - 256)
        omitted += sum(max(0, len(item.events) - 64) for item in package.ranges[:32])
        omitted += sum(not _fits_string(item) for item in set(package.versions))
        omitted += sum(not _fits_string(item.type) for item in package.ranges[:32])
        omitted += sum(
            not _event_fits(event) for item in package.ranges[:32] for event in item.events[:64]
        )
        if package.purl is not None and not _fits_string(package.purl):
            omitted += 1
    return omitted


def _all_optional_advisory_value_count(advisory: AdvisoryRecord) -> int:
    return (
        len(set(advisory.aliases))
        + len(advisory.severity)
        + sum(len(records) for records in advisory.field_provenance.values())
    )


def _validate_boundary_identities(
    advisory: AdvisoryRecord,
    inventory: DependencyInventory,
    report: DependencyMatchReport,
) -> None:
    required = [
        advisory.primary_id,
        inventory.snapshot.repository_url,
        report.advisory_id,
    ]
    for package in advisory.affected_packages:
        required.extend(value for value in (package.ecosystem, package.name) if value is not None)
    for match in report.matches:
        required.extend(
            value
            for value in (
                match.advisory_ecosystem,
                match.advisory_name,
                match.component_id,
            )
            if value is not None
        )
        if match.coordinate is not None:
            required.extend(
                (
                    match.coordinate.ecosystem.value,
                    match.coordinate.name,
                    match.coordinate.version,
                )
            )
    if not all(_fits_string(value) for value in required):
        raise InvestigationInputError("an investigation identity exceeds its schema bound")


def _fits_string(value: str) -> bool:
    return 0 < len(value) <= 4096


def _event_fits(value: VersionEvent) -> bool:
    selected = next(
        item
        for item in (value.introduced, value.fixed, value.last_affected, value.limit)
        if item is not None
    )
    return _fits_string(selected)


def _revalidate[TModel: BaseModel](value: TModel) -> TModel:
    return type(value).model_validate(value.model_dump(mode="python"))
