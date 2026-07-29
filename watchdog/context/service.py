from __future__ import annotations

import asyncio
import threading
import time
from contextlib import suppress

from watchdog.config.settings import Settings
from watchdog.context._recognition import (
    RecognitionBudget,
    RecognitionDeadlineExceeded,
    RecognitionResult,
)
from watchdog.context.catalog import DEFAULT_CONTEXT_CATALOG, catalog_metadata
from watchdog.context.configuration import recognize_configuration
from watchdog.context.discovery import (
    ContextCancelled,
    DiscoveryOmission,
    DiscoveryResult,
    discover_sources,
)
from watchdog.context.evidence import EvidenceBuildResult, build_context_evidence
from watchdog.context.go import recognize_go
from watchdog.context.graph import (
    GraphBuildResult,
    GraphDeadlineExceeded,
    build_observation_graph,
)
from watchdog.context.identifiers import (
    context_bundle_id,
    context_configuration_sha256,
)
from watchdog.context.javascript import recognize_javascript
from watchdog.context.limits import ContextConfiguration, ContextLimits
from watchdog.context.python import recognize_python
from watchdog.context.ranking import RankingBuildResult, build_context_signals
from watchdog.context.targets import build_context_targets, validate_context_inputs
from watchdog.domain.context import (
    ContextBundle,
    ContextCoverage,
    ContextCoverageKind,
    ContextLimitation,
    ContextProducer,
    ContextSignal,
    ContextTarget,
    ContextWarning,
    MatchContextLink,
    SourceFileOutcome,
    SourceFileStatus,
    SourceLanguage,
)
from watchdog.domain.evidence import EvidenceBundle
from watchdog.domain.inventory import DependencyInventory
from watchdog.domain.matching import DependencyMatchReport
from watchdog.domain.repositories import AcquiredRepository
from watchdog.evidence.redaction import Redactor


class ContextService:
    """Lease-scoped deterministic contextual analysis over validated Phase 3/4 input."""

    def __init__(
        self,
        configuration: ContextConfiguration | ContextLimits | None = None,
    ) -> None:
        metadata = catalog_metadata()
        if configuration is None:
            configured = ContextConfiguration.from_settings(Settings(), catalog=metadata)
        elif isinstance(configuration, ContextLimits):
            configured = ContextConfiguration(
                limits=configuration,
                catalog_version=metadata.version,
                catalog_sha256=metadata.sha256,
            )
        else:
            configured = configuration
        if (
            configured.catalog_version != metadata.version
            or configured.catalog_sha256 != metadata.sha256
        ):
            raise ValueError("ContextService configuration must use the checked-in catalog")
        trusted_configuration = ContextConfiguration(
            limits=configured.limits,
            catalog_version=metadata.version,
            catalog_sha256=metadata.sha256,
        )
        if configured != trusted_configuration:
            raise ValueError("ContextService producer and redaction versions are fixed")
        self._configuration = configured
        self._catalog_metadata = metadata
        self._redactor = Redactor(configured.enabled_detectors)

    @property
    def configuration(self) -> ContextConfiguration:
        return self._configuration

    async def collect(
        self,
        acquired: AcquiredRepository,
        inventory: DependencyInventory,
        report: DependencyMatchReport,
        evidence: EvidenceBundle,
    ) -> ContextBundle:
        validate_context_inputs(acquired, inventory, report, evidence)
        targets = build_context_targets(inventory, report, evidence)
        deadline = time.monotonic() + self._configuration.limits.deadline_seconds
        cancel_event = threading.Event()
        task = asyncio.create_task(
            asyncio.to_thread(
                self._collect_sync,
                acquired,
                inventory,
                report,
                evidence,
                targets,
                deadline,
                cancel_event,
            )
        )
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            cancel_event.set()
            with suppress(Exception):
                await task
            raise

    def _collect_sync(
        self,
        acquired: AcquiredRepository,
        inventory: DependencyInventory,
        report: DependencyMatchReport,
        phase4_evidence: EvidenceBundle,
        targets: tuple[ContextTarget, ...],
        deadline: float,
        cancel_event: threading.Event,
    ) -> ContextBundle:
        discovery = discover_sources(
            acquired.root,
            self._configuration.limits,
            DEFAULT_CONTEXT_CATALOG,
            deadline=deadline,
            cancel_event=cancel_event,
        )
        recognition = self._recognize(
            discovery,
            targets,
            deadline=deadline,
            cancel_event=cancel_event,
        )
        producer = self._producer()
        evidence = build_context_evidence(
            recognition,
            targets,
            inventory.snapshot,
            producer,
            self._configuration.limits,
            self._redactor,
            deadline=deadline,
            cancel_event=cancel_event,
        )
        try:
            graph = build_observation_graph(
                targets,
                evidence.observations,
                DEFAULT_CONTEXT_CATALOG,
                self._configuration.limits,
                deadline=deadline,
                cancel_event=cancel_event,
            )
        except GraphDeadlineExceeded:
            graph = GraphBuildResult(
                nodes=(),
                edges=(),
                limitation_codes=(ContextLimitation.CONTEXT_DEADLINE_EXCEEDED,),
            )
        limitations = self._coverage_limitations(discovery, evidence, graph, targets)
        ranking = build_context_signals(
            match_count=len(report.matches),
            targets=targets,
            observations=evidence.observations,
            graph_edges=graph.edges,
            coverage_limitations=limitations,
            deadline=deadline,
            cancel_event=cancel_event,
        )
        limitations = tuple(sorted({*limitations, *ranking.limitation_codes}))
        signals = ranking.signals
        file_outcomes = self._file_outcomes(discovery, evidence)
        warnings, warning_limited = self._warnings(discovery, evidence, graph, ranking)
        if warning_limited:
            limitations = tuple(sorted({*limitations, ContextLimitation.WARNING_LIMIT_EXCEEDED}))
            # Signals are rebuilt because warning truncation is a coverage limit.
            rebuilt_ranking = build_context_signals(
                match_count=len(report.matches),
                targets=targets,
                observations=evidence.observations,
                graph_edges=graph.edges,
                coverage_limitations=limitations,
                deadline=deadline,
                cancel_event=cancel_event,
            )
            limitations = tuple(sorted({*limitations, *rebuilt_ranking.limitation_codes}))
            signals = rebuilt_ranking.signals
        links = self._match_links(
            report,
            phase4_evidence,
            targets,
            evidence,
            signals,
            limitations,
        )
        coverage = ContextCoverage(
            kind=(ContextCoverageKind.PARTIAL if limitations else ContextCoverageKind.COMPLETE),
            directories_enumerated=discovery.directories_enumerated,
            candidate_paths=discovery.candidate_paths,
            excluded_directories=discovery.excluded_directories,
            eligible_source_files=discovery.eligible_source_files,
            files_read=discovery.files_read,
            source_bytes_read=discovery.source_bytes_read,
            lexical_tokens=sum(result.lexical_tokens for result in recognition),
            observations=len(evidence.observations),
            evidence_items=len(evidence.evidence),
            graph_nodes=len(graph.nodes),
            graph_edges=len(graph.edges),
            signals=len(signals),
            limitation_codes=limitations,
        )
        configuration_sha = context_configuration_sha256(self._configuration)
        payload = {
            "snapshot": inventory.snapshot,
            "configuration": self._configuration,
            "configuration_sha256": configuration_sha,
            "catalog": self._catalog_metadata,
            "targets": targets,
            "file_outcomes": file_outcomes,
            "evidence": evidence.evidence,
            "observations": evidence.observations,
            "graph_nodes": graph.nodes,
            "graph_edges": graph.edges,
            "signals": signals,
            "match_links": links,
            "warnings": warnings,
            "coverage": coverage,
            "partial": bool(limitations),
        }
        return ContextBundle(id=context_bundle_id(payload), **payload)

    def _recognize(
        self,
        discovery: DiscoveryResult,
        targets: tuple[ContextTarget, ...],
        *,
        deadline: float,
        cancel_event: threading.Event,
    ) -> tuple[RecognitionResult, ...]:
        results: list[RecognitionResult] = []
        total_tokens = 0
        limits = self._configuration.limits
        for source in discovery.sources:
            if cancel_event.is_set():
                raise ContextCancelled
            remaining = limits.max_total_tokens - total_tokens
            if remaining <= 0:
                results.append(
                    RecognitionResult(
                        source=source,
                        facts=(),
                        lexical_tokens=0,
                        limitation_codes=(ContextLimitation.TOTAL_TOKEN_LIMIT_EXCEEDED,),
                    )
                )
                continue
            if time.monotonic() >= deadline:
                results.append(
                    RecognitionResult(
                        source=source,
                        facts=(),
                        lexical_tokens=0,
                        limitation_codes=(ContextLimitation.CONTEXT_DEADLINE_EXCEEDED,),
                    )
                )
                continue
            per_file_tokens = min(limits.max_tokens_per_file, remaining)
            file_limits = limits.model_copy(update={"max_tokens_per_file": per_file_tokens})
            budget = RecognitionBudget(
                limits=file_limits,
                deadline=deadline,
                cancel_event=cancel_event,
            )
            try:
                if source.language == SourceLanguage.PYTHON:
                    applicable = tuple(
                        target for target in targets if target.ecosystem.value == "PyPI"
                    )
                    result = recognize_python(source, applicable, DEFAULT_CONTEXT_CATALOG, budget)
                elif source.language == SourceLanguage.JAVASCRIPT:
                    applicable = tuple(
                        target for target in targets if target.ecosystem.value == "npm"
                    )
                    result = recognize_javascript(
                        source, applicable, DEFAULT_CONTEXT_CATALOG, budget
                    )
                elif source.language == SourceLanguage.GO:
                    applicable = tuple(
                        target for target in targets if target.ecosystem.value == "Go"
                    )
                    result = recognize_go(source, applicable, DEFAULT_CONTEXT_CATALOG, budget)
                else:
                    result = recognize_configuration(
                        source, targets, DEFAULT_CONTEXT_CATALOG, budget
                    )
            except RecognitionDeadlineExceeded:
                result = RecognitionResult(
                    source=source,
                    facts=(),
                    lexical_tokens=min(budget.lexical_tokens, remaining),
                    limitation_codes=(ContextLimitation.CONTEXT_DEADLINE_EXCEEDED,),
                )
            except ContextCancelled:
                raise
            except Exception:
                result = RecognitionResult(
                    source=source,
                    facts=(),
                    lexical_tokens=min(budget.lexical_tokens, remaining),
                    limitation_codes=(ContextLimitation.RECOGNIZER_FAILED,),
                )
            if result.lexical_tokens > remaining:
                result = RecognitionResult(
                    source=source,
                    facts=(),
                    lexical_tokens=remaining,
                    limitation_codes=tuple(
                        sorted(
                            {
                                *result.limitation_codes,
                                ContextLimitation.TOTAL_TOKEN_LIMIT_EXCEEDED,
                            }
                        )
                    ),
                )
            total_tokens += result.lexical_tokens
            results.append(result)
        return tuple(results)

    def _producer(self) -> ContextProducer:
        configuration = self._configuration
        return ContextProducer(
            name=configuration.producer_name,
            version=configuration.producer_version,
            python_recognizer_version=configuration.python_recognizer_version,
            javascript_recognizer_version=configuration.javascript_recognizer_version,
            go_recognizer_version=configuration.go_recognizer_version,
            configuration_recognizer_version=configuration.configuration_recognizer_version,
            graph_version=configuration.graph_version,
            ranking_version=configuration.ranking_version,
            catalog_version=configuration.catalog_version,
            catalog_sha256=configuration.catalog_sha256,
            redaction_policy_version=configuration.redaction_policy_version,
        )

    def _coverage_limitations(
        self,
        discovery: DiscoveryResult,
        evidence: EvidenceBuildResult,
        graph: GraphBuildResult,
        targets: tuple[ContextTarget, ...],
    ) -> tuple[ContextLimitation, ...]:
        return tuple(
            sorted(
                {
                    *discovery.limitation_codes,
                    *evidence.limitation_codes,
                    *graph.limitation_codes,
                    *(code for target in targets for code in target.limitation_codes),
                }
            )
        )

    def _file_outcomes(
        self, discovery: DiscoveryResult, evidence: EvidenceBuildResult
    ) -> tuple[SourceFileOutcome, ...]:
        omissions = tuple(self._omitted_outcome(item) for item in discovery.omissions)
        return tuple(
            sorted(
                (*evidence.file_outcomes, *omissions),
                key=lambda item: item.path.encode("utf-8"),
            )
        )

    def _omitted_outcome(self, omission: DiscoveryOmission) -> SourceFileOutcome:
        return SourceFileOutcome(
            path=omission.path,
            language=omission.language,
            status=SourceFileStatus.OMITTED,
            byte_count=0,
            lexical_tokens=0,
            limitation_codes=(omission.limitation,),
            test_source=omission.test_source,
        )

    def _warnings(
        self,
        discovery: DiscoveryResult,
        evidence: EvidenceBuildResult,
        graph: GraphBuildResult,
        ranking: RankingBuildResult,
    ) -> tuple[tuple[ContextWarning, ...], bool]:
        candidates = [*discovery.warnings, *evidence.warnings]
        for code in graph.limitation_codes:
            candidates.append(ContextWarning(code=code, message="context graph limit was exceeded"))
        for code in ranking.limitation_codes:
            candidates.append(
                ContextWarning(code=code, message="context ranking deadline was exceeded")
            )
        ordered = tuple(
            sorted(
                candidates,
                key=lambda item: (
                    item.code.value,
                    item.path or "",
                    item.match_ordinal if item.match_ordinal is not None else -1,
                    item.message,
                ),
            )
        )
        maximum = self._configuration.limits.max_warnings
        if len(ordered) <= maximum:
            return ordered, False
        summary = ContextWarning(
            code=ContextLimitation.WARNING_LIMIT_EXCEEDED,
            message="additional context warnings were omitted after the configured limit",
        )
        if maximum == 1:
            return (summary,), True
        bounded = tuple(
            sorted(
                (*ordered[: maximum - 1], summary),
                key=lambda item: (
                    item.code.value,
                    item.path or "",
                    item.match_ordinal if item.match_ordinal is not None else -1,
                    item.message,
                ),
            )
        )
        return bounded, True

    def _match_links(
        self,
        report: DependencyMatchReport,
        phase4_evidence: EvidenceBundle,
        targets: tuple[ContextTarget, ...],
        evidence: EvidenceBuildResult,
        signals: tuple[ContextSignal, ...],
        coverage_limitations: tuple[ContextLimitation, ...],
    ) -> tuple[MatchContextLink, ...]:
        target_by_match = {target.match_ordinal: target for target in targets}
        links: list[MatchContextLink] = []
        for ordinal, _match in enumerate(report.matches):
            target = target_by_match.get(ordinal)
            context_items = tuple(
                item for item in evidence.evidence if item.match_ordinal == ordinal
            )
            observations = tuple(
                item for item in evidence.observations if item.match_ordinal == ordinal
            )
            match_signals = tuple(item for item in signals if item.match_ordinal == ordinal)
            limitations = set(coverage_limitations)
            if target is not None:
                limitations.update(target.limitation_codes)
            links.append(
                MatchContextLink(
                    match_ordinal=ordinal,
                    target_id=target.id if target is not None else None,
                    dependency_evidence_ids=tuple(
                        sorted(phase4_evidence.match_links[ordinal].evidence_ids)
                    ),
                    context_evidence_ids=tuple(sorted(item.id for item in context_items)),
                    observation_ids=tuple(sorted(item.id for item in observations)),
                    signal_ids=tuple(sorted(item.id for item in match_signals)),
                    limitation_codes=tuple(sorted(limitations)),
                )
            )
        return tuple(links)
