from __future__ import annotations

import asyncio
import threading
import time
from collections import defaultdict
from contextlib import suppress
from dataclasses import dataclass

from watchdog.config.settings import Settings
from watchdog.domain.evidence import (
    EvidenceBundle,
    EvidenceCoverage,
    EvidenceCoverageKind,
    EvidenceItem,
    EvidenceKind,
    EvidenceProducer,
    EvidenceSource,
    EvidenceStatus,
    EvidenceWarning,
    MatchEvidenceLink,
    MatchSourceOutcome,
    SourceLineRange,
)
from watchdog.domain.inventory import DependencyComponent, DependencyInventory, SourceReference
from watchdog.domain.matching import DependencyMatchReport
from watchdog.domain.repositories import AcquiredRepository
from watchdog.evidence.identifiers import (
    evidence_bundle_id,
    evidence_configuration_sha256,
    evidence_item_id,
)
from watchdog.evidence.limits import EvidenceConfiguration, EvidenceLimits
from watchdog.evidence.reader import (
    DescriptorRepositoryReader,
    EvidenceCancelled,
    EvidenceDeadlineExceeded,
    ReadResult,
)
from watchdog.evidence.redaction import RedactionResult, Redactor, evidence_content
from watchdog.evidence.selectors import (
    SelectorResolutionError,
    resolve_selector,
    selection_supports_component,
)

_WARNING_MESSAGES = {
    "source_path_invalid": "A source reference path was invalid and its content was omitted.",
    "source_digest_conflict": "References to one source path disagreed on its file digest.",
    "source_file_limit_exceeded": "The source-file limit omitted additional evidence content.",
    "source_missing": "A referenced source file was no longer present.",
    "source_unsafe_path": "A referenced source path could not be opened without following links.",
    "source_not_regular_file": "A referenced source target was not a regular file.",
    "source_unreadable": "A referenced source file could not be read safely.",
    "source_file_bytes_limit_exceeded": "A referenced source file exceeded its byte limit.",
    "source_total_bytes_limit_exceeded": "The total source-byte limit omitted additional content.",
    "source_changed_during_read": "A referenced source file changed while it was read.",
    "source_digest_mismatch": "A referenced source file no longer matched its inventory digest.",
    "source_invalid_utf8": "Selected source content was not valid UTF-8.",
    "selector_invalid": "A source selector was invalid and its content was omitted.",
    "selector_kind_unsupported": "A source selector kind was not supported by this producer.",
    "selector_unsupported_or_ambiguous": "A source selector was unsupported or ambiguous.",
    "selector_ambiguous": "A source selector resolved ambiguously.",
    "selector_stale": "A source selector no longer supported the inventory component.",
    "source_line_span_limit_exceeded": "Selected content exceeded the line-span limit.",
    "redaction_failed": "Safe redaction failed, so all selected display content was omitted.",
    "redaction_limit_exceeded": "Selected content exceeded the redaction-record limit.",
    "display_item_bytes_limit_exceeded": (
        "Redacted display content was truncated to the item limit."
    ),
    "bundle_display_bytes_limit_exceeded": (
        "The bundle display-byte limit omitted or truncated content."
    ),
    "item_limit_exceeded": (
        "The evidence-item limit omitted an item; its source outcome remains visible."
    ),
    "evidence_deadline_exceeded": "The evidence deadline omitted unfinished content.",
    "inventory_partial": "The Phase 3 inventory carried explicit partial coverage.",
    "match_report_partial": "The Phase 3 match report carried explicit partial coverage.",
    "warning_limit_exceeded": "The warning limit was reached; additional warnings were omitted.",
}


def _reference_key(reference: SourceReference) -> tuple[str, str, str, str]:
    return (
        reference.path,
        reference.selector.kind.value,
        reference.selector.value,
        reference.file_sha256,
    )


def _warning_key(warning: EvidenceWarning) -> tuple[str, str, str, str, str]:
    return (
        warning.code,
        warning.path or "",
        warning.selector.kind.value if warning.selector else "",
        warning.selector.value if warning.selector else "",
        warning.message,
    )


class _Warnings:
    def __init__(self, maximum: int) -> None:
        self._maximum = maximum
        self._values: list[EvidenceWarning] = []
        self._seen: set[EvidenceWarning] = set()
        self.limit_reached = False

    def add(self, code: str, reference: SourceReference | None = None) -> None:
        if self.limit_reached:
            return
        candidate = EvidenceWarning(
            code=code,
            message=_WARNING_MESSAGES[code],
            path=reference.path if reference else None,
            selector=reference.selector if reference else None,
        )
        if candidate in self._seen:
            return
        if len(self._values) < self._maximum - 1:
            self._seen.add(candidate)
            self._values.append(candidate)
        else:
            self.limit_reached = True

    def finish(self) -> tuple[EvidenceWarning, ...]:
        values = list(self._values)
        if self.limit_reached:
            values.append(
                EvidenceWarning(
                    code="warning_limit_exceeded",
                    message=_WARNING_MESSAGES["warning_limit_exceeded"],
                )
            )
        return tuple(sorted(values, key=_warning_key))


@dataclass(frozen=True, slots=True)
class _Outcome:
    evidence_id: str | None
    limitations: tuple[str, ...]


class EvidenceService:
    """Convert Phase 3 match references into deterministic evidence inside a lease."""

    def __init__(
        self,
        configuration: EvidenceConfiguration | EvidenceLimits | None = None,
        *,
        redactor: Redactor | None = None,
    ) -> None:
        if configuration is None:
            configuration = EvidenceConfiguration.from_settings(Settings())
        elif isinstance(configuration, EvidenceLimits):
            configuration = EvidenceConfiguration(limits=configuration)
        self._configuration = configuration
        self._redactor = redactor or Redactor(configuration.enabled_detectors)

    @property
    def configuration(self) -> EvidenceConfiguration:
        return self._configuration

    async def collect(
        self,
        acquired: AcquiredRepository,
        inventory: DependencyInventory,
        report: DependencyMatchReport,
    ) -> EvidenceBundle:
        self._validate_snapshots(acquired, inventory, report)
        self._validate_report_references(inventory, report)
        cancel_event = threading.Event()
        deadline = time.monotonic() + self._configuration.limits.deadline_seconds
        task = asyncio.create_task(
            asyncio.to_thread(
                self._collect_sync,
                acquired,
                inventory,
                report,
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

    def _validate_snapshots(
        self,
        acquired: AcquiredRepository,
        inventory: DependencyInventory,
        report: DependencyMatchReport,
    ) -> None:
        expected = inventory.snapshot
        if report.snapshot != expected or (
            acquired.snapshot.repository.canonical_url != expected.repository_url
            or acquired.snapshot.commit_sha != expected.commit_sha
            or acquired.snapshot.tree_sha != expected.tree_sha
            or acquired.snapshot.archive_sha256 != expected.archive_sha256
        ):
            raise ValueError("evidence inputs must reference the same exact repository snapshot")

    def _validate_report_references(
        self,
        inventory: DependencyInventory,
        report: DependencyMatchReport,
    ) -> None:
        components = {component.id: component for component in inventory.components}
        for match in report.matches:
            if match.component_id is None:
                if match.source_references:
                    raise ValueError(
                        "evidence report contains a source not generated by the inventory"
                    )
                continue
            component = components.get(match.component_id)
            if component is None or match.source_references != component.source_references:
                raise ValueError("evidence report contains a source not generated by the inventory")
            for reference in match.source_references:
                try:
                    EvidenceSource(
                        repository_url=inventory.snapshot.repository_url,
                        commit_sha=inventory.snapshot.commit_sha,
                        tree_sha=inventory.snapshot.tree_sha,
                        path=reference.path,
                        selector=reference.selector,
                        file_sha256=reference.file_sha256,
                    )
                except ValueError:
                    raise ValueError(
                        "evidence report contains an invalid generated source anchor"
                    ) from None

    def _collect_sync(
        self,
        acquired: AcquiredRepository,
        inventory: DependencyInventory,
        report: DependencyMatchReport,
        deadline: float,
        cancel_event: threading.Event,
    ) -> EvidenceBundle:
        limits = self._configuration.limits
        warnings = _Warnings(limits.max_warnings)
        components = {component.id: component for component in inventory.components}
        all_references = sorted(
            {reference for match in report.matches for reference in match.source_references},
            key=_reference_key,
        )
        components_by_reference: dict[SourceReference, list[DependencyComponent]] = defaultdict(
            list
        )
        for match in report.matches:
            component = components.get(match.component_id or "")
            if component is None:
                continue
            for reference in match.source_references:
                if component not in components_by_reference[reference]:
                    components_by_reference[reference].append(component)

        by_path: dict[str, list[SourceReference]] = defaultdict(list)
        for reference in all_references:
            by_path[reference.path].append(reference)
        read_results: dict[tuple[str, str], ReadResult] = {}
        deadline_reached = False
        try:
            with DescriptorRepositoryReader(
                acquired.root,
                limits,
                deadline=deadline,
                cancel_event=cancel_event,
            ) as reader:
                for path in sorted(by_path):
                    digests = {reference.file_sha256 for reference in by_path[path]}
                    if len(digests) != 1:
                        for digest in digests:
                            read_results[(path, digest)] = ReadResult(
                                None, "source_digest_conflict", 0
                            )
                        continue
                    digest = next(iter(digests))
                    try:
                        read_results[(path, digest)] = reader.read(path, digest)
                    except EvidenceDeadlineExceeded:
                        deadline_reached = True
                        break
                files_read = reader.files_read
                source_bytes_read = reader.total_bytes_read
        except EvidenceCancelled:
            raise
        except EvidenceDeadlineExceeded:
            deadline_reached = True
            files_read = 0
            source_bytes_read = 0

        producer = EvidenceProducer(
            name=self._configuration.producer_name,
            version=self._configuration.producer_version,
            selector_resolver_version=self._configuration.selector_resolver_version,
            redaction_policy_version=self._configuration.redaction_policy_version,
        )
        items: list[EvidenceItem] = []
        outcomes: dict[SourceReference, _Outcome] = {}
        bundle_display_bytes = 0
        global_limitations: list[str] = []
        if inventory.partial:
            global_limitations.append("inventory_partial")
            warnings.add("inventory_partial")
        if report.partial:
            global_limitations.append("match_report_partial")
            warnings.add("match_report_partial")

        for ordinal, reference in enumerate(all_references):
            self._check_cancel(cancel_event)
            if ordinal >= limits.max_evidence_items:
                outcomes[reference] = _Outcome(None, ("item_limit_exceeded",))
                warnings.add("item_limit_exceeded", reference)
                global_limitations.append("item_limit_exceeded")
                continue
            if deadline_reached or time.monotonic() >= deadline:
                code = "evidence_deadline_exceeded"
                item = self._omitted_item(reference, producer, inventory, code)
                items.append(item)
                outcomes[reference] = _Outcome(item.id, (code,))
                warnings.add(code, reference)
                global_limitations.append(code)
                deadline_reached = True
                continue
            read = read_results.get((reference.path, reference.file_sha256))
            if read is None:
                code = "evidence_deadline_exceeded" if deadline_reached else "source_unreadable"
                item = self._omitted_item(reference, producer, inventory, code)
                items.append(item)
                outcomes[reference] = _Outcome(item.id, (code,))
                warnings.add(code, reference)
                global_limitations.append(code)
                continue
            if read.data is None:
                assert read.limitation_code is not None
                code = read.limitation_code
                item = self._omitted_item(reference, producer, inventory, code)
                items.append(item)
                outcomes[reference] = _Outcome(item.id, (code,))
                warnings.add(code, reference)
                global_limitations.append(code)
                continue
            component_values = components_by_reference.get(reference, [])
            component = component_values[0] if component_values else None
            try:
                selection = resolve_selector(
                    read.data,
                    reference.selector,
                    max_line_span=limits.max_line_span,
                    component=component,
                )
                if any(
                    not selection_supports_component(
                        selection, reference.selector, candidate_component
                    )
                    for candidate_component in component_values[1:]
                ):
                    raise SelectorResolutionError("selector_stale")
            except SelectorResolutionError as error:
                item = self._omitted_item(reference, producer, inventory, error.code)
                items.append(item)
                outcomes[reference] = _Outcome(item.id, (error.code,))
                warnings.add(error.code, reference)
                global_limitations.append(error.code)
                continue
            if time.monotonic() >= deadline:
                code = "evidence_deadline_exceeded"
                item = self._omitted_item(reference, producer, inventory, code)
                items.append(item)
                outcomes[reference] = _Outcome(item.id, (code,))
                warnings.add(code, reference)
                global_limitations.append(code)
                deadline_reached = True
                continue
            try:
                redaction = self._redactor.redact(
                    selection.text,
                    max_redactions=limits.max_redactions_per_item,
                )
            except Exception:
                redaction = RedactionResult(None, (), "redaction_failed")
            if redaction.text is None:
                assert redaction.limitation_code is not None
                code = redaction.limitation_code
                item = self._omitted_item(
                    reference,
                    producer,
                    inventory,
                    code,
                    line_range=selection.line_range,
                )
                items.append(item)
                outcomes[reference] = _Outcome(item.id, (code,))
                warnings.add(code, reference)
                global_limitations.append(code)
                continue
            remaining_bundle = limits.max_bundle_display_bytes - bundle_display_bytes
            if remaining_bundle <= 0:
                code = "bundle_display_bytes_limit_exceeded"
                item = self._omitted_item(
                    reference,
                    producer,
                    inventory,
                    code,
                    line_range=selection.line_range,
                )
                items.append(item)
                outcomes[reference] = _Outcome(item.id, (code,))
                warnings.add(code, reference)
                global_limitations.append(code)
                continue
            maximum_display = min(limits.max_display_bytes_per_item, remaining_bundle)
            try:
                content = evidence_content(redaction, max_display_bytes=maximum_display)
            except Exception:
                content = None
            if content is None:
                code = "redaction_failed"
                item = self._omitted_item(
                    reference,
                    producer,
                    inventory,
                    code,
                    line_range=selection.line_range,
                )
                items.append(item)
                outcomes[reference] = _Outcome(item.id, (code,))
                warnings.add(code, reference)
                global_limitations.append(code)
                continue
            bundle_display_bytes += content.byte_count
            redacted_byte_count = len(redaction.text.encode("utf-8"))
            item_limit_hit = redacted_byte_count > limits.max_display_bytes_per_item
            bundle_limit_hit = redacted_byte_count > remaining_bundle
            outcome_limitations: list[str] = []
            if item_limit_hit:
                outcome_limitations.append("display_item_bytes_limit_exceeded")
                warnings.add("display_item_bytes_limit_exceeded", reference)
                global_limitations.append("display_item_bytes_limit_exceeded")
            if bundle_limit_hit:
                outcome_limitations.append("bundle_display_bytes_limit_exceeded")
                warnings.add("bundle_display_bytes_limit_exceeded", reference)
                global_limitations.append("bundle_display_bytes_limit_exceeded")
            source = self._source(reference, inventory, line_range=selection.line_range)
            status = EvidenceStatus.REDACTED if content.redacted else EvidenceStatus.EXTRACTED
            payload = {
                "kind": EvidenceKind.DEPENDENCY_SOURCE,
                "producer": producer,
                "source": source,
                "status": status,
                "content": content,
                "limitation_codes": (),
            }
            item = EvidenceItem(id=evidence_item_id(payload), **payload)
            items.append(item)
            outcomes[reference] = _Outcome(item.id, tuple(outcome_limitations))

        if warnings.limit_reached:
            global_limitations.append("warning_limit_exceeded")
        links: list[MatchEvidenceLink] = []
        for match_ordinal, match in enumerate(report.matches):
            source_outcomes: list[MatchSourceOutcome] = []
            for reference in sorted(match.source_references, key=_reference_key):
                outcome = outcomes[reference]
                source_outcomes.append(
                    MatchSourceOutcome(
                        source=reference,
                        evidence_id=outcome.evidence_id,
                        limitation_codes=outcome.limitations,
                    )
                )
            outcome_tuple = tuple(source_outcomes)
            evidence_ids = tuple(
                outcome.evidence_id for outcome in outcome_tuple if outcome.evidence_id is not None
            )
            evidence_limitations = tuple(
                dict.fromkeys(
                    code for outcome in outcome_tuple for code in outcome.limitation_codes
                )
            )
            links.append(
                MatchEvidenceLink(
                    match_ordinal=match_ordinal,
                    advisory_component_index=match.advisory_component_index,
                    component_id=match.component_id,
                    match_state=match.state,
                    match_coverage_limitations=match.coverage_limitations,
                    evidence_ids=evidence_ids,
                    source_outcomes=outcome_tuple,
                    limitation_codes=evidence_limitations,
                )
            )
        sorted_items = tuple(sorted(items, key=lambda item: item.id))
        extracted = sum(item.status == EvidenceStatus.EXTRACTED for item in sorted_items)
        redacted = sum(item.status == EvidenceStatus.REDACTED for item in sorted_items)
        omitted = sum(item.status == EvidenceStatus.CONTENT_OMITTED for item in sorted_items)
        overflow = sum(outcome.evidence_id is None for outcome in outcomes.values())
        limitation_codes = tuple(sorted(set(global_limitations)))
        partial = bool(omitted or overflow or limitation_codes)
        coverage = EvidenceCoverage(
            kind=EvidenceCoverageKind.PARTIAL if partial else EvidenceCoverageKind.COMPLETE,
            source_references=len(all_references),
            unique_source_files=len(by_path),
            files_read=files_read,
            source_bytes_read=source_bytes_read,
            evidence_items=len(sorted_items),
            extracted_items=extracted,
            redacted_items=redacted,
            omitted_items=omitted,
            overflow_outcomes=overflow,
            limitation_codes=limitation_codes,
        )
        configuration_sha = evidence_configuration_sha256(self._configuration)
        bundle_payload = {
            "snapshot": inventory.snapshot,
            "configuration": self._configuration,
            "configuration_sha256": configuration_sha,
            "items": sorted_items,
            "match_links": tuple(links),
            "warnings": warnings.finish(),
            "coverage": coverage,
            "partial": partial,
        }
        return EvidenceBundle(id=evidence_bundle_id(bundle_payload), **bundle_payload)

    def _source(
        self,
        reference: SourceReference,
        inventory: DependencyInventory,
        *,
        line_range: SourceLineRange | None = None,
    ) -> EvidenceSource:
        return EvidenceSource(
            repository_url=inventory.snapshot.repository_url,
            commit_sha=inventory.snapshot.commit_sha,
            tree_sha=inventory.snapshot.tree_sha,
            path=reference.path,
            selector=reference.selector,
            line_range=line_range,
            file_sha256=reference.file_sha256,
        )

    def _omitted_item(
        self,
        reference: SourceReference,
        producer: EvidenceProducer,
        inventory: DependencyInventory,
        code: str,
        *,
        line_range: SourceLineRange | None = None,
    ) -> EvidenceItem:
        payload = {
            "kind": EvidenceKind.DEPENDENCY_SOURCE,
            "producer": producer,
            "source": self._source(reference, inventory, line_range=line_range),
            "status": EvidenceStatus.CONTENT_OMITTED,
            "content": None,
            "limitation_codes": (code,),
        }
        return EvidenceItem(id=evidence_item_id(payload), **payload)

    def _check_cancel(self, cancel_event: threading.Event) -> None:
        if cancel_event.is_set():
            raise EvidenceCancelled
