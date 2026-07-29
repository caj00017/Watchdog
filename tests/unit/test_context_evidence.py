from __future__ import annotations

import threading
import time

import pytest
from pydantic import ValidationError

from watchdog.config.settings import Settings
from watchdog.context.catalog import catalog_metadata
from watchdog.context.evidence import EvidenceBuildResult, build_context_evidence
from watchdog.context.identifiers import canonical_json_bytes, context_evidence_id
from watchdog.context.limits import ContextConfiguration
from watchdog.domain.context import (
    ContextEvidenceItem,
    ContextLimitation,
    ContextProducer,
    ObservationKind,
)
from watchdog.domain.evidence import EvidenceStatus
from watchdog.domain.inventory import InventorySnapshot
from watchdog.evidence.redaction import RedactionResult, Redactor

from ..security.test_context_discovery import context_limits
from .test_context_python import recognize, target


def snapshot() -> InventorySnapshot:
    return InventorySnapshot(
        repository_url="https://github.com/example/fixture",
        commit_sha="a" * 40,
        tree_sha="b" * 40,
        archive_sha256="c" * 64,
    )


def producer() -> ContextProducer:
    configuration = ContextConfiguration.from_settings(Settings(), catalog=catalog_metadata())
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


def build(
    text: str,
    *,
    redactor: Redactor | None = None,
    max_display: int = 1024,
    max_bundle_display: int = 4096,
    max_evidence: int = 1_000,
) -> EvidenceBuildResult:
    context_target = target("requests", "requests", complete=False)
    result = recognize(text, context_target)
    limits = context_limits(
        max_display_bytes_per_item=max_display,
        max_bundle_display_bytes=max_bundle_display,
        max_evidence_items=max_evidence,
    )
    return build_context_evidence(
        (result,),
        (context_target,),
        snapshot(),
        producer(),
        limits,
        redactor or Redactor(("credential_assignment",)),
        deadline=time.monotonic() + 10,
        cancel_event=threading.Event(),
    )


def test_complete_syntactic_span_is_redacted_before_outward_model_construction() -> None:
    synthetic = "SYNTHETIC_PASSWORD_VALUE"
    result = build(
        f'import requests\nrequests.get("https://example.invalid", password="{synthetic}")\n',
        redactor=Redactor(("credential_assignment",)),
    )

    assert len(result.evidence) == len(result.observations)
    assert all(item.id.startswith("context-evidence:sha256:") for item in result.evidence)
    call_item = next(
        item for item in result.evidence if item.observation_kind == ObservationKind.EXPLICIT_CALL
    )
    assert call_item.status == EvidenceStatus.REDACTED
    assert call_item.content is not None
    assert synthetic not in call_item.content.text
    assert (
        synthetic
        not in canonical_json_bytes(
            (result.evidence, result.observations, result.file_outcomes, result.warnings)
        ).decode()
    )
    assert synthetic not in repr(result)
    assert result.file_outcomes[0].observation_ids == tuple(
        sorted(item.id for item in result.observations)
    )


class _RaisingRedactor(Redactor):
    def __init__(self) -> None:
        super().__init__(("credential_assignment",))

    def redact(self, text: str, *, max_redactions: int) -> RedactionResult:
        del max_redactions
        raise RuntimeError(f"synthetic failure contains {text}")


def test_redaction_failure_omits_all_display_but_preserves_evidence_links() -> None:
    synthetic = "SYNTHETIC_REDACTION_FAILURE_SECRET"
    result = build(
        f'import requests\nrequests.get(password="{synthetic}")\n',
        redactor=_RaisingRedactor(),
    )

    assert all(item.status == EvidenceStatus.CONTENT_OMITTED for item in result.evidence)
    assert all(item.content is None for item in result.evidence)
    assert all(
        item.limitation_codes == (ContextLimitation.REDACTION_FAILED,) for item in result.evidence
    )
    assert len(result.observations) == len(result.evidence)
    assert (
        synthetic
        not in canonical_json_bytes(
            (result.evidence, result.observations, result.file_outcomes, result.warnings)
        ).decode()
    )
    assert synthetic not in repr(result)


def test_display_and_evidence_limits_are_explicit_and_deterministic() -> None:
    text = 'import requests\nrequests.get("abcdefghijklmnopqrstuvwxyz")\n'
    first = build(text, max_display=8, max_bundle_display=16)
    second = build(text, max_display=8, max_bundle_display=16)

    assert first == second
    assert all(item.status == EvidenceStatus.CONTENT_OMITTED for item in first.evidence)
    assert all(item.content is None for item in first.evidence)
    assert ContextLimitation.DISPLAY_ITEM_BYTES_LIMIT_EXCEEDED in first.limitation_codes

    bundle_limited = build(text, max_display=20, max_bundle_display=20)
    assert any(
        item.limitation_codes == (ContextLimitation.BUNDLE_DISPLAY_BYTES_LIMIT_EXCEEDED,)
        and item.content is None
        for item in bundle_limited.evidence
    )

    limited = build(text, max_evidence=1)
    assert len(limited.evidence) == 1
    assert len(limited.observations) == 1
    assert ContextLimitation.EVIDENCE_LIMIT_EXCEEDED in limited.limitation_codes


def test_context_evidence_schema_rejects_truncated_display() -> None:
    result = build("import requests\nrequests.get()\n")
    payload = next(item for item in result.evidence if item.content is not None).model_dump(
        mode="json"
    )
    payload["content"]["truncated"] = True
    payload["id"] = context_evidence_id(payload)

    with pytest.raises(ValidationError, match="must omit display content"):
        ContextEvidenceItem.model_validate(payload)


def test_deadline_marks_files_partial_without_creating_negative_evidence() -> None:
    context_target = target("requests", "requests", complete=False)
    source_result = recognize("import requests\nrequests.get()\n", context_target)
    limits = context_limits()
    result = build_context_evidence(
        (source_result,),
        (context_target,),
        snapshot(),
        producer(),
        limits,
        Redactor(("credential_assignment",)),
        deadline=time.monotonic() - 1,
        cancel_event=threading.Event(),
    )

    assert result.evidence == ()
    assert result.observations == ()
    assert ContextLimitation.CONTEXT_DEADLINE_EXCEEDED in result.limitation_codes
    assert result.file_outcomes[0].status.value == "partial"
