from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from watchdog.domain.evidence import (
    EvidenceBundle,
    EvidenceContent,
    EvidenceCoverage,
    EvidenceCoverageKind,
    EvidenceItem,
    EvidenceKind,
    EvidenceProducer,
    EvidenceSource,
    EvidenceStatus,
    MatchEvidenceLink,
    MatchSourceOutcome,
    SourceLineRange,
)
from watchdog.domain.inventory import (
    InventorySnapshot,
    SelectorKind,
    SourceReference,
    SourceSelector,
)
from watchdog.domain.matching import MatchState
from watchdog.evidence.identifiers import (
    evidence_bundle_id,
    evidence_configuration_sha256,
    evidence_item_id,
)
from watchdog.evidence.limits import EvidenceConfiguration

from ..integration.test_evidence_service import evidence_limits


def reference() -> SourceReference:
    return SourceReference(
        path="requirements.txt",
        selector=SourceSelector(kind=SelectorKind.LINE, value="line:1"),
        file_sha256="a" * 64,
    )


def snapshot() -> InventorySnapshot:
    return InventorySnapshot(
        repository_url="https://github.com/example/repository",
        commit_sha="b" * 40,
        tree_sha="c" * 40,
        archive_sha256="d" * 64,
    )


def configuration() -> EvidenceConfiguration:
    return EvidenceConfiguration(limits=evidence_limits())


def producer() -> EvidenceProducer:
    config = configuration()
    return EvidenceProducer(
        name=config.producer_name,
        version=config.producer_version,
        selector_resolver_version=config.selector_resolver_version,
        redaction_policy_version=config.redaction_policy_version,
    )


def item() -> EvidenceItem:
    text = "requests==2.32.3"
    content = EvidenceContent(
        text=text,
        sha256=hashlib.sha256(text.encode()).hexdigest(),
        byte_count=len(text),
        redacted=False,
        truncated=False,
    )
    source = EvidenceSource(
        repository_url=snapshot().repository_url,
        commit_sha=snapshot().commit_sha,
        tree_sha=snapshot().tree_sha,
        path=reference().path,
        selector=reference().selector,
        line_range=SourceLineRange(start=1, end=1),
        file_sha256=reference().file_sha256,
    )
    payload = {
        "kind": EvidenceKind.DEPENDENCY_SOURCE,
        "producer": producer(),
        "source": source,
        "status": EvidenceStatus.EXTRACTED,
        "content": content,
        "limitation_codes": (),
    }
    return EvidenceItem(id=evidence_item_id(payload), **payload)


def bundle() -> EvidenceBundle:
    evidence = item()
    outcome = MatchSourceOutcome(source=reference(), evidence_id=evidence.id)
    link = MatchEvidenceLink(
        match_ordinal=0,
        advisory_component_index=0,
        component_id="component",
        match_state=MatchState.VERSION_UNKNOWN,
        evidence_ids=(evidence.id,),
        source_outcomes=(outcome,),
    )
    coverage = EvidenceCoverage(
        kind=EvidenceCoverageKind.COMPLETE,
        source_references=1,
        unique_source_files=1,
        files_read=1,
        source_bytes_read=20,
        evidence_items=1,
        extracted_items=1,
        redacted_items=0,
        omitted_items=0,
        overflow_outcomes=0,
    )
    config = configuration()
    payload = {
        "snapshot": snapshot(),
        "configuration": config,
        "configuration_sha256": evidence_configuration_sha256(config),
        "items": (evidence,),
        "match_links": (link,),
        "warnings": (),
        "coverage": coverage,
        "partial": False,
    }
    return EvidenceBundle(id=evidence_bundle_id(payload), **payload)


def test_models_are_strict_frozen_and_identity_bound() -> None:
    evidence_bundle = bundle()
    assert evidence_item_id(evidence_bundle.items[0]) == evidence_item_id(
        evidence_bundle.items[0].model_dump()
    )
    assert evidence_bundle_id(evidence_bundle) == evidence_bundle_id(evidence_bundle.model_dump())
    with pytest.raises(ValidationError):
        EvidenceContent.model_validate(
            {
                "text": "safe",
                "sha256": hashlib.sha256(b"safe").hexdigest(),
                "byte_count": 4,
                "redacted": False,
                "truncated": False,
                "unexpected": True,
            }
        )
    with pytest.raises(ValidationError):
        evidence_bundle.partial = True  # type: ignore[misc]

    invalid = evidence_bundle.model_dump()
    invalid["id"] = "bundle:sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="identity"):
        EvidenceBundle.model_validate(invalid)


@pytest.mark.parametrize(
    "source",
    [
        {"path": "/absolute"},
        {"path": "../escape"},
        {"path": "a\\b"},
        {"selector": {"kind": "line", "value": "line:0"}},
        {"selector": {"kind": "json_pointer", "value": "/bad~2escape"}},
        {"file_sha256": "not-a-digest"},
    ],
)
def test_evidence_source_rejects_invalid_anchors(source: dict[str, object]) -> None:
    values = item().source.model_dump()
    values.update(source)
    with pytest.raises(ValidationError):
        EvidenceSource.model_validate(values)


def test_status_content_invariants_are_fail_closed() -> None:
    evidence = item()
    values = evidence.model_dump()
    values["status"] = "content_omitted"
    with pytest.raises(ValidationError):
        EvidenceItem.model_validate(values)

    values = evidence.model_dump()
    values["content"] = None
    with pytest.raises(ValidationError):
        EvidenceItem.model_validate(values)


def test_bundle_rejects_broken_or_source_mismatched_links() -> None:
    evidence_bundle = bundle()
    values = evidence_bundle.model_dump()
    values["match_links"][0]["evidence_ids"] = ("evidence:sha256:" + "0" * 64,)
    values["match_links"][0]["source_outcomes"][0]["evidence_id"] = "evidence:sha256:" + "0" * 64
    values["id"] = evidence_bundle_id({key: value for key, value in values.items() if key != "id"})
    with pytest.raises(ValidationError, match="broken"):
        EvidenceBundle.model_validate(values)

    values = evidence_bundle.model_dump()
    values["match_links"][0]["source_outcomes"][0]["source"]["path"] = "other.txt"
    values["id"] = evidence_bundle_id({key: value for key, value in values.items() if key != "id"})
    with pytest.raises(ValidationError, match="unrelated"):
        EvidenceBundle.model_validate(values)


def test_configuration_and_snapshot_disagreement_are_rejected() -> None:
    evidence_bundle = bundle()
    values = evidence_bundle.model_dump()
    values["configuration_sha256"] = "0" * 64
    values["id"] = evidence_bundle_id({key: value for key, value in values.items() if key != "id"})
    with pytest.raises(ValidationError, match="configuration digest"):
        EvidenceBundle.model_validate(values)

    values = evidence_bundle.model_dump()
    values["snapshot"]["tree_sha"] = "e" * 40
    values["id"] = evidence_bundle_id({key: value for key, value in values.items() if key != "id"})
    with pytest.raises(ValidationError, match="snapshot"):
        EvidenceBundle.model_validate(values)
