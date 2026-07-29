from __future__ import annotations

import hashlib
import threading
import time

from watchdog.context._recognition import RecognitionBudget, RecognitionResult
from watchdog.context.configuration import recognize_configuration
from watchdog.context.discovery import DiscoveredSource
from watchdog.context.identifiers import context_target_id
from watchdog.domain.context import (
    ConfigurationRule,
    ContextLimitation,
    ContextRuleCatalog,
    ContextTarget,
    MappingKind,
    ObservationKind,
    SourceLanguage,
    TargetApplicability,
)
from watchdog.domain.inventory import Ecosystem, VersionKind

from ..security.test_context_discovery import context_limits

RULE = ConfigurationRule(
    id="npm-jsonwebtoken-config-file",
    ecosystem="npm",
    package_name="jsonwebtoken",
    keys=("algorithms",),
    normalized_paths=("config/settings.json", "config/settings.toml"),
    review_reference="https://example.invalid/reviewed-contract",
)
CATALOG = ContextRuleCatalog(version="test", configuration_rules=(RULE,))


def target() -> ContextTarget:
    payload = {
        "match_ordinal": 0,
        "component_id": "component:jsonwebtoken",
        "ecosystem": Ecosystem.NPM,
        "package_name": "jsonwebtoken",
        "version": "1.0.0",
        "version_kind": VersionKind.EXACT,
        "applicability": TargetApplicability.APPLICABLE,
        "mapping_kind": MappingKind.GENERIC,
        "mapping_complete": True,
        "import_roots": ("jsonwebtoken",),
        "member_rule_ids": (),
        "configuration_rule_ids": (RULE.id,),
        "endpoint_rule_ids": (),
        "dependency_evidence_ids": ("evidence:sha256:" + "d" * 64,),
        "limitation_codes": (),
    }
    return ContextTarget(id=context_target_id(payload), **payload)


def recognize(
    text: str | bytes,
    language: SourceLanguage,
    *,
    path: str,
    max_depth: int = 64,
) -> RecognitionResult:
    content = text.encode("utf-8") if isinstance(text, str) else text
    source = DiscoveredSource(
        path=path,
        language=language,
        file_sha256=hashlib.sha256(content).hexdigest(),
        byte_count=len(content),
        test_source=False,
        content=content,
    )
    limits = context_limits(max_nesting_depth=max_depth)
    return recognize_configuration(
        source,
        (target(),),
        CATALOG,
        RecognitionBudget(
            limits=limits,
            deadline=time.monotonic() + 10,
            cancel_event=threading.Event(),
        ),
    )


def test_exact_json_and_toml_paths_and_keys_create_configuration_facts() -> None:
    json_result = recognize(
        '{"verification":{"algorithms":["RS256"]}}',
        SourceLanguage.JSON,
        path="config/settings.json",
    )
    toml_result = recognize(
        '[verification]\nalgorithms = ["RS256"]\n',
        SourceLanguage.TOML,
        path="config/settings.toml",
    )

    for result in (json_result, toml_result):
        assert len(result.facts) == 1
        assert result.facts[0].kind == ObservationKind.TARGET_CONFIGURATION
        assert result.facts[0].rule_id == RULE.id


def test_wrong_path_or_key_never_becomes_a_generic_configuration_search() -> None:
    wrong_path = recognize(
        '{"algorithms":["none"]}',
        SourceLanguage.JSON,
        path="other.json",
    )
    wrong_key = recognize(
        '{"algorithm":"none"}',
        SourceLanguage.JSON,
        path="config/settings.json",
    )

    assert wrong_path.facts == ()
    assert wrong_key.facts == ()


def test_duplicate_malformed_utf8_and_depth_conditions_fail_closed() -> None:
    duplicate = recognize(
        '{"algorithms":[],"algorithms":[]}',
        SourceLanguage.JSON,
        path="config/settings.json",
    )
    malformed = recognize(
        "algorithms = [",
        SourceLanguage.TOML,
        path="config/settings.toml",
    )
    invalid = recognize(
        b'{"algorithms":"\xff"}',
        SourceLanguage.JSON,
        path="config/settings.json",
    )
    nested = recognize(
        '{"a":{"b":{"algorithms":[]}}}',
        SourceLanguage.JSON,
        path="config/settings.json",
        max_depth=2,
    )

    assert duplicate.facts == ()
    assert malformed.facts == ()
    assert invalid.facts == ()
    assert nested.facts == ()
    assert ContextLimitation.MALFORMED_SYNTAX in duplicate.limitation_codes
    assert ContextLimitation.MALFORMED_SYNTAX in malformed.limitation_codes
    assert invalid.limitation_codes == (ContextLimitation.INVALID_UTF8,)
    assert ContextLimitation.NESTING_DEPTH_EXCEEDED in nested.limitation_codes


def test_configuration_secret_values_never_enter_result_repr() -> None:
    synthetic = "SYNTHETIC_CONFIGURATION_SECRET"
    result = recognize(
        f'{{"algorithms":["RS256"],"password":"{synthetic}"}}',
        SourceLanguage.JSON,
        path="config/settings.json",
    )
    assert synthetic not in repr(result)
