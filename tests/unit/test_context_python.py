from __future__ import annotations

import hashlib
import threading
import time

from watchdog.context._recognition import RecognitionBudget, RecognitionResult
from watchdog.context.catalog import DEFAULT_CONTEXT_CATALOG
from watchdog.context.discovery import DiscoveredSource
from watchdog.context.identifiers import context_target_id
from watchdog.context.python import recognize_python
from watchdog.domain.context import (
    ContextLimitation,
    ContextTarget,
    MappingKind,
    ObservationKind,
    SourceLanguage,
    TargetApplicability,
)
from watchdog.domain.inventory import Ecosystem, VersionKind

from ..security.test_context_discovery import context_limits


def target(package: str, root: str, *, complete: bool = True) -> ContextTarget:
    member_ids = ("pypi-pyyaml-load",) if package == "pyyaml" else ()
    configuration_ids = ("pypi-requests-verify",) if package == "requests" else ()
    endpoint_ids = ("pypi-flask-route",) if package == "flask" else ()
    limitations = () if complete else (ContextLimitation.IMPORT_MAPPING_INCOMPLETE,)
    payload = {
        "match_ordinal": 0,
        "component_id": f"component:{package}",
        "ecosystem": Ecosystem.PYPI,
        "package_name": package,
        "version": "1.0.0",
        "version_kind": VersionKind.EXACT,
        "applicability": TargetApplicability.APPLICABLE,
        "mapping_kind": MappingKind.CATALOG_EXACT if complete else MappingKind.GENERIC,
        "mapping_complete": complete,
        "import_roots": (root,),
        "member_rule_ids": member_ids,
        "configuration_rule_ids": configuration_ids,
        "endpoint_rule_ids": endpoint_ids,
        "dependency_evidence_ids": ("evidence:sha256:" + "a" * 64,),
        "limitation_codes": limitations,
    }
    return ContextTarget(id=context_target_id(payload), **payload)


def recognize(
    text: str | bytes,
    *targets: ContextTarget,
    max_tokens: int = 1_000,
    max_depth: int = 64,
) -> RecognitionResult:
    content = text.encode("utf-8") if isinstance(text, str) else text
    source = DiscoveredSource(
        path="src/app.py",
        language=SourceLanguage.PYTHON,
        file_sha256=hashlib.sha256(content).hexdigest(),
        byte_count=len(content),
        test_source=False,
        content=content,
    )
    limits = context_limits(
        max_tokens_per_file=max_tokens,
        max_total_tokens=max_tokens,
        max_nesting_depth=max_depth,
    )
    budget = RecognitionBudget(
        limits=limits,
        deadline=time.monotonic() + 10,
        cancel_event=threading.Event(),
    )
    return recognize_python(source, targets, DEFAULT_CONTEXT_CATALOG, budget)


def test_python_import_alias_reference_call_and_keyword_configuration() -> None:
    result = recognize(
        """
import requests as client

response = client.get("https://example.invalid", verify=False)
""",
        target("requests", "requests", complete=False),
    )

    kinds = [fact.kind for fact in result.facts]
    assert kinds.count(ObservationKind.IMPORT_DECLARATION) == 1
    assert kinds.count(ObservationKind.TARGET_REFERENCE) == 1
    assert kinds.count(ObservationKind.EXPLICIT_CALL) == 1
    assert kinds.count(ObservationKind.TARGET_CONFIGURATION) == 1
    call = next(fact for fact in result.facts if fact.kind == ObservationKind.EXPLICIT_CALL)
    assert call.binding == "client"
    assert call.member_path == ("get",)
    assert call.anchor.start_line == 4
    assert call.anchor.end_line == 4

    nonliteral = recognize(
        "import requests\nrequests.get(url, verify=runtime_setting)\n",
        target("requests", "requests", complete=False),
    )
    assert not any(fact.kind == ObservationKind.TARGET_CONFIGURATION for fact in nonliteral.facts)
    assert ContextLimitation.UNSUPPORTED_SYNTAX in nonliteral.limitation_codes


def test_python_from_import_and_reviewed_member_rule_are_exact() -> None:
    result = recognize(
        "from yaml import load as parse\nvalue = parse(document)\n",
        target("pyyaml", "yaml"),
    )

    call = next(fact for fact in result.facts if fact.kind == ObservationKind.EXPLICIT_CALL)
    assert call.binding == "parse"
    assert call.member_path == ("load",)
    assert call.rule_id == "pypi-pyyaml-load"


def test_python_configuration_assignment_requires_a_literal_value() -> None:
    literal = recognize(
        "import requests\nrequests.verify = False\n",
        target("requests", "requests", complete=False),
    )
    nonliteral = recognize(
        "import requests\nrequests.verify = runtime_setting\n",
        target("requests", "requests", complete=False),
    )

    assert any(fact.kind == ObservationKind.TARGET_CONFIGURATION for fact in literal.facts)
    assert not any(fact.kind == ObservationKind.TARGET_CONFIGURATION for fact in nonliteral.facts)
    assert ContextLimitation.UNSUPPORTED_SYNTAX in nonliteral.limitation_codes


def test_python_multiline_import_and_crlf_positions_are_deterministic() -> None:
    result = recognize(
        b"from yaml import (\r\n    load as parse,\r\n)\r\nparse(\r\n    payload,\r\n)\r\n",
        target("pyyaml", "yaml"),
    )

    call = next(fact for fact in result.facts if fact.kind == ObservationKind.EXPLICIT_CALL)
    assert call.anchor.start_line == 4
    assert call.anchor.end_line == 6


def test_python_shadowing_relative_star_and_dynamic_imports_limit_coverage() -> None:
    result = recognize(
        """
import requests
from .local import value
from requests import *
requests = replacement
requests.get()
module = __import__("requests")
""",
        target("requests", "requests", complete=False),
    )

    assert [fact.kind for fact in result.facts] == [ObservationKind.IMPORT_DECLARATION]
    assert ContextLimitation.AMBIGUOUS_BINDING in result.limitation_codes
    assert ContextLimitation.RELATIVE_IMPORT_UNSUPPORTED in result.limitation_codes
    assert ContextLimitation.STAR_IMPORT_UNSUPPORTED in result.limitation_codes
    assert ContextLimitation.DYNAMIC_IMPORT_UNSUPPORTED in result.limitation_codes

    parameter = recognize(
        "import requests\ndef scoped(requests):\n    requests.get()\nrequests.get()\n",
        target("requests", "requests", complete=False),
    )
    assert [fact.kind for fact in parameter.facts] == [ObservationKind.IMPORT_DECLARATION]
    assert ContextLimitation.AMBIGUOUS_BINDING in parameter.limitation_codes


def test_python_malformed_invalid_utf8_and_bounds_fail_closed() -> None:
    malformed = recognize("import requests\nrequests.get(\n", target("requests", "requests"))
    assert malformed.facts == ()
    assert ContextLimitation.MALFORMED_SYNTAX in malformed.limitation_codes

    invalid = recognize(b"import requests\n\xff", target("requests", "requests"))
    assert invalid.facts == ()
    assert invalid.limitation_codes == (ContextLimitation.INVALID_UTF8,)

    token_limited = recognize(
        "import requests\n" + "value = value\n" * 20,
        target("requests", "requests"),
        max_tokens=10,
    )
    assert token_limited.facts == ()
    assert ContextLimitation.TOKEN_LIMIT_EXCEEDED in token_limited.limitation_codes

    nested = recognize(
        "import requests\nvalue = (((requests.get())))\n",
        target("requests", "requests"),
        max_depth=2,
    )
    assert nested.facts == ()
    assert ContextLimitation.NESTING_DEPTH_EXCEEDED in nested.limitation_codes

    error_token = recognize(
        "import requests\n??? requests.get()\n",
        target("requests", "requests"),
    )
    assert error_token.facts == ()
    assert ContextLimitation.MALFORMED_SYNTAX in error_token.limitation_codes


def test_python_secret_text_never_enters_result_repr_or_diagnostics() -> None:
    synthetic = "SYNTHETIC_CONTEXT_SECRET"
    result = recognize(
        f'import requests\nrequests.get("{synthetic}")\n',
        target("requests", "requests"),
    )

    assert synthetic not in repr(result)
    assert all(synthetic not in limitation.value for limitation in result.limitation_codes)
