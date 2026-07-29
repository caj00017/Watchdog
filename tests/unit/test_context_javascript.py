from __future__ import annotations

import hashlib
import threading
import time

from watchdog.context._recognition import RecognitionBudget, RecognitionResult
from watchdog.context.catalog import DEFAULT_CONTEXT_CATALOG
from watchdog.context.discovery import DiscoveredSource
from watchdog.context.identifiers import context_target_id
from watchdog.context.javascript import recognize_javascript
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


def target(package: str) -> ContextTarget:
    configuration_ids = ("npm-jsonwebtoken-algorithms",) if package == "jsonwebtoken" else ()
    endpoint_ids = ("npm-express-routes",) if package == "express" else ()
    payload = {
        "match_ordinal": 0,
        "component_id": f"component:{package}",
        "ecosystem": Ecosystem.NPM,
        "package_name": package,
        "version": "1.0.0",
        "version_kind": VersionKind.EXACT,
        "applicability": TargetApplicability.APPLICABLE,
        "mapping_kind": MappingKind.GENERIC,
        "mapping_complete": True,
        "import_roots": (package,),
        "member_rule_ids": (),
        "configuration_rule_ids": configuration_ids,
        "endpoint_rule_ids": endpoint_ids,
        "dependency_evidence_ids": ("evidence:sha256:" + "b" * 64,),
        "limitation_codes": (),
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
        path="src/app.ts",
        language=SourceLanguage.JAVASCRIPT,
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
    return recognize_javascript(
        source,
        targets,
        DEFAULT_CONTEXT_CATALOG,
        RecognitionBudget(
            limits=limits,
            deadline=time.monotonic() + 10,
            cancel_event=threading.Event(),
        ),
    )


def test_javascript_commonjs_call_and_reviewed_configuration_property() -> None:
    result = recognize(
        """
const jwt = require("jsonwebtoken");
jwt.verify(token, secret, { algorithms: ["RS256"] });
""",
        target("jsonwebtoken"),
    )

    kinds = [fact.kind for fact in result.facts]
    assert kinds.count(ObservationKind.IMPORT_DECLARATION) == 1
    assert kinds.count(ObservationKind.TARGET_REFERENCE) == 1
    assert kinds.count(ObservationKind.EXPLICIT_CALL) == 1
    assert kinds.count(ObservationKind.TARGET_CONFIGURATION) == 1
    configuration = next(
        fact for fact in result.facts if fact.kind == ObservationKind.TARGET_CONFIGURATION
    )
    assert configuration.rule_id == "npm-jsonwebtoken-algorithms"

    nonliteral = recognize(
        'const jwt = require("jsonwebtoken");\n'
        "jwt.verify(token, secret, { algorithms: runtimeAlgorithms });\n",
        target("jsonwebtoken"),
    )
    assert not any(fact.kind == ObservationKind.TARGET_CONFIGURATION for fact in nonliteral.facts)
    assert ContextLimitation.UNSUPPORTED_SYNTAX in nonliteral.limitation_codes


def test_javascript_malformed_and_member_import_forms_fail_closed() -> None:
    malformed = recognize(
        'import unexpected "jsonwebtoken";\nunexpected.verify(token);\n',
        target("jsonwebtoken"),
    )
    member_require = recognize(
        'const jwt = loader.require("jsonwebtoken");\njwt.verify(token);\n',
        target("jsonwebtoken"),
    )
    member_import = recognize(
        'const jwt = loader.import("jsonwebtoken");\njwt.verify(token);\n',
        target("jsonwebtoken"),
    )
    shadowed_require = recognize(
        "function require(name) { return loader(name); }\n"
        'const jwt = require("jsonwebtoken");\n'
        "jwt.verify(token);\n",
        target("jsonwebtoken"),
    )

    assert malformed.facts == ()
    assert ContextLimitation.MALFORMED_SYNTAX in malformed.limitation_codes
    assert member_require.facts == ()
    assert member_import.facts == ()
    assert shadowed_require.facts == ()
    assert ContextLimitation.AMBIGUOUS_BINDING in shadowed_require.limitation_codes


def test_javascript_esm_named_default_subpath_and_endpoint_forms() -> None:
    express = target("express")
    default = recognize(
        'import app from "express";\napp.get("/health", handler);\n',
        express,
    )
    assert any(fact.kind == ObservationKind.ENDPOINT_DECLARATION for fact in default.facts)
    assert any(fact.rule_id == "npm-express-routes" for fact in default.facts)

    named = recognize(
        'import { verify as check } from "jsonwebtoken/lib/verify";\ncheck(token);\n',
        target("jsonwebtoken"),
    )
    call = next(fact for fact in named.facts if fact.kind == ObservationKind.EXPLICIT_CALL)
    assert call.binding == "check"
    assert call.member_path == ("verify",)


def test_javascript_literal_dynamic_import_is_observed_but_nonliteral_is_not() -> None:
    literal = recognize(
        'const jwt = await import("jsonwebtoken");\njwt.verify(token);\n',
        target("jsonwebtoken"),
    )
    assert any(fact.kind == ObservationKind.EXPLICIT_CALL for fact in literal.facts)

    nonliteral = recognize(
        "const jwt = require(packageName);\njwt.verify(token);\n",
        target("jsonwebtoken"),
    )
    assert nonliteral.facts == ()
    assert ContextLimitation.DYNAMIC_IMPORT_UNSUPPORTED in nonliteral.limitation_codes


def test_javascript_comments_strings_templates_reexports_and_computed_members_do_not_fallback() -> (
    None
):
    result = recognize(
        """
// require("jsonwebtoken").verify(secret)
const prose = "jsonwebtoken.verify(secret)";
const template = `${name}: jsonwebtoken.verify(secret)`;
/jsonwebtoken.verify(secret)/;
export { verify } from "jsonwebtoken";
const jwt = require("jsonwebtoken");
jwt["verify"](token);
""",
        target("jsonwebtoken"),
    )

    assert [fact.kind for fact in result.facts] == [ObservationKind.IMPORT_DECLARATION]
    assert ContextLimitation.TEMPLATE_INTERPOLATION_UNSUPPORTED in result.limitation_codes
    assert ContextLimitation.REEXPORT_UNSUPPORTED in result.limitation_codes
    assert ContextLimitation.COMPUTED_MEMBER_UNSUPPORTED in result.limitation_codes
    assert ContextLimitation.UNSUPPORTED_SYNTAX in result.limitation_codes


def test_javascript_shadowing_jsx_typescript_and_crlf_are_explicit() -> None:
    result = recognize(
        b'import jwt from "jsonwebtoken";\r\n'
        b"jwt = replacement;\r\n"
        b"const node: Widget = <View />;\r\n"
        b"jwt.verify(token);\r\n",
        target("jsonwebtoken"),
    )

    assert [fact.kind for fact in result.facts] == [ObservationKind.IMPORT_DECLARATION]
    assert ContextLimitation.AMBIGUOUS_BINDING in result.limitation_codes
    assert ContextLimitation.UNSUPPORTED_SYNTAX in result.limitation_codes


def test_javascript_function_parameter_shadowing_fails_closed() -> None:
    result = recognize(
        'import jwt from "jsonwebtoken";\n'
        "function scoped(jwt) { jwt.verify(token); }\n"
        "jwt.verify(token);\n",
        target("jsonwebtoken"),
    )

    assert [fact.kind for fact in result.facts] == [ObservationKind.IMPORT_DECLARATION]
    assert ContextLimitation.AMBIGUOUS_BINDING in result.limitation_codes


def test_javascript_malformed_utf8_token_and_depth_limits_fail_closed() -> None:
    malformed = recognize(
        'import jwt from "jsonwebtoken";\n/* never closed',
        target("jsonwebtoken"),
    )
    assert malformed.facts == ()
    assert ContextLimitation.MALFORMED_SYNTAX in malformed.limitation_codes

    invalid = recognize(b'import jwt from "jsonwebtoken";\n\xff', target("jsonwebtoken"))
    assert invalid.facts == ()
    assert invalid.limitation_codes == (ContextLimitation.INVALID_UTF8,)

    token_limited = recognize(
        'import jwt from "jsonwebtoken";\n' + "const value = 1;\n" * 20,
        target("jsonwebtoken"),
        max_tokens=10,
    )
    assert token_limited.facts == ()
    assert ContextLimitation.TOKEN_LIMIT_EXCEEDED in token_limited.limitation_codes

    nested = recognize(
        'import jwt from "jsonwebtoken";\njwt.verify((((token))));\n',
        target("jsonwebtoken"),
        max_depth=2,
    )
    assert nested.facts == ()
    assert ContextLimitation.NESTING_DEPTH_EXCEEDED in nested.limitation_codes


def test_javascript_secret_text_never_enters_result_repr() -> None:
    synthetic = "SYNTHETIC_JAVASCRIPT_SECRET"
    result = recognize(
        f'import jwt from "jsonwebtoken";\njwt.verify("{synthetic}");\n',
        target("jsonwebtoken"),
    )
    assert synthetic not in repr(result)
