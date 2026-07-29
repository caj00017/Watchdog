from __future__ import annotations

import hashlib
import threading
import time

from watchdog.context._recognition import RecognitionBudget, RecognitionResult
from watchdog.context.catalog import DEFAULT_CONTEXT_CATALOG
from watchdog.context.discovery import DiscoveredSource
from watchdog.context.go import recognize_go
from watchdog.context.identifiers import context_target_id
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
    endpoint_ids = ("go-net-http-handlers",) if package == "net/http" else ()
    payload = {
        "match_ordinal": 0,
        "component_id": f"component:{package}",
        "ecosystem": Ecosystem.GO,
        "package_name": package,
        "version": "v1.0.0",
        "version_kind": VersionKind.EXACT,
        "applicability": TargetApplicability.APPLICABLE,
        "mapping_kind": MappingKind.GENERIC,
        "mapping_complete": True,
        "import_roots": (package,),
        "member_rule_ids": (),
        "configuration_rule_ids": (),
        "endpoint_rule_ids": endpoint_ids,
        "dependency_evidence_ids": ("evidence:sha256:" + "c" * 64,),
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
        path="cmd/app/main.go",
        language=SourceLanguage.GO,
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
    return recognize_go(
        source,
        targets,
        DEFAULT_CONTEXT_CATALOG,
        RecognitionBudget(
            limits=limits,
            deadline=time.monotonic() + 10,
            cancel_event=threading.Event(),
        ),
    )


def test_go_explicit_alias_selector_call_and_endpoint_are_exact() -> None:
    result = recognize(
        """
package main
import web "net/http"
func main() { web.HandleFunc("/health", handler) }
""",
        target("net/http"),
    )

    kinds = [fact.kind for fact in result.facts]
    assert kinds.count(ObservationKind.IMPORT_DECLARATION) == 1
    assert kinds.count(ObservationKind.TARGET_REFERENCE) == 1
    assert kinds.count(ObservationKind.EXPLICIT_CALL) == 1
    assert kinds.count(ObservationKind.ENDPOINT_DECLARATION) == 1
    endpoint = next(
        fact for fact in result.facts if fact.kind == ObservationKind.ENDPOINT_DECLARATION
    )
    assert endpoint.rule_id == "go-net-http-handlers"
    assert endpoint.member_path == ("HandleFunc",)


def test_go_default_package_binding_is_not_inferred_from_the_import_path() -> None:
    package = "github.com/gin-gonic/gin"
    result = recognize(
        f'package main\nimport "{package}"\nfunc main() {{ gin.Default() }}\n',
        target(package),
    )

    assert [fact.kind for fact in result.facts] == [ObservationKind.IMPORT_DECLARATION]
    assert result.facts[0].binding is None
    assert ContextLimitation.AMBIGUOUS_BINDING in result.limitation_codes


def test_go_grouped_raw_dot_blank_and_cgo_imports_preserve_limitations() -> None:
    package = "github.com/example/module"
    result = recognize(
        f"""
package main
import (
    web `{package}`
    . "{package}/dot"
    _ "{package}/blank"
    "C"
)
func main() {{ web.Run() }}
""",
        target(package),
    )

    assert sum(fact.kind == ObservationKind.IMPORT_DECLARATION for fact in result.facts) == 3
    assert any(fact.kind == ObservationKind.EXPLICIT_CALL for fact in result.facts)
    assert ContextLimitation.DOT_IMPORT_UNSUPPORTED in result.limitation_codes
    assert ContextLimitation.BLANK_IMPORT_UNSUPPORTED in result.limitation_codes
    assert ContextLimitation.CGO_UNSUPPORTED in result.limitation_codes


def test_go_build_generated_interface_and_shadowing_conditions_are_explicit() -> None:
    package = "github.com/example/module"
    build = recognize(
        f"//go:build linux\n"
        f"package main\n"
        f'import web "{package}"\n'
        f"type Handler interface {{ Run() }}\n"
        f"web := other\n"
        f"web.Run()\n",
        target(package),
    )
    assert [fact.kind for fact in build.facts] == [ObservationKind.IMPORT_DECLARATION]
    assert ContextLimitation.BUILD_CONSTRAINT_UNEVALUATED in build.limitation_codes
    assert ContextLimitation.DYNAMIC_DISPATCH_UNRESOLVED in build.limitation_codes
    assert ContextLimitation.AMBIGUOUS_BINDING in build.limitation_codes

    generated = recognize(
        f"// Code generated by fixture. DO NOT EDIT.\n"
        f"package main\n"
        f'import web "{package}"\n'
        f"web.Run()\n",
        target(package),
    )
    assert generated.facts == ()
    assert generated.limitation_codes == (ContextLimitation.GENERATED_FILE_OMITTED,)

    parameter = recognize(
        f"package main\n"
        f'import web "{package}"\n'
        f"func scoped(web any) {{ web.Run() }}\n"
        f"func main() {{ web.Run() }}\n",
        target(package),
    )
    assert [fact.kind for fact in parameter.facts] == [ObservationKind.IMPORT_DECLARATION]
    assert ContextLimitation.AMBIGUOUS_BINDING in parameter.limitation_codes


def test_go_comments_and_strings_never_create_substring_fallback() -> None:
    package = "github.com/example/module"
    result = recognize(
        f"""
package main
// import web "{package}"
var prose = "{package}.Run()"
""",
        target(package),
    )
    assert result.facts == ()


def test_go_malformed_utf8_token_and_depth_limits_fail_closed() -> None:
    package = "github.com/example/module"
    malformed = recognize(
        f'package main\nimport web "{package}\n',
        target(package),
    )
    assert malformed.facts == ()
    assert ContextLimitation.MALFORMED_SYNTAX in malformed.limitation_codes

    invalid = recognize(b"package main\n\xff", target(package))
    assert invalid.facts == ()
    assert invalid.limitation_codes == (ContextLimitation.INVALID_UTF8,)

    token_limited = recognize(
        f'package main\nimport web "{package}"\n' + "var value = 1\n" * 20,
        target(package),
        max_tokens=10,
    )
    assert token_limited.facts == ()
    assert ContextLimitation.TOKEN_LIMIT_EXCEEDED in token_limited.limitation_codes

    nested = recognize(
        f'package main\nimport web "{package}"\nfunc main() {{ web.Run((((value)))) }}\n',
        target(package),
        max_depth=2,
    )
    assert nested.facts == ()
    assert ContextLimitation.NESTING_DEPTH_EXCEEDED in nested.limitation_codes


def test_go_crlf_positions_and_secret_confidentiality_are_deterministic() -> None:
    package = "github.com/example/module"
    synthetic = "SYNTHETIC_GO_SECRET"
    result = recognize(
        (
            f"package main\r\n"
            f'import web "{package}"\r\n'
            f'func main() {{ web.Run("{synthetic}") }}\r\n'
        ).encode(),
        target(package),
    )
    call = next(fact for fact in result.facts if fact.kind == ObservationKind.EXPLICIT_CALL)
    assert call.anchor.start_line == 3
    assert synthetic not in repr(result)
