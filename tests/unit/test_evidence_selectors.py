from __future__ import annotations

import pytest

from watchdog.domain.inventory import SelectorKind, SourceSelector
from watchdog.evidence.selectors import SelectorResolutionError, resolve_selector


def selector(kind: SelectorKind, value: str) -> SourceSelector:
    return SourceSelector(kind=kind, value=value)


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_line_selector_returns_complete_logical_requirement(newline: str) -> None:
    text = f"first==1{newline}requests==2.32.3 \\{newline}  --hash=sha256:fixture{newline}"

    selected = resolve_selector(
        text.encode(),
        selector(SelectorKind.LINE, "line:2"),
        max_line_span=3,
    )

    assert selected.text == "requests==2.32.3 \\\n  --hash=sha256:fixture"
    assert selected.line_range.start == 2
    assert selected.line_range.end == 3


def test_json_pointer_handles_escaped_keys_and_returns_complete_member() -> None:
    selected = resolve_selector(
        b'{"dependencies":{"@scope/pkg":"1.2.3"}}',
        selector(SelectorKind.JSON_POINTER, "/dependencies/@scope~1pkg"),
        max_line_span=10,
    )

    assert selected.text == '"@scope/pkg":"1.2.3"'
    assert selected.value == "1.2.3"
    assert selected.key == "@scope/pkg"

    bundled = resolve_selector(
        b'{"bundleDependencies":["fixture"]}',
        selector(SelectorKind.JSON_POINTER, "/bundledDependencies/fixture"),
        max_line_span=10,
    )
    assert bundled.text == '"fixture"'
    assert bundled.key == "fixture"


def test_json_pointer_rejects_duplicate_keys_and_stale_pointer() -> None:
    with pytest.raises(SelectorResolutionError) as duplicate:
        resolve_selector(
            b'{"dependencies":{"a":"1","a":"2"}}',
            selector(SelectorKind.JSON_POINTER, "/dependencies/a"),
            max_line_span=10,
        )
    assert duplicate.value.code == "selector_ambiguous"

    with pytest.raises(SelectorResolutionError) as stale:
        resolve_selector(
            b'{"dependencies":{}}',
            selector(SelectorKind.JSON_POINTER, "/dependencies/a"),
            max_line_span=10,
        )
    assert stale.value.code == "selector_stale"


def test_json_pointer_handles_many_primitives_without_suffix_reparsing() -> None:
    values = ",".join(str(index) for index in range(10_000))
    selected = resolve_selector(
        f'{{"values":[{values}]}}'.encode(),
        selector(SelectorKind.JSON_POINTER, "/values/9999"),
        max_line_span=1,
    )

    assert selected.text == "9999"
    assert selected.value == 9999


def test_pyproject_multiline_array_selects_only_requested_entry() -> None:
    selected = resolve_selector(
        b"""
[project]
dependencies = [
  "requests==2.32.3",
  "httpx==0.27.2",
]
""",
        selector(SelectorKind.TOML, "project.dependencies[1]"),
        max_line_span=10,
    )

    assert selected.text == '"httpx==0.27.2"'
    assert selected.value == "httpx==0.27.2"
    assert selected.line_range.start == 5


def test_pyproject_optional_and_dependency_group_selectors_support_comments_and_crlf() -> None:
    data = (
        b"[project] # trusted table marker\r\n"
        b'dependencies = ["requests==2.32.3"]\r\n'
        b"[project.optional-dependencies]\r\n"
        b'docs = [\r\n  "sphinx==8.0.0",\r\n]\r\n'
        b"[dependency-groups]\r\n"
        b'test = [\r\n  "pytest==8.3.0",\r\n]\r\n'
        b"# trailing neighboring comment must not be selected\r\n"
    )

    optional = resolve_selector(
        data,
        selector(SelectorKind.TOML, "project.optional-dependencies.docs[0]"),
        max_line_span=10,
    )
    group = resolve_selector(
        data,
        selector(SelectorKind.TOML, "dependency-groups.test[0]"),
        max_line_span=10,
    )

    assert optional.text == '"sphinx==8.0.0"'
    assert group.text == '"pytest==8.3.0"'
    assert "neighboring" not in optional.text + group.text


def test_toml_dependency_group_quoted_key_ambiguity_fails_closed() -> None:
    with pytest.raises(SelectorResolutionError) as error:
        resolve_selector(
            b"""
[dependency-groups]
"a.b" = ["one==1"]
[dependency-groups.a]
b = ["two==2"]
""",
            selector(SelectorKind.TOML, "dependency-groups.a.b[0]"),
            max_line_span=10,
        )
    assert error.value.code == "selector_ambiguous"


def test_uv_package_and_dependency_selectors_are_positional() -> None:
    data = b"""
version = 1
[[package]]
name = "app"
version = "1.0"
source = { editable = "." }
dependencies = [
  { name = "httpx", version = "0.27.2" },
]
[[package]]
name = "httpx"
version = "0.27.2"
source = { registry = "https://example.invalid/simple" }
"""
    package = resolve_selector(
        data,
        selector(SelectorKind.TOML, "package[name='httpx',version='0.27.2',index=1]"),
        max_line_span=20,
    )
    dependency = resolve_selector(
        data,
        selector(
            SelectorKind.TOML,
            "package[name='app',version='1.0',index=0].dependencies[0]",
        ),
        max_line_span=20,
    )

    assert package.text.startswith("[[package]]")
    assert package.value == {
        "name": "httpx",
        "version": "0.27.2",
        "source": {"registry": "https://example.invalid/simple"},
    }
    assert dependency.value == {"name": "httpx", "version": "0.27.2"}
    assert "app" not in dependency.text


def test_uv_package_span_excludes_trailing_neighboring_comments() -> None:
    data = b"""
[[package]]
name = "httpx"
version = "0.27.2"
source = { registry = "https://example.invalid/simple" }
# token=synthetic-neighboring-value

[[package]]
name = "other"
version = "1.0.0"
source = { registry = "https://example.invalid/simple" }
"""

    selected = resolve_selector(
        data,
        selector(SelectorKind.TOML, "package[name='httpx',version='0.27.2',index=0]"),
        max_line_span=20,
    )

    assert selected.text.endswith('source = { registry = "https://example.invalid/simple" }')
    assert "neighboring" not in selected.text


def test_invalid_utf8_and_line_span_limit_omit_content() -> None:
    with pytest.raises(SelectorResolutionError) as invalid:
        resolve_selector(
            b"\xff",
            selector(SelectorKind.LINE, "line:1"),
            max_line_span=1,
        )
    assert invalid.value.code == "source_invalid_utf8"

    with pytest.raises(SelectorResolutionError) as limited:
        resolve_selector(
            b"a==1 \\\n  --hash=x\n",
            selector(SelectorKind.LINE, "line:1"),
            max_line_span=1,
        )
    assert limited.value.code == "source_line_span_limit_exceeded"

    with pytest.raises(SelectorResolutionError) as empty:
        resolve_selector(
            b"",
            selector(SelectorKind.LINE, "line:1"),
            max_line_span=1,
        )
    assert empty.value.code == "selector_stale"
