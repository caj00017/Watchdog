from __future__ import annotations

import pytest

from watchdog.tui.backend import investigation_request
from watchdog.tui.display import contains_forbidden_input, display_bytes, display_text
from watchdog.tui.driver import filter_terminal_modes


@pytest.mark.parametrize(
    "hostile",
    [
        "\x00\x07\x1b[31m",
        "\x1b]8;;https://example.invalid\x07link\x1b]8;;\x07",
        "\x1b]52;c;Y2xpcGJvYXJk\x07",
        "\x1bPqpayload\x1b\\",
        "left\u202eright\u202c",
        "zero\u200bwidth\u2060",
        "line\nnext\tfield",
        "c1\x9b31m",
    ],
)
def test_display_policy_visibly_encodes_terminal_and_spoofing_controls(hostile: str) -> None:
    rendered = display_text(hostile)

    assert "\x1b" not in rendered.text
    assert "\x07" not in rendered.text
    assert "\u202e" not in rendered.text
    assert "\u200b" not in rendered.text
    assert "<U+" in rendered.text
    assert rendered.escaped_codepoints > 0
    assert contains_forbidden_input(hostile)


def test_display_policy_bounds_combining_floods_and_long_values() -> None:
    hostile = "a" + "\u0301" * 1_000 + "z" * 10_000
    rendered = display_text(hostile, max_codepoints=256)

    assert len(rendered.text) <= 256
    assert rendered.omitted_codepoints > 0
    assert "<OMITTED:" in rendered.text
    assert rendered.truncated


def test_canonical_bytes_remain_frozen_while_display_is_safe() -> None:
    canonical = b'{"value":"\\u001b[2J","markup":"[bold]data[/bold]"}'
    original = bytes(canonical)

    rendered = display_bytes(canonical, max_codepoints=512)

    assert canonical == original
    assert "[bold]data[/bold]" in rendered.text
    assert rendered.policy_version == "1"


def test_unauthorized_terminal_input_modes_are_filtered() -> None:
    rendered = filter_terminal_modes(
        "before\x1b[?1004hmiddle\x1b[?2004hafter\x1b[?1004l\x1b[?2004l"
    )

    assert rendered == "beforemiddleafter\x1b[?1004l\x1b[?2004l"


@pytest.mark.parametrize("value", ["CVE-2026-12345\x1b", "CVE-2026-12345\u202e", "x\u200b"])
def test_tui_request_rejects_forbidden_invisible_input(value: str) -> None:
    with pytest.raises(ValueError, match="forbidden"):
        investigation_request(value, "https://github.com/octocat/Hello-World", None)
