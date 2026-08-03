from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from watchdog.tui import DISPLAY_POLICY_VERSION

MAX_DISPLAY_CODEPOINTS = 16_384
MAX_CANONICAL_DISPLAY_CODEPOINTS = 131_072
MAX_COMBINING_RUN = 8
MAX_FORMAT_RUN = 8


@dataclass(frozen=True, slots=True)
class DisplayText:
    text: str
    escaped_codepoints: int
    omitted_codepoints: int
    truncated: bool
    policy_version: str = DISPLAY_POLICY_VERSION


def _token(character: str) -> str:
    width = 4 if ord(character) <= 0xFFFF else 6
    return f"<U+{ord(character):0{width}X}>"


def _unsafe_category(character: str) -> bool:
    category = unicodedata.category(character)
    return category in {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def contains_forbidden_input(value: str) -> bool:
    """Reject semantics-changing controls and invisible format characters."""

    return any(_unsafe_category(character) for character in value)


def display_text(value: str, *, max_codepoints: int = MAX_DISPLAY_CODEPOINTS) -> DisplayText:
    """Return inert terminal text without changing the source value."""

    if max_codepoints < 64:
        raise ValueError("display bound must leave room for an omission marker")
    units: list[str] = []
    used = 0
    escaped = 0
    omitted = 0
    combining_run = 0
    format_run = 0
    truncated = False

    for index, character in enumerate(value):
        category = unicodedata.category(character)
        is_combining = category in {"Mn", "Mc", "Me"}
        is_format = category == "Cf"
        combining_run = combining_run + 1 if is_combining else 0
        format_run = format_run + 1 if is_format else 0
        if combining_run > MAX_COMBINING_RUN or format_run > MAX_FORMAT_RUN:
            omitted += 1
            continue
        unit = _token(character) if _unsafe_category(character) else character
        escaped += unit != character
        reserve = 32
        if used + len(unit) > max_codepoints - reserve:
            omitted += len(value) - index
            truncated = True
            break
        units.append(unit)
        used += len(unit)

    if omitted:
        marker = f"<OMITTED:{omitted}>"
        while units and used + len(marker) > max_codepoints:
            removed = units.pop()
            used -= len(removed)
        units.append(marker)
    return DisplayText(
        text="".join(units),
        escaped_codepoints=escaped,
        omitted_codepoints=omitted,
        truncated=truncated,
    )


def display_bytes(value: bytes, *, max_codepoints: int) -> DisplayText:
    """Decode validated canonical UTF-8 and render a bounded safe representation."""

    return display_text(value.decode("utf-8", errors="strict"), max_codepoints=max_codepoints)
