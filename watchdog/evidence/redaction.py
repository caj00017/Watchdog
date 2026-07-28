from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from watchdog.domain.evidence import EvidenceContent, RedactionRecord

REDACTION_MARKER = "[REDACTED]"
DETECTOR_VERSION = "1"


@dataclass(frozen=True, slots=True)
class _Detector:
    name: str
    category: str
    priority: int
    pattern: re.Pattern[str]
    group: str | None = None


@dataclass(frozen=True, slots=True)
class _Candidate:
    start: int
    end: int
    detector: _Detector


@dataclass(frozen=True, slots=True)
class RedactionResult:
    text: str | None
    records: tuple[RedactionRecord, ...]
    limitation_code: str | None = None


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


DEFAULT_DETECTORS: tuple[_Detector, ...] = (
    _Detector(
        "private_key",
        "private_key",
        0,
        _compile(
            r"-----BEGIN (?P<kind>(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY|"
            r"PGP PRIVATE KEY BLOCK)-----"
            r".*?-----END (?P=kind)-----",
            re.DOTALL,
        ),
    ),
    _Detector(
        "github_token",
        "github_token",
        10,
        _compile(
            r"(?<![A-Za-z0-9_])(?:github_pat_[A-Za-z0-9_]{50,255}|gh[pousr]_[A-Za-z0-9]{36,255})(?![A-Za-z0-9_])"
        ),
    ),
    _Detector(
        "gitlab_token",
        "gitlab_token",
        11,
        _compile(r"(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])"),
    ),
    _Detector(
        "slack_token",
        "slack_token",
        12,
        _compile(r"(?<![A-Za-z0-9-])xox[baprs]-[A-Za-z0-9-]{10,255}(?![A-Za-z0-9-])"),
    ),
    _Detector(
        "npm_token",
        "npm_token",
        13,
        _compile(r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9_])"),
    ),
    _Detector(
        "pypi_token",
        "pypi_token",
        14,
        _compile(r"(?<![A-Za-z0-9_-])pypi-[A-Za-z0-9_-]{50,255}(?![A-Za-z0-9_-])"),
    ),
    _Detector(
        "stripe_key",
        "stripe_key",
        15,
        _compile(r"(?<![A-Za-z0-9_])sk_(?:test|live)_[A-Za-z0-9]{16,255}(?![A-Za-z0-9_])"),
    ),
    _Detector(
        "google_api_key",
        "google_api_key",
        16,
        _compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])"),
    ),
    _Detector(
        "aws_access_key",
        "aws_access_key",
        17,
        _compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ),
    _Detector(
        "jwt",
        "jwt",
        18,
        _compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\."
            r"[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
        ),
    ),
    _Detector(
        "uri_userinfo",
        "uri_userinfo",
        20,
        _compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://(?P<secret>[^\s/@:]+(?::[^\s/@]*)?)@"),
        "secret",
    ),
    _Detector(
        "credential_assignment",
        "credential_assignment",
        30,
        _compile(
            r"(?i)\b(?:password|passwd|token|api[_-]?key|secret|client[_-]?secret|"
            r"access[_-]?key)\b\s*[:=]\s*[\"'](?P<secret>[^\"'\r\n]*)[\"']"
        ),
        "secret",
    ),
    _Detector(
        "credential_assignment",
        "credential_assignment",
        30,
        _compile(
            r"(?i)\b(?:password|passwd|token|api[_-]?key|secret|client[_-]?secret|"
            r"access[_-]?key)\b\s*[:=]\s*(?P<secret>[^\"'\s,}\]]+)"
        ),
        "secret",
    ),
)


class Redactor:
    def __init__(self, enabled_detectors: tuple[str, ...]) -> None:
        enabled = set(enabled_detectors)
        self._detectors = tuple(
            detector for detector in DEFAULT_DETECTORS if detector.name in enabled
        )

    def redact(self, text: str, *, max_redactions: int) -> RedactionResult:
        try:
            candidates = self._candidates(text)
        except Exception:
            return RedactionResult(None, (), "redaction_failed")
        selected: list[_Candidate] = []
        occupied_until = -1
        for candidate in sorted(
            candidates,
            key=lambda item: (
                item.start,
                item.detector.priority,
                -(item.end - item.start),
                item.detector.name,
            ),
        ):
            if candidate.start < occupied_until:
                continue
            selected.append(candidate)
            occupied_until = candidate.end
        if len(selected) > max_redactions:
            return RedactionResult(None, (), "redaction_limit_exceeded")
        if not selected:
            return RedactionResult(text, ())
        output: list[str] = []
        records: list[RedactionRecord] = []
        cursor = 0
        for ordinal, candidate in enumerate(selected, start=1):
            output.append(text[cursor : candidate.start])
            output.append(REDACTION_MARKER)
            records.append(
                RedactionRecord(
                    category=candidate.detector.category,
                    detector=candidate.detector.name,
                    detector_version=DETECTOR_VERSION,
                    ordinal=ordinal,
                )
            )
            cursor = candidate.end
        output.append(text[cursor:])
        return RedactionResult("".join(output), tuple(records))

    def _candidates(self, text: str) -> list[_Candidate]:
        candidates: list[_Candidate] = []
        for detector in self._detectors:
            for match in detector.pattern.finditer(text):
                start, end = match.span(detector.group) if detector.group else match.span()
                if start < end:
                    candidates.append(_Candidate(start, end, detector))
        return candidates


def evidence_content(
    redaction: RedactionResult,
    *,
    max_display_bytes: int,
) -> EvidenceContent | None:
    if redaction.text is None:
        return None
    encoded = redaction.text.encode("utf-8")
    truncated = len(encoded) > max_display_bytes
    if truncated:
        display = encoded[:max_display_bytes].decode("utf-8", errors="ignore")
        encoded = display.encode("utf-8")
    else:
        display = redaction.text
    return EvidenceContent(
        text=display,
        sha256=hashlib.sha256(encoded).hexdigest(),
        byte_count=len(encoded),
        redacted=bool(redaction.records),
        truncated=truncated,
        redactions=redaction.records,
    )
