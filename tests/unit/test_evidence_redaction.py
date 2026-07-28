from __future__ import annotations

import json

import pytest

from watchdog.evidence.limits import DEFAULT_EVIDENCE_DETECTORS
from watchdog.evidence.redaction import REDACTION_MARKER, Redactor, evidence_content


@pytest.mark.parametrize(
    ("detector", "synthetic"),
    [
        (
            "private_key",
            "-----BEGIN PRIVATE KEY-----\nSYNTHETIC_ONLY\n-----END PRIVATE KEY-----",
        ),
        (
            "private_key",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nSYNTHETIC_ONLY\n"
            "-----END ENCRYPTED PRIVATE KEY-----",
        ),
        (
            "private_key",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nSYNTHETIC_ONLY\n"
            "-----END PGP PRIVATE KEY BLOCK-----",
        ),
        ("github_token", "ghp_" + "A" * 36),
        ("gitlab_token", "glpat-" + "B" * 20),
        ("slack_token", "xoxb-" + "C" * 20),
        ("npm_token", "npm_" + "D" * 36),
        ("pypi_token", "pypi-" + "E" * 50),
        ("stripe_key", "sk_test_" + "F" * 24),
        ("google_api_key", "AIza" + "G" * 35),
        ("aws_access_key", "AKIA" + "H" * 16),
        ("jwt", "eyJ" + "a" * 8 + "." + "b" * 8 + "." + "c" * 10),
        ("uri_userinfo", "https://synthetic:credential@example.invalid/index"),
        ("credential_assignment", 'password = "synthetic-value"'),
    ],
)
def test_every_versioned_detector_removes_synthetic_secret(detector: str, synthetic: str) -> None:
    result = Redactor((detector,)).redact(synthetic, max_redactions=10)

    assert result.text is not None
    assert synthetic not in result.text
    assert REDACTION_MARKER in result.text
    assert result.records[0].detector == detector
    assert synthetic not in json.dumps([record.model_dump() for record in result.records])


def test_overlap_uses_detector_priority_and_stable_ordinals() -> None:
    token = "ghp_" + "A" * 36
    result = Redactor(tuple(sorted(DEFAULT_EVIDENCE_DETECTORS))).redact(
        f'token = "{token}" and password=second',
        max_redactions=10,
    )

    assert result.text == f'token = "{REDACTION_MARKER}" and password={REDACTION_MARKER}'
    assert [record.detector for record in result.records] == [
        "github_token",
        "credential_assignment",
    ]
    assert [record.ordinal for record in result.records] == [1, 2]


def test_redaction_limit_omits_all_content_and_truncation_is_utf8_safe() -> None:
    result = Redactor(("credential_assignment",)).redact("token=one password=two", max_redactions=1)
    assert result.text is None
    assert result.limitation_code == "redaction_limit_exceeded"

    safe = Redactor(("credential_assignment",)).redact("ééé", max_redactions=1)
    content = evidence_content(safe, max_display_bytes=5)
    assert content is not None
    assert content.text == "éé"
    assert content.byte_count == 4
    assert content.truncated
