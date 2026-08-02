from __future__ import annotations

from pathlib import Path

import pytest

from scripts.verify_release import (
    ReleaseVerificationError,
    _lock_entries,
    _safe_archive_name,
    verify_repository,
)

_ROOT = Path(__file__).resolve().parents[2]


def test_repository_release_contract_is_internally_consistent() -> None:
    verify_repository(_ROOT, "0.1.0")


@pytest.mark.parametrize(
    "name",
    [
        "/absolute",
        "../escape",
        "root/../escape",
        "root\\file",
        "C:/windows-drive",
        "root/control\x00",
        "root/" + "x" * 256,
    ],
)
def test_archive_names_fail_closed(name: str) -> None:
    with pytest.raises(ReleaseVerificationError):
        _safe_archive_name(name)


def test_lock_parser_rejects_unhashed_remote_and_malformed_requirements(tmp_path: Path) -> None:
    unhashed = tmp_path / "unhashed.lock"
    unhashed.write_text("example==1.0\n", encoding="utf-8")
    with pytest.raises(ReleaseVerificationError, match="unhashed"):
        _lock_entries(unhashed)

    remote = tmp_path / "remote.lock"
    remote.write_text("example @ https://example.invalid/archive.whl\n", encoding="utf-8")
    with pytest.raises(ReleaseVerificationError, match="forbidden"):
        _lock_entries(remote)

    malformed = tmp_path / "malformed.lock"
    malformed.write_text("example==1.0 \\\n    --hash=sha256:not-a-digest\n", encoding="utf-8")
    with pytest.raises(ReleaseVerificationError, match="malformed"):
        _lock_entries(malformed)


def test_release_tag_must_exactly_match_package_version() -> None:
    with pytest.raises(ReleaseVerificationError, match="tag"):
        verify_repository(_ROOT, "0.1.0", tag="v0.1.0-rc1")
