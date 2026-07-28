from __future__ import annotations

import hashlib
import os
import threading
import time
from pathlib import Path

import pytest

from watchdog.evidence.limits import EvidenceLimits
from watchdog.evidence.reader import (
    DescriptorRepositoryReader,
    EvidenceCancelled,
    EvidenceDeadlineExceeded,
    ReadResult,
)


def limits(**overrides: object) -> EvidenceLimits:
    values: dict[str, object] = {
        "deadline_seconds": 10,
        "max_source_files": 10,
        "max_bytes_per_source_file": 1024,
        "max_total_source_bytes": 2048,
        "max_evidence_items": 100,
        "max_line_span": 20,
        "max_display_bytes_per_item": 512,
        "max_bundle_display_bytes": 1024,
        "max_redactions_per_item": 10,
        "max_warnings": 20,
    }
    values.update(overrides)
    return EvidenceLimits.model_validate(values)


def read(
    root: Path,
    relative: str,
    digest: str,
    configured: EvidenceLimits | None = None,
) -> ReadResult:
    with DescriptorRepositoryReader(
        root,
        configured or limits(),
        deadline=time.monotonic() + 10,
        cancel_event=threading.Event(),
    ) as reader:
        return reader.read(relative, digest)


def test_reader_hashes_regular_file_from_descriptor(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    data = b"requests==2.32.3\n"
    (root / "requirements.txt").write_bytes(data)

    result = read(root, "requirements.txt", hashlib.sha256(data).hexdigest())

    assert result.data == data
    assert result.limitation_code is None


@pytest.mark.parametrize("path", ["../outside", "/etc/passwd", "a\\b", "a//b", "./a"])
def test_reader_rejects_non_normalized_paths(tmp_path: Path, path: str) -> None:
    root = tmp_path / "root"
    root.mkdir()
    result = read(root, path, "0" * 64)
    assert result.limitation_code == "source_path_invalid"


def test_reader_never_follows_final_or_parent_symlink(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "manifest").write_text("secret", encoding="utf-8")
    os.symlink(outside / "manifest", root / "final")
    os.symlink(outside, root / "parent")

    final = read(root, "final", hashlib.sha256(b"secret").hexdigest())
    parent = read(root, "parent/manifest", hashlib.sha256(b"secret").hexdigest())

    assert final.data is None
    assert final.limitation_code == "source_not_regular_file"
    assert parent.data is None
    assert parent.limitation_code == "source_unsafe_path"


def test_reader_rejects_directory_fifo_mismatch_and_limits(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "directory").mkdir()
    os.mkfifo(root / "fifo")
    data = b"abcdef"
    (root / "manifest").write_bytes(data)

    assert read(root, "directory", "0" * 64).limitation_code == "source_not_regular_file"
    assert read(root, "fifo", "0" * 64).limitation_code == "source_not_regular_file"
    assert read(root, "manifest", "0" * 64).limitation_code == "source_digest_mismatch"
    assert (
        read(
            root,
            "manifest",
            hashlib.sha256(data).hexdigest(),
            limits(max_bytes_per_source_file=5),
        ).limitation_code
        == "source_file_bytes_limit_exceeded"
    )


def test_reader_source_file_and_total_budgets_are_deterministic(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    first = b"a" * 8
    second = b"b" * 8
    (root / "a").write_bytes(first)
    (root / "b").write_bytes(second)
    configured = limits(
        max_source_files=1,
        max_bytes_per_source_file=8,
        max_total_source_bytes=8,
    )
    with DescriptorRepositoryReader(
        root,
        configured,
        deadline=time.monotonic() + 10,
        cancel_event=threading.Event(),
    ) as reader:
        assert reader.read("a", hashlib.sha256(first).hexdigest()).data == first
        second_result = reader.read("b", hashlib.sha256(second).hexdigest())
    assert second_result.limitation_code == "source_file_limit_exceeded"

    total_configured = limits(
        max_source_files=2,
        max_bytes_per_source_file=8,
        max_total_source_bytes=8,
    )
    with DescriptorRepositoryReader(
        root,
        total_configured,
        deadline=time.monotonic() + 10,
        cancel_event=threading.Event(),
    ) as reader:
        assert reader.read("a", hashlib.sha256(first).hexdigest()).data == first
        total_result = reader.read("b", hashlib.sha256(second).hexdigest())
    assert total_result.limitation_code == "source_total_bytes_limit_exceeded"


def test_reader_reports_missing_and_detects_in_place_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "manifest"
    original = b"original"
    target.write_bytes(original)

    assert read(root, "missing", "0" * 64).limitation_code == "source_missing"

    original_read = os.read
    changed = False

    def changing_read(descriptor: int, maximum: int) -> bytes:
        nonlocal changed
        chunk = original_read(descriptor, maximum)
        if chunk and not changed:
            changed = True
            target.write_bytes(b"modified")
        return chunk

    monkeypatch.setattr("watchdog.evidence.reader.os.read", changing_read)
    result = read(root, "manifest", hashlib.sha256(original).hexdigest())

    assert result.data is None
    assert result.limitation_code == "source_changed_during_read"


def test_reader_honors_deadline_cancellation_and_root_no_follow(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    data = b"fixture"
    (root / "manifest").write_bytes(data)

    with (
        pytest.raises(EvidenceDeadlineExceeded),
        DescriptorRepositoryReader(
            root,
            limits(),
            deadline=time.monotonic() - 1,
            cancel_event=threading.Event(),
        ),
    ):
        pass

    cancelled = threading.Event()
    cancelled.set()
    with (
        pytest.raises(EvidenceCancelled),
        DescriptorRepositoryReader(
            root,
            limits(),
            deadline=time.monotonic() + 10,
            cancel_event=cancelled,
        ),
    ):
        pass

    root_link = tmp_path / "root-link"
    os.symlink(root, root_link)
    with (
        pytest.raises(ValueError, match="unavailable or unsafe"),
        DescriptorRepositoryReader(
            root_link,
            limits(),
            deadline=time.monotonic() + 10,
            cancel_event=threading.Event(),
        ),
    ):
        pass
