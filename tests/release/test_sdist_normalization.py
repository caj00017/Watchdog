from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from scripts.normalize_sdist import normalize_sdist
from scripts.verify_release import ReleaseVerificationError

_EPOCH = 1_785_628_800


def _archive(path: Path, *, mtime: int, link: bool = False) -> None:
    with tarfile.open(path, mode="w:gz") as archive:
        root = tarfile.TarInfo("nexura_watchdog-0.1.0")
        root.type = tarfile.DIRTYPE
        root.mode = 0o700
        root.mtime = mtime
        root.uid = 1000
        root.gid = 1000
        archive.addfile(root)

        member = tarfile.TarInfo("nexura_watchdog-0.1.0/file.txt")
        member.mtime = mtime
        member.uid = 1000
        member.gid = 1000
        if link:
            member.type = tarfile.SYMTYPE
            member.linkname = "target"
            archive.addfile(member)
            return
        content = b"trusted release fixture\n"
        member.size = len(content)
        member.mode = 0o600
        archive.addfile(member, io.BytesIO(content))


def test_normalized_sdist_is_reproducible_and_has_canonical_metadata(tmp_path: Path) -> None:
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    _archive(first, mtime=1_700_000_000)
    _archive(second, mtime=1_800_000_000)

    normalize_sdist(first, _EPOCH)
    normalize_sdist(second, _EPOCH)

    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, mode="r:gz") as archive:
        members = archive.getmembers()
    assert [member.name for member in members] == [
        "nexura_watchdog-0.1.0",
        "nexura_watchdog-0.1.0/file.txt",
    ]
    assert all(member.mtime == _EPOCH for member in members)
    assert all(member.uid == member.gid == 0 for member in members)
    assert all(not member.uname and not member.gname for member in members)
    assert members[0].mode == 0o755
    assert members[1].mode == 0o644


def test_sdist_normalization_rejects_links_without_replacing_input(tmp_path: Path) -> None:
    path = tmp_path / "linked.tar.gz"
    _archive(path, mtime=1_700_000_000, link=True)
    original = path.read_bytes()

    with pytest.raises(ReleaseVerificationError, match="non-file"):
        normalize_sdist(path, _EPOCH)

    assert path.read_bytes() == original
