from __future__ import annotations

import argparse
import copy
import gzip
import os
import sys
import tarfile
import tempfile
from collections.abc import Sequence
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.verify_release import (  # noqa: E402
    ReleaseVerificationError,
    _safe_archive_name,
)

_MAX_MEMBERS = 800
_MAX_MEMBER_BYTES = 5_000_000
_MAX_TOTAL_BYTES = 50_000_000


def normalize_sdist(path: Path, epoch: int) -> None:
    if epoch < 315_532_800:
        raise ReleaseVerificationError("release epoch is before 1980")
    destination = path.resolve()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    raw_output = os.fdopen(descriptor, mode="wb")
    try:
        with (
            tarfile.open(destination, mode="r:gz") as source,
            raw_output,
            gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw_output,
                mtime=epoch,
            ) as compressed_output,
            tarfile.open(
                fileobj=compressed_output,
                mode="w|",
                format=tarfile.PAX_FORMAT,
            ) as target,
        ):
            members = source.getmembers()
            if len(members) > _MAX_MEMBERS:
                raise ReleaseVerificationError("sdist member limit exceeded")
            names: set[str] = set()
            total_size = 0
            for member in sorted(members, key=lambda item: item.name):
                name = str(_safe_archive_name(member.name))
                if name in names:
                    raise ReleaseVerificationError("sdist repeats an archive member")
                names.add(name)
                if not (member.isfile() or member.isdir()):
                    raise ReleaseVerificationError("sdist contains a non-file member")
                total_size += member.size
                if member.size > _MAX_MEMBER_BYTES or total_size > _MAX_TOTAL_BYTES:
                    raise ReleaseVerificationError("sdist content size limit exceeded")

                normalized = copy.copy(member)
                normalized.uid = 0
                normalized.gid = 0
                normalized.uname = ""
                normalized.gname = ""
                normalized.mtime = epoch
                normalized.mode = 0o644 if member.isfile() else 0o755
                normalized.pax_headers = {}
                if member.isdir():
                    target.addfile(normalized)
                    continue
                content = source.extractfile(member)
                if content is None:
                    raise ReleaseVerificationError("sdist member content is unreadable")
                with content:
                    target.addfile(normalized, content)
        os.replace(temporary, destination)
    except BaseException:
        raw_output.close()
        temporary.unlink(missing_ok=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize a trusted Watchdog sdist.")
    parser.add_argument("--epoch", required=True, type=int)
    parser.add_argument("path", type=Path)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = _parser().parse_args(arguments)
    try:
        normalize_sdist(namespace.path, namespace.epoch)
    except (OSError, ReleaseVerificationError, tarfile.TarError) as exc:
        print(f"sdist normalization failed: {exc}")
        return 1
    print(f"sdist normalization passed: {namespace.path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
