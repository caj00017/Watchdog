from __future__ import annotations

import os
import threading
import time
from pathlib import Path

import pytest

from watchdog.context.catalog import DEFAULT_CONTEXT_CATALOG
from watchdog.context.discovery import ContextCancelled, DiscoveryResult, discover_sources
from watchdog.context.limits import ContextLimits
from watchdog.domain.context import (
    ConfigurationRule,
    ContextLimitation,
    ContextRuleCatalog,
)


def context_limits(**overrides: object) -> ContextLimits:
    values: dict[str, object] = {
        "deadline_seconds": 10,
        "max_directories": 100,
        "max_candidate_paths": 100,
        "max_directory_depth": 10,
        "max_path_bytes": 256,
        "max_source_files": 20,
        "max_bytes_per_source_file": 1024,
        "max_total_source_bytes": 4096,
        "max_tokens_per_file": 1_000,
        "max_total_tokens": 10_000,
        "max_nesting_depth": 64,
        "max_observations": 1_000,
        "max_graph_nodes": 1_000,
        "max_graph_edges": 2_000,
        "max_evidence_items": 1_000,
        "max_line_span": 50,
        "max_display_bytes_per_item": 1024,
        "max_bundle_display_bytes": 4096,
        "max_redactions_per_item": 20,
        "max_warnings": 100,
    }
    values.update(overrides)
    return ContextLimits.model_validate(values)


def discover(
    root: Path,
    *,
    limits: ContextLimits | None = None,
    catalog: ContextRuleCatalog = DEFAULT_CONTEXT_CATALOG,
    cancel_event: threading.Event | None = None,
    deadline: float | None = None,
) -> DiscoveryResult:
    return discover_sources(
        root,
        limits or context_limits(),
        catalog,
        deadline=deadline if deadline is not None else time.monotonic() + 10,
        cancel_event=cancel_event or threading.Event(),
    )


def test_discovery_is_sorted_allowlisted_and_exclusions_limit_coverage(tmp_path: Path) -> None:
    (tmp_path / "z.py").write_text("import z\n", encoding="utf-8")
    (tmp_path / "a.ts").write_text("import a from 'a';\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("untrusted instructions", encoding="utf-8")
    (tmp_path / "ignored.json").write_text('{"token":"secret"}', encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "hidden.py").write_text("outside()\n", encoding="utf-8")

    first = discover(tmp_path)
    second = discover(tmp_path)

    assert first == second
    assert [item.path for item in first.sources] == ["a.ts", "z.py"]
    assert first.excluded_directories == 1
    assert ContextLimitation.DIRECTORY_EXCLUDED in first.limitation_codes
    assert all("README" not in warning.message for warning in first.warnings)
    assert "import z" not in repr(first.sources[-1])


def test_data_configuration_requires_an_exact_catalog_path(tmp_path: Path) -> None:
    (tmp_path / "watchdog.json").write_text('{"algorithms":["RS256"]}', encoding="utf-8")
    rule = ConfigurationRule(
        id="npm-jsonwebtoken-config-file",
        ecosystem="npm",
        package_name="jsonwebtoken",
        keys=("algorithms",),
        normalized_paths=("watchdog.json",),
        review_reference="https://example.invalid/reviewed-contract",
    )
    catalog = ContextRuleCatalog(version="test", configuration_rules=(rule,))

    assert not discover(tmp_path).sources
    result = discover(tmp_path, catalog=catalog)
    assert [item.path for item in result.sources] == ["watchdog.json"]


def test_symlinks_hardlinks_fifo_and_invalid_names_never_cross_the_boundary(
    tmp_path: Path,
) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.py"
    outside.write_text("SYNTHETIC_OUTSIDE_SECRET\n", encoding="utf-8")
    os.symlink(outside, tmp_path / "linked.py")
    os.symlink(tmp_path.parent, tmp_path / "parent-link")
    regular = tmp_path / "regular.py"
    regular.write_text("safe = True\n", encoding="utf-8")
    os.link(regular, tmp_path / "duplicate.py")
    os.mkfifo(tmp_path / "pipe.py")
    invalid_name = os.fsencode(tmp_path) + b"/invalid-\xff.py"
    invalid_fd = os.open(invalid_name, os.O_CREAT | os.O_WRONLY, 0o600)
    os.close(invalid_fd)

    result = discover(tmp_path)

    assert len(result.sources) == 1
    assert result.sources[0].path == "duplicate.py"
    assert all(b"SYNTHETIC_OUTSIDE_SECRET" not in item.content for item in result.sources)
    assert ContextLimitation.SOURCE_SYMLINK_REJECTED in result.limitation_codes
    assert ContextLimitation.DUPLICATE_FILE_IDENTITY in result.limitation_codes
    assert ContextLimitation.SOURCE_NOT_REGULAR in result.limitation_codes
    assert ContextLimitation.UNSAFE_SOURCE_PATH in result.limitation_codes
    assert all("SYNTHETIC_OUTSIDE_SECRET" not in warning.message for warning in result.warnings)


def test_case_collision_discards_the_directory_without_order_selected_subset(
    tmp_path: Path,
) -> None:
    (tmp_path / "Case.py").write_text("upper = True\n", encoding="utf-8")
    (tmp_path / "case.py").write_text("lower = True\n", encoding="utf-8")

    result = discover(tmp_path)

    assert result.sources == ()
    assert ContextLimitation.CASE_COLLIDING_PATH in result.limitation_codes


def test_candidate_overflow_discards_directory_without_nondeterministic_subset(
    tmp_path: Path,
) -> None:
    for name in ("z.py", "a.py", "m.py"):
        (tmp_path / name).write_text("safe = True\n", encoding="utf-8")

    result = discover(tmp_path, limits=context_limits(max_candidate_paths=2))

    assert result.sources == ()
    assert result.candidate_paths == 0
    assert ContextLimitation.CANDIDATE_PATH_LIMIT_EXCEEDED in result.limitation_codes


def test_file_total_depth_path_and_directory_limits_are_explicit(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_bytes(b"a" * 11)
    (tmp_path / "b.py").write_bytes(b"b" * 5)
    deep = tmp_path / "one" / "two"
    deep.mkdir(parents=True)
    (deep / "deep.py").write_text("safe = True\n", encoding="utf-8")
    (tmp_path / ("p" * 40 + ".py")).write_text("safe = True\n", encoding="utf-8")

    per_file = discover(
        tmp_path,
        limits=context_limits(max_bytes_per_source_file=10, max_total_source_bytes=20),
    )
    assert ContextLimitation.SOURCE_FILE_BYTES_LIMIT_EXCEEDED in per_file.limitation_codes

    total = discover(
        tmp_path,
        limits=context_limits(max_bytes_per_source_file=20, max_total_source_bytes=20),
    )
    assert ContextLimitation.SOURCE_TOTAL_BYTES_LIMIT_EXCEEDED in total.limitation_codes

    depth = discover(tmp_path, limits=context_limits(max_directory_depth=1))
    assert ContextLimitation.DIRECTORY_DEPTH_LIMIT_EXCEEDED in depth.limitation_codes

    path = discover(tmp_path, limits=context_limits(max_path_bytes=30))
    assert ContextLimitation.PATH_LENGTH_LIMIT_EXCEEDED in path.limitation_codes

    directories = discover(tmp_path, limits=context_limits(max_directories=1))
    assert ContextLimitation.DIRECTORY_LIMIT_EXCEEDED in directories.limitation_codes


def test_source_file_and_warning_limits_remain_visible(tmp_path: Path) -> None:
    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / name).write_text("safe = True\n", encoding="utf-8")

    result = discover(
        tmp_path,
        limits=context_limits(max_source_files=1, max_warnings=1),
    )

    assert [item.path for item in result.sources] == ["a.py"]
    assert ContextLimitation.SOURCE_FILE_LIMIT_EXCEEDED in result.limitation_codes
    assert result.warnings[0].code == ContextLimitation.SOURCE_FILE_LIMIT_EXCEEDED


def test_file_mutation_is_omitted_without_returning_partial_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "changed.py"
    source.write_bytes(b"a" * 70_000)
    real_read = os.read
    changed = False

    def mutating_read(fd: int, size: int) -> bytes:
        nonlocal changed
        chunk = real_read(fd, size)
        if chunk and not changed:
            changed = True
            source.write_bytes(b"b" * 70_001)
        return chunk

    monkeypatch.setattr("watchdog.context.discovery.os.read", mutating_read)
    result = discover(
        tmp_path,
        limits=context_limits(
            max_bytes_per_source_file=100_000,
            max_total_source_bytes=100_000,
        ),
    )

    assert result.sources == ()
    assert result.omissions[0].limitation == ContextLimitation.SOURCE_FILE_CHANGED


def test_read_and_directory_errors_are_explicit_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "source.py").write_text("safe = True\n", encoding="utf-8")

    def failed_read(_fd: int, _size: int) -> bytes:
        raise OSError("synthetic read failure")

    monkeypatch.setattr("watchdog.context.discovery.os.read", failed_read)
    unreadable = discover(tmp_path)

    assert unreadable.sources == ()
    assert unreadable.omissions[0].limitation == ContextLimitation.SOURCE_FILE_UNREADABLE
    assert "synthetic read failure" not in repr(unreadable)

    def failed_scandir(_fd: int) -> object:
        raise OSError("synthetic enumeration failure")

    monkeypatch.setattr("watchdog.context.discovery.os.scandir", failed_scandir)
    changed = discover(tmp_path)

    assert changed.sources == ()
    assert ContextLimitation.SOURCE_TREE_CHANGED in changed.limitation_codes
    assert "synthetic enumeration failure" not in repr(changed)


def test_deadline_and_cancellation_are_cooperative(tmp_path: Path) -> None:
    (tmp_path / "source.py").write_text("safe = True\n", encoding="utf-8")

    deadline = discover(tmp_path, deadline=time.monotonic() - 1)
    assert ContextLimitation.CONTEXT_DEADLINE_EXCEEDED in deadline.limitation_codes

    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(ContextCancelled):
        discover(tmp_path, cancel_event=cancelled)
