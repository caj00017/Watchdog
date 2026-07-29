from __future__ import annotations

import pytest
from pydantic import ValidationError

from watchdog.config.settings import Settings
from watchdog.context.catalog import catalog_metadata
from watchdog.context.limits import ContextConfiguration, ContextLimits


def test_phase5_settings_and_limits_have_authorized_defaults() -> None:
    settings = Settings()
    limits = ContextLimits.from_settings(settings)
    configuration = ContextConfiguration.from_settings(settings, catalog=catalog_metadata())

    assert limits.deadline_seconds == 120
    assert limits.max_directories == 5_000
    assert limits.max_candidate_paths == 10_000
    assert limits.max_directory_depth == 64
    assert limits.max_path_bytes == 4_096
    assert limits.max_source_files == 2_000
    assert limits.max_bytes_per_source_file == 2 * 1024 * 1024
    assert limits.max_total_source_bytes == 50 * 1024 * 1024
    assert limits.max_tokens_per_file == 100_000
    assert limits.max_total_tokens == 1_000_000
    assert limits.max_nesting_depth == 256
    assert limits.max_observations == 50_000
    assert limits.max_graph_nodes == 50_000
    assert limits.max_graph_edges == 100_000
    assert limits.max_evidence_items == 10_000
    assert limits.max_line_span == 100
    assert limits.max_display_bytes_per_item == 16 * 1024
    assert limits.max_bundle_display_bytes == 5 * 1024 * 1024
    assert limits.max_redactions_per_item == 100
    assert limits.max_warnings == 1_000
    assert configuration.catalog_version == "1"
    assert configuration.enabled_detectors == tuple(sorted(configuration.enabled_detectors))


def test_phase5_environment_prefix_and_related_limits_are_strict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WATCHDOG_CONTEXT_MAX_SOURCE_FILES", "17")
    assert ContextLimits.from_settings(Settings()).max_source_files == 17

    with pytest.raises(ValidationError):
        ContextLimits.from_settings(
            Settings(
                context_max_bytes_per_source_file=20,
                context_max_total_source_bytes=10,
            )
        )
    with pytest.raises(ValidationError):
        ContextConfiguration(
            limits=ContextLimits.from_settings(Settings()),
            catalog_version="1",
            catalog_sha256="0" * 64,
            enabled_detectors=("caller_selected_detector",),
        )
