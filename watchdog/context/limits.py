from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from watchdog.config.settings import Settings
from watchdog.evidence.limits import DEFAULT_EVIDENCE_DETECTORS


class ContextLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    deadline_seconds: float = Field(gt=0, le=600)
    max_directories: int = Field(gt=0, le=100_000)
    max_candidate_paths: int = Field(gt=0, le=1_000_000)
    max_directory_depth: int = Field(gt=0, le=64)
    max_path_bytes: int = Field(gt=0, le=4096)
    max_source_files: int = Field(gt=0, le=100_000)
    max_bytes_per_source_file: int = Field(gt=0, le=50 * 1024 * 1024)
    max_total_source_bytes: int = Field(gt=0, le=250 * 1024 * 1024)
    max_tokens_per_file: int = Field(gt=0, le=1_000_000)
    max_total_tokens: int = Field(gt=0, le=10_000_000)
    max_nesting_depth: int = Field(gt=0, le=256)
    max_observations: int = Field(gt=0, le=50_000)
    max_graph_nodes: int = Field(gt=0, le=50_000)
    max_graph_edges: int = Field(gt=0, le=100_000)
    max_evidence_items: int = Field(gt=0, le=10_000)
    max_line_span: int = Field(gt=0, le=100)
    max_display_bytes_per_item: int = Field(gt=0, le=16 * 1024)
    max_bundle_display_bytes: int = Field(gt=0, le=5 * 1024 * 1024)
    max_redactions_per_item: int = Field(gt=0, le=100)
    max_warnings: int = Field(gt=0, le=1_000)

    @model_validator(mode="after")
    def validate_related_limits(self) -> Self:
        if self.max_bytes_per_source_file > self.max_total_source_bytes:
            raise ValueError("per-file context bytes cannot exceed total source bytes")
        if self.max_tokens_per_file > self.max_total_tokens:
            raise ValueError("per-file context tokens cannot exceed total tokens")
        if self.max_display_bytes_per_item > self.max_bundle_display_bytes:
            raise ValueError("per-item context display cannot exceed bundle display")
        return self

    @classmethod
    def from_settings(cls, settings: Settings) -> ContextLimits:
        return cls(
            deadline_seconds=settings.context_deadline_seconds,
            max_directories=settings.context_max_directories,
            max_candidate_paths=settings.context_max_candidate_paths,
            max_directory_depth=settings.context_max_directory_depth,
            max_path_bytes=settings.context_max_path_bytes,
            max_source_files=settings.context_max_source_files,
            max_bytes_per_source_file=settings.context_max_bytes_per_source_file,
            max_total_source_bytes=settings.context_max_total_source_bytes,
            max_tokens_per_file=settings.context_max_tokens_per_file,
            max_total_tokens=settings.context_max_total_tokens,
            max_nesting_depth=settings.context_max_nesting_depth,
            max_observations=settings.context_max_observations,
            max_graph_nodes=settings.context_max_graph_nodes,
            max_graph_edges=settings.context_max_graph_edges,
            max_evidence_items=settings.context_max_evidence_items,
            max_line_span=settings.context_max_line_span,
            max_display_bytes_per_item=settings.context_max_display_bytes_per_item,
            max_bundle_display_bytes=settings.context_max_bundle_display_bytes,
            max_redactions_per_item=settings.context_max_redactions_per_item,
            max_warnings=settings.context_max_warnings,
        )


class ContextConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    limits: ContextLimits
    enabled_detectors: tuple[str, ...] = Field(
        default=DEFAULT_EVIDENCE_DETECTORS, min_length=1, max_length=64
    )
    producer_name: str = Field(default="watchdog-context", pattern=r"^[a-z][a-z0-9._-]{0,127}$")
    producer_version: str = Field(default="1", min_length=1, max_length=128)
    python_recognizer_version: str = Field(default="1", min_length=1, max_length=128)
    javascript_recognizer_version: str = Field(default="1", min_length=1, max_length=128)
    go_recognizer_version: str = Field(default="1", min_length=1, max_length=128)
    configuration_recognizer_version: str = Field(default="1", min_length=1, max_length=128)
    graph_version: str = Field(default="1", min_length=1, max_length=128)
    ranking_version: str = Field(default="1", min_length=1, max_length=128)
    catalog_version: str = Field(min_length=1, max_length=128)
    catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    redaction_policy_version: str = Field(default="1", min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_detectors(self) -> Self:
        if self.enabled_detectors != tuple(sorted(set(self.enabled_detectors))):
            raise ValueError("context detectors must be unique and sorted")
        if not set(self.enabled_detectors).issubset(DEFAULT_EVIDENCE_DETECTORS):
            raise ValueError("context configuration contains an unknown redaction detector")
        return self

    @classmethod
    def from_settings(cls, settings: Settings, *, catalog: object) -> ContextConfiguration:
        from watchdog.domain.context import CatalogMetadata

        metadata = CatalogMetadata.model_validate(catalog)
        return cls(
            limits=ContextLimits.from_settings(settings),
            catalog_version=metadata.version,
            catalog_sha256=metadata.sha256,
        )
