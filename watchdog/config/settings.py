from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration loaded from WATCHDOG_-prefixed environment variables."""

    model_config = SettingsConfigDict(env_prefix="WATCHDOG_", extra="ignore")

    app_name: str = "Nexura Watchdog"
    environment: Literal["development", "test", "production"] = "development"
    osv_base_url: AnyHttpUrl = AnyHttpUrl("https://api.osv.dev/v1")
    upstream_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    include_raw_source_records: bool = True
    github_api_version: str = Field(default="2026-03-10", pattern=r"^\d{4}-\d{2}-\d{2}$")
    repository_network_timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    repository_max_duration_seconds: float = Field(default=600.0, gt=0, le=3600)
    repository_max_archive_bytes: int = Field(default=250 * 1024 * 1024, gt=0)
    repository_max_extracted_bytes: int = Field(default=250 * 1024 * 1024, gt=0)
    repository_max_files: int = Field(default=25_000, gt=0)
    repository_max_path_length: int = Field(default=1024, gt=0, le=4096)
    repository_max_concurrent_intakes: int = Field(default=1, gt=0, le=16)
    repository_workspace_root: Path | None = None
    inventory_deadline_seconds: float = Field(default=120.0, gt=0, le=600)
    inventory_max_manifest_files: int = Field(default=200, gt=0)
    inventory_max_bytes_per_manifest: int = Field(default=5 * 1024 * 1024, gt=0)
    inventory_max_total_parsed_bytes: int = Field(default=25 * 1024 * 1024, gt=0)
    inventory_max_components: int = Field(default=50_000, gt=0)
    inventory_max_edges: int = Field(default=200_000, gt=0)
    inventory_max_parser_nesting_depth: int = Field(default=64, gt=0, le=256)
    inventory_max_requirements_include_depth: int = Field(default=10, ge=0, le=100)
    inventory_max_warnings: int = Field(default=1_000, gt=0)
    osv_scanner_path: Path = Path("/usr/local/bin/osv-scanner")
    scanner_timeout_seconds: float = Field(default=120.0, gt=0, le=600)
    scanner_max_input_bytes: int = Field(default=5 * 1024 * 1024, gt=0)
    scanner_max_stdout_bytes: int = Field(default=25 * 1024 * 1024, gt=0)
    scanner_max_stderr_bytes: int = Field(default=1 * 1024 * 1024, gt=0)
    evidence_deadline_seconds: float = Field(default=60.0, gt=0, le=600)
    evidence_max_source_files: int = Field(default=200, gt=0)
    evidence_max_bytes_per_source_file: int = Field(default=5 * 1024 * 1024, gt=0)
    evidence_max_total_source_bytes: int = Field(default=25 * 1024 * 1024, gt=0)
    evidence_max_items: int = Field(default=10_000, gt=0)
    evidence_max_line_span: int = Field(default=200, gt=0)
    evidence_max_display_bytes_per_item: int = Field(default=16 * 1024, gt=0)
    evidence_max_bundle_display_bytes: int = Field(default=5 * 1024 * 1024, gt=0)
    evidence_max_redactions_per_item: int = Field(default=100, gt=0)
    evidence_max_warnings: int = Field(default=1_000, gt=0)
    context_deadline_seconds: float = Field(default=120.0, gt=0, le=600)
    context_max_directories: int = Field(default=5_000, gt=0)
    context_max_candidate_paths: int = Field(default=10_000, gt=0)
    context_max_directory_depth: int = Field(default=64, gt=0, le=64)
    context_max_path_bytes: int = Field(default=4_096, gt=0, le=4_096)
    context_max_source_files: int = Field(default=2_000, gt=0)
    context_max_bytes_per_source_file: int = Field(default=2 * 1024 * 1024, gt=0)
    context_max_total_source_bytes: int = Field(default=50 * 1024 * 1024, gt=0)
    context_max_tokens_per_file: int = Field(default=100_000, gt=0)
    context_max_total_tokens: int = Field(default=1_000_000, gt=0)
    context_max_nesting_depth: int = Field(default=256, gt=0, le=256)
    context_max_observations: int = Field(default=50_000, gt=0)
    context_max_graph_nodes: int = Field(default=50_000, gt=0)
    context_max_graph_edges: int = Field(default=100_000, gt=0)
    context_max_evidence_items: int = Field(default=10_000, gt=0)
    context_max_line_span: int = Field(default=100, gt=0, le=100)
    context_max_display_bytes_per_item: int = Field(default=16 * 1024, gt=0)
    context_max_bundle_display_bytes: int = Field(default=5 * 1024 * 1024, gt=0)
    context_max_redactions_per_item: int = Field(default=100, gt=0)
    context_max_warnings: int = Field(default=1_000, gt=0)
    investigation_enabled: bool = False
    investigation_loopback_host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    investigation_loopback_port: int = Field(default=11434, ge=1, le=65535)
    investigation_model: str | None = Field(default=None, min_length=1, max_length=256)
    investigation_deadline_seconds: float = Field(default=60.0, gt=0, le=600)
    investigation_max_concurrent_requests: int = Field(default=1, ge=1, le=1)
    investigation_max_input_bytes: int = Field(default=256 * 1024, gt=0, le=1024 * 1024)
    investigation_max_output_bytes: int = Field(default=64 * 1024, gt=0, le=256 * 1024)
    investigation_max_evidence_items: int = Field(default=256, gt=0, le=1_000)
    investigation_max_claims: int = Field(default=64, gt=0, le=256)
    investigation_max_evidence_links_per_claim: int = Field(default=32, gt=0, le=128)
    investigation_max_assumptions: int = Field(default=32, gt=0, le=128)
    investigation_max_missing_evidence_codes: int = Field(default=64, gt=0, le=256)
    investigation_max_validation_actions: int = Field(default=32, gt=0, le=128)
    investigation_max_rationale_bytes_per_claim: int = Field(default=2_048, gt=0, le=8_192)
    investigation_max_output_tokens: int = Field(default=4_096, gt=0, le=16_384)
    workflow_max_concurrent_requests: int = Field(default=1, ge=1, le=1)
    workflow_deadline_seconds: float = Field(default=180.0, gt=0, le=600)
    workflow_max_advisory_identifier_bytes: int = Field(default=128, gt=0, le=128)
    workflow_max_repository_url_bytes: int = Field(default=2_048, gt=0, le=2_048)
    workflow_max_repository_ref_bytes: int = Field(default=255, gt=0, le=255)
    workflow_max_report_json_bytes: int = Field(default=1_048_576, gt=0, le=1_048_576)
    workflow_max_markdown_bytes: int = Field(default=1_048_576, gt=0, le=1_048_576)
    workflow_max_report_entries: int = Field(default=1_024, gt=0, le=1_024)
    workflow_max_evidence_references: int = Field(default=2_048, gt=0, le=2_048)
    workflow_max_report_diagnostics: int = Field(default=512, gt=0, le=512)
    local_interfaces_enabled: bool = False
    local_interfaces_host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    local_interfaces_port: int = Field(default=8765, ge=1, le=65535)
    local_interfaces_max_request_bytes: int = Field(default=8_192, gt=0, le=8_192)
    local_interfaces_max_static_asset_bytes: int = Field(default=256 * 1024, gt=0, le=256 * 1024)

    @field_validator("osv_scanner_path")
    @classmethod
    def validate_scanner_path(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("OSV-Scanner path must be absolute")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
