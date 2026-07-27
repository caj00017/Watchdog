from pydantic import BaseModel, ConfigDict, Field

from watchdog.config.settings import Settings


class InventoryLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    deadline_seconds: float = Field(gt=0)
    max_manifest_files: int = Field(gt=0)
    max_bytes_per_manifest: int = Field(gt=0)
    max_total_parsed_bytes: int = Field(gt=0)
    max_components: int = Field(gt=0)
    max_edges: int = Field(gt=0)
    max_parser_nesting_depth: int = Field(gt=0)
    max_requirements_include_depth: int = Field(ge=0)
    max_warnings: int = Field(gt=0)

    @classmethod
    def from_settings(cls, settings: Settings) -> "InventoryLimits":
        return cls(
            deadline_seconds=settings.inventory_deadline_seconds,
            max_manifest_files=settings.inventory_max_manifest_files,
            max_bytes_per_manifest=settings.inventory_max_bytes_per_manifest,
            max_total_parsed_bytes=settings.inventory_max_total_parsed_bytes,
            max_components=settings.inventory_max_components,
            max_edges=settings.inventory_max_edges,
            max_parser_nesting_depth=settings.inventory_max_parser_nesting_depth,
            max_requirements_include_depth=settings.inventory_max_requirements_include_depth,
            max_warnings=settings.inventory_max_warnings,
        )
