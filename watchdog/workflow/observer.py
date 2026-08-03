from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum


class WorkflowStage(StrEnum):
    """Data-free, controlled progress stages for trusted local projections."""

    ADVISORY_RESOLUTION = "advisory_resolution"
    SNAPSHOT_ACQUISITION = "snapshot_acquisition"
    INVENTORY = "inventory"
    COORDINATE_MATCHING = "coordinate_matching"
    EVIDENCE = "evidence"
    CONTEXT = "context"
    CANDIDATE_DERIVATION = "candidate_derivation"
    PREVIEW_COLLECTION = "preview_collection"
    CLEANUP_VERIFICATION = "cleanup_verification"
    INVESTIGATION = "investigation"
    OUTPUT_ASSEMBLY = "output_assembly"


WorkflowObserver = Callable[[WorkflowStage], None]
