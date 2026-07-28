"""Lease-scoped, bounded repository evidence collection."""

from typing import Any

from watchdog.evidence.limits import EvidenceConfiguration, EvidenceLimits

__all__ = ["EvidenceConfiguration", "EvidenceLimits", "EvidenceService"]


def __getattr__(name: str) -> Any:
    if name == "EvidenceService":
        from watchdog.evidence.service import EvidenceService

        return EvidenceService
    raise AttributeError(name)
