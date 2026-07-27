from __future__ import annotations

from typing import Protocol

from watchdog.domain.matching import ExactPackageCoordinate, ScannerRunResult


class VulnerabilityScanner(Protocol):
    async def scan(self, coordinates: tuple[ExactPackageCoordinate, ...]) -> ScannerRunResult: ...
