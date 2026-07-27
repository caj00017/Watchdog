"""Source-neutral domain models."""

from watchdog.domain.advisories import AdvisoryRecord
from watchdog.domain.identifiers import AdvisoryIdentifier, parse_advisory_identifier

__all__ = ["AdvisoryIdentifier", "AdvisoryRecord", "parse_advisory_identifier"]
