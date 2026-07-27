from watchdog.domain.advisories import AdvisoryRecord
from watchdog.domain.identifiers import parse_advisory_identifier
from watchdog.vulnerability_sources.base import AdvisorySource


class AdvisoryService:
    def __init__(self, source: AdvisorySource) -> None:
        self._source = source

    async def resolve(self, raw_identifier: str) -> AdvisoryRecord:
        identifier = parse_advisory_identifier(raw_identifier)
        return await self._source.get_advisory(identifier)
