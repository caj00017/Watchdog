class WatchdogError(Exception):
    """Base class for expected service failures safe to expose to clients."""

    code = "watchdog_error"


class InvalidIdentifierError(WatchdogError):
    code = "invalid_identifier"

    def __init__(self, identifier: str) -> None:
        super().__init__(
            f"Unsupported or malformed advisory identifier: {identifier!r}. "
            "Expected a CVE, GHSA, or OSV database identifier."
        )


class AdvisoryNotFoundError(WatchdogError):
    code = "advisory_not_found"

    def __init__(self, identifier: str) -> None:
        super().__init__(f"No advisory record was found for {identifier!r}.")


class SourceUnavailableError(WatchdogError):
    code = "source_unavailable"

    def __init__(self, source: str, detail: str = "temporarily unavailable") -> None:
        super().__init__(f"The {source} vulnerability source is {detail}.")


class MalformedSourceResponseError(WatchdogError):
    code = "malformed_source_response"

    def __init__(self, source: str, detail: str) -> None:
        super().__init__(f"The {source} vulnerability source returned malformed data: {detail}.")


class PartialResultError(WatchdogError):
    code = "partial_result"

    def __init__(self, detail: str) -> None:
        super().__init__(f"Only a partial advisory result is available: {detail}.")
