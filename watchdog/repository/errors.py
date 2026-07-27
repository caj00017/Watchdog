from watchdog.domain.errors import WatchdogError
from watchdog.domain.repositories import CleanupResult


class RepositoryIntakeError(WatchdogError):
    code = "repository_intake_error"


class InvalidRepositoryUrlError(RepositoryIntakeError):
    code = "invalid_repository_url"

    def __init__(self) -> None:
        super().__init__("Expected a public HTTPS GitHub repository URL without extra components.")


class InvalidRepositoryRefError(RepositoryIntakeError):
    code = "invalid_repository_ref"

    def __init__(self) -> None:
        super().__init__("The repository ref is malformed or unsupported.")


class RepositoryNotFoundError(RepositoryIntakeError):
    code = "repository_not_found"

    def __init__(self) -> None:
        super().__init__("The repository or ref was not found or is not publicly accessible.")


class RepositorySourceUnavailableError(RepositoryIntakeError):
    code = "repository_source_unavailable"

    def __init__(self, detail: str = "temporarily unavailable") -> None:
        super().__init__(f"The GitHub repository source is {detail}.")


class MalformedRepositorySourceError(RepositoryIntakeError):
    code = "malformed_repository_source"

    def __init__(self, detail: str) -> None:
        super().__init__(f"GitHub returned malformed repository data: {detail}.")


class UnsafeRepositoryArchiveError(RepositoryIntakeError):
    code = "unsafe_repository_archive"

    def __init__(self, detail: str) -> None:
        super().__init__(f"The repository archive was rejected: {detail}.")


class EmptyRepositoryError(RepositoryIntakeError):
    code = "empty_repository"

    def __init__(self) -> None:
        super().__init__("The repository archive contains no files or safe symlinks.")


class RepositoryLimitExceededError(RepositoryIntakeError):
    code = "repository_limit_exceeded"

    def __init__(self, limit_name: str, limit: int, observed: int) -> None:
        self.limit_name = limit_name
        self.limit = limit
        self.observed = observed
        super().__init__(
            f"Repository {limit_name} limit exceeded (limit {limit}, observed at least {observed})."
        )


class RepositoryIntakeTimeoutError(RepositoryIntakeError):
    code = "repository_intake_timeout"

    def __init__(self) -> None:
        super().__init__("Repository intake exceeded its configured duration limit.")


class RepositoryCleanupError(RepositoryIntakeError):
    code = "repository_cleanup_failed"

    def __init__(self, result: CleanupResult) -> None:
        self.result = result
        super().__init__("The disposable repository workspace could not be fully removed.")
