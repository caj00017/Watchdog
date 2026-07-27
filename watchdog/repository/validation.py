import re
from urllib.parse import urlsplit

from watchdog.domain.repositories import GitHubRepository
from watchdog.repository.errors import InvalidRepositoryUrlError

_OWNER_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,100}")


def parse_github_repository_url(raw_url: str) -> GitHubRepository:
    try:
        parsed = urlsplit(raw_url)
        port = parsed.port
    except ValueError as exc:
        raise InvalidRepositoryUrlError from exc

    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or "%" in parsed.path
    ):
        raise InvalidRepositoryUrlError

    path = parsed.path[:-1] if parsed.path.endswith("/") else parsed.path
    parts = path.split("/")
    if len(parts) != 3 or parts[0] or not parts[1] or not parts[2]:
        raise InvalidRepositoryUrlError

    owner, name = parts[1], parts[2]
    if name.lower().endswith(".git"):
        name = name[:-4]
    if (
        not _OWNER_PATTERN.fullmatch(owner)
        or "--" in owner
        or not _REPOSITORY_PATTERN.fullmatch(name)
        or name in {".", ".."}
    ):
        raise InvalidRepositoryUrlError

    return GitHubRepository(
        owner=owner,
        name=name,
        canonical_url=f"https://github.com/{owner}/{name}",
    )
