import pytest
from pydantic import ValidationError

from watchdog.domain.repositories import RepositoryRequest
from watchdog.repository.errors import InvalidRepositoryUrlError
from watchdog.repository.validation import parse_github_repository_url


@pytest.mark.parametrize(
    ("raw_url", "canonical"),
    [
        ("https://github.com/octocat/Hello-World", "https://github.com/octocat/Hello-World"),
        ("https://github.com/octocat/Hello-World/", "https://github.com/octocat/Hello-World"),
        ("https://github.com/octocat/Hello-World.git", "https://github.com/octocat/Hello-World"),
    ],
)
def test_parse_public_github_repository_url(raw_url: str, canonical: str) -> None:
    result = parse_github_repository_url(raw_url)

    assert result.owner == "octocat"
    assert result.name == "Hello-World"
    assert result.canonical_url == canonical


@pytest.mark.parametrize(
    "raw_url",
    [
        "http://github.com/owner/repo",
        "https://gitlab.com/owner/repo",
        "https://user@github.com/owner/repo",
        "https://github.com:443/owner/repo",
        "https://github.com/owner/repo/issues",
        "https://github.com/owner/repo?tab=readme",
        "https://github.com/owner/repo#readme",
        "https://github.com/owner%2Frepo",
        "git@github.com:owner/repo.git",
        "https://github.com/-owner/repo",
        "https://github.com/owner--name/repo",
        "https://github.com/owner/..",
    ],
)
def test_reject_noncanonical_or_unsafe_repository_url(raw_url: str) -> None:
    with pytest.raises(InvalidRepositoryUrlError):
        parse_github_repository_url(raw_url)


@pytest.mark.parametrize("ref", ["", " main", "main ", "x" * 256, "main\nnext"])
def test_repository_request_rejects_malformed_ref(ref: str) -> None:
    with pytest.raises(ValidationError):
        RepositoryRequest(repository_url="https://github.com/owner/repo", ref=ref)


def test_repository_request_accepts_branch_with_slash() -> None:
    request = RepositoryRequest(
        repository_url="https://github.com/owner/repo",
        ref="feature/safe-intake",
    )

    assert request.ref == "feature/safe-intake"
