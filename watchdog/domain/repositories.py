from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

NonEmptyString = Annotated[str, StringConstraints(min_length=1)]
CommitSha = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
DigestSha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class RepositoryModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class GitHubRepository(RepositoryModel):
    owner: NonEmptyString
    name: NonEmptyString
    canonical_url: NonEmptyString


class RepositoryRequest(RepositoryModel):
    repository_url: NonEmptyString
    ref: str | None = None

    @field_validator("ref")
    @classmethod
    def validate_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value != value.strip() or not value or len(value) > 255:
            raise ValueError(
                "repository ref must be 1-255 characters without surrounding whitespace"
            )
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("repository ref must not contain control characters")
        return value


class ResolvedRepository(RepositoryModel):
    repository: GitHubRepository
    requested_ref: str | None
    resolved_ref: NonEmptyString
    commit_sha: CommitSha
    tree_sha: CommitSha


class RepositorySnapshot(RepositoryModel):
    repository: GitHubRepository
    requested_ref: str | None
    resolved_ref: NonEmptyString
    commit_sha: CommitSha
    tree_sha: CommitSha
    retrieved_at: datetime
    archive_sha256: DigestSha256
    archive_bytes: int = Field(ge=0)
    extracted_bytes: int = Field(ge=0)
    file_count: int = Field(ge=0)
    symlink_count: int = Field(ge=0)


class AcquiredRepository(RepositoryModel):
    root: Path
    snapshot: RepositorySnapshot


class CleanupResult(RepositoryModel):
    status: Literal["verified", "failed"]
    started_at: datetime
    completed_at: datetime
    archive_removed: bool
    workspace_removed: bool
    verified: bool
