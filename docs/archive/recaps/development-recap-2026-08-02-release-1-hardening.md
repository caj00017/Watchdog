# Development Recap — Release 1 Hardening

**Date:** August 2, 2026

**Phase 9 baseline:** `97f2a057c23fc23fb4ef678703691e5aa54bee76`

**Planning commit:** `12511ae`

## Outcome

The authorized Release 1 pre-release boundary is complete. Watchdog now has a
reviewable Apache-2.0 governance baseline, exact hash-checked dependency locks,
least-privilege CI, a separated human-gated publication workflow, strict
package/archive verification, deterministic package construction, and a
digest-pinned standalone container path. Product behavior and Phase 1–9
identities remain unchanged.

The local release candidate is not a published release. No stable tag was
created or pushed, no package was uploaded, and no GitHub or PyPI setting was
changed.

## Implemented controls

- Added `LICENSE`, `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`,
  `GOVERNANCE.md`, CODEOWNERS, a pull-request template, and a release process.
- Completed static package metadata for `nexura-watchdog` 0.1.0 without adding
  or widening a runtime dependency.
- Added Python 3.12-generated runtime, development, and release locks with exact
  versions and SHA-256 hashes.
- Added Python 3.12, 3.13, and 3.14 CI; package and container jobs; immutable
  third-party action pins; read-only default permissions; and no
  `pull_request_target`, secret, or OIDC authority in pull-request jobs.
- Added a release workflow that builds once, validates and retains the same
  artifacts, and exposes OIDC only to a protected `pypi` publication job after
  an exact stable tag.
- Added bounded checks for version agreement, lock structure, direct dependency
  coverage, workflow pins and permissions, container pins, archive paths and
  types, package contents, metadata, timestamps, ownership, and modes.
- Replaced the mutable development container build with digest-pinned Python and
  OSV-Scanner stages, hash-locked installs, no dependency resolution for the
  Watchdog wheel, and OCI release metadata.

## Reproducibility correction

The first two package builds produced identical wheels but different source
distribution bytes. Inspection showed that generated tar member timestamps and
ownership metadata varied by build. That failed the candidate gate.

A release-only, bounded normalizer now rejects unsafe archive names, duplicate
members, links and special files, oversized members, and oversized archives;
sorts members; canonicalizes timestamps, ownership, names, and modes; and
replaces the input only after successful reconstruction. Regression tests prove
deterministic output and fail-closed link handling. Two subsequent independent
clean Python 3.12 builds produced byte-identical wheel and source-distribution
artifacts and passed the strict artifact verifier.

## Verification

- Ruff formatting and linting pass for 209 files.
- Strict mypy passes for 183 source files.
- Bytecode compilation passes for applications, package, tests, and scripts.
- 374 deterministic tests pass; the one bounded live OSV scanner contract
  remains explicitly opt-in and skipped in the deterministic suite.
- The release repository contract and Docker Compose configuration pass.
- Clean hash-locked environments pass on Python 3.12, 3.13, and 3.14.
- Wheel and source-distribution metadata, archive contents, clean installs, and
  launcher smoke tests pass.
- The standalone image retains exact OSV-Scanner 2.4.0 and passes a no-mount
  local health check.

Exact final candidate checksums, image identity and size, implementation commit,
and environment limitations are recorded in
`../../release/v0.1.0-rc1-validation.md`.

## Remaining human gates

- Review and configure branch protection, required checks, CODEOWNERS review,
  GitHub private vulnerability reporting, and the protected `pypi` environment.
- Configure PyPI Trusted Publishing for the exact repository, workflow, and
  environment.
- Make the final go/no-go decision, create and push `v0.1.0`, approve the
  publication job, verify published checksums, and create the GitHub release.
- Decide the TUI direction under a separate design and security-boundary review.

Hosted operation, remote model providers, authentication, persistence,
telemetry, private repositories, runtime dependency changes, repository writes,
commands, and patch application remain out of scope.
