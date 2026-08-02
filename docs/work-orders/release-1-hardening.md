# Release 1 Work Order — Local-First v0.1.0 Hardening

**Status:** Completed August 2, 2026; final publication pending human approval

**Authorized baseline:** `97f2a057c23fc23fb4ef678703691e5aa54bee76`

**Release target:** `v0.1.0`

**Authority:** On August 2, 2026, after reviewing the Phase 9 closeout and the
remaining release gaps, the user authorized proceeding with each described
pre-release item: a release-hardening work order, governance, dependency
locking, CI, release checks and documentation, release-candidate production and
validation, and a reproducible tag/package workflow. This authority does not
authorize publishing a final package, pushing a tag, changing remote repository
settings, or introducing the separately proposed TUI. Those remain explicit
human release or follow-on design decisions.

## Objective

Turn the completed Phase 0–9 local-first implementation into a reviewable,
reproducible release candidate without changing Watchdog's analytical behavior,
runtime destinations, trust boundaries, defaults, or canonical artifacts.

Release one remains a local application. Model synthesis remains disabled by
default and limited to the existing credential-free, operator-managed literal-
loopback adapter. The browser interface, CLI, reports, remediation plans,
scanner boundary, and no-write guarantees remain unchanged.

## Authorized changes

This work order permits only:

- repository governance and contribution documentation;
- an explicit project license and package metadata for the existing owner,
  repository, Python support policy, and `v0.1.0` release;
- a changelog, vulnerability-disclosure policy, and release process;
- exact, hash-checked runtime, development, and release dependency locks
  derived from the reviewed `pyproject.toml`;
- trusted-project build tooling and checked-in verification scripts;
- GitHub CI that runs the existing deterministic quality gates on isolated
  hosted runners without secrets or elevated permissions;
- a release workflow that builds and validates artifacts first, retains them as
  workflow artifacts, and permits final PyPI publication only from an exact
  stable-version tag through a separately approved protected environment and
  PyPI Trusted Publishing;
- a standalone container release-candidate build from the final reviewed
  commit, retaining the exact OSV-Scanner 2.4.0 digest pin; and
- release-candidate verification records, checksums, and documentation.

No new runtime dependency is authorized. Build, test, lock-generation, and
publication tools are release-only dependencies and may not become application
imports or runtime destinations.

## Trust and CI boundary

Release automation acts on the trusted Watchdog source tree. It must never
clone, execute, build, resolve, or install code or dependencies from a repository
being analyzed by Watchdog.

Pull-request CI must use ephemeral hosted runners, read-only repository
permission, no secrets, no OIDC token, and no `pull_request_target` trigger.
Every third-party action must be pinned to a full reviewed commit SHA. A
pull-request author can change project source and tests, so PR jobs are treated
as untrusted code execution and receive no release authority.

Release publication must be isolated in a job that:

1. consumes only artifacts produced by the preceding trusted-tag build;
2. checks that the tag exactly equals the package version prefixed with `v`;
3. uses a protected GitHub environment requiring human approval;
4. receives only `id-token: write` and no long-lived package credential; and
5. publishes through PyPI Trusted Publishing without rebuilding the artifacts.

The workflow may contact GitHub's action/artifact services and PyPI only for
dependency acquisition, runner setup, artifact retention, and an explicitly
approved final publication. These are release-system destinations, not new
Watchdog runtime destinations.

## Dependency and build policy

- `pyproject.toml` remains the human-reviewed direct dependency policy.
- Checked-in lock files pin the complete transitive environments and require
  package hashes.
- Runtime dependencies remain unchanged from the Phase 9 baseline.
- Lock regeneration uses a documented exact tool version in a clean Python 3.12
  environment and requires review of every changed package and hash.
- CI and release builds install locked dependencies with `--require-hashes` and
  install Watchdog itself with `--no-deps` and `--no-build-isolation`.
- The source distribution and wheel are built once, checked, inspected, and
  installed into clean environments before they may be considered candidates.
- Candidate checksums identify exact local artifacts; a commit hash or mutable
  image tag is never presented as an artifact checksum.

## Governance policy

The release requires documented ownership, review expectations, versioning,
support scope, vulnerability reporting, and rollback/yank decisions. Security-
boundary changes continue to require a separate work order, tests, architecture
and threat-model updates, and human review. Generated remediation patches remain
previews and cannot be applied by release automation.

The release license is Apache-2.0 unless the owner changes that legal decision
before final publication. The security policy must not invent or expose a new
contact address; it uses GitHub private vulnerability reporting and forbids
public disclosure of sensitive details.

## Sequential acceptance gates

1. **Baseline:** verify the exact Phase 9 commit, clean tree, ancestry, and all
   documented deterministic checks before changes.
2. **Governance:** add license, governance, contribution, security, changelog,
   ownership, and release-process artifacts.
3. **Locking:** produce reviewed hash-checked runtime, development, and release
   locks without changing runtime dependency intent.
4. **CI:** add least-privilege, SHA-pinned workflows for supported Python
   versions, package validation, and container validation.
5. **Release contract:** add deterministic checks for version agreement,
   lock-file structure, workflow permissions/action pins, package contents, and
   tag/version agreement.
6. **Regression:** pass format, lint, strict type checking, compilation, the
   complete deterministic suite, Compose validation, and immutable Phase 1–9
   identity/behavior regressions.
7. **Package candidate:** build the sdist and wheel once, inspect contents and
   metadata, run package checks, install each artifact in a clean environment,
   and exercise fixed offline-safe launcher behavior.
8. **Container candidate:** rebuild from the reviewed hardening commit, verify
   the embedded scanner is exactly 2.4.0, run the no-mount health check, and
   record the image ID, digest where available, and limitations.
9. **Release-candidate record:** record exact commit, artifact names, SHA-256
   checksums, verification results, skipped live/network checks, and remaining
   human setup or publication gates.

No failed, skipped, unavailable, or unperformed gate may be represented as
passing. The opt-in live OSV scanner contract remains separate and a failure is
incomplete validation, never a negative vulnerability result.

## Final publication gate

Creating or pushing `v0.1.0`, approving the protected publication environment,
configuring PyPI Trusted Publishing, publishing artifacts, creating a GitHub
release, or changing repository settings are external release actions. They
must use the already validated candidate and require a final human go/no-go
decision after this work order is complete.

## Explicitly out of scope

- Any Phase 1–9 behavior, schema, identity, prompt, parser, scanner, evidence,
  route, setting default, egress destination, or trust-boundary change.
- Hosted/non-loopback operation, authentication, credentials, private
  repositories, persistence, telemetry, jobs/history, uploads, registry queries
  by the application, repository writes, commands, apply behavior, or new
  runtime dependencies.
- A production/container-hosted service or a claim that the development Compose
  service is production hardened.
- TUI selection or implementation. Replacing or supplementing the browser UI
  requires a separate design and boundary review after release hardening.
- The version-two AWS/DeepSeek direction.

## Completion definition

This work order is complete when gates 1–9 pass against one reviewed commit and
the resulting local candidate can be reproduced by the checked-in process. It
does not become a published release until the final external publication gate is
separately approved and exercised.

## Completion result

All nine pre-release gates completed on August 2, 2026. The final candidate
record identifies the reviewed implementation commit, byte-reproducible package
artifacts, container identity, checksums, verification coverage, and explicit
limitations. The stable tag, remote release controls, PyPI publication, and
GitHub release remain unperformed human actions under the final publication
gate.
