# Release 1 Hardening Implementation Plan

**Status:** Completed August 2, 2026; publication not performed

**Immutable Phase 9 baseline:**
`97f2a057c23fc23fb4ef678703691e5aa54bee76`

**Governing boundary:** `../work-orders/release-1-hardening.md`

## Baseline result

Before release-hardening changes, the exact baseline was clean, matched
`origin/main`, descended from the Phase 8 freeze, and passed:

- Ruff formatting and linting: 195 files checked;
- strict mypy: 177 source files checked;
- deterministic pytest: 362 passed, one opt-in live OSV contract skipped;
- compileall for `apps`, `watchdog`, and `tests`; and
- Docker Compose configuration validation.

No final tag or release artifact existed. The baseline had no dependency lock,
CI workflow, license, changelog/release process, vulnerability disclosure
policy, or package-publication workflow.

## Implementation sequence

1. Record the release boundary and immutable baseline before implementation.
2. Add Apache-2.0 licensing, contribution/governance/security policies,
   ownership, changelog, and an operator release checklist.
3. Complete package metadata without changing the package name, version,
   console entry point, supported runtime, dependencies, or included assets.
4. Generate exact hash-checked runtime, development, and release lock files in
   a clean Python 3.12 environment. Install them with hash enforcement and
   compare the runtime direct dependencies to `pyproject.toml`.
5. Add a repository-local release verifier and regression tests covering
   version/tag agreement, lock structure, workflow action pins and permissions,
   package file inclusion, and immutable scanner/container constraints.
6. Add least-privilege CI for Python 3.12, 3.13, and 3.14 plus package and
   container jobs. Keep pull-request jobs credential-free and avoid
   `pull_request_target`.
7. Add a separate final-tag publication workflow. Build once; pass the same
   artifacts through validation and a protected PyPI Trusted Publishing job.
8. Run all deterministic baseline gates after changes.
9. Build `v0.1.0-rc1` artifacts locally from the reviewed tree, inspect their
   contents and metadata, install them in clean environments, and record
   SHA-256 checksums.
10. Build and exercise the standalone candidate container, verify exact
    OSV-Scanner 2.4.0, and retain explicit environment/network limitations.
11. Reconcile README, documentation index, architecture, threat model, AGENTS,
    canonical project record, TODO, and a dated release-hardening recap.

All eleven steps completed. The package reproducibility gate initially exposed
source-distribution timestamps and ownership metadata that varied between
builds. A bounded fail-closed normalizer and regression tests now canonicalize
those fields, and two independent clean Python 3.12 builds compare byte for
byte for both the wheel and source distribution. The exact candidate evidence
is retained in `../release/v0.1.0-rc1-validation.md`.

## Fixed implementation choices

- Release version remains `0.1.0`; candidate naming belongs to artifact/record
  metadata and does not change canonical application output.
- Supported Python versions are 3.12, 3.13, and 3.14.
- Runtime dependencies and the `watchdog` command surface remain unchanged.
- Lock files use pip-compatible requirements syntax with exact versions and
  SHA-256 hashes.
- CI runs on GitHub-hosted Ubuntu runners with repository contents read-only.
- Third-party actions use full commit SHAs with a review comment naming the
  corresponding release.
- Final publication uses PyPI Trusted Publishing and a protected `pypi`
  environment; no API token is stored in the repository or workflow.
- Workflow-dispatch builds are candidate-only. Publication occurs only for an
  exact stable SemVer tag that matches package metadata.
- The local candidate is not pushed, tagged, uploaded, or published by this
  implementation plan.

## Required verification

- clean-diff and whitespace checks;
- Ruff format/lint, strict mypy, compileall, and deterministic pytest;
- exact runtime-direct-dependency agreement and hash enforcement;
- clean installs from the development and release locks;
- sdist and wheel metadata/content inspection;
- `twine check` or an equivalent standards check;
- clean wheel and sdist installation with `watchdog --help` and controlled
  `watchdog doctor` behavior;
- deterministic rebuild comparison where archive formats permit it, with any
  non-reproducible bytes explained rather than ignored;
- Compose validation, standalone container build, scanner version check,
  no-mount health check, and product-runtime destination regression; and
- static inspection proving CI and publication permission separation.

## Pause conditions

Pause and obtain separate authority before changing application behavior,
adding a runtime dependency/destination, weakening a Phase 1–9 invariant,
publishing or yanking a package, pushing a release tag, changing remote GitHub
or PyPI settings, or starting TUI implementation.
