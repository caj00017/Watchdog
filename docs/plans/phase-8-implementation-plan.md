# Phase 8 Formal Implementation Plan — Evidence-Bound Remediation Assistant

**Status:** Complete; all sequential implementation and release gates passed

**Authorized:** July 29, 2026

**Baseline:** `60079274ea4ea9784391b3b34712fd3b3d8ad519`

**Planning commit:** `8d5df91f672a2dfe027169da40c6abc9faa9909f`

**Governing boundary:** `../work-orders/phase-8-remediation-assistant.md`

## Baseline and authority gate

The planning commit was verified to descend from the immutable Phase 7 baseline.
Its complete post-baseline delta modifies documentation only. The user separately
authorized this staged implementation on July 29, 2026. Runtime work may proceed
only inside the work-order boundary.

Phase 1–7 canonical artifacts, source eligibility, scanner behavior and the
OSV-Scanner 2.4.0 pin remain frozen. Phase 8 is additive, internal, disabled by
default, synchronous, non-persistent, non-executing, and non-writing.

## Frozen versions and wording

- remediation schema, producer, candidate policy, configuration and wording: `1`
- preview locator, semantic-reparse and redaction policies: `1`
- JSON and Markdown renderer versions: `1`
- fixed statement: no change was applied; availability, compatibility,
  deployment applicability, generated artifacts, testing, and remediation
  completeness remain unverified
- statuses: `unavailable`, `manual_review_required`, `candidates_available`,
  `previews_available`

The artifact cannot express affected/not-affected status, compatibility, safety,
runtime or data-flow reachability, exploitability, deployment exposure, or
remediation success.

## Sequential implementation gates

1. Freeze strict extra-forbidden contracts, typed canonical identities, bounded
   settings, controlled wording, and Phase 1–7 regression fixtures.
2. Derive candidates only from provenance-complete fixed-version facts for an
   eligible exact affected match with Phase 4 evidence. Preserve conditional,
   conflict, ambiguity and overflow limitations.
3. Add fail-closed PyPI, npm SemVer 2.0.0 and Go module comparators. Select only
   one distinct supported strictly-greater target for an unconditional,
   conflict-free match.
4. Add the optional lease-scoped descriptor reader and versioned locators for
   unambiguous direct exact declarations in requirements files, PEP 621,
   package.json through the approved same-root lockfile bridge, and go.mod.
   Verify digest, file identity, byte boundaries, single-token replacement,
   semantic reparse, redaction and workspace invariance without writing bytes.
5. Assemble the canonical plan only after verified cleanup and render fully
   buffered bounded JSON and escaped Markdown projections.
6. Extract one private Phase 7 workflow core and add an optional trusted lease
   hook. Keep the existing investigation workflow and bytes unchanged. Add a
   separately admitted remediation workflow that rejects disabled use before
   advisory, network or lease activity.
7. Add the stdout-only `remediate` CLI and register the local remediation route
   and checked-in UI variant only when both local interfaces and remediation are
   enabled.
8. Synchronize architecture, threat model, evidence and operator policy,
   canonical records, indexes, AGENTS instructions and a dated completion recap.
9. Run formatting, Ruff, strict mypy, compileall, all deterministic tests,
   Compose and package-asset validation, standalone container build and health,
   public-route regression, scanner pin and local/no-network security checks.

No later package waives an earlier gate. Preview support for one manifest format
does not waive another format's security and semantic fixtures.

## Absolute ceilings

The defaults and hard maxima are those in the governing work order: remediation
and preview are independently disabled; one concurrent workflow; 180/600 second
deadline; 64/256 candidates; 16/64 versions per match; 16/64 source files;
5 MiB per source file; 20/25 MiB total source bytes; 16/64 previews; exactly one
changed token; 16/64 KiB per diff; 256 KiB/1 MiB total display; 128/512 warnings;
32/64 validation actions; and 1 MiB JSON or Markdown. The smaller Phase 3, 4 or
8 limit always controls.

## Permanent escalation boundary

A new work order and explicit approval are required for repository writes or
apply behavior; commands; generated lock/checksum changes; multi-token,
multi-file or source-code previews; model-selected versions or instructions;
registry/release queries; dependency resolution or installation; repository,
package-manager, build or test execution; compatibility, availability,
affectedness, reachability, exposure or remediation-success claims; remote or
private inputs; credentials; persistence, jobs or history; authentication;
telemetry; new dependencies, parsers, executables, sources or egress; or any
Phase 1–7 identity/default behavior change.

## Completion result

All nine gates completed on July 29, 2026. The deterministic suite passes 339
tests with the separately enabled live OSV scanner contract skipped by default;
format, Ruff, strict mypy, compileall, Compose, package assets, standalone image,
no-mount/no-network health, public-route regression, scanner 2.4.0, and literal-
loopback checks all pass. The exact environment-dependent evidence is preserved
in `../archive/recaps/development-recap-2026-07-29-phase-8.md`.
