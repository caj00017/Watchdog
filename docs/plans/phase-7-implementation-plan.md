# Phase 7 Formal Implementation Plan — Evidence-Safe Reporting and Local Interfaces

**Status:** Complete; all staged packages and acceptance gates passed

**Authorized:** July 29, 2026

**Completed:** July 29, 2026

**Baseline:** `02abea580723461e0a8b02a07a93cc5438d9a63b`

**Governing boundary:** `../work-orders/phase-7-reporting-and-local-interfaces.md`

## Outcome and invariant

Phase 7 adds a strict canonical report and deterministic summary/technical JSON
and escaped-Markdown projections, one lease-safe synchronous workflow, a direct
stdout-only CLI, and a separate disabled literal-loopback application. It
consumes revalidated Phase 1–6 artifacts without changing their identities or
meaning and introduces no new analysis phase.

Every Phase 2–5 repository operation remains inside the existing lease. Cleanup
must be verified before Phase 6 or report assembly. Reports distinguish target
metadata, deterministic facts, model inference, assumptions, gaps, limitations,
and controlled validation actions and never assert affected/not-affected status,
runtime reachability, exploitability, deployment exposure, or remediation.

## Completed packages

1. Froze the `02abea5` Phase 6 baseline and Phase 7 request, report, status, and
   wording vocabularies.
2. Added frozen extra-forbidden report/configuration models, canonical report
   IDs, same-advisory/same-snapshot validation, deterministic selection, and
   exact Phase 6 envelope/result linkage.
3. Added bounded JSON and hostile-text-safe Markdown renderers that buffer and
   size-check all bytes before emission.
4. Added the shared-deadline workflow with preflight input validation, fixed
   Phase 1 → lease-scoped Phase 2–5 → cleanup → Phase 6 → report ordering, and
   awaited cancellation cleanup. Interface calls keep the same admission slot
   and deadline through fully buffered rendering.
5. Added `python -m apps.cli investigate` with strict arguments, report-only
   stdout, controlled stderr, and distinct complete/incomplete/failure exits.
6. Added the separate `python -m apps.web` launcher, disabled-by-default literal
   loopback configuration, exact Host/origin/custom-header controls, five fixed
   routes, generic errors, security headers, and no access logging.
7. Added dependency-free checked-in UI assets using same-origin requests and
   text-only variable sinks with no browser persistence or external assets.
8. Added report, workflow, CLI, local HTTP, UI, hostile-rendering, identity,
   cleanup, and regression tests and synchronized governing documentation.

## Verification gates

- 280 deterministic tests pass; the bounded live scanner contract remains
  explicitly opt-in.
- Ruff format/check, strict mypy across 152 files, and compileall pass.
- Existing advisory routes, OSV-Scanner 2.4.0 pin and generated-coordinate
  contract, Phase 4–6 identities, dependencies, and default container command
  remain unchanged.
- The local application has no import-time listener, OpenAPI/docs, CORS, cookies,
  persistence, remote assets, arbitrary static paths, or new outbound target.

## Mandatory escalation

Pause for a new reviewed work order before remote or non-loopback binding,
reverse proxy/container publication, authentication, private repositories,
persistence/jobs/history, remote model providers or credentials, new inputs or
dependencies, affected/not-affected or reachability/exposure classification,
remediation, executable commands, code generation, or patch behavior.
