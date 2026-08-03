# Nexura Watchdog Documentation

This directory is tracked with the repository so architecture, security policy,
work orders, and implementation status remain versioned with the code they
describe.

## Canonical record

- [Project Design and Implementation Record](Nexura_Watchdog_Project_Design_and_Implementation_Record.md)
  is the single source of truth for current status, implemented behavior,
  boundaries, decisions, roadmap, and immediate milestone.

## Supporting detail

- [Technical README reference](reference/README-technical.md) preserves the
  complete configuration, API, container, internal-service, security, and
  verification documentation that supports the newcomer-focused root README.
- [Architecture](architecture/architecture.md) describes current runtime flows
  and module boundaries.
- [Threat model](security/threat-model.md) describes active trust boundaries,
  controls, and residual risks.
- [Evidence policy](security/evidence-policy.md) defines provenance, conflicts,
  failures, acquisition metadata, the completed Phase 4 evidence contract, and
  completed Phase 5 context evidence, Phase 6 inference/evidence separation, and
  the Phase 7 report/export policy plus Phase 8 remediation support/preview
  evidence boundary.

## Completed work orders

- [Phase 4 evidence engine](work-orders/phase-4-evidence-engine.md) is the
  reviewed implementation boundary and acceptance contract completed on July
  28, 2026.
- [Phase 5 deterministic contextual analysis](work-orders/phase-5-contextual-analysis.md)
  is the completed internal lexical-context security boundary and acceptance
  contract.
- [Phase 5 formal implementation plan](plans/phase-5-implementation-plan.md)
  records the completed sequential work packages, gates, tests, risks, and
  mandatory pause conditions.

## Completed Phase 6 boundary

- [Phase 6 evidence-bound model investigation](work-orders/phase-6-evidence-bound-model-investigation.md)
  is the completed internal, strictly validated model-synthesis boundary.
- [Phase 6 formal implementation plan](plans/phase-6-implementation-plan.md)
  records its staged gates, tests, and mandatory escalation conditions.

## Completed Phase 7 boundary

- [Phase 7 evidence-safe reporting and local interfaces](work-orders/phase-7-reporting-and-local-interfaces.md)
  is the completed canonical report, workflow, CLI, and disabled literal-
  loopback interface boundary.
- [Phase 7 formal implementation plan](plans/phase-7-implementation-plan.md)
  records the immutable Phase 6 baseline, completed packages, verification, and
  mandatory escalation conditions.

## Completed Phase 8 boundary

- [Phase 8 evidence-bound remediation assistant](work-orders/phase-8-remediation-assistant.md)
  is the completed source-reported candidate, controlled validation-action,
  single-token in-memory preview, and no-write/human-approval boundary.
- [Phase 8 formal implementation plan](plans/phase-8-implementation-plan.md)
  records the immutable Phase 7 baseline, staged gates, limits, tests, and
  permanent escalation conditions.

## Completed Phase 9 boundary

- [Phase 9 local-first guided experience](work-orders/phase-9-local-first-guided-experience.md)
  is the completed launcher, readiness, guided projection, and local-only
  usability boundary against immutable Phase 8 commit `87ea89a`.
- [Phase 9 formal implementation plan](plans/phase-9-implementation-plan.md)
  records its completed sequential gates, fixed interface choices, regression
  matrix, operator desktop review, review-driven fixes, retained manual coverage,
  and mandatory escalation boundary.

## Release 1 hardening

- [Release 1 hardening work order](work-orders/release-1-hardening.md) records the
  authorized governance, locking, CI, package, container, candidate, and
  human-gated publication boundary against Phase 9 closeout commit `97f2a05`.
- [Release 1 hardening implementation plan](plans/release-1-hardening-implementation-plan.md)
  records its sequential gates and immutable product-behavior constraints.
- [Release process](release/release-process.md) defines reproducible candidate
  construction, artifact inspection, checksums, remote-control prerequisites,
  and the final human go/no-go.
- [Release 1 hardening recap](archive/recaps/development-recap-2026-08-02-release-1-hardening.md)
  records the completed local gates, the reproducibility correction, and the
  publication controls that remain external.

## Completed Release 1 local terminal experience

- [Release 1 local terminal UI work order](work-orders/release-1-tui-and-ssh-trial.md)
  records the authorized and completed local TUI, unchanged side-by-side web UI,
  and replacement-candidate boundary. Hosted operation and SSH remain deferred
  to Version 2.
- [Release 1 local TUI implementation plan](plans/release-1-local-tui-implementation-plan.md)
  records module ownership, lifecycle, display policy, dependency gate, and
  verification sequence.
- [Textual 8.2.8 dependency review](release/textual-8.2.8-dependency-review.md)
  records exact distributions, license, graph, excluded features, point-in-time
  advisory evidence, and rollback.
- [v0.1.0-rc2 validation record](release/v0.1.0-rc2-validation.md) records the
  exact replacement-candidate source, locks, artifacts, image identity, test
  matrix, measurements, platform observations, and remaining human gates.

Supporting documents should agree with the canonical record. If they do not,
inspect the implementation and tests, correct the canonical record first, and
then reconcile the supporting document.

## Archive

- `archive/planning/` contains pre-implementation plans.
- `archive/prompts/` contains completed work orders and prompts.
- `archive/recaps/` contains dated implementation-session snapshots.

The current archived development snapshot is
[`development-recap-2026-08-02-release-1-hardening.md`](archive/recaps/development-recap-2026-08-02-release-1-hardening.md).
It includes the completed governance, locking, CI, package, reproducibility,
and pre-TUI container gates. The completed rc2 validation record above
supersedes it for publication decisions without rewriting its historical
evidence.

Archived files preserve historical context. They are not current instructions or
authoritative descriptions of the codebase.

## Version-control policy

Documentation changes must be reviewed and committed with the behavior or
boundary they describe. Archived files remain historical context and should not
be rewritten merely to match later project state.
