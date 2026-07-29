# Nexura Watchdog Documentation

This directory is tracked with the repository so architecture, security policy,
work orders, and implementation status remain versioned with the code they
describe.

## Canonical record

- [Project Design and Implementation Record](Nexura_Watchdog_Project_Design_and_Implementation_Record.md)
  is the single source of truth for current status, implemented behavior,
  boundaries, decisions, roadmap, and immediate milestone.

## Supporting detail

- [Architecture](architecture/architecture.md) describes current runtime flows
  and module boundaries.
- [Threat model](security/threat-model.md) describes active trust boundaries,
  controls, and residual risks.
- [Evidence policy](security/evidence-policy.md) defines provenance, conflicts,
  failures, acquisition metadata, the completed Phase 4 evidence contract, and
  completed Phase 5 context evidence plus the proposed Phase 6 inference/evidence
  separation.

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

## Proposed work orders

- [Phase 6 evidence-bound model investigation](work-orders/phase-6-evidence-bound-model-investigation.md)
  is a readiness-reviewed proposal for an internal, strictly validated model
  synthesis boundary. It is ready for an explicit authorization decision but
  does not authorize implementation, network access, credentials, interfaces,
  persistence, exposure classification, or remediation behavior.

Supporting documents should agree with the canonical record. If they do not,
inspect the implementation and tests, correct the canonical record first, and
then reconcile the supporting document.

## Archive

- `archive/planning/` contains pre-implementation plans.
- `archive/prompts/` contains completed work orders and prompts.
- `archive/recaps/` contains dated implementation-session snapshots.

The current archived verification snapshot is
[`development-recap-2026-07-29-phase-5-verification.md`](archive/recaps/development-recap-2026-07-29-phase-5-verification.md).

Archived files preserve historical context. They are not current instructions or
authoritative descriptions of the codebase.

## Version-control policy

Documentation changes must be reviewed and committed with the behavior or
boundary they describe. Archived files remain historical context and should not
be rewritten merely to match later project state.
