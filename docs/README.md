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
  future finding evidence.

## Completed work order

- [Phase 4 evidence engine](work-orders/phase-4-evidence-engine.md) is the
  reviewed implementation boundary and acceptance contract completed on July
  28, 2026.

## Proposed work order

- [Phase 5 deterministic contextual analysis](work-orders/phase-5-contextual-analysis.md)
  is a security-boundary proposal for review. It does not authorize Phase 5
  implementation.

Supporting documents should agree with the canonical record. If they do not,
inspect the implementation and tests, correct the canonical record first, and
then reconcile the supporting document.

## Archive

- `archive/planning/` contains pre-implementation plans.
- `archive/prompts/` contains completed work orders and prompts.
- `archive/recaps/` contains dated implementation-session snapshots.

The current archived implementation snapshot is
[`development-recap-2026-07-28-phase-4.md`](archive/recaps/development-recap-2026-07-28-phase-4.md).

Archived files preserve historical context. They are not current instructions or
authoritative descriptions of the codebase.

## Version-control policy

Documentation changes must be reviewed and committed with the behavior or
boundary they describe. Archived files remain historical context and should not
be rewritten merely to match later project state.
