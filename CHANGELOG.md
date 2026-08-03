# Changelog

All notable changes to Nexura Watchdog are documented here. The project follows
[Semantic Versioning](https://semver.org/) beginning with `0.1.0`; while the
major version is zero, trust-boundary and artifact compatibility changes are
still reviewed and called out explicitly.

## [Unreleased]

### Added

- Keyboard-first local Textual TUI launched by bare `watchdog` or
  `watchdog tui`, with readiness, bounded progress, Summary, Evidence,
  Remediation, and display-safe Canonical JSON views.
- Optional data-free workflow-stage observer with cancellation-safe repository
  cleanup behavior.
- Reviewed Textual 8.2.8 dependency and exact hash-locked pure-Python graph.

### Security

- Non-TTY and unsupported terminals fail before Textual/runtime construction;
  dynamic terminal data is visibly escaped under a bounded versioned display
  policy.
- TUI cancellation and catchable termination wait for the existing workflow
  cleanup path. Uncatchable process/host termination remains an explicit
  limitation.
- The existing web UI, routes, direct command bytes, scanner behavior,
  analytical artifacts, and Phase 1–9 identities remain unchanged.

## [0.1.0] - 2026-08-02 release candidate

### Added

- OSV advisory retrieval with source-neutral normalization, provenance,
  conflict reporting, and explicit partial-failure state.
- Safe archive-only intake of exact public GitHub snapshots with bounded,
  no-follow extraction and verified cleanup.
- Data-only Python, npm, and Go dependency inventory plus exact-coordinate
  matching through pinned OSV-Scanner 2.4.0.
- Bounded redacted evidence, deterministic lexical context, and controlled
  evidence-linked non-classification signals.
- Optional strict evidence-bound model synthesis through a disabled-by-default,
  credential-free literal-loopback adapter.
- Canonical reports, direct CLI workflows, a guided literal-loopback browser
  experience, scanner readiness, and no-write remediation candidate previews.
- Hash-locked release environments, least-privilege CI, reproducible package
  validation, and a human-gated PyPI Trusted Publishing workflow.

### Security boundaries and limitations

- Public GitHub repositories only; no private repository credentials.
- OSV is the only active advisory source and OSV-Scanner remains pinned to
  exactly 2.4.0.
- Watchdog does not execute analyzed repository code, install analyzed
  dependencies, or follow repository symlinks.
- Findings retain evidence links, uncertainty, partial coverage, and scanner
  failures. The release does not claim runtime reachability, exploitability,
  deployment exposure, compatibility, or repository affected/not-affected
  status.
- The model adapter and local interfaces are disabled by default and restricted
  to literal loopback. There is no hosted service, authentication, persistence,
  telemetry, repository write, command generation, or patch application.

[Unreleased]: https://github.com/caj00017/Watchdog/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/caj00017/Watchdog/releases/tag/v0.1.0
