# Phase 9 Formal Implementation Plan — Local-First Guided Experience

**Status:** Implementation and exercised desktop operator review complete;
automated/environment-capable gates passed and unreported manual checks are
retained explicitly

**Authorized:** July 29, 2026

**Immutable baseline:** `87ea89a5313c3dcb9cdc349a27691f91d83e623d`

**Governing boundary:** `../work-orders/phase-9-local-first-guided-experience.md`

## Authority and regression gate

The exact Phase 8 baseline passed 339 deterministic tests with one explicit
opt-in live-network scanner test skipped, Ruff format/lint, strict mypy,
compileall, Compose parsing, dependency-hash regression, and the OSV-Scanner
2.4.0 pin check before it was committed. The user then explicitly directed
implementation of this plan on July 29, 2026.

Freeze before code changes:

- Phase 1–8 canonical identity and renderer fixtures;
- existing module-command output bytes, exit codes, routes, settings defaults,
  and asset selection;
- launcher option names and fixed controlled readiness wording;
- exact OSV-Scanner 2.4.0 version parsing and bounded preflight limits; and
- the local-only, synchronous, non-persistent, non-writing scope.

## Sequential implementation gates

1. **Launcher contracts.** Add the installed console entry point and a separate
   launcher module. Reuse the direct CLI implementation without changing its
   parser identity or behavior. Add trusted immutable per-process settings for
   guided candidate planning, optional previews, and optional existing
   literal-loopback model selection.
2. **Scanner readiness.** Build one bounded readiness service around only
   regular/executable-file validation and the existing absolute-argument-array,
   minimal-environment, process-group-cleaned scanner version operation. Freeze
   controlled states and safe messages. Add `doctor` with no repository,
   advisory, source, or model construction.
3. **Server lifecycle and browser opener.** Bind successfully before printing
   or opening. Construct the URL only from the already validated literal
   loopback address and bounded integer port. Use a direct standard-library
   browser API with no shell or untrusted template. Treat open failure as
   non-fatal. Cover bind conflict, SIGINT/SIGTERM, cancellation, and joined
   server cleanup.
4. **Guided application selection.** Add a trusted guided-mode setting used only
   by the new launcher. Select a separate checked-in HTML/CSS/JavaScript asset
   variant and conditionally register `/api/v1/readiness`. Preserve all legacy
   assets and route tables outside guided mode.
5. **Admission gate.** Cache one immutable bounded scanner readiness result for
   the guided process. Reject guided investigation and remediation requests
   before request parsing can trigger advisory lookup, network access, or lease
   acquisition when scanner readiness is unavailable. Do not alter legacy
   scanner-failure semantics.
6. **Progressive UI.** Implement the two-field first-run form, collapsed
   advanced inputs, readiness guidance, non-streaming progress, AbortController
   cancellation, text-node structured report projection, separate remediation
   review action, raw canonical artifact disclosure, fixed errors, keyboard
   flow, and responsive styles.
7. **Security regressions.** Prove Host/origin/Fetch-Metadata/local-header,
   no-store/no-CORS/no-cookie, body/result limits, disconnection cleanup,
   hostile-text inertness, no prohibited browser APIs, no arbitrary paths or
   browser commands, and no repository writes.
8. **Documentation.** Synchronize the operator guide, README, settings reference,
   architecture, threat model, evidence/report projection policy where needed,
   canonical implementation record, AGENTS boundary, indexes, and dated recap.
9. **Completion gate.** Run format, Ruff, strict mypy, compileall, the full test
   suite, installed-wheel command and asset checks, Compose, standalone
   container, scanner pin, public-route regression, no-network, and literal-
   loopback checks. Record every environment-dependent limitation explicitly.

No later gate waives an earlier boundary. A working browser page does not waive
readiness admission, canonical artifact, cleanup, or no-write requirements.

## Fixed interface choices

- entry point: `watchdog = watchdog.launcher:main`;
- commands: `ui`, `doctor`, `investigate`, and `remediate`;
- UI options: only `--model`, `--enable-previews`, and `--no-open`;
- guided initial inputs: advisory ID and public GitHub URL;
- advanced inputs: optional ref, summary/technical view, JSON/Markdown format;
- readiness capabilities: scanner, AI, remediation, and preview only;
- AI labels: `Off`, `Configured`, and `Unavailable`;
- browser target: one fixed validated `http://<literal-loopback>:<port>/` URL;
- investigation and remediation remain separate synchronous requests; and
- cancellation uses client disconnect and existing lease cleanup.

The implementation may refine internal type/module names, but may not expand
options, states, routes, destinations, data sources, or capabilities.

## Required test matrix

- installed wheel: help plus all four commands; legacy module-command byte and
  exit compatibility fixtures;
- launcher: successful bind, port conflict, no-open, non-fatal open failure,
  fixed URL, no shell, signal shutdown, no orphan process, no environment
  browser-template use;
- readiness: missing, non-regular, non-executable, malformed, timed out,
  wrong-version, and exact-version scanner; safe doctor output; no advisory,
  repository, OSV, registry, GitHub, or model call;
- guided admission: unavailable scanner blocks both workflows before any source
  or lease activity and still serves readiness guidance;
- AI: off, configured, unreachable, timed out, malformed JSON, and schema-
  invalid output with deterministic report preservation;
- remediation: enabled only by guided launcher; previews require explicit opt-
  in; no apply/write/command behavior;
- browser security: hostile advisory, repository, evidence, Markdown, HTML,
  ANSI, control, and bidirectional text; no `innerHTML`, external asset,
  storage, clipboard, upload, automatic download, arbitrary path, or apply UI;
- projection agreement: guided JSON display maps to unchanged canonical
  artifact without hiding incomplete coverage, scanner failure, conflict, or
  model uncertainty; and
- regression: all Phase 1–8 identities, bytes, routes, settings, scanner
  arguments, egress boundaries, and legacy assets.

## Completion rule

Phase 9 may be marked complete only after all in-scope tests and documentation
pass and the current implementation is committed separately from the immutable
Phase 8 baseline and this planning record. Scanner/model installation, hosted
operation, authentication, persistence, repository mutation, release publishing,
and all work-order pause conditions remain deferred even after completion.

## Completion result

All nine gates completed on July 29, 2026. The initial implementation passed
Ruff format/lint, strict mypy, compileall, Compose, public routes, installed-
wheel command/asset checks, legacy command-byte compatibility, standalone image
build, embedded scanner 2.4.0, public/guided no-network/no-mount health,
controlled readiness, and signal cleanup. After operator-review fixes, the full
deterministic suite passes 362 tests with the separately enabled live OSV
scanner network contract skipped by default; current guided assets pass their
size and package-selection gates. The environment image was not rebuilt after
the presentation-only review revisions, so release hardening must build its
candidate from the reviewed closeout commit. Exact environment-dependent
evidence is preserved in
`../archive/recaps/development-recap-2026-07-29-phase-9.md`.

The local environment's sandboxed headless Firefox failed during graphics
initialization before producing a screenshot, but the user subsequently
completed a real desktop Firefox review. It exercised startup/readiness,
cancellation, a live two-field investigation, canonical disclosure, visible
uncertainty, and result readability, and drove four separately committed fixes
recorded in the completion recap. The final evidence-summary revision did not
receive a separately reported post-change screenshot; remediation review,
keyboard-only traversal, and a narrow responsive viewport were not explicitly
reported as manual observations. Deterministic/static coverage for those
controls remains green, and the omissions remain explicit rather than inferred
as passed.
