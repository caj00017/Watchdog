# Release 1 Local TUI Implementation Plan

**Status:** Authorized August 4, 2026

**Baseline:** Release 1 candidate implementation commit
`7041e26570ae3555066aa221b31f80a49c298d35`, with the amended work order and
intentional documentation changes preserved

**Authority:** The owner's August 4, 2026 instruction approved the amended
Stage A boundary and requested this plan's implementation. Tagging, publication,
hosted operation, SSH, and remote access remain unauthorized.

## Objective and fixed boundary

Implement a keyboard-first Textual TUI as a new projection over the existing
investigation and remediation services. Bare `watchdog` and `watchdog tui`
launch it only with interactive stdin and stdout. Preserve the web UI, direct
commands, analytical models, routes, canonical identities, scanner behavior,
network destinations, and repository trust boundaries.

Use a guided start screen followed by a result workspace with Summary, Evidence,
Remediation, and Canonical JSON views. Permit one active workflow and retain no
history or repository capability in presentation state.

## Dependency gate

- Add the direct constraint `textual>=8.2.8,<9` and select exactly Textual 8.2.8
  in the runtime, development, and release locks.
- Record the MIT license, wheel SHA-256
  `267375fd402dc8d981457212efa71f0e3365fd17bba144ba9bb3ed7563cb374a`,
  sdist SHA-256
  `3f106a9fbc73e39dd266c9712432087de78a6d644084c7c241d6a25c3169115b`,
  declared dependencies, pure-Python graph, and point-in-time OSV review.
- Do not add Textual syntax extras, Tree-sitter, native extensions, dev-console,
  browser-serving, remote, telemetry, or snapshot-test dependencies.
- Regenerate every trusted-project lock with hashes in a clean Python 3.12
  environment and extend release verification for Textual and packaged TUI
  modules.
- Measure cold startup plus wheel, sdist, and container size deltas. Roll back
  launcher and dependencies if licensing, pure-Python, terminal-safety, or
  supported-platform gates fail.

## Architecture and ownership

Create `watchdog/tui/` with a Textual application/state machine, a production
backend adapter around `workflow_runtime`, and pure projection/display helpers.
The app receives a narrow backend protocol returning only `GuidedReadiness`,
`InvestigationReport`, `RemediationPlan`, and existing canonical JSON bytes.
Tests inject in-memory backends. The TUI does not call HTTP or receive scanner,
repository, filesystem, evidence-reader, or model-provider capabilities.

Add an optional synchronous data-free workflow observer. `WorkflowStage` is a
fixed enum; workflow `run()` methods accept a keyword-only observer defaulting
to `None`. Events contain only stages for advisory resolution, snapshot
acquisition, inventory, matching, evidence, context, candidate derivation,
preview collection, cleanup verification, investigation, and output assembly.
Observer failure is controlled and still traverses lease cleanup. Omitting the
observer preserves existing bytes and identities.

The application state is one of `READY`, `RUNNING_INVESTIGATION`,
`SHOWING_REPORT`, `RUNNING_REMEDIATION`, `SHOWING_PLAN`, `CANCELLING`, or
`FATAL`. It owns at most one worker. Starting a new investigation releases prior
canonical models, rendered bytes, and widget buffers. Remediation is an explicit
separate workflow and does not imply identity equality with an earlier run.

## Command and lifecycle contract

- `watchdog` and `watchdog tui [--model MODEL] [--enable-previews]` require TTY
  stdin/stdout. Preflight failure returns 2 with one fixed plain-text diagnostic
  before importing Textual or constructing workflow services.
- Keep `watchdog ui`, `doctor`, `investigate`, `remediate`, and `--help`
  arguments/defaults/outputs unchanged except documenting the new TUI command.
- TUI settings keep HTTP interfaces off; enable candidate planning for the TUI
  process only; previews require the flag; AI remains under the existing
  disabled-by-default literal-loopback boundary.
- Exit 0 covers clean exit and cancellation after verified cleanup; exit 1
  covers fatal runtime/render/cleanup failure; exit 2 covers startup,
  configuration, terminal, or TTY failure.
- Catchable cancellation, render/resize failures, `SIGINT`, and `SIGTERM`
  cancel and join the worker, verify lease cleanup, close runtime clients, and
  release buffers. Repeated exit requests remain pending. `SIGKILL`, OOM, host
  loss, and equivalent uncatchable termination remain explicit limitations.

## Presentation and terminal safety

The start view contains controlled readiness plus advisory, public GitHub URL,
and optional ref inputs. The running view contains only an observer stage,
bounded monotonic elapsed time, cancel action, evidence-boundary reminder, and
validated target display. Result tabs separate summary facts/inference/coverage/
limitations/actions, canonical evidence and redacted detail, remediation
planning and optional previews, and frozen canonical JSON.

Dynamic values enter plain-text widgets with markup disabled. A checked-in
versioned pure display policy visibly encodes C0/C1 controls, ESC, bidi and
zero-width format controls, and unsafe scalars as deterministic ASCII tokens,
bounds combining/default-ignorable runs, and reports omitted code points. Source
redaction, display sanitization, and truncation remain separate labels. The
frozen bounded canonical bytes stay unchanged in memory; their terminal view is
identified as a display-safe representation with original length and ID.

Do not use Markdown, syntax highlighting, auto-links, terminal hyperlinks,
clipboard, commands, arbitrary paths, downloads, or shell behavior. Disable the
command palette, mouse/focus reporting, title changes, and unnecessary paste
modes. Inputs reject forbidden controls rather than changing request semantics.
Support `NO_COLOR`, monochrome, high contrast, Tab/Shift-Tab, Enter, Escape,
Ctrl+C, and Ctrl+Q. Single-character global commands remain disabled while an
input is focused. Enforce 60x20 minimum, clamp retained layout to 240x80, and
coalesce resize work.

## Verification sequence

1. Freeze web assets, launcher/direct-command fixtures, canonical artifacts,
   settings, routes, scanner arguments, and Phase 1–9 identities.
2. Complete the dependency dossier, locks, packaging, and release-verification
   updates.
3. Add observer ordering, compatibility, cancellation, timeout, and cleanup
   regression tests.
4. Add pure display policy and canonical projection tests with hostile terminal
   fixtures.
5. Build the injected-backend TUI and headless state/focus/resize tests.
6. Add production backend, readiness admission, launcher dispatch, signals,
   TTY checks, and lazy imports.
7. Run Ruff format/lint, strict mypy, compileall, full pytest, release
   verification, wheel/sdist installation, Compose validation, image build,
   embedded OSV-Scanner 2.4.0 verification, and no-network/no-mount health
   checks where the environment supports them.
8. Record exact results, startup/size changes, platform observations, skips,
   limitations, locks, artifacts, and image hashes in a new immutable rc2 record.

Headless tests cover every state, focus order, form validation, evidence detail,
remediation, canonical view, cancellation, and resize. Adversarial tests cover
ESC/CSI/OSC/DCS, OSC 8/52, markup, bidi, zero-width, combining floods, C0/C1,
long values, hostile URLs, and truncation. PTY tests cover bare/explicit launch,
signals, unsupported/small terminals, redirected streams, and control-free
preflight failure. Exact web/TUI identity comparisons use the same frozen
artifact; separate live runs compare semantic facts and disclose retrieval-time
differences.

## Documentation and release limits

Synchronize AGENTS, README/operator guidance, documentation index, architecture,
threat model, canonical implementation record, release process, changelog, and a
new rc2 validation record. Preserve rc1 unchanged except for a superseded label.
No stable tag, publication, hosted operation, remote access, SSH, authentication,
persistence, telemetry, scanner/model installation, new destination, repository
write, command, patch apply, analytical classification, or identity/default
change is authorized.
