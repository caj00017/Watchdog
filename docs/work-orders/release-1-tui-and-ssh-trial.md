# Release 1 Work Order — Local Terminal UI; Hosted SSH Deferred

**Status:** Drafted August 2, 2026; amended, explicitly authorized, implemented,
and deterministically source-verified for Stage A on August 4, 2026; replacement
candidate artifact evidence follows the exact source commit; hosted operation
and SSH remain deferred to Version 2

**Required baseline:** Validated Release 1 candidate record commit
`01a0d2a` and candidate implementation commit
`7041e26570ae3555066aa221b31f80a49c298d35`

**Release target:** `v0.1.0`, after a replacement release candidate

**Decision context:** On August 2, 2026, after validating the first local
release candidate, the user selected a terminal-first experience for Release 1.
The existing web UI must remain available and unchanged so the two interfaces
can be compared side by side. The desired local entry point is `$ watchdog`.
Version 2 may migrate Watchdog to a hosted product with a separately reviewed
remote access experience.

This document is the authorized Stage A implementation boundary. The August 4,
2026 owner instruction approved the amended local-TUI boundary against the
required baseline and requested implementation of the formal plan. Hosted
operation, SSH transport, public listeners, DNS, infrastructure, host keys, and
deployment remain future Version 2 work and require a separate work order.

## Objective

Add one robust, keyboard-first TUI over the existing Phase 7 report and Phase 8
remediation-plan workflows without changing their inputs, outputs, identities,
or analytical meaning. An installed operator should be able to run `watchdog`
in an interactive terminal, enter one advisory identifier and one public GitHub
repository URL, follow bounded progress, inspect evidence and limitations, and
optionally review source-reported remediation candidates.

Retain `watchdog ui` and every existing web route, asset, admission control, and
browser behavior unchanged. The TUI is a second projection for direct
comparison, not a rewrite of the web application.

Release 1 is local-first: the operator installs Watchdog on their own machine
and uses the TUI locally. No hosted or remote access surface is included.

## Effect on the validated candidate

The candidate recorded in `../release/v0.1.0-rc1-validation.md` remains valid
evidence for the pre-TUI baseline, but it is no longer the intended Release 1
publication artifact. Publication of that candidate pauses when this direction
is accepted.

Any TUI implementation changes the no-argument launcher contract, adds a runtime
dependency, changes package metadata and locks, and adds packaged modules. All
existing wheel, sdist, image, test-count, size, and SHA-256 evidence must be
treated as historical after implementation. Release 1 requires a new clean
candidate and validation record; no old checksum or image identity may be
reused.

## Independently gated stages

### Stage A — local TUI

After explicit owner authorization, Stage A may add the local TUI, one reviewed
TUI runtime dependency, launcher dispatch, package/lock changes, deterministic
tests, and synchronized documentation. It may not add an SSH listener or hosted
deployment.

Stage A is the complete Release 1 implementation boundary. A replacement
Release 1 package candidate may proceed after Stage A and its verification gates.

### Future work — hosted product and SSH access

Version 2 may define a hosted Watchdog product and a remote access mechanism,
including SSH if still appropriate. That work is not authorized by this
document, is not part of the Release 1 candidate, and requires a separate
architecture, security, privacy, operations, dependency, and deployment review.

## Frozen analytical and repository boundaries

All Phase 1–9 security invariants remain binding:

- OSV remains the only active advisory source.
- Inputs remain one allowlisted advisory identifier, one strict public
  `github.com` repository URL, and one optional validated ref.
- Repository intake remains archive-only, exact-commit, bounded, no-follow,
  lease-scoped, and cleanup-verified.
- Analyzed repository code, modules, manifests, scripts, tools, and dependencies
  are never imported, installed, or executed.
- OSV-Scanner remains exactly 2.4.0 and receives only Watchdog-generated exact
  coordinates plus trusted configuration under the existing subprocess limits.
- Phase 2–5 work completes inside the existing repository lease. Phase 6 and
  all presentation occur only after verified cleanup.
- The TUI consumes only validated canonical reports and
  remediation plans. They do not gain repository, scanner, evidence-reader,
  model-provider, arbitrary filesystem, or arbitrary network capabilities.
- Every finding retains evidence/provenance links. Scanner failure, unsupported
  structures, unknown versions, omissions, and partial coverage remain visible.
- No interface may claim affected/not-affected status, runtime/data-flow
  reachability, exploitability, deployment exposure, compatibility, package
  availability, or completed remediation.
- Remediation remains candidate planning and optional in-memory preview only.
  No repository byte is written, command generated, or patch applied.

This work order changes presentation and launcher defaults only. It does not
authorize a new analysis phase or any hosted/remote transport.

## Local command contract

After Stage A, the installed command surface is:

- `watchdog` — launch the TUI only when standard input and standard output are
  interactive terminals;
- `watchdog tui [--model MODEL] [--enable-previews]` — explicit local TUI with
  the same interactive standard-input and standard-output requirement;
- `watchdog ui [--model MODEL] [--enable-previews] [--no-open]` — unchanged
  guided literal-loopback web UI;
- `watchdog doctor` — unchanged bounded scanner readiness;
- `watchdog investigate ...` — unchanged direct stdout workflow; and
- `watchdog remediate ...` — unchanged direct stdout remediation workflow.

Bare `watchdog` in a pipe, redirected stream, unsupported terminal, or missing
TTY must not emit terminal control sequences or start work. It returns a fixed
controlled diagnostic and non-zero status directing the operator to
`watchdog --help` or the direct commands. `watchdog --help` may add the new TUI
form, but existing direct command arguments and exit semantics remain unchanged.

Bare `watchdog` is equivalent only to `watchdog tui`; it does not implicitly
enable model synthesis or remediation previews. Local model synthesis remains
off unless explicitly configured through the existing literal-loopback
provider boundary. Preview generation remains off unless
`--enable-previews` is supplied. Trusted command options are per-process and do
not mutate environment variables or configuration files.

## TUI dependency boundary

The preferred toolkit is Textual 8.x. The direct project constraint may be no
broader than `textual>=8.2.8,<9`, and the exact selected version plus every
transitive package must enter the hash-checked runtime, development, and release
locks. No Textual web-serving or remote-serving feature is authorized.

Before implementation, the formal plan must record:

1. license compatibility and package ownership;
2. source and wheel hashes from the trusted package index;
3. complete transitive dependency and native-extension changes;
4. import/startup cost and wheel/sdist/container size deltas;
5. supported Python 3.12–3.14 and Linux/macOS/Windows terminal behavior;
6. known advisories and maintenance/release cadence; and
7. a rollback path if the dependency cannot meet terminal-safety or test needs.

The choice is based on Textual's full-screen application model and official
headless `run_test()`/Pilot support for keyboard, mouse, and terminal-size
testing. Snapshot tooling is not automatically authorized as another
dependency; deterministic state assertions and manually reviewed controlled
screens are sufficient unless a later plan justifies it.

Do not install or invoke Textual development tools in production. Do not use
Textual's browser-serving capability, telemetry, dev console, external themes,
or network features.

## TUI information architecture

The initial TUI contains only these screens or modes:

1. **Readiness and new investigation** — controlled scanner, AI, remediation,
   and preview status plus advisory, repository, and optional ref fields.
2. **Running** — fixed stage labels, elapsed bounded progress, cancel control,
   and no untrusted repository/advisory text beyond the already validated target
   display.
3. **Investigation result** — target/exact commit, dependency matches,
   deterministic context, visibly separate optional model inference, coverage,
   limitations, and validation actions.
4. **Evidence detail** — only evidence already eligible and redacted in the
   canonical report, selected by existing canonical IDs rather than arbitrary
   paths or selectors.
5. **Remediation review** — source-reported candidates and controlled actions;
   local previews only when the process was explicitly enabled.
6. **Raw canonical view** — the unchanged bounded canonical JSON as inert,
   scrollable terminal text.

There is no dashboard, account, workspace picker, filesystem browser, repository
discovery, report history, saved session, upload, download, clipboard action,
shell, command palette capable of arbitrary execution, editable patch, or apply
control.

The first result region must identify the output as an evidence-bound
investigation rather than an affected/not-affected or runtime-exposure
determination. Deterministic facts, model inference, assumptions, coverage gaps,
limitations, and human validation actions remain structurally and visually
distinct. Color, icons, ordering, focus, and status labels may not imply a
stronger conclusion than the canonical enums.

## Workflow, cancellation, and memory lifecycle

The TUI constructs the same strict workflow request models and calls the same
internal orchestration services as the CLI and web adapters. It does not call
the local HTTP API and does not duplicate repository or analysis logic.

Only one workflow may run per TUI session. Submission is rejected before
advisory lookup or repository acquisition when scanner readiness is unavailable.
All existing per-phase and 180-second workflow deadlines remain in force.

Cancellation, terminal close, resize failure, render failure, `Ctrl+C`, and
catchable `SIGINT` or `SIGTERM` must cancel through the existing workflow path,
await repository workers, and verify lease cleanup before the session can
finish. “Cancelled” may be shown only after cleanup succeeds. Cleanup failure is
a controlled terminal error and non-zero session result, never successful
cancellation. `SIGKILL`, OOM termination, host loss, and equivalent uncatchable
failures cannot guarantee in-process cleanup and must remain explicit, untested
limitations rather than being represented as verified behavior.

Unredacted repository content remains transient and bounded inside the existing
lease services. TUI state receives only canonical redacted projections. When a
new investigation starts or the application exits, prior report, remediation,
input, widget, and render buffers are released; no history is retained.

## Terminal rendering boundary

Repository, advisory, model, and upstream values are hostile terminal data.
They must enter widgets through plain-text APIs with markup disabled. The TUI
must remove or visibly encode C0/C1 controls, ESC, CSI/OSC/DCS sequences,
bidirectional controls, zero-width spoofing characters, terminal hyperlinks,
and overlong grapheme sequences according to one checked-in versioned display
policy. It must never emit OSC 52 clipboard operations.

The display policy must preserve the original bounded canonical JSON bytes in
memory as one frozen artifact while making its terminal presentation inert by
visibly escaping unsafe code points. The displayed canonical view identifies
itself as a display-safe representation and reports the original byte length and
artifact identity. Sanitization warnings and truncation counts remain explicit;
display sanitization must not be misrepresented as source redaction or evidence
alteration.

Input fields enforce the existing byte bounds before request construction. Paste
is data, not a command. Bracketed-paste, mouse, focus, color, and terminal-title
features must be disabled unless narrowly required and tested. Client-provided
terminal type, dimensions, locale, color capability, and environment are
untrusted hints, never configuration authority.

The minimum supported viewport is 60 columns by 20 rows. Dimensions above 240
columns by 80 rows are clamped for layout and allocation purposes. Smaller
terminals receive fixed guidance without starting a workflow. Resize events are
bounded and coalesced. The interface must remain fully operable by keyboard and
must have a monochrome/high-contrast-safe representation.

## Web-interface freeze and side-by-side comparison

Stage A may not modify `apps/web/**`, any existing route, HTTP admission rule,
static asset, CSP/security header, browser opener, guided request/response byte,
or `watchdog ui` startup behavior. Existing web tests remain byte-compatible.

The TUI may share only canonical presentation-neutral helpers extracted without
changing web output. If sharing would alter web bytes or behavior, duplicate
small trusted wording/layout adapters instead and record the maintenance cost.

Side-by-side acceptance uses the same frozen canonical fixture artifacts and at
least one operator-approved live public advisory/repository pair. Exact identity
comparisons use the same frozen canonical artifact. Separate live web and TUI
runs compare semantic facts, exact target commit, match states, inference
labels, coverage, limitations, evidence IDs, candidate versions, and preview
availability because independently retrieved timestamps can legitimately change
artifact identities. Layout may differ; facts may not.

## Deferred Version 2 direction — hosted product and remote access

The prior SSH-trial concept is intentionally deferred. Version 2 planning may
consider hosted operation and SSH or another remote access mechanism, but this
Release 1 work order grants no authority for transport code, hosted services,
credentials, public listeners, DNS, infrastructure, host keys, remote egress,
authentication, persistence, or deployment. Those concerns require a new
work order and independent security, privacy, operations, and product review.

## Testing and verification

Stage A requires:

- headless Textual tests for every screen, key binding, focus order, submit,
  cancellation, resize, terminal-limit, scanner-unavailable, timeout, cleanup-
  failure, and rendering state;
- adversarial terminal tests covering ESC/CSI/OSC/DCS, OSC 8/52, bidi, control,
  combining/zero-width, markup, overlong, and truncation inputs;
- deterministic comparisons proving TUI values and evidence links derive only
  from unchanged canonical reports/plans;
- TTY/non-TTY launcher tests and installed-wheel tests on Python 3.12–3.14;
- Linux, macOS, and Windows manual terminal smoke tests, with unsupported
  terminal behavior recorded rather than inferred as passing;
- keyboard-only and monochrome/high-contrast review at minimum, narrow and wide
  viewport review, cancellation during each lease stage, and process-signal
  cleanup; and
- byte/regression tests proving the existing web UI, direct CLI renderers,
  routes, defaults, scanner behavior, and Phase 1–9 identities remain unchanged.

No test may execute or install an analyzed repository or expose a real secret.

## Sequential acceptance gates

1. **Authorization:** owner reviews this draft, resolves amendments, explicitly
   authorizes Stage A, and commits the approved boundary separately.
2. **Dependency readiness:** Textual license, hashes, dependency graph,
   advisories, platforms, size, and rollback are reviewed before lock changes.
3. **Local architecture:** a formal implementation plan fixes module ownership,
   state transitions, render policy, cancellation, and test fixtures.
4. **Local implementation:** TUI and launcher changes land without modifying the
   web implementation or analytical artifacts.
5. **Local verification:** deterministic, hostile-terminal, installed-package,
   platform/manual, package, container, and Phase 1–9 regression gates pass.
6. **Replacement release candidate:** regenerate all locks and package/container
   evidence, run the complete matrix, record exact checksums and limitations,
   and obtain a new final `v0.1.0` publication go/no-go.

No failed, skipped, unavailable, or unperformed gate is passing evidence.

## Acceptance criteria

The work order is complete only when:

1. interactive local `watchdog` and explicit `watchdog tui` provide the bounded
   terminal workflow while non-TTY invocation fails safely;
2. `watchdog ui` and existing web behavior remain unchanged and operable for
   side-by-side comparison;
3. local TUI and web UI agree on all canonical facts, identities, coverage,
   limitations, and remediation candidates;
4. hostile values cannot emit terminal controls, markup, links, clipboard
   operations, commands, or misleading hidden/reordered text;
5. cancellation and disconnect always await verified repository cleanup;
6. dependencies and package inputs are exact, hash-pinned, reviewed, and
   represented in release verification; and
7. a replacement Release 1 candidate passes all prior and new gates with new
   checksums before any stable tag or publication.

## Explicitly out of scope

- Removing, rewriting, or deprecating the web UI in this work order.
- A public HTTP TUI, Textual web serving, or browser replacement.
- Hosted operation, SSH, user accounts, teams, tenant data, private repositories,
  uploads, local paths, arbitrary repositories, or credentials.
- Session history, saved reports, databases, queues, jobs, shared caches,
  downloads, clipboard integration, shell access, commands, or patch apply.
- Remote model providers, model credentials, server-side model installation, or
  hosted AI operation.
- More advisory sources, ecosystems, scanners, parser dependencies, source/data-
  flow analysis, classification, reachability, exposure, exploitability,
  compatibility, availability, registry resolution, or automatic remediation.
- Hosted Version 2 product design and deployment.

## Mandatory pause conditions

Pause and amend this work order before:

- changing any canonical report/plan/artifact identity or analytical meaning;
- changing the web UI or `watchdog ui` behavior;
- adding a dependency other than the separately reviewed Textual choice;
- adding hosted operation, SSH, public or non-loopback listeners, credentials,
  remote inputs, remote egress, persistence, telemetry, DNS, firewall, host keys,
  cloud/service infrastructure, or deployment; or
- publishing, tagging, or representing `v0.1.0` as ready before a replacement
  candidate passes.

## Authorization record

On August 4, 2026, the owner supplied and requested implementation of the formal
Release 1 Local TUI Implementation Plan, explicitly authorizing Stage A against
the recorded baseline and approving this amended boundary. This authorization
does not include tagging, publication, hosted Version 2, or any SSH/remote access
work; each remains subject to its separate gate.

## Stage A implementation result

Stage A completed on August 4, 2026 with Textual 8.2.8 exact in every generated
lock, the capability-narrow `watchdog/tui/` package, fixed data-free workflow
observer, separate TUI process settings, lazy TTY-gated launcher dispatch,
versioned display policy, and bounded terminal driver. The deterministic source
matrix, frozen web tree, direct-command regressions, packaging contract, and
Linux PTY lifecycle passed. Exact artifacts, installation tests, measurements,
container identity, unavailable manual platforms, and skipped opt-in live
network coverage belong to the separately generated rc2 validation record.

No stable tag, publication, hosted operation, SSH, or remote access was
performed or authorized by completing Stage A.
