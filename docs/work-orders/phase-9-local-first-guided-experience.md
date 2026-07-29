# Phase 9 Work Order — Local-First Guided Experience

**Status:** Implementation complete; deterministic and environment-capable gates
passed July 29, 2026; desktop usability sign-off remains an explicit manual
coverage limitation

**Prepared:** July 29, 2026

**Required baseline:** Completed Phase 8 commit
`87ea89a5313c3dcb9cdc349a27691f91d83e623d`

**Implementation authority:** On July 29, 2026, after Phase 8 verification and
commit, the user supplied the decision-complete Phase 9 plan and explicitly
instructed its implementation. This authorizes only the staged local-first
guided experience in `../plans/phase-9-implementation-plan.md` against the exact
baseline above.

**Planning commit:** `81763ffd84aef418c49793e9059b3bb16492e93c`

**Implementation commit:** `5c8be6cb732ef46bb43b62675b8d4276eba91723`

**Completion finding:** All staged implementation packages and automated or
environment-capable acceptance gates passed. Exact deterministic,
installed-wheel, container, scanner, route, asset, no-network/no-mount,
signal-cleanup, retained manual/live coverage limitations, and permanent
deferral results are recorded in
`../archive/recaps/development-recap-2026-07-29-phase-9.md`.

## Objective

Make the completed Phase 1–8 system understandable to a first-time local
operator without changing any analytical contract. With prerequisites already
installed, the operator can run `watchdog ui`, enter one advisory identifier and
one public GitHub repository URL, and receive an evidence-bound guided summary.

Phase 9 is a local interface and readiness layer. It adds no new analysis,
artifact schema, canonical identity, source, destination, parser, dependency,
repository capability, or remediation authority.

## Authorized interfaces

An installed `watchdog` entry point may expose exactly:

- `watchdog ui [--model MODEL] [--enable-previews] [--no-open]`;
- `watchdog doctor`;
- `watchdog investigate ...`; and
- `watchdog remediate ...`.

`python -m apps.cli` and `python -m apps.web` retain their existing defaults,
output bytes, exit codes, routes, asset selection, and disabled behavior.

For its own process, `watchdog ui` is explicit authorization to enable the
guided literal-loopback interface and Phase 8 candidate planning. Preview
generation remains independently off unless `--enable-previews` is supplied.
AI remains off unless `--model` or the existing explicit model settings enable
it. Trusted overrides are per-process and do not mutate environment variables,
configuration files, or global state.

The launcher must retain the validated literal-loopback host and configured
port. It prints the exact fixed local URL and, unless `--no-open` is supplied,
opens it only after successful binding. Browser opening uses no shell or command
template, ignores browser-command environment overrides, includes no advisory
or repository value, and is non-fatal on failure.

## Readiness boundary

`watchdog doctor` performs only bounded, non-repository checks:

1. validate trusted settings;
2. verify that the configured scanner path identifies a regular executable;
3. invoke that executable with only the existing bounded `--version` operation;
4. require exactly OSV-Scanner 2.4.0; and
5. emit fixed safe status text without paths, environment values, credentials,
   repository/advisory data, network access, or model requests.

The guided application may expose one bounded `/api/v1/readiness` projection
containing only controlled scanner, AI, remediation, and preview capability
states. In guided mode only, a non-ready scanner must reject investigation and
remediation requests before advisory lookup, outbound access, or repository
lease acquisition. Legacy CLI and local-API scanner-failure semantics remain
unchanged.

Readiness vocabulary is fixed and non-diagnostic: scanner `ready` or
`unavailable`; AI `off`, `configured`, or `unavailable`; remediation `enabled`;
and previews `enabled` or `disabled`. Fixed guidance may tell an operator to
install/configure the pinned scanner or check a configured local model. It must
not expose paths, environment values, exception text, response bodies, or
credentials.

## Guided browser experience

Guided mode uses a separate checked-in asset variant. Its initial page shows
only Advisory ID, Public GitHub repository URL, and Investigate. A collapsed
Advanced section contains the optional ref, summary/technical view, and
JSON/Markdown artifact format.

The default summary/JSON result is rendered as text-only sections for status,
exact snapshot, dependency findings, evidence, model synthesis, coverage gaps,
limitations, and validation actions. Deterministic facts and model inference
must be visibly distinct. The unchanged raw canonical output remains available
in a collapsed advanced result area.

Remediation becomes available only after an investigation completes. Its
separate action reuses transient in-page form values, starts an independent
synchronous workflow, and states that nothing is applied. Running forms are
disabled, progress wording remains honest and non-streaming, and Cancel aborts
the request through the existing disconnect-cleanup path.

Hostile values are inserted only with text-node APIs. Phase 9 adds no clipboard,
upload, filesystem picker, browser storage, history, job, persistence, automatic
download, arbitrary path, command, apply, write, or external asset control.

## Frozen Phase 1–8 invariants

Phase 9 must not change:

- Phase 1 advisory normalization, provenance, conflicts, or OSV-only behavior;
- Phase 2 public-GitHub-only intake, exact snapshot identity, hostile archive
  controls, or cleanup semantics;
- Phase 3 inventory/matching behavior, scanner arguments/input/network boundary,
  failure semantics, or the OSV-Scanner 2.4.0 pin;
- Phase 4/5 evidence eligibility, observations, redaction, or identities;
- Phase 6 prompt, schema, gateway, policy, evidence links, identity, or
  credential-free literal-loopback transport;
- Phase 7 request/report schema, canonical identity, renderer bytes, direct CLI,
  existing routes, existing checked-in asset variants, or local-app defaults;
- Phase 8 plan schema, identity, candidate/preview eligibility, renderers,
  no-write guarantee, direct CLI behavior, routes, or disabled defaults; or
- the public advisory application, dependencies, external destinations, and
  default settings.

The guided summary is a projection over unchanged Phase 7 and Phase 8 canonical
artifacts. It cannot repair, reinterpret, omit, or downgrade scanner failures,
partial coverage, conflicts, assumptions, limitations, or model uncertainty.

## Security and lifecycle controls

- Binding, startup failure, signal handling, cancellation, and shutdown must
  leave no running server or workflow worker.
- Existing exact-Host, same-origin, Fetch Metadata, local-request-header,
  no-store, no-CORS, no-cookie, literal-loopback, bounded-body, and fully
  buffered response controls apply to all guided routes.
- Readiness probes are bounded and never touch a repository or network.
- An explicitly configured but failed or invalid model run must not suppress a
  deterministic report; it produces only the existing controlled limitation.
- The launcher accepts no listener host, arbitrary URL, output path, browser
  command, scanner path, repository path, credential, or remote provider option.
- Watchdog does not install or download OSV-Scanner, a model, or a model server.

## Acceptance criteria

1. Phase 8 is independently verified and immutable at the exact required hash.
2. Installed-wheel invocation covers every `watchdog` command, while legacy
   module commands remain byte-for-byte compatible.
3. Startup, bind conflict, signal, cleanup, `--no-open`, browser failure, and
   fixed-URL behavior are deterministic and tested without a shell.
4. Scanner missing, wrong-type, non-executable, malformed, timeout, and wrong
   version states are controlled; guided workflow admission occurs before all
   advisory/repository/network work.
5. `doctor` provably performs no advisory, repository, GitHub, OSV, registry, or
   model request and never prints a path or environment value.
6. Guided candidate planning is launcher-enabled; previews require explicit
   startup opt-in; no repository byte is written.
7. AI off/configured/unavailable and invalid-response paths preserve the
   deterministic report and controlled limitations.
8. The page is keyboard-accessible, responsive, cancellable, and renders all
   hostile data as inert text without prohibited browser APIs or external
   assets.
9. Guided JSON sections agree with the canonical artifact and keep deterministic
   facts separate from model inference and coverage limitations.
10. Phase 1–8 identities, renderer bytes, routes, defaults, scanner boundary,
    and egress controls have regression coverage.
11. Operator, architecture, threat-model, settings, canonical-record, AGENTS,
    README, package-asset, and completion documentation agree.
12. A first-time operator with documented prerequisites can launch, understand
    readiness, submit the two required values, distinguish facts from AI, and
    locate limitations within five minutes without environment-variable docs.

## Mandatory pause conditions

Pause for a separate explicit boundary review before adding hosted or non-
loopback listening, authentication, credentials, private repositories, remote
model providers, model/scanner installation, persistence, telemetry, jobs or
history, uploads, arbitrary paths or URLs, external assets, browser storage,
clipboard/download controls, repository writes, patch application, commands,
classification, runtime/data-flow reachability, deployment exposure,
compatibility/availability claims, dependency resolution, registry access, a
new dependency, a new destination, or any Phase 1–8 identity/default change.

## Deferred work

Release governance, dependency locking, CI, release-candidate production, and
v0.1.0 publication remain in the separate release-hardening work order tracked
from item 2 of `~/TODO.txt`. Hosted Watchdog remains an independent later product
decision.
