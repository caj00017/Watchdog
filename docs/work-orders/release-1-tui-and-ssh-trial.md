# Release 1 Work Order — Terminal UI and Anonymous SSH Trial

**Status:** Drafted August 2, 2026; implementation and deployment are not yet
authorized

**Required baseline:** Validated Release 1 candidate record commit
`01a0d2a` and candidate implementation commit
`7041e26570ae3555066aa221b31f80a49c298d35`

**Release target:** `v0.1.0`, after a replacement release candidate

**Decision context:** On August 2, 2026, after validating the first local
release candidate, the user selected a terminal-first experience for Release 1.
The existing web UI must remain available and unchanged so the two interfaces
can be compared side by side. The desired local entry point is `$ watchdog`.
The desired no-install trial is `$ ssh watchdog.nexura.fyi`.

This document is a proposed implementation boundary. Writing and reviewing it
does not authorize adding dependencies, changing launcher behavior, opening a
public listener, changing DNS, provisioning infrastructure, generating or
mounting host keys, or deploying the SSH trial. Local implementation and public
deployment require the separate approvals defined below.

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

Separately, make the same restricted TUI available as an anonymous, ephemeral
public trial at `watchdog.nexura.fyi` over SSH. The hosted trial is not a shell,
an account, a tunnel, a file-transfer service, or a remote form of the complete
local configuration surface.

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

Stage A must be complete and independently verified before any SSH transport
code is implemented. A Release 1 package candidate may proceed after Stage A
even if the public SSH trial is delayed by its separate operational gate.

### Stage B — loopback SSH transport prototype

After Stage A passes and the owner separately approves the SSH dependency and
license/security review, Stage B may implement a disabled-by-default SSH
application gateway that binds only to literal loopback in tests and manual
staging. It may add a deployment-only dependency lock and a separate service
entry point/image. It may not bind publicly, alter DNS, or deploy to a server.

### Stage C — public SSH trial deployment

Public binding, DNS changes, firewall changes, persistent host-key provisioning,
and production process supervision require a final deployment-specific go/no-go
after Stage B acceptance. That decision must record the exact image digest,
configuration, host-key fingerprints, resource limits, egress policy, rollback
procedure, monitoring destination, and responsible operator.

Passing Stage A or B does not imply Stage C approval.

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
- The TUI and SSH adapter consume only validated canonical reports and
  remediation plans. They do not gain repository, scanner, evidence-reader,
  model-provider, arbitrary filesystem, or arbitrary network capabilities.
- Every finding retains evidence/provenance links. Scanner failure, unsupported
  structures, unknown versions, omissions, and partial coverage remain visible.
- No interface may claim affected/not-affected status, runtime/data-flow
  reachability, exploitability, deployment exposure, compatibility, package
  availability, or completed remediation.
- Remediation remains candidate planning and optional in-memory preview only.
  No repository byte is written, command generated, or patch applied.

This work order changes presentation, launcher defaults, and the separately
gated hosted transport. It does not authorize a new analysis phase.

## Local command contract

After Stage A, the installed command surface is:

- `watchdog` — launch the TUI only when standard input and standard output are
  interactive terminals;
- `watchdog tui [--model MODEL] [--enable-previews]` — explicit local TUI;
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

Cancellation, terminal close, SSH disconnect, resize failure, render failure,
`Ctrl+C`, and process termination must cancel through the existing workflow
path, await repository workers, and verify lease cleanup before the session can
finish. “Cancelled” may be shown only after cleanup succeeds. Cleanup failure is
a controlled terminal error and non-zero session result, never successful
cancellation.

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

The display policy must preserve canonical raw bytes separately in the existing
validated artifact while making terminal presentation inert. Sanitization
warnings and truncation counts remain explicit; display sanitization must not be
misrepresented as source redaction or evidence alteration.

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

Side-by-side acceptance uses the same synthetic fixtures and at least one
operator-approved live public advisory/repository pair. The web UI, local TUI,
and staged SSH TUI must agree on canonical report/plan IDs, exact target commit,
match states, inference labels, coverage, limitations, evidence IDs, candidate
versions, and preview availability. Layout may differ; facts may not.

## Anonymous SSH trial contract

The exact UX target is:

```text
ssh watchdog.nexura.fyi
```

Standard SSH clients supply the local operating-system username when `user@` is
omitted. To preserve the exact command, the dedicated application gateway may
accept any syntactically bounded SSH username, immediately discard it, and map
the connection to an anonymous session. It must not create or select an OS
account, display or persist the username, or use it as an authorization,
filesystem, process, cache, or log key.

The service uses SSH encryption and a persistent server host key for server
identity, but it performs no end-user authentication in the initial public
trial. The welcome screen must state that the session is anonymous, limited to
public GitHub inputs, transient, and subject to resource limits. It must not
invite credentials or private data.

Only one interactive shell request with one PTY is accepted per connection, and
that request starts only the restricted remote TUI profile. The gateway rejects:

- remote command execution and client-supplied command strings;
- second or multiplexed channels;
- SFTP, SCP, subsystem, and file-transfer requests;
- local, remote, dynamic, UNIX-socket, TUN/TAP, and agent forwarding;
- X11 forwarding;
- environment-variable setting, agent use, user rc files, and login shells;
- all client-supplied signal requests; disconnect and bounded window-size
  changes are handled only as gateway lifecycle events; and
- terminals outside the bounded type/size policy.

The remote profile has AI off with no provider configuration or credentials.
Remediation candidates may be displayed; token previews are always disabled.
There is no remote option or environment value that can enable models, previews,
the web UI, a shell, arbitrary output, or another destination.

## SSH transport dependency gate

Do not implement SSH framing, cryptography, key exchange, authentication, or
channel parsing in Watchdog. The candidate prototype transport is AsyncSSH
2.24.x because it supports a Python asyncio server and explicit session/channel
handlers. It is deployment-only and must not become a dependency of the
published local `nexura-watchdog` wheel unless a later review justifies that
change.

Before Stage B, the owner must approve a dependency record covering the exact
AsyncSSH version/hashes, PyCA cryptography/native-wheel changes, EPL-2.0 or
GPL-2.0-or-later license compatibility, supported algorithms, current security
advisories, upstream maintenance, and all feature defaults. Any unresolved
license or security concern blocks AsyncSSH and requires an alternative work
order amendment; it does not authorize bespoke SSH code.

Every permissive transport feature must be explicitly disabled even when the
library currently defaults it off. A library upgrade is a new SSH-boundary
review, not an automatic lock refresh.

## Hosted isolation and egress boundary

The public gateway runs as a dedicated unprivileged service in a separate
digest-pinned image. It may expose only TCP port 22 through infrastructure port
mapping. It exposes no public HTTP health, metrics, API, web UI, container
socket, management port, or debug console.

Each session receives a distinct process and ephemeral workspace under a
read-only root filesystem with bounded tmpfs. The deployment must drop Linux
capabilities, set no-new-privileges, use a reviewed seccomp/AppArmor equivalent,
set CPU/memory/PID/file-descriptor/file-size limits, and mount neither the host
filesystem nor Docker/container control sockets. Sessions share no Python
object, temporary directory, report, repository lease, cache, credential, or
model state.

The gateway starts only one fixed absolute Watchdog executable with a fixed
argument array and a minimal allowlisted environment. It uses no shell,
client-selected command, interpolation, search path, working directory, startup
file, or inherited credential. The TUI process starts in its own process group;
disconnect, timeout, gateway shutdown, and cancellation terminate the complete
group and verify repository cleanup before capacity is released.

Outbound traffic is denied by default and allowlisted only for the existing OSV
API, GitHub API, GitHub codeload host validated by repository intake, and the
existing OSV-Scanner lookup destination. DNS resolution and redirects remain
bounded by existing destination policy. Cloud metadata, RFC1918, loopback,
link-local, cluster, and arbitrary Internet destinations are denied. The SSH
gateway itself performs no advisory or repository request before TUI admission.

The initial conservative operational limits are:

- at most 10 active SSH sessions globally and 2 per source address;
- at most 2 active investigation workflows globally and 1 per session;
- at most 20 unauthenticated handshakes in progress;
- 15 seconds for handshake/session setup;
- 5 minutes of session inactivity;
- 15 minutes maximum session lifetime; and
- the unchanged 180-second Watchdog workflow deadline.

Connection attempts above 10 per source address per minute are refused using
bounded in-memory state. Source addresses may exist transiently only for active
connection control and a maximum 10-minute rate-limit window. They are not
written to application logs or retained across process restart.

## Host keys, privacy, logs, and operations

SSH host private keys are operator-managed secrets created outside the
repository and image, mounted read-only only into the gateway, never printed or
included in an exception, and readable only by the service identity. Public key
fingerprints must be published over a separately trusted Nexura channel before
launch. Rotation, compromise response, backup, and rollback are documented and
tested before Stage C.

Application logs contain only controlled event codes, coarse duration/resource
buckets, release/configuration identity, and aggregate counters. They contain no
source address, username, advisory identifier, repository URL/ref, commit,
evidence/report/plan ID, repository content, terminal bytes, model data,
credential, key material, or traceback. Access logging is disabled. No session
recording, keystroke logging, analytics, crash-report upload, or third-party
telemetry is permitted.

Before Stage C, the deployment record must audit host, firewall, DNS, cloud,
container, and network-provider logging separately from application logging.
Any unavoidable source-address processing or retention at those layers requires
an explicit purpose, access policy, minimum retention period, deletion path,
privacy notice, and owner approval; an undocumented infrastructure default is a
deployment blocker.

The Stage C deployment record must define health monitoring that does not open a
public endpoint, aggregate capacity/error alerts, patch cadence, dependency and
base-image scanning, host-key expiry/rotation checks, disk/tmpfs exhaustion
alerts, denial-of-service response, incident response, rollback to no listener,
and an operator who can disable the service immediately.

No uptime, confidentiality, anonymity, or security SLA is claimed for the
trial. The privacy notice must explain that source network addresses are
necessarily processed transiently by the network stack and in-memory abuse
controls even though Watchdog does not persist them.

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

Stage B additionally requires protocol-level tests for arbitrary usernames,
none-auth disclosure, host-key verification, one-PTY admission, rejected exec,
subsystems, forwarding, environment, extra channels, malformed packets,
handshake/idle/lifetime limits, disconnect cancellation, process-group cleanup,
global/per-address admission, and controlled logs. Tests must use synthetic
inputs and a literal-loopback listener only.

Stage C requires an isolated staging host review, external SSH-client checks
from at least OpenSSH on Linux/macOS and Windows OpenSSH, public host-key
fingerprint verification, DNS and firewall review, egress-denial proof,
container escape/mount/capability inspection, load/admission testing, abrupt
disconnect and service-restart cleanup, monitoring/alert exercise, and rollback
exercise. Any unperformed environment or client check remains an explicit
coverage limitation.

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
6. **SSH authorization:** owner separately approves Stage B and its exact
   transport/license record.
7. **Loopback prototype:** protocol, isolation adapter, remote profile, and
   abuse controls pass literal-loopback tests with no public listener.
8. **Operations review:** exact hosting, DNS, firewall, host-key, sandbox,
   egress, privacy, monitoring, incident, capacity, and cost records are approved.
9. **Public deployment approval:** owner explicitly authorizes Stage C against
   one immutable image/configuration digest.
10. **Replacement release candidate:** regenerate all locks and package/container
    evidence, run the complete matrix, record exact checksums and limitations,
    and obtain a new final `v0.1.0` publication go/no-go.

No failed, skipped, unavailable, or unperformed gate is passing evidence.

## Acceptance criteria

The work order is complete only when:

1. interactive local `watchdog` and explicit `watchdog tui` provide the bounded
   terminal workflow while non-TTY invocation fails safely;
2. `watchdog ui` and existing web behavior remain unchanged and operable for
   side-by-side comparison;
3. local TUI, web UI, and staged remote TUI agree on all canonical facts,
   identities, coverage, limitations, and remediation candidates;
4. hostile values cannot emit terminal controls, markup, links, clipboard
   operations, commands, or misleading hidden/reordered text;
5. cancellation and disconnect always await verified repository cleanup;
6. the remote service exposes only one anonymous PTY-bound TUI session and no
   shell, command, transfer, subsystem, forwarding, model, preview, persistence,
   or cross-session state;
7. resource, egress, privacy, host-key, logging, monitoring, incident, and
   rollback controls pass their explicit gates;
8. dependencies and deployment inputs are exact, hash/digest pinned, reviewed,
   and represented in release verification; and
9. a replacement Release 1 candidate passes all prior and new gates with new
   checksums before any stable tag or publication.

## Explicitly out of scope

- Removing, rewriting, or deprecating the web UI in this work order.
- A public HTTP TUI, Textual web serving, or browser replacement.
- User accounts, authenticated SSH, teams, tenant data, private repositories,
  uploads, local paths, arbitrary repositories, or credentials.
- Session history, saved reports, databases, queues, jobs, shared caches,
  downloads, clipboard integration, shell access, commands, or patch apply.
- Remote model providers, model credentials, server-side model installation,
  or AI in the anonymous SSH profile.
- More advisory sources, ecosystems, scanners, parser dependencies, source/data-
  flow analysis, classification, reachability, exposure, exploitability,
  compatibility, availability, registry resolution, or automatic remediation.
- The broader AWS/DeepSeek hosted version-two direction.

## Mandatory pause conditions

Pause and amend this work order before:

- changing any canonical report/plan/artifact identity or analytical meaning;
- changing the web UI or `watchdog ui` behavior;
- adding a dependency other than the separately reviewed Textual or SSH
  transport choices;
- accepting private or non-GitHub repository inputs, credentials, files, paths,
  commands, arbitrary environment values, or model configuration over SSH;
- persisting session/user/input/result/network identifiers or adding telemetry;
- widening SSH channels, auth, forwarding, filesystem, process, listener,
  egress, resource, concurrency, timeout, or deployment privileges;
- binding a listener beyond literal loopback before Stage C approval;
- changing DNS, firewall, host keys, cloud/service infrastructure, or public
  availability without the exact deployment record; or
- publishing, tagging, or representing `v0.1.0` as ready before a replacement
  candidate passes.

## Required authorization statement

Implementation must not begin from this draft alone. A future owner instruction
must identify this work order, approve any amendments, explicitly authorize
Stage A against the recorded baseline, and request a formal implementation plan.
Stage B and Stage C each require their own later explicit approval.
