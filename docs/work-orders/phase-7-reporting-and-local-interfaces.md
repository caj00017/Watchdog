# Phase 7 Work Order — Evidence-Safe Reporting and Local Interfaces

**Status:** Authorized and complete; all acceptance gates passed

**Prepared:** July 29, 2026

**Prerequisite:** Satisfied by immutable Phase 6 baseline `02abea5`

**Authority:** On July 29, 2026, the user first authorized this work order as a
planning boundary and later explicitly instructed implementation of the
decision-complete Phase 7 plan. Implementation used `02abea5` as the immutable
Phase 6 baseline and completed the authorized report, workflow, CLI, and local
interface boundary without adding persistence or a new outbound destination.

## Completion finding

The completed Phase 6 boundary has a governing work order, formal implementation
plan, architecture description, active threat controls, evidence/inference
policy, settings reference, adversarial tests, completion recap, and canonical
record. Its final deterministic baseline is 266 passing tests with the bounded
live scanner contract opt-in. The completed service remains internal,
disabled-by-default, credential-free, and restricted to literal loopback.

The Phase 1–6 services provided the validated artifacts for the presentation
layer. Phase 7 now has strict report and request schemas, deterministic bounded
renderers, lease-safe orchestration, a stdout-only CLI, and a separately launched
disabled literal-loopback application. The deterministic completion baseline is
280 passing tests with the existing bounded live scanner contract opt-in.

## Objective

Make the existing one-advisory/one-public-repository workflow usable by a local
operator without weakening the evidence chain. Phase 7 adds:

- one strict canonical investigation-report model assembled only from validated
  Phase 1–6 artifacts;
- deterministic summary and technical projections;
- bounded JSON and escaped Markdown renderers;
- one synchronous end-to-end orchestration service that preserves the existing
  repository lease and cleanup boundary;
- one direct local CLI that writes reports to standard output; and
- one separately launched, disabled-by-default, literal-loopback web application
  containing a minimal same-origin UI and synchronous investigation API.

The phase is a presentation and orchestration boundary, not a new analysis
phase. It must not add evidence, reinterpret missing evidence as absence, broaden
the Phase 6 disposition vocabulary, or claim affected/not-affected status,
runtime/data-flow reachability, exploitability, or deployment exposure.

## Why this phase is separate

Phases 2–6 are deliberately internal. Exposing them through a workflow introduces
new trust and availability concerns even when the interface is local:

- untrusted advisory, repository, evidence, and model text reaches a terminal or
  browser rendering boundary;
- one request can trigger bounded outbound OSV/GitHub/scanner activity and
  relatively expensive repository processing;
- client cancellation must not race repository cleanup;
- a loopback listener is exposed to same-host processes, browser cross-origin
  requests, DNS-rebinding attempts, and operator launch mistakes;
- exports can accidentally erase provenance, partial coverage, or the
  distinction between deterministic facts and model inference; and
- retained jobs, report history, arbitrary output files, or hosted exposure would
  add persistence, authorization, retention, and multi-tenant boundaries.

These risks belong in a reviewed interface phase, not inside existing domain or
analysis services.

## Frozen Phase 1–6 invariants

Phase 7 must consume completed artifacts without changing their meaning or
identity:

- OSV remains the only active advisory source.
- Repository intake remains public `github.com` archive-only intake resolved to
  one exact commit with verified cleanup.
- Every repository read, inventory operation, scanner call, evidence extraction,
  and contextual-analysis operation finishes inside the existing Phase 2 lease.
- Parsers and recognizers remain bounded and data-only; analyzed repository code
  and dependencies are never executed or installed.
- OSV-Scanner remains pinned to 2.4.0 and receives only Watchdog-generated exact
  coordinates plus its trusted empty configuration.
- Phase 4 remains the only source of repository evidence eligible for reports;
  Phase 5 cannot broaden that eligibility or rewrite Phase 4 identities.
- Phase 5 observations remain lexical facts and controlled non-classification
  signals.
- Phase 6 receives no repository access, runs only after verified cleanup, and
  emits untrusted inference rather than evidence.
- Existing canonical artifact IDs, source provenance, coverage, conflicts,
  warnings, omissions, failures, and limitations remain visible and immutable.

Phase 7 must not silently rerun, repair, enrich, downgrade, or replace a supplied
artifact.

## Implemented user boundary

The initial Phase 7 request contains only:

- one allowlisted advisory identifier already accepted by Phase 1;
- one repository URL already accepted by the strict public-GitHub validator;
- an optional repository ref already accepted by `RepositoryRequest`; and
- a controlled output view (`summary` or `technical`) and format (`json` or
  `markdown`).

The request cannot contain an advisory URL, arbitrary source record, local path,
archive, uploaded file, repository content, evidence selector, rule, prompt,
schema, model destination, tool definition, command, output template, stylesheet,
script, or report fragment.

The CLI and local API must construct the same strict `InvestigationWorkflowRequest`
and call the same orchestration service. Neither interface may duplicate or
weaken validation.

## Implemented end-to-end service boundary

The internal orchestration boundary is:

```text
InvestigationWorkflowService.run(
    request: InvestigationWorkflowRequest,
) -> InvestigationReport
```

The CLI and local HTTP adapter use the companion `run_rendered` entry point,
which applies the same admission slot and end-to-end deadline through complete
buffered rendering. It delegates to the same validated workflow and renderer;
it does not create a second analysis path.

The workflow order is fixed:

1. validate the advisory identifier and repository request before any outbound
   or filesystem action;
2. resolve and normalize the advisory through the existing Phase 1 service;
3. acquire one exact repository snapshot through the existing Phase 2 lease;
4. while that lease is active, build the Phase 3 inventory, perform exact
   matching, build Phase 4 evidence, and build Phase 5 context;
5. exit the lease and require verified archive/workspace cleanup;
6. only after cleanup, optionally invoke the existing Phase 6 service according
   to trusted operator configuration; and
7. assemble and validate one bounded report, render the selected representation,
   emit it, and retain no server-side copy.

The orchestrator may coordinate existing services but must not copy their
repository-reading logic. It owns one shared workflow deadline and cancellation
path while preserving every stricter per-phase limit. It must await all active
repository workers and verified cleanup before propagating timeout,
cancellation, client disconnect, or analysis failure.

Advisory resolution may occur before repository acquisition. No Phase 6 model
operation may overlap an active repository lease. Report rendering receives no
repository capability and performs no network or filesystem read.

## Canonical investigation report

The `InvestigationReport` is a strict, frozen, extra-field-forbidden
source-neutral domain model. It contains bounded allowlisted projections,
not copies of raw source or provider payloads:

- report schema, producer, wording-policy, and renderer versions;
- a canonical report ID over the exact validated report content excluding only
  its own ID field;
- normalized advisory identity and allowlisted display facts with field-level
  provenance references;
- canonical repository URL, requested/resolved ref, exact commit and tree SHA,
  archive digest, and snapshot identity without any workspace path;
- exact Phase 3 scanner/tool version and configuration identity;
- relevant dependency matches with their original states and evidence links;
- bounded Phase 4 dependency evidence and Phase 5 lexical observations/signals
  using their existing IDs and already-redacted display content;
- the exact Phase 6 result ID, run status, controlled disposition, claims,
  assumptions, gaps, and validation-action codes when available;
- explicit coverage, conflicts, warnings, omissions, failures, and limitations
  from every contributing phase; and
- deterministic summary and technical section entries, each labeled by source
  category and linked to supporting artifact/evidence/provenance IDs.

The report excludes raw OSV records, complete upstream JSON, raw or omitted
repository content, absolute/temporary paths, environment values, headers,
credentials, prompts, raw model responses, opaque provider identifiers, logs,
tracebacks, and unrelated inventory components.

All IDs and collections must be unique, canonically ordered, and semantically
linked to the same advisory and exact repository snapshot. The report assembler
must revalidate every supplied domain object and canonical identity. Any
cross-snapshot, cross-advisory, stale, unknown, omitted, or broken link fails
before a report is constructed.

Report identity is deterministic for the same validated artifacts,
configuration, wording policy, and renderer-independent report model. It does
not claim that a later model request will reproduce a prior Phase 6 result.

## Facts, findings, inference, and uncertainty

The report must keep these categories structurally and visually distinct:

| Category | Permitted source | Required support |
| --- | --- | --- |
| Target metadata | Validated advisory/snapshot/tool artifacts | Canonical artifact and provenance IDs |
| Deterministic fact | Validated Phase 1 and Phase 3–5 fields | Exact evidence/provenance links |
| Model inference | Validated Phase 6 result only | Original Phase 6 claim and evidence links |
| Assumption | Controlled Phase 6 assumption code | Visible assumption label |
| Coverage gap | Existing coverage/failure/omission state | Visible limitation and causing artifact |
| Validation action | Checked-in controlled action code | Watchdog-authored text and related evidence |

Every vulnerability-relevant assertion must link to evidence or field
provenance. Report section headings, fixed explanatory text, and target/tool
metadata are not findings, but their variable values must retain canonical
artifact linkage.

The report must never:

- convert `not_reported_affected` into “not vulnerable,” “not affected,” “safe,”
  or an equivalent repository-level negative;
- convert lexical non-observation into runtime absence or non-exposure;
- hide scanner failure, unknown versions, unsupported structures, conflicts,
  redaction omissions, truncated envelopes, gateway failure, or partial
  coverage;
- promote a Phase 6 rationale into deterministic fact;
- synthesize new model prose, recommendations, versions, commands, or patches;
  or
- use color, ordering, badges, icons, HTTP status, or process exit status to
  imply a stronger conclusion than the controlled domain state.

The first line of every human-readable report and the primary UI result region
must state that the output is an evidence-bound investigation, not an
affected/not-affected or runtime-exposure determination.

## Deterministic report wording

Plain-English output is produced by checked-in deterministic wording templates,
not by an additional model call. Template selection is controlled only by strict
enums and coverage state. Untrusted values are inserted only as escaped data.

Wording-policy changes are versioned and must have snapshot tests. A wording
template cannot suppress a required limitation or use unsupported
classification terms. Summary and technical projections are views of the same
canonical report; they cannot contain different findings or coverage states.

The summary view provides target identity, exact commit, dependency-match state,
context state, optional visibly labeled Phase 6 inference, material limitations,
and controlled validation actions. The technical view additionally exposes
producer/configuration IDs, provenance, exact evidence links, scanner status,
omission counts, and all bounded warnings. Neither view is a remediation report.

## JSON and Markdown rendering

Renderers accept only a validated `InvestigationReport` and controlled view. They
do not accept arbitrary dictionaries, templates, fragments, paths, or raw model
output.

JSON output must:

- serialize the strict report projection with stable ordering and media type
  `application/json`;
- preserve IDs, enums, provenance, coverage, and limitations without lossy
  display aliases;
- reject non-finite values, duplicate keys, unknown fields, or output over the
  configured byte limit; and
- complete in bounded memory before any response bytes are emitted.

Markdown output must:

- escape Markdown metacharacters, raw HTML, control characters, terminal escape
  sequences, bidirectional-control characters, and hostile link text;
- emit no raw HTML, image, data URI, autolink, executable code block, or
  model-authored Markdown;
- render only validated `http`/`https` advisory references, never fetch them, and
  add plain-text fallbacks for rejected URLs;
- use fixed headings and deterministic ordering; and
- complete in bounded memory before any response bytes are emitted.

Filenames or `Content-Disposition` values, if used for a browser download, must
derive only from the canonical report ID and fixed ASCII text. Repository,
advisory, ref, or model values must never enter a header.

## Direct local CLI

The CLI is a thin adapter over `InvestigationWorkflowService`; it does not call
the local HTTP API or construct shell commands. The implemented form is:

```text
python -m apps.cli investigate \
  --advisory GHSA-... \
  --repository https://github.com/owner/name \
  [--ref REF] \
  [--view summary|technical] \
  [--format json|markdown]
```

The initial CLI writes the fully rendered report to standard output only. It
does not accept an output path, config file, template, prompt, endpoint, token,
or arbitrary environment-variable name. Operators may redirect standard output
under their own shell/file policy; Watchdog itself adds no report persistence.

Diagnostics go to standard error as stable codes and bounded trusted text. They
must not include repository content, model output, headers, credentials,
temporary paths, or tracebacks by default. Untrusted control characters must
never reach the terminal. Exit codes distinguish complete report, invalid input,
upstream/acquisition failure, incomplete analysis/report, and cancellation;
success must not conceal scanner or cleanup failure.

## Loopback web application and investigation API

The web interface is a separate application from `apps/api`. The existing
advisory API and its OpenAPI paths remain unchanged. The Phase 7 application is
disabled by default and must be started through a dedicated launcher that binds
only to a configured literal `127.0.0.1` or `::1` address.

The implemented local surface is deliberately small:

```text
GET  /health
GET  /
GET  /assets/watchdog.css
GET  /assets/watchdog.js
POST /api/v1/investigations
```

The POST is synchronous and returns one bounded JSON or escaped-Markdown report.
There is no create-and-poll job, report lookup, history, evidence browser,
arbitrary artifact endpoint, websocket, server-sent event, upload, or static
directory traversal. Failure before a report is available returns a strict
generic error schema; partial analytical coverage is represented inside the
report rather than disguised as HTTP success metadata.

Local HTTP controls must include:

- literal-loopback bind configuration and startup refusal for hostnames,
  wildcard, unspecified, multicast, link-local, private, public, or Unix-socket
  destinations;
- exact allowlisted `Host` validation including the configured port;
- no CORS response headers and rejection of cross-site `Origin` or
  `Sec-Fetch-Site` values;
- `application/json` plus a fixed custom request header on POST so a cross-origin
  simple browser form cannot trigger analysis;
- strict request-content length and schema before workflow admission;
- one shared bounded concurrency gate and deadline, including queue wait;
- cancellation on client disconnect with awaited repository cleanup;
- `Cache-Control: no-store`, a restrictive Content Security Policy,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, frame denial,
  and no cookies;
- disabled OpenAPI, Swagger UI, and ReDoc routes plus exact fixed asset routes
  rather than a caller-selected static-file path;
- no access-log query/body/header values and generic error responses; and
- no automatic browser launch unless separately reviewed.

Loopback is an operator-local deployment assumption, not authentication. It does
not protect against a malicious same-user process. Binding beyond literal
loopback, running behind a reverse proxy, containers that publish the listener,
remote access, authentication, authorization, TLS, or multi-user hosting require
a separate threat-boundary review.

## Minimal web UI

The UI contains only fields for advisory ID, public GitHub URL, optional ref,
view, and format plus a result display/download action. It is served from
checked-in local assets by the Phase 7 application.

The initial UI must:

- use no CDN, external font, analytics, telemetry, service worker, web worker,
  third-party script, package-manager build, or new frontend dependency;
- send requests only to its exact same origin;
- use DOM `textContent` or equivalent safe property assignment for all variable
  values and never use `innerHTML`, dynamic script, dynamic style, or Markdown-
  to-HTML rendering;
- display the exact commit, report ID, producer/tool versions, evidence links,
  inference labels, and material coverage limitations;
- avoid color-only meaning and remain keyboard/screen-reader usable;
- retain no data in cookies, local storage, session storage, IndexedDB, caches,
  service workers, URL query strings, or browser history; and
- clear result state on navigation or explicit reset.

Repository-relative paths and already-redacted evidence displays may appear only
inside the bounded report. They are text, never browser-fetchable file paths or
route parameters.

## Network and data-egress boundary

Phase 7 adds no outbound destination. The orchestrator may use only the already
reviewed Phase 1–6 adapters and their existing network rules:

- OSV advisory access;
- public GitHub metadata/archive access;
- pinned OSV-Scanner vulnerability lookup over Watchdog-generated exact
  coordinates; and
- the optional disabled-by-default Phase 6 literal-loopback gateway.

The UI ships with no external assets and neither renderer resolves links. The
local listener is inbound-only and disabled by default. Remote model providers,
webhooks, report uploads, telemetry, update checks, URL previews, browser-side
fetches to repository/advisory hosts, and arbitrary destinations are outside the
phase.

## Persistence and lifecycle boundary

The initial phase has no database, queue, background worker, cache, report
history, server-side output file, browser storage, or retained model result.
Validated artifacts and rendered bytes exist only in bounded process memory for
one synchronous request and are released after response/output completion.

An explicit CLI standard-output stream or HTTP response is the only export.
Adding output paths, automatic files, report IDs that can be retrieved later,
resume/replay, caching, jobs, or retention changes the confidentiality and
authorization boundary and requires separate approval.

## Implemented settings and limits

Phase 7 adds a strict `WATCHDOG_WORKFLOW_` and
`WATCHDOG_LOCAL_INTERFACES_` configuration boundary. Initial ceilings are:

| Limit | Implemented default | Meaning |
| --- | ---: | --- |
| Local interfaces enabled | `false` | No listener unless explicitly enabled |
| Local host | `127.0.0.1` | Literal loopback only; `::1` also allowed |
| Local port | `8765` | Fixed trusted integer configuration |
| Concurrent workflows | `1` | Shared maximum per process, including CLI/service instances |
| Workflow deadline | 180 seconds | Admission through report rendering and cleanup |
| Request body | 8,192 bytes | Maximum local API request bytes |
| Advisory identifier | 128 bytes | Maximum normalized user input |
| Repository URL | 2,048 bytes | Still subject to strict GitHub validation |
| Repository ref | 255 bytes | Existing `RepositoryRequest` ceiling |
| Canonical report JSON | 1,048,576 bytes | Maximum validated report/export bytes |
| Markdown report | 1,048,576 bytes | Maximum fully rendered Markdown bytes |
| Report entries | 1,024 | Maximum combined bounded section entries |
| Report evidence references | 2,048 | Maximum included citation references |
| Report warnings/limitations | 512 | Maximum visible controlled diagnostics |
| Static UI assets | 262,144 bytes | Maximum total checked-in asset bytes |

All existing Phase 1–6 limits remain independently controlling. Phase 7 cannot
raise them through orchestration or configuration aliases. Report selection must
be deterministic when its own limit is reached and must record exact omission
counts plus incomplete-report status. Output overflow fails before any partial
JSON/Markdown is emitted.

## Failure semantics

Expected workflow states remain explicit and typed:

- invalid advisory or repository input fails before outbound activity;
- advisory not found/unavailable and repository resolution/acquisition failure
  produce no fabricated report;
- inventory, scanner, matching, evidence, or context partial state may produce a
  visibly incomplete report only when all returned artifacts remain valid;
- cleanup failure prevents Phase 6 and report generation and is never hidden;
- disabled, unavailable, timed-out, invalid, rejected, or cancelled Phase 6
  inference leaves deterministic Phase 1–5 results intact and appears as an
  explicit model-section status;
- report-link disagreement or rendering overflow invalidates the report; and
- cancellation or client disconnect waits for repository workers and cleanup
  before returning.

Scanner or source failure must never be represented as “not affected.” A report
can be successfully rendered yet analytically incomplete; its report status,
CLI exit code, primary UI banner, and limitation section must all preserve that
distinction.

## Logging and confidentiality

Logs and generic errors may contain stable error codes, trusted producer/config
identities, canonical report/envelope/bundle IDs, durations, and bounded numeric
counts. They must not contain request bodies, advisory prose, repository URLs or
refs, evidence displays, report text, model text, headers, browser origins,
credentials, absolute paths, archive paths, or raw exceptions whose messages
could include those values.

Access logs must be disabled or replaced with a controlled structured event that
omits path parameters, query strings, headers, bodies, and response content.
Report output is intentionally visible to the requesting local operator but is
not also copied to logs or telemetry.

## Implemented modules

```text
watchdog/domain/reports.py
watchdog/reporting/identifiers.py
watchdog/reporting/limits.py
watchdog/reporting/assembler.py
watchdog/reporting/report_json.py
watchdog/reporting/report_markdown.py
watchdog/reporting/renderers.py
watchdog/workflow/__init__.py
watchdog/workflow/errors.py
watchdog/workflow/limits.py
watchdog/workflow/runtime.py
watchdog/workflow/service.py
apps/cli/__init__.py
apps/cli/__main__.py
apps/web/__init__.py
apps/web/__main__.py
apps/web/main.py
apps/web/security.py
apps/web/routes.py
apps/web/static/index.html
apps/web/static/watchdog.css
apps/web/static/watchdog.js
```

The domain report model remains independent of FastAPI, terminal handling, and
HTML. The assembler, renderers, orchestrator, CLI, HTTP security controls, and UI
assets stay separate. `apps/api` remains unchanged.

## Completed implementation sequence

1. Record explicit implementation authorization, review/commit the Phase 6
   baseline, and freeze Phase 7 request/report/status/wording vocabularies.
2. Add strict report domain models, configuration, canonical identities, and
   same-input semantic validation with no renderer, workflow, or interface.
3. Add the deterministic bounded report assembler and prove that every finding,
   inference, limitation, and action retains exact Phase 1–6 support.
4. Add JSON and escaped-Markdown renderers with adversarial terminal/Markdown/
   HTML/control-character tests and no I/O behavior.
5. Add the internal workflow orchestrator with fakes; verify fixed ordering,
   shared deadline, Phase 2–5 lease containment, verified cleanup, and Phase 6
   invocation only after cleanup.
6. Add the direct standard-output CLI and fixed diagnostics/exit codes without
   adding filesystem output or HTTP indirection.
7. Add the disabled loopback application shell, bind/Host/origin/request-header/
   resource controls, and synchronous API using fake workflows.
8. Add the checked-in dependency-free UI and verify safe DOM rendering,
   accessibility, same-origin behavior, and absence of browser persistence or
   external requests.
9. Integrate the real local workflow, run end-to-end hostile-fixture and
   cancellation tests, reproduce whole-project/container gates, synchronize all
   documentation, and publish a dated recap before declaring Phase 7 complete.

Each step is a mandatory exit gate. Interface work cannot begin until report and
workflow semantics are accepted, and real outbound adapters cannot be exercised
through the interface until its abuse-case tests pass with fakes.

## Required tests

### Report schema and identity

- strict extra-field rejection, immutability, controlled enums, string/list/byte
  ceilings, canonical ordering, and report/configuration/wording identities;
- duplicate, fabricated, omitted, cross-advisory, cross-snapshot, stale, or
  semantically unrelated artifact/evidence/provenance IDs;
- stable report identity and output for the same exact validated artifacts,
  including a fixed Phase 6 result;
- Phase 1–6 canonical inputs remain byte-for-byte unchanged after assembly.

### Evidence and classification policy

- every deterministic finding cites eligible Phase 1/3/4/5 support and every
  inference retains its Phase 6 evidence links;
- assumptions, gaps, actions, conflicts, omissions, failures, and partial state
  remain separate and visible in both views/formats;
- exhaustive mapping of scanner/context/model states to approved wording;
- no wording, enum, badge, HTTP status, or exit code can represent affected/not-
  affected, runtime reachability, exploitability, exposure, remediation, command,
  or patch state;
- negative/non-observation language always carries explicit coverage limits.

### Renderer safety

- hostile Markdown, HTML, URLs, Unicode, bidirectional controls, ANSI/terminal
  escapes, very long values, embedded newlines, and prompt-like text remain data;
- no raw HTML, executable link, image, code block, response-header injection,
  terminal control, or partial output;
- JSON and Markdown byte caps, stable ordering, summary/technical consistency,
  and deterministic omission counts;
- no renderer reads files, resolves URLs, calls a model, or logs report content.

### Workflow and cleanup

- fixed Phase 1 → lease-scoped Phase 2–5 → verified cleanup → optional Phase 6 →
  report order;
- Phase 6 is never called while the repository exists and report rendering has
  no repository path/capability;
- timeout, cancellation, client disconnect, worker failure, scanner failure,
  cleanup failure, invalid Phase 6 output, and renderer failure;
- one shared admission limit with no deadlock or orphan task;
- no repository execution, dependency installation, extra subprocess, or new
  outbound destination.

### CLI

- strict arguments and no arbitrary path/template/prompt/model controls;
- report bytes only on stdout and generic bounded diagnostics only on stderr;
- stable exit codes that distinguish complete, incomplete, failed, and cancelled
  workflows;
- hostile values cannot inject terminal controls, extra arguments, logs, or
  commands.

### Local API and browser boundary

- disabled-by-default startup; literal IPv4/IPv6 loopback acceptance and
  wildcard/hostname/non-loopback rejection;
- exact Host validation, cross-origin and DNS-rebinding attempts, CORS absence,
  custom-header preflight behavior, wrong content type, oversized body, schema
  rejection, rate/concurrency bounds, timeout, and disconnect cleanup;
- exact five-route surface, security/cache headers, generic errors, no cookies,
  no access-log data, no history/job/evidence/dynamic-static-path route;
- UI uses only local checked-in assets, same-origin requests, safe text sinks,
  accessible labels/status, no external URL, no browser storage, and no dynamic
  HTML/script/style;
- malicious report content cannot execute script, navigate the browser, trigger
  a network fetch, or alter interface controls.

### Whole-project regression

- the existing `apps/api` OpenAPI paths remain exactly `/health` and
  `/api/v1/advisories/{identifier}`;
- scanner pin/input/environment/network behavior, Phase 4/5 identities, Phase 6
  envelope/prompt/policy/gateway behavior, and dependencies remain unchanged;
- no database, queue, cache, worker, remote provider, credentials, private-repo
  support, patch behavior, or production listener appears;
- Ruff format/lint, strict mypy, deterministic pytest, compileall, Compose
  validation, standalone image build, no-mount health, scanner 2.4.0 check, and
  relevant no-network/local-interface container tests pass.

## Acceptance criteria

Phase 7 was marked complete only after:

1. One strict request drives exactly one bounded one-advisory/one-public-
   repository workflow using only existing validated service boundaries.
2. Every Phase 2–5 repository operation finishes inside the lease and verified
   cleanup completes before any Phase 6 or report work.
3. The canonical report contains only allowlisted validated Phase 1–6 data,
   preserves all identities and uncertainty, and links every finding to evidence
   or provenance.
4. Deterministic fact, model inference, assumption, gap, limitation, and
   validation action are structurally and visually distinct.
5. Summary/technical and JSON/Markdown views cannot disagree about findings,
   status, coverage, or limitations.
6. No output vocabulary or presentation implies affected/not-affected status,
   runtime/data-flow reachability, exploitability, deployment exposure,
   remediation, executable commands, or patches.
7. Hostile values cannot inject Markdown/HTML/script/terminal controls, headers,
   links, logs, arguments, prompts, or interface state.
8. The CLI is direct, bounded, stdout-only, and signals analytical incompleteness
   without hiding valid deterministic results.
9. The separate web application is disabled by default, literal-loopback only,
   same-origin, synchronous, non-persistent, dependency-free, and protected
   against cross-origin browser triggering and resource exhaustion.
10. Timeout, cancellation, disconnect, scanner failure, cleanup failure, model
    failure, and rendering failure remain explicit and fail closed.
11. Phase 7 adds no outbound destination, credential, persistence, background
    job, uploaded input, arbitrary path, provider, parser, or executable action.
12. Existing dependencies, public advisory API, scanner boundary, Phase 4–6
    canonical behavior, tests, and container verification remain green.
13. Architecture, threat model, evidence policy, operator guidance, AGENTS,
    canonical record, tests, and a dated completion recap accurately describe
    the implemented boundary before completion is declared.

## Mandatory pause and escalation conditions

Implementation must pause for a separate explicit review before:

- binding any interface to a hostname, wildcard, non-loopback address, Unix
  socket, reverse proxy, container-published port, or remote network;
- adding authentication, authorization, cookies, sessions, credentials, TLS,
  hosted or multi-user behavior, private repositories, or tenant separation;
- adding persistence, output files, caches, jobs, queues, report history,
  retrieval/resume/replay, browser storage, telemetry, or report upload;
- adding a remote model provider, API key, retry/fallback, new destination,
  webhook, external UI asset, browser-side third-party request, or new
  dependency;
- adding an advisory URL, uploaded archive/file, local repository path, Git
  clone, arbitrary evidence selector, caller-selected rule/prompt/schema/model,
  or output template;
- adding affected/not-affected, runtime/data-flow reachability, exploitability,
  deployment exposure, risk score, remediation, upgrade, command, script,
  validation execution, code generation, or patch vocabulary;
- changing repository intake, inventory/parsers, scanner or OSV-Scanner 2.4.0,
  Phase 4 evidence eligibility/redaction, Phase 5 recognition, Phase 6 prompt/
  policy/gateway, or any existing canonical identity; or
- exposing full canonical internal bundles, raw upstream records, omitted/raw
  content, provider responses, secrets, or operational paths through an export
  or interface.

## Explicitly deferred

Public/remote or production interfaces, hosted deployment, authentication,
private repositories, advisory URLs, uploads, local-path repositories, durable
reports, background jobs, queues, caches, report history, evidence browsing,
remote providers, credentials, retries/fallbacks, telemetry, external UI assets,
new frontend frameworks, SBOM generation, broader parsers, source-to-sink/runtime
reachability, exploitability, deployment exposure, affected/not-affected
classification, risk scoring, remediation guidance, upgrade commands,
executable validation, code generation, and patch previews remain outside this
implemented initial Phase 7 boundary.

The separate Phase 8 remediation-assistant work order is now planning-only;
Phase 8 implementation remains unapproved. This Phase 7 work order creates no
later-phase implementation authority by itself.
