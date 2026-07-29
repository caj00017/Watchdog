# Phase 6 Proposed Work Order — Evidence-Bound Model Investigation

**Status:** Ready for explicit authorization review; implementation is not authorized

**Prepared:** July 28, 2026

**Readiness reviewed:** July 29, 2026

**Prerequisite:** Completed Phase 5 deterministic contextual analysis

**Authority:** The user requested a Phase 6 work order and a documentation
status pass on July 28, 2026, then requested a Phase 5 completion and Phase 6
readiness audit on July 29, 2026. Those requests authorize planning,
reconciliation, and readiness review, not runtime model integration.
Implementation requires separate explicit authorization and synchronized
updates to `AGENTS.md`, the canonical project record, architecture, threat
model, and evidence policy.

## Readiness finding

The July 29 review confirmed the prerequisite Phase 5 boundary against its work
order, tightened the remaining fail-closed gaps, synchronized active
documentation, and reproduced the deterministic and container acceptance gates.
The Phase 1–5 inputs required by this proposal are therefore available as strict
internal domain objects, and the proposed Phase 6 scope is sufficiently bounded
for an explicit implementation-authorization decision.

This is a readiness finding only. Until that separate authorization is granted,
the implementation sequence below must not begin and no Phase 6 model schema,
prompt, gateway, setting, network behavior, or result may be added.

## Objective

Add a separate internal investigation service that asks a model to synthesize a
bounded, redacted, evidence-linked view of one advisory and one repository
snapshot. The service may identify supported dependency/context relationships,
state assumptions and missing evidence, and select controlled follow-up
validation steps. It must never treat the model as a scanner or evidence source.

Phase 6 consumes only already-validated Phase 1 and Phase 3–5 domain objects. It
does not receive an acquired repository, filesystem path, archive, raw source
record, scanner subprocess handle, or repository lease. Phase 2–5 cleanup may
finish before a model request begins.

The initial result remains an evidence-bound investigation synthesis. It does
not claim runtime/data-flow reachability, exploitability, deployment exposure,
or repository affected/not-affected status.

## Why this phase is separate

Phase 5 is deterministic and lexical. A model call adds nondeterministic output,
prompt-injection risk, a new response-validation boundary, possible data egress,
availability and cost failure modes, and new operator configuration. Those
risks must not be hidden inside `ContextService`, and model output must not
rewrite deterministic Phase 1–5 evidence or identities.

Phase 6 therefore requires its own input envelope, producer/configuration
identity, gateway protocol, strict response schema, semantic validator, run
status, and inference/evidence separation. The service remains internal until a
later interface phase reviews authentication, retention, authorization, and
presentation.

## Proposed service boundary

The proposed internal boundary is:

```text
InvestigationService.investigate(
    advisory,
    inventory,
    match_report,
    evidence_bundle,
    context_bundle,
) -> InvestigationResult
```

Before constructing model input, the service must verify:

- the inventory, match report, Phase 4 bundle, and Phase 5 bundle refer to the
  same exact repository snapshot;
- the advisory identifier and affected-package components correspond to the
  match report;
- every Phase 4 and Phase 5 item, match link, observation, graph edge, signal,
  configuration digest, and bundle ID passes its existing strict schema and
  canonical identity validation;
- every repository evidence ID exposed to the model belongs to the supplied
  canonical bundles; and
- partial, unsupported, unknown, scanner-failed, omitted, redaction-failed, and
  coverage-limited states remain explicit.

Input disagreement must fail before any model gateway is invoked.

## Proposed implementation boundary

If separately authorized, the initial implementation may:

- add strict source-neutral models for the model-input envelope, gateway
  request, validated model draft, investigation claims, run status, coverage,
  and final result;
- create a deterministic bounded envelope from allowlisted normalized advisory
  facts, exact match state, Phase 4 evidence, Phase 5 context evidence/signals,
  and their coverage limitations;
- send that envelope to an injected provider-neutral `ModelGateway`;
- include one disabled-by-default loopback-only OpenAI-compatible gateway using
  the existing HTTP dependency and no provider credentials;
- accept one bounded non-streaming JSON response with no tool calls;
- strictly validate syntax, schema, controlled vocabulary, evidence links, and
  disposition preconditions before constructing any outward result;
- return explicit unavailable, timeout, invalid-response, incomplete-input, and
  cancelled run states; and
- content-address the exact validated result and record the input-envelope,
  prompt, policy, gateway, model, and parameter versions used.

The initial implementation may not:

- accept an `AcquiredRepository`, repository path, caller-selected source
  content, arbitrary evidence, prompt, system instruction, schema, tool, or
  function definition;
- read the repository, extend Phase 4/5 eligibility, rerun analysis, execute
  repository code, install dependencies, invoke a subprocess, or call an
  ecosystem tool;
- send raw OSV source records, unredacted content, omitted content, complete
  repository files, archives, temporary paths, environment variables, secrets,
  credentials, or unrelated inventory components to a model;
- use a remote hosted provider, hostname-based endpoint, redirect, proxy,
  provider file API, image/audio input, embedding endpoint, web search, tool
  calling, streaming response, or model-selected URL;
- persist prompts, request bodies, responses, results, or repository data;
- expose a public or private HTTP route, CLI workflow, web UI, evidence browser,
  background job, queue, cache, telemetry export, or hosted multi-tenant path;
- emit runtime reachability, data-flow reachability, exploitability, deployment
  exposure, `confirmed_affected`, `likely_affected`, `probably_not_affected`, or
  `not_affected` classifications;
- generate remediation advice, package commands, executable validation scripts,
  code changes, or patch previews; or
- change the Phase 3 scanner, OSV-Scanner 2.4.0 pin/input/network behavior,
  Phase 4 evidence, Phase 5 catalog/recognizers, or any existing canonical ID.

## Trust and data classification

The fixed system instruction, response schema, policy rules, and operator-owned
model configuration are trusted control data. Advisory prose, package values,
paths, selectors, redacted display text, context observations, and all model
output remain untrusted data.

Redaction lowers disclosure risk but does not make repository content trusted.
Prompt delimiters and instructions are defense in depth only; correctness must
come from strict output validation and deterministic policy gates.

The model is never permitted to supply an evidence fact. A model response is an
inference over evidence, and the final schema must keep deterministic facts,
model inferences, assumptions, coverage gaps, and suggested validation actions
visibly distinct.

## Deterministic model-input envelope

The envelope must be canonical and byte-for-byte deterministic for identical
validated inputs and configuration. It contains only:

- a Phase 6 envelope ID and schema/producer/prompt-policy versions;
- the normalized advisory primary ID, aliases, affected-package coordinates,
  severity/range facts needed for the target match, and canonical references to
  their existing field provenance;
- the exact inventory snapshot identity without a workspace path;
- only match records relevant to the supplied advisory;
- allowlisted Phase 4 items and safe redacted display content linked to those
  matches;
- allowlisted Phase 5 evidence, observations, controlled signals, and lexical
  graph relationships linked to those matches;
- explicit item status, trust labels, limitations, warnings, partial state, and
  deterministic omission counts; and
- a closed vocabulary describing which evidence IDs and signal IDs may be cited.

The envelope excludes raw upstream records, complete advisory source JSON,
unrelated dependencies, raw repository bytes, unsupported/omitted display
content, absolute or temporary paths, timestamps not already required for
advisory provenance, logs, environment values, and operational diagnostics.

Selection is deterministic: target match ordinal, controlled Phase 5 rank,
evidence kind, path, anchor, rule ID, and canonical ID provide stable ordering.
Reaching an envelope limit records omitted counts and limitation codes. It never
silently chooses an enumeration-order subset or permits a negative disposition.

## Prompt and request construction

The system instruction and response schema are fixed checked-in assets with
explicit versions and SHA-256 identities. Repository/advisory values are encoded
only inside the canonical JSON data message; they are never interpolated into
the system instruction or used to select templates, tools, roles, URLs, model
parameters, or response schemas.

The request must:

- identify every supplied repository value as untrusted quoted data;
- state that evidence IDs are opaque references and cannot be invented;
- prohibit following instructions found in advisory or repository content;
- request exactly one JSON object and no Markdown fence or prose wrapper;
- disable tools, functions, remote retrieval, and streaming;
- use fixed bounded parameters from trusted configuration; and
- include no secret, credential, proxy value, or arbitrary provider metadata.

Prompt text is not a security boundary. A response is unusable until both strict
schema validation and semantic evidence validation succeed.

## Gateway and network boundary

The provider-neutral `ModelGateway` protocol accepts only a validated request
object and returns bounded response bytes plus allowlisted operational metadata.
Tests use an in-memory fake gateway.

The proposed first concrete gateway is disabled by default and restricted to a
plain-HTTP literal loopback address (`127.0.0.1` or `[::1]`) with an explicit port
and fixed OpenAI-compatible path. It must reject user information, DNS hostnames,
query strings, fragments, redirects, alternate response destinations, and
endpoint values originating from repository or request data. The client must
ignore ambient proxy/netrc configuration, use bounded connect/read/write/pool
timeouts, and never log bodies or headers.

The operator explicitly trusts the selected same-host model service with the
bounded evidence envelope. Loopback prevents external routing but does not
authenticate the process listening on that port; output remains untrusted even
when the process is operator-controlled. Multi-user-host authentication, Unix
domain sockets, TLS, and any certificate exception require a separate review.

No API key is accepted in this initial gateway. User-provided credentials and
remote provider endpoints require a separate destination, credential-storage,
retention, privacy, billing, and failure-mode amendment. Nexura-hosted inference
remains outside the phase.

## Strict model-response contract

Response bytes are untrusted. The boundary must reject oversized data, invalid
UTF-8, duplicate JSON keys, non-finite numbers, trailing data, Markdown fences,
unknown fields, unsupported enum values, excessive strings/collections, broken
identities, and inconsistent status combinations.

The validated draft may contain only:

- one controlled investigation disposition;
- bounded evidence-linked claims with a controlled claim kind;
- bounded assumptions and missing-evidence codes;
- bounded references to controlled validation-action codes; and
- an optional bounded rationale for each claim that remains clearly labeled as
  model-generated inference.

Every claim must cite at least one evidence ID included in the envelope. Claims
about contextual observations must cite Phase 5 evidence and their supporting
Phase 4 dependency evidence. Advisory claims must cite canonical advisory
provenance references. Unknown, omitted, cross-snapshot, or non-envelope IDs
invalidate the entire response; the service must not repair or partially accept
it.

Raw provider output and provider-generated identifiers must not enter the final
domain model, logs, exceptions, or canonical result. The validated structured
fields are content-addressed after validation. Because model generation is
nondeterministic, the result identity attests to one exact validated output; it
does not claim that repeated calls produce the same result.

## Controlled dispositions and policy gates

The initial vocabulary is deliberately narrower than a vulnerability exposure
classification:

- `dependency_match_and_context_observed`;
- `dependency_match_context_unconfirmed`;
- `insufficient_evidence`; and
- `unsupported`.

Deterministic code, not the model, enforces eligibility:

- `dependency_match_and_context_observed` requires a supported exact dependency
  match plus at least one positive Phase 5 context observation with valid Phase
  4/5 evidence links;
- `dependency_match_context_unconfirmed` requires a supported dependency match
  but never converts missing or partial context into absence;
- any scanner failure, unknown version, unsupported advisory component, broken
  linkage, omitted decisive evidence, partial Phase 4/5 coverage, or Phase 6
  envelope truncation permits only `insufficient_evidence` or `unsupported` as
  applicable; and
- `unsupported` requires a deterministic unsupported state in the validated
  inputs.

An ineligible disposition invalidates the entire response. No output vocabulary
represents “not affected,” runtime absence, non-exposure, or safe deployment.
The broader classifications listed in the product roadmap remain deferred until
a later work order defines sufficient deterministic prerequisites and negative-
finding coverage policy.

## Validation actions

The model may select only checked-in action codes such as reviewing a cited call
site, confirming deployment-specific conditions, checking runtime configuration,
or obtaining missing lockfile evidence. Watchdog supplies the user-facing text
for those codes.

Phase 6 does not accept or emit shell commands, package-manager invocations,
scripts, code blocks, file edits, upgrade versions, or patches. Model-selected
actions are suggestions for human investigation, never executable instructions.

## Proposed limits

The implementation must add `WATCHDOG_INVESTIGATION_` settings and a strict
configuration model. Proposed initial defaults are:

| Limit | Default | Meaning |
| --- | ---: | --- |
| Enabled | `false` | No model request unless an operator explicitly enables it |
| Deadline | 60 seconds | Complete gateway request and response-validation deadline |
| Concurrent requests | 1 | Maximum requests per service instance |
| Input envelope | 262,144 bytes | Maximum canonical model-input JSON |
| Output response | 65,536 bytes | Maximum raw response bytes read |
| Included evidence items | 256 | Maximum Phase 4/5 items supplied |
| Claims | 64 | Maximum validated claims |
| Evidence links per claim | 32 | Maximum citations on one claim |
| Assumptions | 32 | Maximum controlled assumptions |
| Missing-evidence codes | 64 | Maximum explicit gaps |
| Validation actions | 32 | Maximum controlled follow-up actions |
| Rationale bytes per claim | 2,048 | Maximum UTF-8 model rationale |
| Provider output tokens | 4,096 | Fixed requested output ceiling |

Schema ceilings must also cap endpoint/model identifiers, messages, strings,
collections, and metadata. Byte limits are enforced locally; provider token
limits are defense in depth and must not be treated as exact accounting.

Limit exhaustion produces an explicit incomplete run. Input selection may
continue only under canonical bounded ordering and must record omitted counts.
Output overflow invalidates the response and never returns a truncated JSON
object.

## Failure, logging, and cancellation

Disabled configuration, connection failure, timeout, cancellation, response
overflow, invalid response, evidence-link failure, and policy-gate failure are
distinct controlled run statuses. They never become a clean negative assessment
and never cause a fallback provider request.

Initial implementation performs one request and no automatic retry. Cancellation
must close/abort the HTTP operation and await worker/client termination before
returning. Phase 6 has no repository lease or raw repository buffer to retain.

Logs and exceptions may contain only stable error codes, the trusted gateway
kind, model configuration digest, envelope/result IDs, and bounded numeric
counts. They must not contain prompts, evidence display text, model response
text, headers, endpoint credentials, provider opaque IDs, or repository paths.

## Proposed modules

```text
watchdog/domain/investigation.py
watchdog/investigation/identifiers.py
watchdog/investigation/limits.py
watchdog/investigation/envelope.py
watchdog/investigation/prompts.py
watchdog/investigation/gateway.py
watchdog/investigation/loopback.py
watchdog/investigation/validation.py
watchdog/investigation/policy.py
watchdog/investigation/service.py
```

The domain module remains provider-neutral. Envelope selection, prompt assets,
transport, response validation, policy gates, and orchestration remain separate
so no provider response type crosses into the domain layer.

## Proposed implementation sequence

1. Record explicit implementation authorization and freeze the disposition,
   claim, validation-action, limit, and configuration vocabulary.
2. Add strict domain/configuration/identity models and tests with no prompt or
   gateway behavior.
3. Add same-input validation and deterministic bounded envelope construction.
4. Add versioned fixed prompt assets and request serialization tests.
5. Add the gateway protocol and in-memory fake; exercise response schema and
   evidence-link validation without network access.
6. Add deterministic disposition policy gates and adversarial response tests.
7. Add the disabled-by-default loopback-only adapter with destination, proxy,
   redirect, timeout, output, cancellation, and logging tests.
8. Integrate the internal service, verify no repository access or retained raw
   response, and synchronize all documentation.
9. Run the complete acceptance matrix and add a dated completion recap before
   marking Phase 6 complete.

Each step is a reviewable security-boundary change. Later steps must not weaken
schema, evidence, destination, or failure controls established earlier.

## Required tests

### Schema and identity

- extra-field rejection, immutability, string/list bounds, controlled enums,
  canonical ordering, and configuration/envelope/result identity;
- duplicate IDs/keys, broken evidence links, cross-snapshot input, stale bundle
  identity, producer/configuration disagreement, and invalid status combinations;
- explicit proof that result identity binds one validated output without
  claiming cross-request determinism.

### Envelope and confidentiality

- only advisory-relevant matches/evidence enter the envelope;
- raw OSV records, unrelated dependencies, omitted/raw content, temporary paths,
  environment values, and synthetic secrets are absent from request objects,
  bytes, errors, and logs;
- deterministic selection, stable omitted counts, byte/item caps, partial input,
  Unicode, controls, and hostile prompt-like repository/advisory text;
- Phase 4/5 canonical bytes and IDs remain unchanged.

### Response and policy

- valid controlled drafts plus malformed UTF-8/JSON, duplicate keys, trailing
  data, Markdown fences, unknown fields/enums, excessive nesting/collections,
  non-finite values, invented/cross-snapshot evidence IDs, and inconsistent
  links;
- prompt-injection attempts requesting tools, secrets, unsupported conclusions,
  fabricated citations, or executable actions fail validation;
- every disposition gate across affected, conditional, not-reported, unknown,
  scanner-incomplete, unsupported, partial-evidence, partial-context, and
  envelope-truncated inputs;
- no accepted enum or action can represent affected/not-affected, runtime/data-
  flow reachability, exposure, remediation, command execution, or patching.

### Gateway and lifecycle

- disabled-by-default behavior and no gateway call on invalid input;
- literal loopback acceptance plus rejection of DNS names, non-loopback IPs,
  userinfo, queries, fragments, redirects, proxies, and model-selected URLs;
- fixed method/path/body, no tools/streaming, bounded request/response, timeout,
  cancellation, connection failure, and no retry/fallback;
- no request/response/header/evidence text in logs or exception messages;
- no filesystem, repository lease, subprocess, persistence, scanner, or external
  network interaction.

### Whole-project regression

- exact unchanged public OpenAPI paths;
- no new route, CLI/web workflow, database/job/cache, parser dependency, scanner
  behavior, or Phase 4/5 canonical output;
- Ruff formatting/lint, strict mypy, deterministic tests, bytecode compilation,
  Compose validation, and relevant no-network container smoke tests.

## Acceptance criteria

Phase 6 may be marked complete only when:

1. The service accepts only validated, same-snapshot Phase 1 and Phase 3–5
   objects and never receives repository access.
2. The model sees only a bounded deterministic envelope containing redacted,
   allowlisted, explicitly untrusted evidence and coverage state.
3. Every accepted claim links to valid envelope evidence and preserves the
   distinction between fact, inference, assumption, gap, and action.
4. Strict syntax, schema, semantic-link, and policy validation happens before any
   model output enters a domain result.
5. Partial/unknown/unsupported/failure state remains explicit and cannot produce
   a negative vulnerability or exposure conclusion.
6. The initial vocabulary cannot represent affected/not-affected status,
   runtime/data-flow reachability, exploitability, deployment exposure,
   remediation commands, or patches.
7. The only concrete gateway is disabled by default, loopback-only,
   proxy-independent, redirect-free, credential-free, bounded, and tested.
8. Prompt, evidence, response, headers, secrets, paths, and opaque provider data
   never enter logs, exceptions, persistence, or unrelated outputs.
9. Existing Phase 1–5 identities, behavior, scanner pin/input/egress, public
   routes, dependencies, and container boundary remain unchanged.
10. Security documentation, operator guidance, tests, and a completion recap
    accurately describe the implemented boundary before completion is declared.

## Mandatory pause and escalation conditions

Implementation must pause for a separate explicit review before:

- adding a remote or hostname-based provider, API key, credential store,
  provider SDK, new dependency, certificate exception, proxy, redirect, retry,
  fallback model, or additional outbound destination;
- sending new fields, raw records, omitted/raw repository content, full files,
  archives, or unrelated inventory data to a model;
- enabling tools, function calls, streaming, multimodal input, embeddings,
  retrieval, web search, provider files, or model-selected URLs;
- adding persistence, caching, telemetry export, jobs, queues, public/private
  routes, CLI/web interfaces, authentication, hosted/multi-tenant behavior, or
  private repository data;
- adding or changing affected/not-affected, reachability, exploitability,
  exposure, remediation, command, or patch vocabulary;
- permitting model-authored prompts, schemas, validation code, search targets,
  evidence selectors, or executable actions; or
- modifying repository intake, inventory, scanner behavior, OSV-Scanner 2.4.0,
  Phase 4 evidence, Phase 5 analysis, or their canonical identities.

## Explicitly deferred

Remote BYOK providers, Nexura-hosted inference, credentials, private repository
content, prompt/result persistence, jobs, retries, fallbacks, model routing,
streaming, tools, retrieval, embeddings, multimodal input, source-to-sink or
runtime reachability, deployment context, exposure and affected/not-affected
classification, reports, investigation APIs, CLI/web UI, remediation guidance,
package commands, executable validation, and patch previews remain outside this
proposed initial Phase 6 boundary.
