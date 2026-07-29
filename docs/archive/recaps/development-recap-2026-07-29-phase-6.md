# Development Recap — July 29, 2026 — Phase 6 Completion

## Outcome

Phase 6 is complete within the authorized evidence-bound model-investigation
boundary. The internal `InvestigationService` consumes only revalidated Phase 1
and Phase 3–5 artifacts after repository cleanup. It has no repository, route,
CLI, persistence, credential, remote-provider, remediation, or patch capability.

## Implemented boundary

- Strict immutable investigation envelope, claim, response, run-status,
  coverage, configuration, producer, and result models with canonical SHA-256
  identities.
- Deterministic bounded selection of allowlisted advisory provenance, relevant
  matches, redacted Phase 4/5 evidence, Phase 5 observations, lexical graph
  relationships, signals, and explicit omission/partial state.
- Fixed versioned system instruction and strict JSON Schema; hostile values
  appear only in the canonical JSON data message.
- Duplicate-aware JSON parsing, schema/bounds enforcement, exact related Phase
  4/5 citations, controlled assumption/gap/action codes, and deterministic
  disposition gates.
- Provider-neutral gateway injection plus one disabled-by-default,
  credential-free, literal-loopback OpenAI-compatible adapter with no tools,
  streaming, proxy/netrc, redirects, retry, or fallback.
- Explicit disabled, incomplete, unavailable, timeout, overflow, invalid,
  evidence-failed, policy-rejected, cancelled, and completed run states.

The implemented dispositions are limited to dependency match plus observed
context, dependency match with context unconfirmed, insufficient evidence, and
unsupported. They cannot express affected/not-affected status, runtime/data-flow
reachability, exploitability, deployment exposure, remediation, commands, or
patches.

## Verification

- 266 deterministic tests pass; one bounded live OSV-Scanner contract remains
  intentionally opt-in and skipped by default.
- The Phase 6 addition contributes 23 focused unit, integration, and security
  tests covering deterministic envelopes, strict structured output, hostile
  prompt text, fabricated/cross-linked citations, policy matrices, destination
  restrictions, overflow, no retry, concurrency, cancellation cleanup, and
  sensitive response handling.
- Ruff formatting and lint pass; strict mypy passes for 127 source files;
  application and test bytecode compilation pass.
- OpenAPI remains exactly `/health` and
  `/api/v1/advisories/{identifier}`; Docker Compose validates.
- A fresh image built with ID
  `sha256:ca3e5ea6b9c9d9495de444fda10a1e823d2ffd846dd31a3b4e07c86e753a2a3f`
  and size 79,204,201 bytes.
- The image ran with network mode `none` and no mounts, returned HTTP 200 with
  `{"status":"ok","version":"0.1.0"}` from `/health`, and reported
  OSV-Scanner 2.4.0. The temporary verification container was removed.

No live model request was used. Transport tests use in-memory fakes and mocked
literal-loopback HTTP; the production adapter remains disabled by default.

## Preserved boundaries

Dependencies, public routes, OSV as the active advisory source, OSV-Scanner
2.4.0 and its generated-coordinate/proxy-free boundary, repository cleanup,
Phase 4 evidence output, Phase 5 context output, and their canonical identities
remain unchanged. Remote providers, credentials, persistence, interfaces,
broader classifications, reachability, exposure, remediation, and patches
require separate authorization.
