# Phase 6 Formal Implementation Plan — Evidence-Bound Model Investigation

**Status:** Complete; all staged work packages and acceptance gates passed

**Authorized:** July 29, 2026

**Prepared:** July 29, 2026

**Baseline:** `7cdcf88e9c06cda73d924d13fbf480a2e64f40f2`

**Governing boundary:** `../work-orders/phase-6-evidence-bound-model-investigation.md`

## 1. Outcome and invariant

Add a separate internal `InvestigationService` that consumes only validated,
bounded, redacted Phase 1 and Phase 3–5 domain objects after repository cleanup.
It constructs a deterministic envelope, submits it through an injected gateway,
and accepts an investigation inference only after strict syntax, schema,
evidence-link, and deterministic policy validation.

The model is neither a scanner nor an evidence source. Phase 1–5 models,
canonical identities, repository behavior, OSV-Scanner 2.4.0, and public routes
remain unchanged.

## 2. Frozen initial boundary

- The service accepts `AdvisoryRecord`, `DependencyInventory`,
  `DependencyMatchReport`, `EvidenceBundle`, and `ContextBundle`; it never
  accepts a repository, lease, path, raw source record, prompt, schema, or tool.
- The only concrete transport is disabled by default, credential-free, literal
  loopback, `POST /v1/chat/completions`, strict JSON-schema output,
  non-streaming, tool-free, redirect-free, proxy-independent, and single-shot.
- Dispositions are limited to dependency match plus observed context,
  dependency match with unconfirmed context, insufficient evidence, and
  unsupported. No affected/not-affected, reachability, exploitability, exposure,
  remediation, command, or patch vocabulary exists.
- Raw request/response bodies, evidence display text, headers, paths, secrets,
  and provider identifiers never enter logs, exceptions, persistence, or the
  final domain model.

## 3. Staged work packages

1. Record authority, freeze the Phase 5 baseline, and verify documentation-only
   status before runtime work.
2. Add provider-neutral immutable domain, configuration, controlled vocabulary,
   and canonical identity models with no network behavior.
3. Revalidate same-advisory/same-snapshot Phase 1/3/4/5 inputs and construct the
   deterministic bounded allowlisted envelope with explicit omissions.
4. Add fixed versioned prompt and response-schema assets; encode all hostile
   values only in the canonical JSON data message.
5. Add the gateway protocol, in-memory fake, strict duplicate-aware JSON parser,
   draft schema, evidence-link validation, and raw-response disposal.
6. Add deterministic disposition, assumption, gap, and validation-action gates
   over validated inputs; reject the whole response on disagreement.
7. Add the disabled literal-loopback adapter with bounded HTTP lifecycle,
   cancellation, no proxy/redirect/credential support, and no retry or fallback.
8. Integrate the internal service without registering a route, CLI, job,
   persistence, repository access, or new dependency.
9. Run the complete adversarial and regression matrix, synchronize all security
   documentation, publish a dated recap, and only then mark Phase 6 complete.

Each package is an exit gate. A later package may not weaken an earlier schema,
identity, confidentiality, destination, evidence, or failure control.

## 4. Acceptance gates

- Every accepted claim cites only included canonical evidence; contextual claims
  retain their Phase 4 dependency support.
- Partial, unknown, unsupported, scanner-failed, omitted, redaction-failed, and
  truncated states remain explicit and cannot yield a negative conclusion.
- Hostile prompt text cannot change instructions, roles, schemas, parameters,
  destination, tool settings, or evidence eligibility.
- The adapter accepts only `127.0.0.1` or `::1`, uses bounded I/O and one shared
  deadline, ignores ambient proxies/netrc, rejects redirects, and fully cleans up
  on timeout or cancellation.
- Existing dependencies, exact OpenAPI paths, scanner boundary, Phase 4/5
  canonical fixtures, deterministic tests, static checks, Compose validation,
  and no-network container smoke tests remain green.

## 5. Mandatory escalation

Pause for separate authorization before adding any remote or hostname endpoint,
credential, provider SDK, TLS exception, retry/fallback, tool, streaming,
retrieval, persistence, telemetry, route, interface, private repository data,
affected/not-affected or exposure classification, runtime/data-flow analysis,
remediation, executable action, or patch behavior.
