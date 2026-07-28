# Development Recap — July 28, 2026 — Phase 4

## Outcome

Phase 4 is complete within the reviewed lease-scoped evidence-engine boundary.
The implementation converts only Watchdog-generated Phase 3 match source
references into deterministic internal evidence bundles before the existing
repository lease exits. It adds no public route, persistence, subprocess,
network client, model call, source/reachability analysis, exposure
classification, or patch behavior.

## Implemented contract

- Strict frozen models cover producer metadata, source anchors and line ranges,
  redacted display content, redaction records, evidence items, per-reference
  outcomes, match links, warnings, coverage, configuration, and bundles.
- Canonical JSON and SHA-256 bind configuration, evidence items, and bundles.
  Bundle identity excludes wall-clock time, temporary paths, and operational
  timing. Items, links, source outcomes, and warnings have validated canonical
  ordering.
- `WATCHDOG_EVIDENCE_` configuration enforces the approved defaults: 60 seconds,
  200 source files, 5 MiB per file, 25 MiB total input, 10,000 items, 200 lines,
  16 KiB display per item, 5 MiB bundle display, 100 redactions per item, and
  1,000 warnings.
- Repository reads open the root and every path component by descriptor with
  close-on-exec and no-follow flags. Final opens are nonblocking; only regular
  files are accepted. Complete bounded bytes are read from the descriptor,
  pre/post identity is checked, and the Phase 3 digest must match.
- Resolvers cover the Phase 3 `line:N`, npm JSON Pointer, PEP 621/dependency
  group TOML, and uv package/dependency selectors. Duplicate, ambiguous, stale,
  unsupported, overlong, or invalid UTF-8 selections omit display content.
- Redaction uses `[REDACTED]` and versioned detectors for private keys, URI user
  information, credential assignments, GitHub, GitLab, Slack, npm, PyPI, Stripe,
  Google API, AWS access-key, and compact JWT formats. Redaction precedes all
  display truncation; detector or replacement-limit failure has no raw fallback.
- Async collection uses a cancellable worker and waits for worker termination on
  cancellation so cleanup cannot race active reads. Match state and Phase 3
  limitations are copied unchanged into every canonical match link.

## Item-cap decision

The evidence-item cap is absolute. Canonically ordered references above 10,000
do not create unlimited omitted items and do not disappear. Their per-match
source outcomes remain visible with `item_limit_exceeded` and no evidence ID.
This bounded outcome behavior is the explicit resolution of the work order's
item-cap conflict.

## Verification snapshot

The deterministic local suite passes 177 tests. The existing live
OSV-Scanner contract remains opt-in and is skipped by default. Formatting, Ruff,
strict mypy, bytecode compilation, unchanged OpenAPI route assertions, and Docker
Compose configuration validation pass. OSV-Scanner remains pinned to 2.4.0 and
the Dockerfile source digest is unchanged.

A fresh standalone image build also passes with Docker Engine 29.6.2. The
resulting local verification image has ID
`sha256:e36f218c2fa95783ef75c8eaab03430c0a7a22247729428cf86898d87e7a91df`
and size 78,641,416 bytes. It starts without a repository mount or network,
returns HTTP 200 with `{"status":"ok","version":"0.1.0"}` from `/health`, and
reports `osv-scanner version: 2.4.0` from the embedded scanner. These values are
an environment-specific verification snapshot, not stable release identifiers.

No live OSV request was required for Phase 4 because this phase adds no scanner,
subprocess, or egress behavior. The opt-in live contract and its prior Phase 3
verification remain the current record for that unchanged outbound boundary.

## Deferred

SBOM generation, arbitrary repository evidence, general source/configuration
analysis, imports/calls/endpoints, reachability, deployment context, exposure
classification, LLM investigation, persistence, jobs, evidence browsing, public
repository routes, CLI/web workflows, remediation, and patch previews remain
outside the completed Phase 4 boundary.
