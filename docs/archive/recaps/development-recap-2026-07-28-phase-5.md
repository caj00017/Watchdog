# Development Recap — July 28, 2026 — Phase 5

## Outcome

Phase 5 is complete within the authorized deterministic contextual-analysis
boundary. The implementation adds a separate internal `ContextService` that
operates only inside the existing repository lease and links bounded lexical
observations back through Phase 4 evidence to the causing Phase 3 match.

It does not claim execution, runtime/data-flow reachability, exploitability,
deployment exposure, or repository affected/not-affected status. It adds no
parser dependency, subprocess, network client, persistence, model call, public
route, CLI/web workflow, evidence browser, or patch behavior.

## Implemented contract

- Strict frozen context models and canonical SHA-256 identities cover the
  checked-in catalog, configuration, targets, file outcomes, redacted evidence,
  observations, lexical graph, signals, links, warnings, coverage, and bundles.
- Targets derive only from same-snapshot Phase 3 inventory/matches and canonical
  Phase 4 match-evidence links. Production always selects the fixed code-native,
  versioned, digest-bound catalog.
- Discovery is descriptor-relative, sorted, no-follow, and bounded before
  sorting and reading. It rejects unsafe names, symlinks, non-regular files,
  duplicate identities, case collisions, mutations, excluded directories, and
  every configured capacity failure with explicit coverage.
- Data-only recognizers cover reviewed Python, JavaScript/TypeScript, and Go
  import, binding, reference, explicit-call, configuration, and endpoint forms.
  Exact catalog-selected JSON/TOML paths and keys are recognized without a
  general repository search or raw-text fallback.
- Complete selected spans pass through the existing versioned redaction policy
  before outward model construction. Redaction or display-limit failure omits
  content; repository text is absent from diagnostics and exceptions.
- The observation graph contains lexical relationships only. Deterministic
  ranking emits evidence-linked positive signals, explicit incomplete-context
  signals, and a guarded static usage-not-observed signal only for complete
  mappings and complete eligible coverage.
- One shared deadline and cooperative cancellation event cover discovery,
  recognition, evidence, graph, and ranking. Async cancellation waits for worker
  termination before lease cleanup proceeds.

## Verification snapshot

The deterministic suite passes 240 tests. The bounded live OSV-Scanner contract
remains intentionally opt-in and is skipped by default. Ruff formatting and
lint, strict mypy over 108 source files, application/test bytecode compilation,
exact unchanged OpenAPI paths, Docker Compose validation, boundary audits, and
synthetic-secret tests pass.

A fresh standalone image builds with Docker Engine 29.6.2. The local verification
image has ID
`sha256:c6a01c9b7b870460e98e46eda4c8f6a9c502cd12884ab80f0d2c45e8d22117a7`
and size 79,005,117 bytes. Without a repository mount or external network, it
returns HTTP 200 with `{"status":"ok","version":"0.1.0"}` from `/health`.
The embedded scanner reports `osv-scanner version: 2.4.0`. These values are a
local verification snapshot, not stable release identifiers.

Scanner code, generated input, arguments, environment, network behavior, and the
digest-pinned scanner image remain unchanged. Phase 4 models, evidence service,
and canonical identity code remain unchanged. No live OSV request was needed
because Phase 5 adds no scanner or egress behavior.

## Residual limitations

Recognition is intentionally lexical and covers only the documented language
subset, extensions, configuration paths, and trusted catalog rules. Excluded,
unsupported, ambiguous, malformed, dynamically dispatched, generated, or
over-limit content makes coverage partial. Python generic distribution-to-import
mapping is incomplete unless the catalog supplies a reviewed exact mapping.

Tree-sitter/native parsers, YAML/XML/templates/notebooks, build-condition
evaluation, interprocedural analysis, runtime call graphs, taint analysis,
deployment analysis, exposure/affected classifications, LLM investigation,
persistence, public repository/evidence routes, user interfaces, remediation,
and patch previews remain deferred.
