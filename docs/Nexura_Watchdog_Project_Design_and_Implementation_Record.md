# Nexura Watchdog

## Project Design and Implementation Record

**Document version:** 7.1

**Last updated:** July 29, 2026

**Owner:** Christopher Jones / Nexura

**Document role:** Canonical living source of truth

**Code version:** 0.1.0

**Current lifecycle state:** Phases 0–7 complete; Phase 8 is planning-only

**Primary deployment direction:** Local-first, open source

> **Project promise:** Watchdog combines authoritative vulnerability data,
> deterministic repository analysis, and bounded model reasoning to produce a
> transparent assessment of whether a specific vulnerability appears to affect
> a specific project.

---

# 1. Authority and Maintenance

This is the canonical record for Nexura Watchdog. It describes both the intended
product and the capabilities that exist in the current codebase. When another
planning note, recap, prompt, or supporting document conflicts with this record,
this record takes precedence after the implementation and tests have been
inspected.

Supporting architecture, threat-model, and evidence-policy documents provide
deeper treatment of individual boundaries. Historical prompts, plans, and
development recaps are archived context rather than current instructions.

Update this document whenever:

- a phase begins or completes;
- a user-visible capability or route changes;
- a trust boundary, external destination, or execution model changes;
- supported inputs, ecosystems, tools, or deployment targets change;
- a known limitation is resolved or a material new limitation is discovered;
- the evidence, confidence, classification, or remediation policy changes.

Never mark a planned capability as implemented until code and proportionate
tests exist. If this document disagrees with executable behavior, the code is the
immediate operational truth and this record must be corrected in the same work
session.

---

# 2. Executive Status

## 2.1 Current phase

Phases 0 through 7 are complete:

- **Phase 0 — Foundation:** package structure, FastAPI, configuration, quality
  tooling, Docker development, and foundational documentation.
- **Phase 1 — Advisory intelligence:** OSV ingestion, supported identifier
  normalization, source-neutral advisory models, provenance, conflict-capable
  merging, typed failures, and JSON/Markdown exports.
- **Phase 2 — Safe repository intake:** strict public GitHub validation,
  exact-commit resolution, bounded archive acquisition, hostile-path extraction,
  disposable leases, cleanup verification, and security tests.
- **Phase 3 — Dependency inventory and advisory matching:** bounded no-follow
  discovery, source-linked Python/npm/Go parsers, deterministic inventory and
  graph models, generated exact coordinates, pinned OSV-Scanner 2.4.0, strict
  scanner evidence, alias matching, explicit partial/unknown states, and lease
  cleanup integration.
- **Phase 4 — Lease-scoped evidence engine:** strict immutable evidence models,
  canonical identities, descriptor-relative no-follow reads, digest-bound
  positional selectors, fail-closed secret redaction, bounded source outcomes,
  deterministic bundles, and lease-cleanup integration.
- **Phase 5 — Deterministic contextual analysis:** validated Phase 3/4 target
  linkage, a trusted versioned catalog, bounded descriptor-relative discovery,
  data-only Python/JavaScript/TypeScript/Go and JSON/TOML recognition, redacted
  context evidence, a lexical observation graph, controlled non-classification
  signals, and cancellation-safe lease integration.
- **Phase 6 — Evidence-bound model investigation:** strict source-neutral
  investigation models, deterministic bounded envelopes over validated Phase
  1/3–5 artifacts, fixed versioned prompt/schema assets, provider-neutral
  gateway injection, evidence-link and deterministic disposition validation,
  explicit run states, and one disabled credential-free literal-loopback
  OpenAI-compatible adapter.
- **Phase 7 — Evidence-safe reporting and local interfaces:** a strict canonical
  report with deterministic summary/technical JSON and escaped-Markdown
  projections, one lease-safe synchronous workflow, a direct stdout-only CLI,
  and a separate disabled literal-loopback UI/API with fixed routes and
  same-origin controls.

Phases 4 and 5 remain internal. Phase 5 observations are lexical and do not
establish execution, runtime/data-flow reachability, exploitability, deployment
exposure, or repository affected/not-affected status. The completed boundary is
recorded in `docs/work-orders/phase-5-contextual-analysis.md` and
`docs/plans/phase-5-implementation-plan.md`.

Phase 6 is complete under its governing work order and formal plan. Its separate
internal model-synthesis boundary operates only after repository cleanup and
permits no repository access. It excludes remote providers, credentials,
persistence, interfaces, remediation, runtime reachability, exposure, and
affected/not-affected classifications.

Phase 7 is complete under its governing work order and formal plan. It preserves
Phase 1–6 identities and uncertainty, performs all repository work inside the
verified lease, invokes Phase 6 only after cleanup, and exports only bounded
allowlisted report projections. It adds no persistence, remote destination,
classification, remediation, command, or patch behavior.

Phase 8 now has a planning-only evidence-bound remediation-assistant work order
against immutable Phase 7 commit
`60079274ea4ea9784391b3b34712fd3b3d8ad519`. It proposes source-reported
fixed-version candidates, controlled human validation actions, and narrowly
bounded in-memory previews for eligible direct exact-version declarations. No
Phase 8 model, repository read, workflow hook, command, route, preview, write, or
apply behavior is implemented or authorized.

## 2.2 Current health

| Area | Status | Current reality |
| --- | --- | --- |
| Product definition | Stable for MVP | One known vulnerability against one repository |
| Advisory API | Implemented | Health plus advisory retrieval in JSON or Markdown |
| Advisory sources | Partial | OSV is the only active adapter |
| Advisory evidence | Implemented | Raw record, field provenance, aliases, conflicts, warnings, partial state |
| Public repository intake | Implemented internally | Public GitHub archives only; exact commit; no API route |
| Hostile archive controls | Implemented | Size/path/entry/time limits and link/type restrictions |
| Workspace cleanup | Implemented | Verified on success, failure, timeout, and cancellation |
| Dependency inventory | Implemented internally | Bounded Python, npm, and Go data parsing with source-linked coverage |
| Scanner integration | Implemented internally | Pinned OSV-Scanner 2.4.0 receives generated exact coordinates only |
| Advisory package matching | Implemented internally | Exact candidate results, aliases, conditions, unknown/incomplete states |
| Evidence engine | Implemented internally | Bounded redacted dependency-source bundles; no API, persistence, model, or exposure result |
| Contextual analysis | Implemented internally | Bounded evidence-linked lexical observations and non-classification signals; no route or runtime reachability |
| Exposure classification | Not implemented | No affected/not-affected conclusions are produced |
| LLM integration | Implemented internally | Evidence-bound, disabled by default, literal-loopback only, credential-free, strict output validation |
| CLI and web UI | Implemented locally | Direct stdout-only CLI plus separate disabled literal-loopback UI/API |
| Remediation assistant | Planning only | Work order drafted; no candidate, preview, write, apply, command, or interface behavior |
| Persistence and jobs | Not implemented | No database, queue, or retained investigation state |
| Container workflow | Verified | Multi-stage image builds; embedded scanner version and no-mount health pass |
| Automated quality | Green | 280 deterministic tests pass; bounded live scanner contract remains opt-in |
| Version-control state | Phase 7 immutable at `6007927` | Phase 8 proposal is planning-only |

## 2.3 Immediate milestone

Review the Phase 8 work order against the immutable Phase 7 baseline and make a
separate implementation decision. Planning does not authorize persistence,
authentication, new destinations or dependencies, private inputs,
classification, reachability/exposure, remediation runtime behavior, commands,
code generation, previews, repository writes, or patch application.

---

# 3. Product Definition

Nexura Watchdog is an evidence-driven vulnerability investigation assistant. A
user supplies one known vulnerability and one source repository. The completed
product should determine whether the disclosed issue appears relevant to that
project, show the evidence behind the conclusion, expose uncertainty, and
recommend the smallest defensible remediation and validation steps.

The central question remains:

> **Does this vulnerability actually matter to this project, why, and what
> should the maintainer do next?**

Watchdog is deliberately not a general “scan everything for everything” product.
It competes on investigation clarity, reproducibility, visible uncertainty, and
useful evidence rather than breadth alone.

## 3.1 Primary users

- Open-source maintainers
- Independent developers and small teams without dedicated AppSec staff
- Security researchers, consultants, students, and educators
- Technical writers and analysts evaluating a specific disclosure

## 3.2 Product invariants

1. Investigate one known vulnerability against one repository at a time.
2. Deterministic tools collect and structure evidence before any model reasons.
3. Repository content is hostile data, never instructions.
4. Repository code and dependency installation never run as part of analysis.
5. Every repository finding must link to evidence.
6. Tool failure, unsupported coverage, or missing data never means “not affected.”
7. Negative conclusions state their coverage limits.
8. Model output, when introduced, must use a strict schema and valid evidence IDs.
9. Remediation patches remain previews until a human explicitly approves them.
10. Security-boundary changes require tests and synchronized documentation.

## 3.3 MVP inputs and outputs

Planned MVP inputs:

- CVE, GHSA, OSV identifier, or supported advisory URL
- Public GitHub repository
- Optional branch, tag, or commit SHA
- Future local privacy/model settings

Current input support is narrower:

- CVE, GHSA, and OSV database identifiers are implemented.
- Advisory URL parsing is not implemented.
- Public GitHub owner/repository URLs and an optional ref are implemented only
  through the internal intake service.

Planned final outputs include a controlled exposure classification, confidence,
advisory facts, dependency/version evidence, dependency paths, relevant source
and configuration evidence, assumptions, missing evidence, remediation, and
plain-English and technical reports in JSON and Markdown.

Current public outputs are normalized advisory JSON/Markdown. Internal Phase 2
and Phase 3 outputs include temporary repository acquisition metadata,
commit-anchored dependency inventories and graphs, coverage warnings, scanner-run
evidence, and source-linked exact-coordinate advisory match reports. These match
reports are not public and are not repository-level vulnerability, reachability,
or exposure conclusions.

---

# 4. Implemented System

## 4.1 Foundation

- Python 3.12 or newer through a setuptools `pyproject.toml` package.
- FastAPI, Pydantic v2, pydantic-settings, HTTPX, and Uvicorn.
- pytest with asyncio support, Ruff formatting/linting, and strict mypy.
- `WATCHDOG_`-prefixed validated settings.
- Multi-stage Dockerfile based on `python:3.12-slim`, with OSV-Scanner 2.4.0
  copied from its digest-pinned multi-architecture image.
- Standalone Compose service without a source bind mount or reload process.
- Application, domain, source-adapter, repository, inventory, scanner, matching,
  reporting, workflow, interface, and test package boundaries, with placeholders
  only for later unapproved phases.
- Repository-wide security rules in `AGENTS.md`.

There is no dependency lockfile, release automation, CI workflow, license,
database migration layer, or published package workflow yet.

## 4.2 Advisory intelligence

### Supported identifiers

- CVE identifiers
- GHSA identifiers
- OSV database identifiers

Identifiers are syntax-validated, bounded, and canonicalized by family. GHSA
suffix case is preserved in the form required by OSV's identifier endpoint. An
OSV response is accepted only if the requested identifier is its primary ID or an
explicit alias.

### Active source

OSV is the only active vulnerability source. The adapter:

- performs asynchronous HTTP retrieval from the configured OSV API base;
- maps external JSON into strict OSV boundary models;
- verifies response identity;
- normalizes into source-neutral immutable domain models;
- retains the parsed raw source object by default;
- records retrieval source, URL, record ID, time, and exact source paths;
- represents fixed version/revision events as deterministic remediation data;
- supports affected Git ranges that omit package metadata;
- maps missing, unavailable, malformed, and partial results to distinct errors.

### Normalized advisory model

The domain represents:

- primary identifier and aliases;
- summary, details, publication and modification times;
- severity values;
- affected packages or Git-only components, versions, ranges, and events;
- CWEs, references, and remediation;
- raw source records and retrieval metadata;
- field-level provenance;
- explicit scalar conflicts, warnings, and partial status.

Normalized fields do not depend on OSV response classes. Provenance is stored in
a parallel map keyed by normalized JSON Pointer-like paths. A source-neutral
merger deduplicates additive values and preserves competing scalar values, though
only one live source currently supplies records.

### Advisory exports

- JSON is the lossless canonical API form.
- Markdown is a human-readable projection selected by `?format=markdown` or
  `Accept: text/markdown`.
- External Markdown text is escaped.
- Markdown omits raw source JSON.

## 4.3 Safe public-GitHub intake

Repository intake is an internal async context-managed service. It is not wired
into FastAPI and cannot currently be triggered by an API client.

### Request boundary

Accepted repository URLs are canonical public HTTPS GitHub owner/repository
URLs. One trailing slash and `.git` suffix are normalized. The parser rejects:

- other schemes or hosts;
- credentials or explicit ports;
- queries, fragments, percent encoding, or extra path segments;
- invalid owner/repository syntax;
- empty, control-containing, whitespace-padded, or overlong refs.

### Resolution and acquisition

- Uses unauthenticated GitHub REST calls only.
- Resolves the supplied ref, or GitHub's reported default branch, to a full
  40-character lowercase commit SHA and tree SHA.
- Confirms GitHub's canonical identity matches the request and rejects private
  metadata.
- Downloads the tar archive for the exact immutable commit, not a mutable branch.
- Restricts manual redirects to HTTPS `api.github.com` and
  `codeload.github.com`.
- Enforces declared and observed compressed byte limits while streaming.
- Records archive SHA-256 and byte count.
- Never invokes Git, a shell, a hook, a credential helper, or a submodule action.

### Extraction boundary

The custom tar extractor enumerates and streams members without using a general
extract call. It:

- requires and strips one consistent archive root;
- rejects absolute paths, traversal, empty components, backslashes, control
  characters, duplicates, and case-fold collisions;
- rejects paths beneath a previously created symlink;
- permits directories, regular files, and lexically contained relative symlinks;
- rejects hardlinks, sparse files, devices, FIFOs, and unsupported member types;
- limits regular-file bytes, unique materialized workspace paths including
  implicit directories, relative path length, and total duration;
- creates workspaces/directories with mode 0700 and files with mode 0600.

### Lease and cleanup

- A lease is single-use and owns acquisition through deletion.
- Its total deadline begins before the shared semaphore wait.
- The compressed archive is removed before the acquired root is yielded.
- The immutable snapshot records canonical repository identity, requested and
  resolved refs, commit and tree SHAs, retrieval time, archive digest and bytes,
  extracted bytes, file count, and symlink count.
- Normal exit, consumer failure, source failure, unsafe archive, limit breach,
  timeout, and cancellation all enter cleanup.
- Cleanup waits for background extraction/removal, verifies both archive and
  workspace absence, and returns a typed status.
- A workspace path replaced by a symlink or non-directory fails closed.

No retention mode exists. A caller must complete all reads inside the lease.

## 4.4 Dependency inventory and advisory matching

Phase 3 operates only inside an active repository lease. Sorted no-follow
discovery recognizes a bounded allowlist of Python, npm, and Go dependency data.
Ecosystem-specific parsers create immutable projects, components, dependency
edges, source references, scanned-file records, warnings, and explicit coverage
states. Every source reference contains a repository-relative POSIX path,
structured selector, and SHA-256 of the parsed file. Deterministic identifiers
include the exact repository commit.

Only exact normalized registry coordinates selected by advisory ecosystem and
package name are eligible for OSV-Scanner. Watchdog generates the scanner's
custom intermediate input and trusted empty configuration; it never supplies
the repository root, original manifests, or repository configuration. The
pinned scanner runs with fixed arguments, `--no-resolve`, a minimal proxy-free
environment, bounded concurrent output, and process-group cleanup. Scanner
failure remains `scanner_incomplete`.

Results preserve direct/transitive/unknown relationships, scope, markers, OS/CPU
conditions, source occurrences, partial coverage, and narrow match states.
`not_reported_affected` applies only to one successfully scanned exact
coordinate. Conditional applicability is preserved without evaluation against
the analysis host.

## 4.5 Current public API

Exactly two routes are exposed:

| Method and path | Behavior |
| --- | --- |
| `GET /health` | Returns service status and version without an upstream request |
| `GET /api/v1/advisories/{identifier}` | Returns normalized advisory JSON or Markdown |

Expected advisory failures use stable JSON envelopes with codes for invalid
identifiers, missing advisories, unavailable sources, malformed source records,
and partial results. Repository-intake errors are typed internally but have no
HTTP mapping because intake has no route.

---

# 5. Current Runtime Architecture

## 5.1 Advisory flow

```text
API client
  -> FastAPI identifier boundary
  -> AdvisoryService
  -> OsvSource / strict OSV response models
  -> source-neutral AdvisoryRecord
  -> JSON or escaped Markdown
```

The FastAPI lifespan owns the advisory HTTP client. Dependency injection allows
tests to substitute a deterministic advisory source. The client never supplies
an arbitrary upstream URL.

## 5.2 Repository, inventory, and matching flow

```text
Trusted internal caller
  -> RepositoryRequest and GitHub URL validation
  -> public metadata and exact commit resolution
  -> bounded exact-SHA tar download
  -> hostile-member validation and bounded extraction
  -> temporary AcquiredRepository inside one lease
  -> sorted allowlisted manifest discovery and data-only parsers
  -> source-linked DependencyInventory and dependency graph
  -> AdvisoryMatchService candidate selection
  -> generated exact-coordinate OSV-Scanner input
  -> source-linked DependencyMatchReport
  -> verified cleanup
```

There is no public application workflow that orchestrates advisory retrieval and
repository intake. An internal trusted caller supplies an `AdvisoryRecord` and a
lease-scoped `DependencyInventory` to `AdvisoryMatchService`; acquiring a
repository does not itself resolve an advisory, and resolving an advisory does
not itself acquire or inspect a repository.

## 5.3 Module map

| Module | Current responsibility |
| --- | --- |
| `apps/api` | FastAPI lifespan, advisory dependency wiring, errors, and routes |
| `watchdog/config` | Validated environment settings |
| `watchdog/domain/advisories.py` | Advisory, provenance, conflict, and source models |
| `watchdog/domain/identifiers.py` | Advisory identifier grammar and canonicalization |
| `watchdog/domain/repositories.py` | Repository request, resolution, snapshot, and cleanup models |
| `watchdog/domain/inventory.py` | Source-neutral inventory, graph, source-reference, warning, and coverage models |
| `watchdog/domain/matching.py` | Scanner coordinate/evidence and dependency match-report models |
| `watchdog/domain/evidence.py` | Strict producer, source, redaction, item, match-link, warning, coverage, and bundle models |
| `watchdog/domain/context.py` | Strict catalog, target, source outcome, context evidence, observation, graph, signal, coverage, and bundle models |
| `watchdog/vulnerability_sources` | Source protocol, OSV boundary, normalization, and merging |
| `watchdog/advisory_service.py` | Identifier-to-advisory orchestration |
| `watchdog/advisory_match_service.py` | Candidate selection, scanner-result mapping, alias matching, and match states |
| `watchdog/reporting` | JSON and escaped Markdown rendering |
| `watchdog/repository/validation.py` | Canonical public-GitHub URL parsing |
| `watchdog/repository/github.py` | GitHub metadata, commit resolution, and archive streaming |
| `watchdog/repository/workspace.py` | Defensive tar validation and extraction |
| `watchdog/repository/cleanup.py` | Cancellation-aware removal and verification |
| `watchdog/repository/intake.py` | Limits, concurrency, deadlines, workspace, and lease lifecycle |
| `watchdog/inventory` | Bounded discovery, normalization, limits, and Python/npm/Go data parsers |
| `watchdog/scanners` | Source-neutral scanner protocol and pinned OSV-Scanner subprocess boundary |
| `watchdog/evidence` | Canonical identity/configuration, safe reads, positional selectors, redaction, and collection |
| `watchdog/context` | Trusted catalog and targets, bounded descriptor discovery, data-only recognizers, redacted evidence, lexical graph/ranking, and collection |
| `watchdog/analysis`, `watchdog/jobs` | Placeholders only |
| `apps/cli`, `apps/web` | Direct Phase 7 CLI and separate disabled literal-loopback application |

---

# 6. Evidence and Result Policy

## 6.1 Current advisory evidence

Advisory facts are claims reported by OSV, not observations about the target
repository. Every normalized source-derived field maps to retrieval metadata and
an upstream source path. Empty source collections receive collection-level
provenance so “reported empty” remains distinguishable from “not inspected.”

Aliases are accepted only when explicitly supplied. Conflicting scalar values
remain data rather than being silently discarded. The deterministic display
value does not erase competing values.

## 6.2 Current repository and dependency provenance

`RepositorySnapshot` identifies the precise acquisition supplied to a later
consumer. Its archive digest demonstrates equality with downloaded bytes; it
does not independently prove Git authorship, commit signatures, or reconstruction
of Git's tree object. The implementation currently trusts GitHub to bind its API
metadata and tarball to the requested commit.

`CleanupResult` is operational provenance, not vulnerability evidence.

Phase 3 inventory occurrences link normalized dependency facts to the exact
commit, repository-relative path, structured selector, and parsed-file SHA-256.
Coverage records distinguish complete, partial, empty-valid, absent,
all-malformed, and unsupported-only input. Scanner evidence retains the pinned
version, logical arguments, timestamps, exit code, generated-input and validated
output hashes, bounded validated result data, and sanitized diagnostics.

An exact-coordinate match is a deterministic tool result rather than an exposure
finding. Conditions are preserved but not evaluated. Tool, parser, format,
network, or limit gaps remain explicit warnings or incomplete states.

## 6.3 Failure rule

Invalid input, missing records, upstream errors, malformed data, unsafe archives,
timeouts, limit failures, unsupported formats, and tool failures must remain
explicit. None may be translated into “not vulnerable” or “not affected.”

The current system emits no exposure classification.

## 6.4 Repository evidence and future result requirements

Implemented Phase 4 repository evidence carries an ID, exact commit, producer
and resolver identity and version, repository-relative source, structured
selector or line range,
content hash, trust level, and redaction record. Reports must distinguish:

- observed repository facts;
- external advisory evidence;
- deterministic tool results;
- Watchdog inference;
- assumptions and missing evidence;
- recommendations.

Every repository-specific factual claim and final classification must link to
evidence IDs.

The Phase 4 work order is now the completed repository-evidence contract.
Inference, exposure classifications, and reports remain future capabilities and
must validate every repository claim against these evidence IDs.

---

# 7. Security and Trust Boundaries

## 7.1 Active boundaries

1. **API client:** advisory identifiers, query parameters, and headers are
   untrusted.
2. **OSV network:** response bodies and failures are untrusted external data.
3. **Internal repository request:** URL and ref are untrusted despite an internal
   caller.
4. **GitHub network:** public API metadata, redirects, and archive bytes are
   untrusted external data.
5. **Archive/workspace:** every filename, member type, symlink, and byte is
   hostile.
6. **Dependency parser:** recognized manifests, lockfiles, includes, selectors,
   package values, and graph declarations are hostile data.
7. **Scanner subprocess and OSV network:** the pinned executable, generated
   control files, subprocess outputs, and remote lookup may fail or be malformed.
8. **Export:** advisory text may contain active Markdown/HTML-like syntax.

## 7.2 Controls in force

- Fixed/validated upstream destinations and percent-encoded identifiers/refs.
- Strict external boundary models and identity checks.
- No GitHub credentials or private repository path.
- No Git, repository code execution, imports, builds, or dependency installation.
- No general tar extraction or shell interpolation.
- Bounded network time, total duration, bytes, materialized paths, path length,
  and per-service concurrency.
- Restricted redirect destinations and archive member types.
- Disposable private workspaces and verified cleanup.
- Sorted no-follow dependency discovery, bounded data-only parsers, and explicit
  unsupported/malformed/partial coverage.
- Generated exact-coordinate scanner input only; fixed arguments,
  `--no-resolve`, trusted empty configuration, minimal proxy-free environment,
  output limits, exact version checking, and process-group termination.
- Escaped Markdown and no repository content export.
- Typed failures instead of clean negative results.

## 7.3 Residual risk

- Application limits are not filesystem quotas or independent CPU/memory
  isolation. Peak storage can approach compressed plus extracted limits.
- Concurrency is per service instance, not distributed across processes/hosts.
- Process or host termination can bypass cleanup; no stale-workspace scavenger
  exists.
- GitHub metadata has time/schema bounds but no explicit response-byte cap,
  cache, retry policy, or hosted rate coordination.
- Contained symlinks remain hostile to future consumers.
- Python's tar and TLS/network stack remain in the trusted computing base.
- Docker currently runs the standalone service as the image's default root user.
  Compose does not bind-mount the source tree, but the container is not a
  hardened production sandbox.
- The embedded scanner increases image size and its normal OSV lookup requires
  outbound network and host DNS/CA trust. `--no-resolve` prevents dependency
  resolution but does not make the OSV lookup offline.
- Package-manager formats can be ambiguous or evolve beyond the supported parser
  schemas; explicit partial coverage cannot prove absence.
- Runtime dependencies use bounded ranges but are not lockfile-pinned.

---

# 8. Configuration

Configuration uses `WATCHDOG_`-prefixed environment variables.

| Variable | Default | Meaning |
| --- | --- | --- |
| `WATCHDOG_ENVIRONMENT` | `development` | `development`, `test`, or `production` |
| `WATCHDOG_OSV_BASE_URL` | `https://api.osv.dev/v1` | Operator-controlled OSV API root |
| `WATCHDOG_UPSTREAM_TIMEOUT_SECONDS` | `10` | Advisory request timeout; max 60 seconds |
| `WATCHDOG_INCLUDE_RAW_SOURCE_RECORDS` | `true` | Include parsed raw OSV record in JSON |
| `WATCHDOG_GITHUB_API_VERSION` | `2026-03-10` | GitHub REST API version header |
| `WATCHDOG_REPOSITORY_NETWORK_TIMEOUT_SECONDS` | `30` | Per-GitHub-request timeout; max 120 seconds |
| `WATCHDOG_REPOSITORY_MAX_DURATION_SECONDS` | `600` | Whole intake deadline including semaphore wait |
| `WATCHDOG_REPOSITORY_MAX_ARCHIVE_BYTES` | `262144000` | Maximum compressed tar bytes |
| `WATCHDOG_REPOSITORY_MAX_EXTRACTED_BYTES` | `262144000` | Maximum extracted regular-file bytes |
| `WATCHDOG_REPOSITORY_MAX_FILES` | `25000` | Maximum unique materialized paths |
| `WATCHDOG_REPOSITORY_MAX_PATH_LENGTH` | `1024` | Maximum stripped relative path length |
| `WATCHDOG_REPOSITORY_MAX_CONCURRENT_INTAKES` | `1` | Lease concurrency per service instance |
| `WATCHDOG_REPOSITORY_WORKSPACE_ROOT` | system temporary directory | Optional workspace parent |
| `WATCHDOG_INVENTORY_DEADLINE_SECONDS` | `120` | End-to-end Phase 3 inventory deadline |
| `WATCHDOG_INVENTORY_MAX_MANIFEST_FILES` | `200` | Maximum recognized dependency files |
| `WATCHDOG_INVENTORY_MAX_BYTES_PER_MANIFEST` | `5242880` | Maximum bytes read from one dependency file |
| `WATCHDOG_INVENTORY_MAX_TOTAL_PARSED_BYTES` | `26214400` | Maximum total unique dependency-file bytes parsed |
| `WATCHDOG_INVENTORY_MAX_COMPONENTS` | `50000` | Maximum inventory components |
| `WATCHDOG_INVENTORY_MAX_EDGES` | `200000` | Maximum dependency graph edges |
| `WATCHDOG_INVENTORY_MAX_PARSER_NESTING_DEPTH` | `64` | Maximum JSON/TOML value nesting |
| `WATCHDOG_INVENTORY_MAX_REQUIREMENTS_INCLUDE_DEPTH` | `10` | Maximum local requirements include depth |
| `WATCHDOG_INVENTORY_MAX_WARNINGS` | `1000` | Maximum retained structured inventory warnings |
| `WATCHDOG_OSV_SCANNER_PATH` | `/usr/local/bin/osv-scanner` | Absolute native scanner executable path |
| `WATCHDOG_SCANNER_TIMEOUT_SECONDS` | `120` | Scanner execution timeout |
| `WATCHDOG_SCANNER_MAX_INPUT_BYTES` | `5242880` | Maximum generated intermediate input |
| `WATCHDOG_SCANNER_MAX_STDOUT_BYTES` | `26214400` | Maximum scanner JSON output |
| `WATCHDOG_SCANNER_MAX_STDERR_BYTES` | `1048576` | Maximum sanitized scanner diagnostics |
| `WATCHDOG_EVIDENCE_DEADLINE_SECONDS` | `60` | Whole evidence-collection deadline |
| `WATCHDOG_EVIDENCE_MAX_SOURCE_FILES` | `200` | Maximum unique referenced files opened |
| `WATCHDOG_EVIDENCE_MAX_BYTES_PER_SOURCE_FILE` | `5242880` | Maximum bytes read from one evidence file |
| `WATCHDOG_EVIDENCE_MAX_TOTAL_SOURCE_BYTES` | `26214400` | Maximum total evidence-source bytes read |
| `WATCHDOG_EVIDENCE_MAX_ITEMS` | `10000` | Maximum canonical evidence items |
| `WATCHDOG_EVIDENCE_MAX_LINE_SPAN` | `200` | Maximum selected lines per item |
| `WATCHDOG_EVIDENCE_MAX_DISPLAY_BYTES_PER_ITEM` | `16384` | Maximum redacted display bytes per item |
| `WATCHDOG_EVIDENCE_MAX_BUNDLE_DISPLAY_BYTES` | `5242880` | Maximum redacted display bytes per bundle |
| `WATCHDOG_EVIDENCE_MAX_REDACTIONS_PER_ITEM` | `100` | Maximum redaction records per item |
| `WATCHDOG_EVIDENCE_MAX_WARNINGS` | `1000` | Maximum evidence warnings including overflow summary |
| `WATCHDOG_CONTEXT_DEADLINE_SECONDS` | `120` | Whole contextual-analysis deadline |
| `WATCHDOG_CONTEXT_MAX_DIRECTORIES` | `5000` | Maximum source directories enumerated |
| `WATCHDOG_CONTEXT_MAX_CANDIDATE_PATHS` | `10000` | Maximum directory entries considered |
| `WATCHDOG_CONTEXT_MAX_DIRECTORY_DEPTH` | `64` | Maximum descriptor-relative depth |
| `WATCHDOG_CONTEXT_MAX_PATH_BYTES` | `4096` | Maximum normalized relative-path bytes |
| `WATCHDOG_CONTEXT_MAX_SOURCE_FILES` | `2000` | Maximum eligible source/configuration files |
| `WATCHDOG_CONTEXT_MAX_BYTES_PER_SOURCE_FILE` | `2097152` | Maximum contextual bytes per file |
| `WATCHDOG_CONTEXT_MAX_TOTAL_SOURCE_BYTES` | `52428800` | Maximum contextual bytes per bundle |
| `WATCHDOG_CONTEXT_MAX_TOKENS_PER_FILE` | `100000` | Maximum lexical tokens per file |
| `WATCHDOG_CONTEXT_MAX_TOTAL_TOKENS` | `1000000` | Maximum lexical tokens per bundle |
| `WATCHDOG_CONTEXT_MAX_NESTING_DEPTH` | `256` | Maximum recognized delimiter depth |
| `WATCHDOG_CONTEXT_MAX_OBSERVATIONS` | `50000` | Maximum canonical observations |
| `WATCHDOG_CONTEXT_MAX_GRAPH_NODES` | `50000` | Maximum lexical graph nodes |
| `WATCHDOG_CONTEXT_MAX_GRAPH_EDGES` | `100000` | Maximum lexical graph edges |
| `WATCHDOG_CONTEXT_MAX_EVIDENCE_ITEMS` | `10000` | Maximum context evidence items |
| `WATCHDOG_CONTEXT_MAX_LINE_SPAN` | `100` | Maximum selected lines per item |
| `WATCHDOG_CONTEXT_MAX_DISPLAY_BYTES_PER_ITEM` | `16384` | Maximum redacted display bytes per item |
| `WATCHDOG_CONTEXT_MAX_BUNDLE_DISPLAY_BYTES` | `5242880` | Maximum redacted display bytes per context bundle |
| `WATCHDOG_CONTEXT_MAX_REDACTIONS_PER_ITEM` | `100` | Maximum redactions per item |
| `WATCHDOG_CONTEXT_MAX_WARNINGS` | `1000` | Maximum retained context warnings |
| `WATCHDOG_INVESTIGATION_ENABLED` | `false` | Explicitly enable the internal model request |
| `WATCHDOG_INVESTIGATION_LOOPBACK_HOST` | `127.0.0.1` | Literal IPv4 or IPv6 loopback address only |
| `WATCHDOG_INVESTIGATION_LOOPBACK_PORT` | `11434` | Loopback model-server port |
| `WATCHDOG_INVESTIGATION_MODEL` | unset | Required bounded model identifier when enabled |
| `WATCHDOG_INVESTIGATION_DEADLINE_SECONDS` | `60` | Request-through-validation deadline |
| `WATCHDOG_INVESTIGATION_MAX_CONCURRENT_REQUESTS` | `1` | Per-service request concurrency |
| `WATCHDOG_INVESTIGATION_MAX_INPUT_BYTES` | `262144` | Canonical envelope byte ceiling |
| `WATCHDOG_INVESTIGATION_MAX_OUTPUT_BYTES` | `65536` | Provider response byte ceiling |
| `WATCHDOG_INVESTIGATION_MAX_EVIDENCE_ITEMS` | `256` | Included Phase 4/5 evidence items |
| `WATCHDOG_INVESTIGATION_MAX_CLAIMS` | `64` | Validated claims |
| `WATCHDOG_INVESTIGATION_MAX_EVIDENCE_LINKS_PER_CLAIM` | `32` | Citations per claim |
| `WATCHDOG_INVESTIGATION_MAX_ASSUMPTIONS` | `32` | Controlled assumption codes |
| `WATCHDOG_INVESTIGATION_MAX_MISSING_EVIDENCE_CODES` | `64` | Controlled gap codes |
| `WATCHDOG_INVESTIGATION_MAX_VALIDATION_ACTIONS` | `32` | Controlled human actions |
| `WATCHDOG_INVESTIGATION_MAX_RATIONALE_BYTES_PER_CLAIM` | `2048` | UTF-8 rationale bytes per claim |
| `WATCHDOG_INVESTIGATION_MAX_OUTPUT_TOKENS` | `4096` | Requested provider output ceiling |

Repository settings are consumed when an internal caller constructs
`RepositoryLimits` and `GitHubRepositorySource`. Inventory and scanner settings
are consumed when internal callers construct `InventoryLimits`, `ScannerLimits`,
`OsvScanner`, `EvidenceLimits`, `EvidenceConfiguration`, and
`ContextConfiguration`, and `InvestigationConfiguration`. The FastAPI lifespan
currently wires only advisory settings; Phase 2–6 services remain internal.

---

# 9. Verification Baseline

As of July 29, 2026:

- `ruff format --check .` passes.
- `ruff check .` passes.
- strict `mypy` passes.
- pytest passes 280 deterministic tests; the bounded live OSV scanner contract
  is skipped unless explicitly enabled.
- Application/test bytecode compilation passes.
- OpenAPI contains exactly `/health` and
  `/api/v1/advisories/{identifier}`.
- Docker Compose configuration parses.

Phase 6 environment-dependent container acceptance also passes:

- Docker built the standalone image with ID
  `sha256:ca3e5ea6b9c9d9495de444fda10a1e823d2ffd846dd31a3b4e07c86e753a2a3f`
  and size 79,204,201 bytes.
- The image started with network mode `none` and no mounts and returned HTTP 200
  with `{"status":"ok","version":"0.1.0"}` from `/health` over loopback.
- `/usr/local/bin/osv-scanner --version` reports OSV-Scanner 2.4.0.
- No live model request was required; the concrete gateway remains disabled by
  default and all transport acceptance uses deterministic mocked loopback I/O.

Phase 5 environment-dependent container acceptance also passes:

- Docker Engine 29.6.2 built the standalone image without changing the pinned
  scanner digest.
- The local verification image is 79,027,530 bytes with image ID
  `sha256:3dbea464e0c9f6b208666c6da14007c9d8bdcbacfd68fec847bd4ce24a76059c`.
- The image started without a repository mount or external network and returned
  HTTP 200 with `{"status":"ok","version":"0.1.0"}` from `/health`.
- `/usr/local/bin/osv-scanner --version` reports `osv-scanner version: 2.4.0`.
- Phase 5 changes neither the scanner nor egress behavior, so the opt-in live
  OSV contract was not repeated.

Phase 4 environment-dependent container acceptance also passes:

- Docker Engine 29.6.2 built the standalone image from the pinned scanner
  digest.
- The local verification image is 78,641,416 bytes with image ID
  `sha256:e36f218c2fa95783ef75c8eaab03430c0a7a22247729428cf86898d87e7a91df`.
- The image started without a repository mount or network and returned HTTP 200
  with `{"status":"ok","version":"0.1.0"}` from `/health`.
- `/usr/local/bin/osv-scanner --version` reports `osv-scanner version: 2.4.0`.
- The live OSV contract remains intentionally opt-in and was not repeated
  because Phase 4 does not change scanner, subprocess, or egress behavior.

Phase 3 environment-dependent acceptance also passes:

- Docker Engine 29.6.2 built the multi-stage `nexura-watchdog:phase3` image from
  the pinned scanner digest.
- The local image is 78,462,929 bytes with image ID
  `sha256:9fd43a0d9e4e7057e4af1dca2d39c1e7be00537e66c4501ae4db36a69a6afa3d`.
- `/usr/local/bin/osv-scanner --version` reports `osv-scanner version: 2.4.0`;
  the extracted binary SHA-256 is
  `15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0`.
- The standalone image started with no mounts and returned HTTP 200 with
  `{"status":"ok","version":"0.1.0"}` from `/health`.
- The opt-in `github.com/gogo/protobuf@1.3.1` / `GO-2021-0053` live OSV contract
  passed with the scanner extracted from that final image, and lease cleanup was
  verified by the test.

The reusable operator commands and expected outcomes remain in the root
`README.md`. The Phase 2 image/build/health values remain historical snapshots in
the dated Phase 2 recap and do not describe the Phase 3 image.

Live checks completed during Phases 1–2:

- OSV records resolved successfully for representative CVE, GHSA, and OSV IDs.
- `https://github.com/octocat/Hello-World` resolved to commit
  `7fd1a60b01f91b314f59955a4e4d4e80d8edf11d`, produced a bounded snapshot,
  and was deleted with verified cleanup without executing repository content.

Any local Docker image ID and upstream live result is a verification snapshot,
not a stable release identifier.

---

# 10. Current Limitations and Debt

## 10.1 Functional gaps

- Inventory is intentionally limited to documented Python, npm, and Go formats;
  Yarn, pnpm, shrinkwrap, go.work, unsupported lock versions, and many ecosystem
  manifest formats remain explicit coverage gaps.
- Matching requires exact supported registry coordinates; declarations,
  constraints, local/editable sources, and package-less Git ranges remain
  unknown or unsupported.
- No SBOM generation.
- No general static/source-to-sink or runtime reachability analysis, deployment
  configuration analysis, exploitability decision, or exposure result. Phase 5
  configuration observations remain catalog-limited lexical facts.
- No remote or credentialed LLM provider, retry/fallback, model routing, tool
  call, or persistent investigation result. Phase 6 supports only an explicitly
  enabled local literal-loopback model server.
- No public/remote investigation API, production listener, retained report, or
  hosted web UI; the Phase 7 interface is local and disabled by default.
- No persistence, job state, authentication, hosted service, or private repos.
- No patch preview or remediation automation; Phase 8 is documentation only.
- No advisory URL input despite its place in the intended MVP.

## 10.2 Source and acquisition gaps

- OSV is the only advisory source.
- Public github.com repositories only; no GitHub Enterprise, credentials,
  history, submodules, signatures, or retention.
- GitHub archive identity is trusted rather than independently reconstructed.
- No metadata response cap, retry/cache layer, or API rate coordination.
- No global admission control, filesystem quota, hard CPU/memory sandbox, or
  stale-workspace startup cleanup.

## 10.3 Project-operational gaps

- The completed Phase 0–7 implementation and documentation are committed at
  immutable baseline `60079274ea4ea9784391b3b34712fd3b3d8ad519`.
- The complete `docs/` tree is tracked so boundary and status changes can be
  reviewed and committed with the implementation they describe.
- No dependency lock, CI, license, changelog/release process, or vulnerability
  disclosure policy exists.
- The development Compose service is not a hardened production deployment.

---

# 11. Roadmap

| Phase | Status | Deliverable |
| --- | --- | --- |
| 0. Foundation | Complete | Structure, API foundation, configuration, tests, Docker, docs |
| 1. Advisory intelligence | Complete | OSV normalization, provenance, conflicts, exports |
| 2. Safe repository intake | Complete | Exact public-GitHub snapshot and verified cleanup |
| 3. Dependency inventory and matching | Complete | Bounded parsers, graph, pinned OSV-Scanner, exact matching |
| 4. Evidence engine | Complete | Internal schema, safe extraction, hashing, redaction, bounded links, and deterministic bundles |
| 5. Contextual analysis | Complete | Bounded import, call, config, endpoint, evidence, lexical graph, and controlled context signals |
| 6. Evidence-bound model investigation | Complete | Internal deterministic envelope, strict schema/evidence/policy validation, and disabled literal-loopback gateway |
| 7. Evidence-safe reports and local interfaces | Complete | Canonical reports, bounded workflow, direct local CLI, disabled loopback UI/API |
| 8. Remediation assistant | Proposed; implementation unauthorized | Evidence-linked upgrade candidates, human validation, bounded patch previews |

---

# 12. Phase 3 Implementation Record

Phase 3 runs only inside an active Phase 2 lease. Immutable source-neutral models
cover PyPI/npm/Go projects, exact/constraint/unknown components,
direct/transitive/unknown relationships, scopes, conditions, graph edges,
scanned files, structured warnings, explicit coverage states, exact scanner
coordinates, run evidence, and match reports. Canonical-JSON SHA-256 IDs and
source references anchor every occurrence to the exact snapshot, project root,
path, selector, and file digest.

Sorted no-follow discovery and worker-thread data parsers support PEP 621,
standard dependency groups, bounded local requirements includes, uv schema 1,
npm declarations and package-lock v2/v3 ancestor resolution, plus bounded
`go.mod` directives. `go.sum` remains integrity metadata. Unsupported structures,
malformed/oversized files, ambiguity, unresolved graph edges, exclusions,
replacements, and all global limits stay visible. No repository dependency,
module, package manager, build, import, or source executes.

OSV-Scanner is pinned to 2.4.0 and embedded from digest
`sha256:5116601dedc01c1c580eb92371883ec052fc4c13c3fbc109d621a63ac416d475`.
The adapter lazily verifies the explicit `osv-scanner version:` line while
permitting additive tool metadata such as the separately reported osv-scalibr
version. It passes only a generated custom intermediate file plus trusted empty
configuration. Fixed argument arrays,
`--no-resolve`, minimal proxy-free environment, disposable home/cache/temp,
bounded concurrent output, process-session cleanup, and forward-compatible
strict-known-field JSON validation enforce the boundary. Exit 0/1 is successful
only with validated JSON; every other result is incomplete.

Matching selects advisory candidates by supported ecosystem and normalized name,
matches primary IDs and aliases, maps exact results to every occurrence, and
preserves conditional applicability without host evaluation. The states are
`affected`, `affected_conditional`, `not_reported_affected`, `version_unknown`,
`scanner_incomplete`, and `unsupported_advisory_component`.
`not_reported_affected` is intentionally limited to one successful exact
coordinate lookup and is never repository-level not-affected evidence.

Acceptance is covered by data-only Python/npm/Go and hostile fixtures,
deterministic scanner runners, lease-cleanup integration, unchanged public API
tests, and an opt-in bounded live `github.com/gogo/protobuf@1.3.1` /
`GO-2021-0053` contract smoke. Syft, SBOM, reachability, exposure, remote model
providers, persistence, and public routes remain deferred.

---

# 13. Phase 4 through Phase 6 Implementation

## 13.1 Phase 4 implementation

Phase 4 is complete under `docs/work-orders/phase-4-evidence-engine.md`. The
implemented boundary includes strict
immutable evidence, source, redaction, link, coverage, and bundle contracts;
descriptor-relative no-follow reads; digest revalidation; bounded positional
selectors; fail-closed redaction; deterministic canonical IDs; explicit limits;
hostile-fixture tests; and lease-cleanup integration.

Only Watchdog-generated Phase 3 source references are eligible. The service
remains internal, in-process, and lease-scoped. Arbitrary paths, general source
analysis, subprocesses, new network access, persistence, model calls, exposure
classification, evidence browsing, and public routes are excluded.

The 10,000-item cap is absolute. Canonically ordered overflow references remain
visible in match-source outcomes with `item_limit_exceeded` and no evidence ID.
This bounded outcome design resolves the item-cap conflict without unlimited
omitted items, silent loss, or a whole-bundle failure. The public API remains
unchanged.

## 13.2 Evidence and contextual analysis

Phase 4 provides canonical repository evidence items, source selectors/line
ranges, content hashing, secret redaction, and bounded evidence bundles. Phase 5
is complete under `docs/work-orders/phase-5-contextual-analysis.md` as a
separate, lease-scoped deterministic context service. The completed staged gates
are recorded in `docs/plans/phase-5-implementation-plan.md`.

The implementation derives targets from validated Phase 3/4 linkage and a
trusted checked-in catalog; performs sorted descriptor-relative discovery;
recognizes bounded Python, JavaScript/TypeScript, Go, JSON, and TOML lexical
forms; creates redacted context evidence and a lexical observation graph; and
emits evidence-linked import, explicit-call, target-configuration, endpoint-
proximity, incomplete-context, and guarded non-observation signals. It excludes
runtime/data-flow reachability, exposure conclusions, execution, parser
dependencies, subprocesses, new egress, persistence, models, routes, and
patches. No phase may execute repository code.

The July 29 final boundary audit tightened the fail-closed contract without
broadening capability: configuration observations require supported literal
values; JavaScript import observations require reviewed static/literal forms; Go
selector observations require an explicit alias; display-budget overflow omits
content instead of truncating it; and bundle validation verifies the semantic
relationship between observations, graph data, signals, file digests, and cited
evidence.

## 13.3 LLM strategy

Phase 6 is complete under
`docs/work-orders/phase-6-evidence-bound-model-investigation.md` and
`docs/plans/phase-6-implementation-plan.md` as the first model boundary.

The internal service operates after repository cleanup and consumes only
validated, bounded, redacted Phase 1 and Phase 3–5 artifacts. It uses a
provider-neutral gateway, canonical bounded input envelope, fixed versioned
prompt and strict response-schema assets, duplicate-aware JSON parsing, exact
evidence-link validation, and deterministic disposition gates. Model output
remains inference rather than evidence and never rewrites existing canonical
artifacts.

The only concrete gateway is disabled by default, credential-free, and limited
to a literal loopback OpenAI-compatible endpoint. It permits no DNS
hostname, redirect, ambient proxy, tool call, streaming, persistence, or remote
provider. Remote BYOK providers remain a later destination and credential-
handling decision.

Nexura-hosted inference remains deferred because it requires authentication,
billing, tenant/job isolation, retention policy, encryption, abuse controls, and
cost management. No model workflow is exposed through the API, CLI, or web UI.

## 13.4 Controlled classifications

The planned classifications are:

- Confirmed affected
- Likely affected
- Dependency present; reachability unconfirmed
- Probably not affected
- Not affected based on available evidence
- Insufficient evidence
- Unsupported ecosystem

The affected, reachability, and exposure classifications remain reserved for a
later work order. Phase 6 implements only dependency/context-observed,
context-unconfirmed, insufficient-evidence, and unsupported dispositions.

## 13.5 Interfaces and deployment

The completed Phase 7 boundary implements an evidence-safe canonical report,
deterministic summary/technical JSON and escaped-Markdown views, one bounded
end-to-end orchestrator, a direct stdout-only CLI, and a separate
disabled-by-default literal-loopback web application with a minimal synchronous
investigation API. The existing advisory API remains unchanged and is the only
default container listener.

The implementation preserves all Phase 1–6 identities, keeps repository work
inside the verified lease, invokes Phase 6 only after cleanup, and adds no
persistence, background job, remote destination, credentials, classification,
remediation, command, or patch behavior. The local app has five fixed routes,
exact Host/same-origin controls, no CORS/cookies/docs/access logs, and checked-in
dependency-free UI assets with no browser storage. A future production or hosted service still requires
non-root containers, admission/rate limits, durable job state, isolated analysis
workers, storage/retention policy, authentication, authorization, and
operational monitoring under a separate review.

---

# 14. Decision Log

## D-001 — Known-vulnerability focus

Investigate one known advisory against one repository. This is clearer and more
achievable than broad general-purpose SAST.

## D-002 — Deterministic tools before model reasoning

Parsers and scanners collect candidates/evidence first. A model may later
interpret bounded evidence but is not the primary scanner.

## D-003 — Local-first initial release

Prefer local execution for privacy, lower infrastructure cost, and open-source
adoption.

## D-004 — BYOK or local model direction

Initial model integration uses a local literal-loopback endpoint without
credentials. Remote BYOK and Nexura-hosted inference are deferred.

## D-005 — Public repositories first

Private repositories and authentication are deferred to avoid early credential
handling and tenant-isolation complexity.

## D-006 — Visible uncertainty

Conflicts, missing evidence, unsupported coverage, and assumptions remain
visible. Failure never becomes a clean negative conclusion.

## D-007 — No automatic patch application

Generated remediation may be previewed later but requires human approval before
application.

## D-008 — Archive-only Phase 2 intake

Use GitHub's exact-commit archive instead of Git clone. History is unnecessary
for the current phase, and avoiding Git removes hook, checkout-filter,
credential-helper, and submodule execution surfaces.

## D-009 — Internal-only repository intake

Do not expose intake through HTTP before job admission, rate, retention, and
abuse controls exist. The current service is the lifecycle boundary for internal
Phase 3 inventory and matching.

## D-010 — Cleanup is part of correctness

An intake is not complete until archive and workspace deletion is verified.
Cleanup failure is a typed operational failure.

## D-011 — Acquisition provenance is not a finding

An exact repository snapshot establishes the inspected artifact. Acquisition
alone does not establish dependency presence, vulnerable range, reachability, or
exposure; those require separately source-linked analysis with explicit coverage.

## D-012 — Canonical record plus tracked supporting docs

This file is the single source of truth. Supporting docs are organized by topic;
prompts/plans/recaps are archived. The complete `docs/` tree is tracked so the
current record and supporting security boundaries remain versioned with code.

## D-013 — Generated-coordinate scanner boundary

Repository dependency files are parsed by Watchdog and never passed to a
scanner subprocess. Only deduplicated exact normalized coordinates enter the
pinned OSV-Scanner custom intermediate format. Repository configuration,
recursive discovery, dependency resolution, plugins, and remediation stay off.

## D-014 — Narrow exact-coordinate negatives

A successful scan that does not return the target ID/alias supports only
`not_reported_affected` for that exact coordinate. It cannot support a
repository, reachability, condition, deployment, or exposure conclusion.

## D-015 — Lease-scoped fail-closed Phase 4 evidence

Phase 4 accepts only Watchdog-generated Phase 3 source references for the same
exact snapshot. It opens path components without following links, verifies the
Phase 3 file digest, extracts only allowlisted bounded selector spans, and
redacts before content crosses into domain models. Failure produces omitted
content and partial coverage. Evidence remains internal; the historical browser
endpoint is not authorized in this phase.

## D-016 — Phase 5 planning does not authorize implementation

Phase 5 contextual analysis requires a separate service and security boundary;
it must not broaden Phase 4 path eligibility. The proposed work order permits
only internally derived targets, descriptor-based discovery, bounded data-only
language recognizers, redacted context evidence, and non-classification signals.
The proposal itself grants no implementation authority. Runtime/data-flow
reachability, exposure conclusions, execution, subprocesses, new egress,
persistence, model calls, and public routes remain deferred.

This decision records why the original planning artifact was insufficient by
itself. It is superseded only as to authorization status by D-017; its separate-
service and scope constraints remain active.

## D-017 — Phase 5 authorization is staged and boundary-limited

The user explicitly authorized Phase 5 commencement on July 28, 2026. That
authorization is recorded in `AGENTS.md`, the authorized work order, and this
canonical record. Implementation must follow the formal Work Package 1–9 gates,
starting with schemas/configuration/targets/catalogs before source discovery and
then adding Python, JavaScript/TypeScript, and Go recognizers sequentially.

Authorization does not permit a parser dependency, Tree-sitter/native grammar,
repository execution, caller-selected search, runtime/data-flow reachability,
exposure or affected classifications, scanner changes, subprocesses, new
network access, persistence, model calls, public routes, interfaces, or patches.
Those changes still require separate explicit review.

## D-018 — Phase 5 output is lexical context, not a vulnerability classification

Phase 5 completed the staged Work Package 1–9 gates on July 28, 2026. Its
canonical observations and graph edges describe only supported lexical syntax,
and every positive signal links to redacted context evidence plus the causing
Phase 4 dependency evidence. A guarded usage-not-observed signal is available
only with complete target mapping and complete eligible coverage and carries the
fixed limitation that static non-observation does not establish runtime absence
or non-exposure.

No Phase 5 enum or model represents runtime/data-flow reachability,
exploitability, deployment exposure, or repository affected/not-affected
status. Extending that vocabulary is a new security and product boundary.

## D-019 — Phase 6 readiness does not authorize a model boundary

The user requested a Phase 6 work order and Phase 5 documentation reconciliation
on July 28, 2026, followed by a Phase 5 completion and Phase 6 readiness audit on
July 29. The resulting evidence-bound model-investigation work order is ready
for an explicit authorization decision. No model schema, prompt, gateway,
setting, network call, credential, result, route, persistence, or classification
is authorized by the planning or readiness documents.

The proposed initial boundary is deliberately local and narrow: a separate
internal service would consume only validated Phase 1 and Phase 3–5 artifacts
after repository cleanup, use a disabled-by-default credential-free literal-
loopback gateway, and accept output only after strict schema, evidence-link, and
deterministic policy validation. Its disposition vocabulary cannot represent
affected/not-affected status, runtime/data-flow reachability, exploitability, or
deployment exposure. Remote providers and every broader capability require a
separate explicit amendment even if initial Phase 6 implementation is later
authorized.

## D-020 — Phase 6 is a local evidence-bound inference service

The user explicitly authorized the formal Phase 6 plan on July 29, 2026. The
completed service is separate from repository acquisition and consumes only
revalidated Phase 1 and Phase 3–5 domain objects after repository cleanup. Its
canonical envelope includes only allowlisted advisory facts, relevant matches,
redacted evidence, lexical observations/graph relationships/signals, and
explicit coverage and omission state.

The checked-in prompt and strict JSON Schema, duplicate-aware parser, exact
evidence links, controlled codes, and deterministic disposition gates are the
acceptance boundary. Model output remains untrusted inference. The only concrete
transport is disabled by default, credential-free, non-streaming, tool-free,
single-shot, proxy-independent, redirect-free, and restricted to a literal
loopback `/v1/chat/completions` destination. Existing Phase 1–5 identities,
scanner behavior, dependencies, and public routes remain unchanged.

Remote providers, credentials, persistence, interfaces, retries/fallbacks,
runtime/data-flow reachability, exploitability, exposure or affected/not-
affected classifications, remediation, commands, and patches remain deferred
and require a separate work order.

## D-021 — Phase 7 required and received separate implementation authority

The user first requested a Phase 7 work order on July 29, 2026; that planning
request did not authorize runtime behavior. After Phase 6 was reviewed and
committed at immutable baseline `02abea5`, the user separately instructed
implementation of the decision-complete plan. That instruction authorized the
bounded report, workflow, direct CLI, and disabled literal-loopback UI/API now
implemented.

The completed boundary is synchronous and non-persistent, adds no outbound
destination, and preserves the narrower Phase 6 vocabulary. Public or production
exposure, authentication, private repositories, jobs, durable reports, remote
providers, credentials, reachability/exposure classification, remediation,
commands, and patches still require later independent review.

## D-022 — Local report interfaces are projections, not new analysis

The Phase 7 report is a canonical allowlisted projection over revalidated Phase
1–6 artifacts. It does not rerun, repair, enrich, or replace evidence and does
not make Phase 5 lexical observations or Phase 6 inference deterministic facts.
The direct CLI and local HTTP adapter construct the same strict workflow request
and invoke the same service. The listener is disabled by default and literal-
loopback only; loopback is an operator-local assumption, not authentication.

## D-023 — Phase 8 planning preserves a permanent human-approval boundary

The user requested a Phase 8 work order after Phase 7 was documented and
committed at `60079274ea4ea9784391b3b34712fd3b3d8ad519`. That request authorizes
planning, documentation, commit, and push only. Phase 8 implementation requires
a separate explicit decision and a formal staged plan.

The proposal permits only provenance-linked source-reported fixed-version
candidates, controlled non-executable human validation actions, and bounded
in-memory previews for narrowly allowlisted direct exact-version declarations.
A preview is not evidence of application, compatibility, or successful
remediation. Watchdog may not write, apply, stage, commit, push, execute, install,
resolve, build, test, or generate commands. Affected/not-affected status,
reachability/exposure, general source patches, production interfaces, and hosted
operation remain separate decisions.

---

# 15. Risks and Mitigation Direction

## Technical

- Version and package naming rules differ by ecosystem.
- Lockfiles and monorepos can encode incomplete or ambiguous graphs.
- Reachability is difficult in dynamic languages.
- Scanners and advisory sources may disagree.
- Model context may omit decisive evidence.

Mitigation: preserve original values, use ecosystem-specific deterministic
logic, report unknown/partial coverage, retain raw tool output, and maintain
fixture-driven contract tests.

## Security

- Archive and parser resource exhaustion
- Symlink/path traversal
- Scanner argument or environment injection
- Repository prompt injection
- Secret leakage
- Fabricated evidence/model claims
- Unsafe remediation

Mitigation: bounded data-only parsing, argument arrays, sanitized subprocesses,
process/resource isolation, redaction, strict schemas, evidence-link validation,
and mandatory human approval.

## Product

- Users may assume Watchdog performs comprehensive scanning.
- Evidence-heavy reports may overwhelm non-specialists.
- Local installation may create adoption friction.
- Existing platforms may add similar workflows.

Mitigation: keep claims narrow, show coverage and uncertainty, provide layered
plain-English/technical views, and validate workflows with maintainers before
expanding scope.

---

# 16. Restart Checklist

When resuming development:

1. Read `AGENTS.md` and this record.
2. Inspect `git status` and `git ls-files`; do not assume local files are committed.
3. Confirm the active phase and its acceptance criteria here.
4. Run `ruff format --check .`, `ruff check .`, `mypy`, and `pytest`.
5. Render OpenAPI and ensure public-route expansion is intentional.
6. Validate Compose and, when Docker is available, build and health-check the
   standalone image.
7. Review current architecture, threat model, and evidence policy before changing
   a boundary.
8. Treat all repository fixtures and acquired content as hostile data.
9. Update this record and supporting docs before declaring a phase complete.
10. Add a dated archived recap for material implementation sessions.

---

# 17. Documentation Layout

```text
docs/
├── Nexura_Watchdog_Project_Design_and_Implementation_Record.md  # canonical
├── README.md                                                     # local index
├── architecture/
│   └── architecture.md
├── plans/
│   ├── phase-5-implementation-plan.md
│   ├── phase-6-implementation-plan.md
│   └── phase-7-implementation-plan.md
├── security/
│   ├── evidence-policy.md
│   └── threat-model.md
├── work-orders/
│   ├── phase-4-evidence-engine.md
│   ├── phase-5-contextual-analysis.md
│   ├── phase-6-evidence-bound-model-investigation.md
│   ├── phase-7-reporting-and-local-interfaces.md
│   └── phase-8-remediation-assistant.md
└── archive/
    ├── planning/
    │   └── nexura_watchdog_formal_plan.md
    ├── prompts/
    │   └── phase-1-foundation-prompt.txt
    └── recaps/
        ├── development-recap-2026-07-27-phase-1.md
        ├── development-recap-2026-07-27-phase-2.md
        ├── development-recap-2026-07-27-phase-3.md
        ├── development-recap-2026-07-28-phase-4.md
        ├── development-recap-2026-07-28-phase-5.md
        ├── development-recap-2026-07-29-phase-5-verification.md
        ├── development-recap-2026-07-29-phase-6.md
        └── development-recap-2026-07-29-phase-7.md
```

The archive preserves historical context but is not current instruction. The
complete documentation tree is tracked and must be updated with relevant code
and boundary changes.

---

# 18. Change History

## Version 7.1 — July 29, 2026

- Recorded completed Phase 7 commit
  `60079274ea4ea9784391b3b34712fd3b3d8ad519` as the immutable Phase 8 baseline.
- Added a planning-only Phase 8 evidence-bound remediation-assistant work order
  with strict provenance, candidate, version-policy, preview, no-write,
  redaction, cleanup, human-approval, interface, limit, test, and escalation
  requirements.
- Kept all Phase 8 runtime behavior unauthorized and made explicit that the
  current Phase 0–8 roadmap still excludes affected/reachability classification,
  production hosting, broader ecosystem coverage, and release hardening.

## Version 7.0 — July 29, 2026

- Recorded explicit Phase 7 implementation authority against immutable Phase 6
  baseline `02abea5` and completed the governing work order and formal plan.
- Added strict canonical report/request/configuration models, deterministic
  identities and bounded projections, fixed evidence-safe wording, JSON and
  hostile-text-safe Markdown renderers, and exact Phase 6 envelope/result links.
- Added one fixed-order lease-safe workflow, a direct stdout-only CLI, and a
  separate disabled literal-loopback application with exact Host/same-origin
  controls, five routes, security headers, and dependency-free text-sink UI.
- Added 14 report/workflow/CLI/HTTP/UI tests and raised the deterministic baseline
  from 266 to 280 passing tests while preserving dependencies, existing advisory
  routes, OSV-Scanner 2.4.0, Phase 4–6 identities, and opt-in live scanner status.
- Kept persistence, public/remote interfaces, authentication, private inputs,
  new destinations, classification, remediation, commands, and patches deferred.

## Version 6.1 — July 29, 2026

- Reconciled the completed Phase 6 work order and supporting architecture and
  evidence policy with implemented rather than proposal-era wording.
- Added a planning-only Phase 7 evidence-safe reporting and local-interfaces
  work order with strict report/evidence semantics, lease-safe orchestration,
  deterministic renderers, a direct local CLI, and a disabled literal-loopback
  UI/API proposal.
- Recorded that Phase 7 implementation remains unauthorized and requires the
  completed Phase 6 boundary to be reviewed and committed first.

## Version 6.0 — July 29, 2026

- Recorded explicit Phase 6 implementation authority and completed the formal
  staged work packages from the Phase 5 commit `7cdcf88`.
- Added strict investigation models and identities, deterministic bounded
  envelopes over revalidated Phase 1/3–5 artifacts, fixed prompt/schema assets,
  exact evidence-link validation, deterministic dispositions, and explicit run
  states.
- Added the provider-neutral gateway and one disabled-by-default,
  credential-free, literal-loopback OpenAI-compatible adapter with strict
  destination, redirect, proxy, response, deadline, concurrency, retry, and
  cancellation controls.
- Added 23 focused adversarial/unit/integration/security tests and raised the
  deterministic baseline to 266 passing tests with the bounded live scanner
  contract still opt-in.
- Reproduced static checks, compilation, exact public routes, Compose, a fresh
  no-network/no-mount container health smoke, and OSV-Scanner 2.4.0 verification
  without changing dependencies, scanner behavior, or Phase 4/5 identities.

## Version 5.2 — July 29, 2026

- Reverified Phase 5 against its authorized work order and corrected fail-closed
  gaps in display limits, literal configuration recognition, JavaScript import
  forms, Go alias binding, and semantic evidence-link validation.
- Added adversarial regression coverage and raised the deterministic baseline to
  243 passing tests, with the bounded live scanner contract still opt-in.
- Reconciled the work order, formal plan, architecture, threat model, evidence
  policy, README files, agent boundary, and canonical record with the final
  Phase 5 behavior.
- Marked the Phase 6 proposal ready for an explicit authorization decision while
  preserving the prohibition on any Phase 6 runtime implementation until that
  separate authorization occurs.

## Version 5.1 — July 28, 2026

- Reconciled the canonical record, architecture, threat model, evidence policy,
  indexes, and root README with the completed Phase 5 implementation and its 240-
  test verification baseline.
- Added a review-only Phase 6 evidence-bound model-investigation work order with
  validated Phase 1/3–5 inputs, deterministic bounded envelopes, strict response
  and evidence-link validation, controlled non-classification dispositions, and
  explicit failure semantics.
- Proposed only a disabled-by-default, credential-free, literal-loopback initial
  gateway and kept remote providers, credentials, persistence, interfaces,
  affected/not-affected classification, remediation, commands, and patches
  outside the boundary.
- Recorded that Phase 6 implementation remains unauthorized and made no runtime,
  dependency, route, scanner, network, persistence, model, or canonical-output
  change.

## Version 5.0 — July 28, 2026

- Completed Phase 5 through the formal Work Package 1–9 gates with strict
  context schemas and identities, a trusted catalog, same-snapshot target
  linkage, bounded descriptor-relative discovery, and data-only Python,
  JavaScript/TypeScript, Go, JSON, and TOML recognition.
- Added redacted context evidence, an evidence-linked lexical observation graph,
  deterministic ranking, positive/incomplete signals, and guarded static
  non-observation without introducing reachability, exposure, exploitability, or
  repository affected/not-affected classifications.
- Added cooperative deadline/cancellation handling and lease-cleanup integration
  across successful, partial, malformed, limit, redaction-failure, deadline, and
  cancellation paths.
- Verified 240 deterministic tests, formatting/lint, strict mypy, compilation,
  exact unchanged OpenAPI paths, Compose, a fresh no-network container health
  smoke, and embedded OSV-Scanner 2.4.0.
- Kept Phase 4 identities, scanner behavior, dependencies, public routes,
  egress, persistence, models, interfaces, and patch behavior unchanged.

## Version 4.2 — July 28, 2026

- Recorded explicit user authorization to commence Phase 5 within the bounded
  deterministic contextual-analysis work order.
- Added the formal Work Package 0–9 implementation plan, sequential ecosystem
  gates, code-native catalog decision, guarded non-observation policy, risk
  register, verification matrix, and mandatory pause conditions.
- Added directory-depth, path-byte, per-file token, and memory-bounded directory
  enumeration controls before source-discovery implementation begins.
- Kept runtime/data-flow reachability, exposure/affected classifications, parser
  dependencies, execution, subprocesses, new egress, persistence, models,
  routes, interfaces, and patches outside the authorization.

## Version 4.1 — July 28, 2026

- Added a review-only Phase 5 deterministic contextual-analysis work order with
  internally derived targets, descriptor-relative discovery, bounded data-only
  language recognition, redacted context evidence, explicit non-classification
  semantics, limits, tests, and acceptance criteria.
- Recorded that the proposal does not authorize implementation and kept runtime
  reachability, exposure classifications, new dependencies, execution,
  subprocesses, egress, persistence, models, routes, and patches deferred.

## Version 4.0 — July 28, 2026

- Completed the internal lease-scoped Phase 4 evidence engine with strict frozen
  models, canonical JSON identities, descriptor-relative no-follow reads,
  digest-bound positional selectors, and fail-closed deterministic redaction.
- Added explicit duration, file, source-byte, item, line, display, redaction, and
  warning limits plus canonical overflow source outcomes that preserve every
  Phase 3 match without exceeding the evidence-item cap.
- Added schema, selector, redaction, hostile-filesystem, determinism,
  cancellation, cleanup, and unchanged-route coverage; retained all Phase 3
  scanner arguments, input behavior, OSV egress, and the 2.4.0 pin.
- Kept public evidence routes, persistence, model calls, general source or
  reachability analysis, exposure classifications, and patch behavior deferred.

## Version 3.2 — July 27, 2026

- Removed `docs/` from `.gitignore` and brought the canonical record, supporting
  security and architecture documents, active work order, and historical archive
  under normal version control.
- Replaced the former local-only backup warning with a policy requiring relevant
  documentation and behavior changes to be reviewed together.

## Version 3.1 — July 27, 2026

- Reconciled the canonical Git state with the committed 86-file Phase 0–3
  baseline and retained the intentionally ignored local documentation boundary.
- Approved Phase 4 to commence under a bounded internal evidence work order with
  deterministic schema, descriptor-based reads, fail-closed redaction, explicit
  limits, lease cleanup, and hostile-input acceptance tests.
- Kept evidence browsing, arbitrary source analysis, new egress, subprocesses,
  persistence, models, exposure classifications, and public routes deferred.

## Version 3.0 — July 27, 2026

- Recorded Phase 3 bounded dependency inventory and exact-coordinate advisory
  matching as implemented while retaining version 0.1.0 and unchanged routes.
- Documented Python/npm/Go parser coverage, limits, deterministic source links,
  pinned OSV-Scanner 2.4.0, OSV egress, failure semantics, and lease cleanup.
- Added generated-coordinate and narrow-negative decisions; kept SBOM, source
  analysis, LLM, persistence, and interfaces deferred.

## Version 2.0 — July 27, 2026

- Reconciled the record with the implemented Phase 0–2 codebase.
- Documented active API, advisory normalization, provenance, repository intake,
  extraction, cleanup, configuration, tests, Docker verification, and known debt.
- Marked Phase 3 dependency inventory/matching as next and made its work order and
  acceptance criteria explicit.
- Recorded archive-only and internal-only repository decisions.
- Distinguished current behavior from planned LLM, classification, report, CLI,
  web, persistence, and hosted capabilities.
- Defined the canonical/local-only documentation structure.

## Version 1.0 — July 27, 2026

- Established product charter, high-level architecture, security posture,
  roadmap, and first foundation work order before implementation began.

---

# 19. Final Boundary Statement

Watchdog is a vulnerability investigation system, not an autonomous security
authority. It must always show what it knows, how it knows it, what it inferred,
what it could not verify, and what the user should validate next.

Today, Watchdog can normalize an OSV advisory, safely acquire an exact public
GitHub snapshot, build a bounded source-linked dependency inventory, and report
whether pinned OSV-Scanner returned the target advisory for exact supported
coordinates. It can also turn those dependency source references into bounded,
redacted, deterministic internal evidence bundles before lease cleanup and add
bounded evidence-linked lexical observations, graph edges, and controlled
non-classification signals. This is deterministic package, artifact, and lexical
evidence, not runtime/data-flow reachability, exploitability, deployment
exposure, or an affected/not-affected repository classification.

Phase 6 can construct a bounded deterministic envelope over those immutable
artifacts and, when explicitly enabled, ask a literal-loopback model for a
strictly validated evidence-linked synthesis. That synthesis is visibly model
inference, not evidence or a vulnerability classification. The service remains
internal, credential-free, and non-persistent; only Phase 7 may consume its
validated result for a report.

Phase 7 presents those artifacts through a canonical evidence-safe report,
deterministic bounded JSON/Markdown projections, a direct stdout-only CLI, and a
separate disabled literal-loopback UI/API. It preserves cleanup, evidence,
inference, scanner, and non-classification boundaries and adds no persistence or
outbound destination. Its local result remains an evidence-bound investigation,
not an affected/not-affected or runtime-exposure determination.

Phase 8 exists only as a proposed work order. No remediation candidate, version
selection, source preview read, plan, workflow hook, command, route, patch
preview, repository write, or patch application is present. Even if the proposed
bounded Phase 8 is later completed, affected/reachability classification,
production/hosted operation, broader coverage, and release hardening remain
separate work rather than implied capabilities.
