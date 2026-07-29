# Phase 5 Formal Implementation Plan — Deterministic Contextual Analysis

**Status:** Complete; Work Packages 0–9 and acceptance gates passed

**Authorized:** July 28, 2026

**Prepared:** July 28, 2026

**Governing boundary:** `../work-orders/phase-5-contextual-analysis.md`

## 1. Purpose and authority

This plan turns the authorized Phase 5 work order into reviewable implementation
packages with explicit entry gates, exit gates, tests, and stop conditions. The
user authorized Phase 5 commencement on July 28, 2026. `AGENTS.md`, the canonical
implementation record, and the authorized work order remain controlling if this
plan is incomplete or ambiguous.

Preliminary work records authority and freezes the implementation approach; it
does not introduce contextual-analysis runtime code. The first production change
after readiness confirmation is Work Package 1, not a broad source-analysis
implementation.

## 2. Verified baseline

Phase 5 starts from commit
`3cd1f0b88be3e2c486d840eb8f378862e1bc9014`, where:

- Phases 0–4 are complete and the working implementation is on `main`;
- the deterministic suite passes 177 tests with one bounded live scanner test
  intentionally opt-in;
- formatting, lint, strict mypy, bytecode compilation, exact OpenAPI paths, and
  Compose validation pass;
- a fresh standalone image builds, returns HTTP 200 from `/health` without a
  repository mount or network, and embeds OSV-Scanner 2.4.0;
- Phase 4 evidence remains internal, lease-scoped, redacted, deterministic, and
  limited to Phase 3 source references;
- the public API contains only health and advisory retrieval; and
- no Phase 5 module, setting, route, dependency, subprocess, persistence, or
  network behavior exists.

Any baseline regression must be resolved before Phase 5 work proceeds.

## 3. Authorized outcome

Phase 5 will add one internal `ContextService` that, inside the existing active
repository lease:

1. validates the exact Phase 3 inventory/match and Phase 4 evidence snapshot;
2. derives dependency targets from those validated inputs and a trusted catalog;
3. discovers only allowlisted source/configuration files through descriptor-
   relative, no-follow traversal;
4. recognizes bounded lexical imports, explicit references/calls, reviewed
   configuration entries, and reviewed endpoint declarations without executing
   repository code;
5. creates redacted context evidence and a deterministic observation graph;
6. emits controlled non-classification signals with explicit coverage; and
7. terminates all worker activity before the repository lease can clean up.

It will not decide exploitability, runtime/data-flow reachability, deployment
exposure, or repository affected/not-affected status.

The frozen service boundary is
`ContextService.collect(acquired, inventory, report, evidence) -> ContextBundle`.
All four inputs must validate to the same exact snapshot before discovery begins,
and `evidence` must be the Phase 4 bundle whose canonical match links correspond
to `report`.

## 4. Frozen design decisions

### P5-D001 — Separate service and identity domain

Phase 5 uses `watchdog/context/` and `watchdog/domain/context.py`. It does not add
source discovery to `EvidenceService`, mutate a Phase 4 bundle, or reuse a Phase
4 evidence ID for context evidence. Phase 4 canonical bytes and IDs become
regression fixtures before shared refactoring is considered.

### P5-D002 — No new parser dependency in the initial boundary

The initial implementation uses Python standard-library primitives and reviewed
bounded recognizers. It does not add Tree-sitter, native grammars, language
servers, compilers, interpreters, or ecosystem tools. If a language cannot be
recognized safely within this boundary, it remains unsupported and coverage is
partial.

### P5-D003 — Ecosystems ship behind sequential acceptance gates

Implementation order is Python, JavaScript/TypeScript, then Go. A later language
does not weaken an earlier recognizer or cause a raw-text fallback. The public
internal `ContextService` is not introduced until all authorized recognizers and
their coverage contracts are integrated; partial work remains isolated pure
modules and tests.

### P5-D004 — Trusted code-native rule catalog

The production catalog is a frozen model constructed from checked-in constants
in `watchdog/context/catalog.py`. The service does not accept a catalog, rule,
path, glob, regular expression, symbol, key, or weight from a caller or
repository. Low-level pure functions may accept validated catalog models for
unit tests, but the production service always selects the checked-in catalog.

Catalog entries use structured identifiers and token/member paths, never raw
search regular expressions. The catalog has a version, canonical SHA-256,
unique sorted rule IDs, bounded values, explicit mapping completeness, and
review references. Adding or changing a rule changes configuration and bundle
identity.

### P5-D005 — Generic mappings are not equivalent to complete mappings

- npm package names and syntactic subpaths are exact import candidates.
- Go module paths or resolved replacement prefixes are exact import candidates.
- Python hyphen-to-underscore conversion is a generic candidate and always
  carries `import_mapping_incomplete` unless a reviewed catalog entry marks the
  exported roots complete.

Only a complete mapping can participate in guarded non-observation. A candidate
mapping can support a positive observation but never an absence claim.

### P5-D006 — Discovery fails closed at enumeration boundaries

Directory enumeration uses an already-open descriptor and buffers no more than
the remaining candidate-path capacity plus one entry. An oversized or changed
directory is discarded as a unit and stops discovery; filesystem enumeration
order never selects a nondeterministic subset. Stable directories are sorted
before processing. Traversal depth and path bytes are explicitly capped.

### P5-D007 — Observation graph, not runtime graph

Nodes and edges represent parsed lexical facts only. `calls` means an explicit
syntactic call expression was observed; it does not mean the call executes.
`declared_near_endpoint` means bounded syntactic proximity under a reviewed rule;
it does not establish request flow or external exposure.

### P5-D008 — Negative semantics remain unavailable by default

`target_usage_not_observed_within_coverage` is created only after every eligible
file and applicable recognizer completes, no relevant limit or ambiguity occurs,
the target mapping is complete, and the fixed static-non-observation limitation
is attached. Until the final integration gate proves those conditions, the
service emits `context_incomplete` instead.

### P5-D009 — Redaction precedes every outward context model

The complete selected syntactic span passes through the existing versioned
redaction policy before the display-budget decision or context model
construction. Redaction failure, replacement exhaustion, or an item/bundle
display-budget overflow omits all display content rather than truncating it.
Context models contain no raw text, secret hashes, offsets, parser exception
text, temporary path, wall-clock timestamp, or operational duration.

### P5-D010 — One shared deadline and cancellation handshake

Discovery, reading, recognition, evidence, graph, signals, and bundle creation
share one monotonic deadline and cancellation event. Async cancellation awaits
worker termination before propagating. No descriptor or raw-content buffer may
outlive the active lease.

## 5. Planned architecture and data flow

| Stage | Trusted inputs | Hostile inputs | Output |
| --- | --- | --- | --- |
| Snapshot validation | Phase 2–4 domain contracts | None | Validated same-snapshot tuple |
| Target generation | Inventory components, match ordinals, catalog | Preserved package values | Canonical bounded targets |
| Discovery | Fixed allowlist/exclusions and limits | Directory names and file types | Canonical file outcomes |
| Safe read | Open descriptors and limits | File bytes and concurrent mutations | Digest-bound bounded bytes or omission |
| Recognition | Versioned recognizer and catalog rules | Source/configuration text | Internal lexical observations or omission |
| Redaction/evidence | Existing redaction policy | Selected syntactic spans | Redacted context evidence |
| Graph/signals | Validated observations and coverage | No new repository input | Canonical graph and controlled signals |
| Bundle | Versioned configuration and all prior outputs | No raw content | Strict immutable `ContextBundle` |

The data flow is strictly one-way. Repository content cannot create a target,
rule, parser choice, path allowlist, weight, or finding classification.

## 6. Domain and identity contract

Work Package 1 will define strict frozen models for:

- `ContextProducer` and catalog metadata;
- `ContextTarget`, mapping kind, applicability, and target limitations;
- normalized source paths and digest-bound context anchors;
- per-file discovery/read/recognizer outcomes;
- redacted context evidence and links to Phase 4 dependency evidence;
- lexical observations, graph nodes, and graph edges;
- controlled signals and supporting evidence IDs;
- per-match context links;
- structured warnings and coverage;
- `ContextLimits`, `ContextConfiguration`, and `ContextBundle`.

Models reject extra fields, unbounded/control strings, invalid paths/digests,
duplicate IDs, broken links, invalid ordering, unsupported enum values,
snapshot disagreement, producer/configuration disagreement, and status/content
inconsistency.

Canonical JSON uses sorted keys, UTF-8, no insignificant whitespace, no NaN, and
SHA-256 identities. Context item IDs include the exact snapshot, file digest,
anchor, producer/recognizer/catalog/redaction versions, redacted display, and
causing match/Phase 4 links. Bundle identity excludes time, temporary paths,
thread identity, descriptor values, and operational timing.

## 7. Catalog v1 contract

The first catalog schema supports four independent rule families:

1. package-to-import mappings with `generic`, `catalog_exact`, or `unavailable`
   completeness;
2. reviewed member/symbol paths relative to an imported target;
3. reviewed literal configuration keys or normalized data-file paths; and
4. reviewed framework endpoint declaration token shapes.

The first schema commit may use an empty symbol/configuration/endpoint catalog
while generic ecosystem mappings and validation are implemented. Real catalog
entries are added in a separate reviewable change with documented references.
No catalog rule is inferred from advisory prose or repository content.

Catalog tests cover duplicate/conflicting IDs, overlapping import roots,
ambiguous rules, invalid package identities, unsorted members, bounds, digest
stability, and version changes. The default service catalog cannot be replaced
through settings or caller input.

## 8. Descriptor discovery algorithm

The discovery work package will implement the following reviewed algorithm:

1. Open the acquired root with read-only, directory, no-follow, and close-on-exec
   flags; verify a real directory with `fstat`.
2. Recursively inspect at most 64 directory levels while holding at most one
   descriptor per active level.
3. For each directory, capture `fstat`, enumerate from the open descriptor with
   a streaming iterator, and retain at most remaining candidate capacity plus
   one entry name.
4. If capacity is exceeded, discard that directory's names, record
   `candidate_path_limit_exceeded`, stop global discovery, and mark coverage
   partial.
5. Capture `fstat` again; identity or relevant metadata disagreement discards
   the enumeration as `source_tree_changed`.
6. Reject non-UTF-8/surrogate names, control characters, slash/backslash,
   empty/dot/parent names, overlong paths, duplicate identities, and case-fold
   collisions before any child is eligible.
7. Sort the stable validated names in repository-relative POSIX UTF-8 byte order
   and process them depth-first in that same canonical order.
8. Open each child relative to its parent descriptor with no-follow and
   close-on-exec flags. Descend only into real directories; final file opens are
   nonblocking and accept only allowlisted regular files.
9. Apply fixed directory exclusions before descent and fixed extension/catalog
   eligibility before reading bytes. Exclusion still records coverage.
10. For a selected file, verify pre/post identity, read bounded chunks, hash all
    permitted bytes, and retain raw bytes only until recognition/redaction ends.
11. Check cancellation/deadline between enumeration, open, read, token, rule,
    evidence, and graph operations.

The walker stays private to Phase 5. It is not a caller-facing filesystem or
search abstraction.

## 9. Recognizer strategy

### 9.1 Python gate

Use `tokenize` to create a bounded token stream and a separate state machine for
imports, aliases, name/attribute chains, call delimiters, reviewed decorators,
and literal configuration assignments. Do not invoke `ast.parse`, import a
module, evaluate a literal, resolve a relative import, or execute a decorator.

Shadowing, star imports, dynamic imports, malformed indentation, f-string
expressions, unsupported grammar, or token/depth/span overflow produce explicit
limitations. Positive observations require an exact token-derived anchor.

### 9.2 JavaScript/TypeScript gate

Implement a bounded lexer for comments, identifiers, punctuators, quoted
strings, template boundaries, and balanced delimiters. Recognize only static
imports, literal `require`/dynamic import forms, directly bound members, explicit
calls, and reviewed endpoint/configuration token shapes.

JSX/TS constructs outside the reviewed lexical subset, interpolation,
nonliteral imports, computed members, re-exports, malformed strings/comments,
and ambiguous nesting omit the affected observation. There is no raw regex
fallback.

### 9.3 Go gate

Implement a bounded lexer for comments, identifiers, import declarations,
interpreted/raw strings, selectors, calls, and balanced delimiters. Recognize
exact imports and aliases, directly bound selector references/calls, and reviewed
endpoint/configuration shapes.

Dot/blank imports, build constraints, generated files, cgo, reflection,
interfaces, malformed syntax, and dynamic dispatch remain explicit limitations.

## 10. Work packages and gates

### Work Package 0 — Authority and readiness documentation

**Deliverables**

- authorize Phase 5 in `AGENTS.md` and the canonical record;
- convert the work order from proposal to authorized boundary;
- publish this formal implementation plan;
- pre-authorize architecture/threat/evidence controls without claiming they are
  implemented; and
- verify no runtime behavior changed.

**Exit gate:** governing documents agree, local links resolve, the Phase 4 suite
still passes, and the diff contains documentation only.

### Work Package 1 — Domain, configuration, targets, and catalog foundation

**Deliverables**

- add `watchdog/domain/context.py`;
- add `watchdog/context/{__init__,identifiers,limits,catalog,targets}.py`;
- add `WATCHDOG_CONTEXT_` settings with authorized defaults;
- implement canonical configuration/catalog/target/graph/evidence/bundle IDs;
- validate Phase 3/4 snapshot and match/evidence linkage without opening files;
- freeze controlled warning, limitation, observation, edge, and signal enums; and
- add schema/identity/settings/target/catalog tests.

**Exit gate:** strict mypy and deterministic unit tests pass; no repository file
opens, route, subprocess, network, persistence, or Phase 4 output change exists.

### Work Package 2 — Descriptor-relative discovery and safe reads

**Deliverables**

- add `watchdog/context/discovery.py` and private safe-read primitives;
- implement the algorithm in Section 8;
- return only canonical file outcomes and bounded internal bytes;
- add hostile filesystem, race, enumeration, limit, deadline, and cancellation
  tests; and
- prove Phase 4 reader behavior/identities are unchanged.

**Exit gate:** discovery is deterministic for stable trees, all unsafe/ambiguous
states fail closed, and no source recognizer exists yet.

### Work Package 3 — Python recognizer

**Deliverables**

- add `watchdog/context/python.py`;
- recognize the bounded Python subset in Section 9.1;
- create internal observations with exact byte/line anchors;
- add hostile/malformed/token/depth/shadowing/Unicode/CRLF fixtures; and
- keep every unsupported condition explicit.

**Exit gate:** Python observations are deterministic and evidence-ready; Python
non-observation remains disabled.

### Work Package 4 — JavaScript/TypeScript recognizer

**Deliverables**

- add `watchdog/context/javascript.py`;
- recognize the bounded JS/TS subset in Section 9.2;
- cover ESM, literal CommonJS/dynamic imports, comments, templates, JSX/TS
  boundaries, and malformed input; and
- demonstrate no substring/regex fallback.

**Exit gate:** supported lexical forms are deterministic and unsupported forms
limit coverage without affecting Python behavior.

### Work Package 5 — Go recognizer

**Deliverables**

- add `watchdog/context/go.py`;
- recognize the bounded Go subset in Section 9.3;
- cover grouped/aliased/dot/blank imports, raw strings, build tags, generated
  markers, and malformed input; and
- preserve explicit dynamic/interface limitations.

**Exit gate:** all three authorized ecosystem recognizers pass independent
security and determinism tests.

### Work Package 6 — Configuration, endpoint, and redacted context evidence

**Deliverables**

- add `watchdog/context/{configuration,evidence}.py`;
- add separately reviewed catalog entries and references;
- select only complete syntactic spans under catalog rules;
- use the existing redaction policy before outward model construction;
- link every item to its causing match ordinal and Phase 4 evidence ID; and
- prove synthetic secrets never enter models, JSON, warnings, exceptions, logs,
  or snapshots.

**Exit gate:** each observation has canonical redacted evidence or an explicit
content omission; Phase 4 bundle bytes remain unchanged.

### Work Package 7 — Observation graph, ranking, and signals

**Deliverables**

- add `watchdog/context/{graph,ranking}.py`;
- construct only the authorized lexical node/edge vocabulary;
- implement versioned deterministic ranking and stable tie-breaks;
- implement positive signals plus guarded non-observation semantics; and
- validate every graph edge and signal evidence link.

**Exit gate:** no model field or enum can represent reachability, exposure,
exploitability, or affected/not-affected repository status.

### Work Package 8 — Lease-scoped service and integration

**Deliverables**

- add `watchdog/context/service.py`;
- orchestrate targets, discovery, recognizers, evidence, graph, and signals under
  one worker/deadline/cancellation handshake;
- add successful, partial, overflow, malformed, deadline, redaction-failure, and
  cancellation pipeline tests;
- prove verified lease cleanup on every tested path; and
- assert unchanged OpenAPI, scanner, inventory, and Phase 4 canonical output.

**Exit gate:** repeated collection is byte-for-byte deterministic and all
failure paths remain explicit rather than negative.

### Work Package 9 — Full acceptance and completion record

**Deliverables**

- run the complete quality, compile, OpenAPI, Compose, and relevant Docker gates;
- run boundary and sensitive-data audits;
- synchronize all architecture/security/operator documentation;
- add a dated Phase 5 completion recap; and
- mark Phase 5 complete only after every authorized acceptance criterion passes.

**Exit gate:** clean reviewed diff, all required verification green, no deferred
capability introduced, and completion status accurate.

## 11. Review and commit strategy

Each work package should be one reviewable commit when practical. A work package
may be split further by model, recognizer, or security-test concern, but unrelated
packages must not be collapsed into a broad commit. Every security-boundary
commit includes its tests and documentation.

Before each commit:

1. inspect the exact staged file list and diff;
2. run targeted tests for the package;
3. run Ruff formatting/lint and strict mypy;
4. run the full deterministic suite;
5. assert exact OpenAPI paths and unchanged scanner pin/arguments/input;
6. scan for raw synthetic secrets and unexpected generated files; and
7. record any environment-dependent gate separately.

Pushes occur only when explicitly authorized for that work session.

## 12. Verification matrix

| Concern | Minimum gate |
| --- | --- |
| Strict schemas and identities | Unit validation plus byte-for-byte canonical fixtures |
| Catalog trust and conflicts | Catalog/target unit tests and caller-input rejection |
| Traversal and descriptor safety | Hostile filesystem security suite |
| Enumeration determinism/bounds | Stable-tree repeats, overflow, mutation, collision tests |
| Recognizer safety | Per-language malformed/adversarial fixtures and no-fallback assertions |
| Secret confidentiality | Every detector plus failure/log/exception/snapshot assertions |
| Coverage semantics | Limit, unsupported, ambiguity, partial, and guarded non-observation tests |
| Evidence linkage | Broken-link, snapshot, match ordinal, and Phase 4 ID validation |
| Async lifecycle | Deadline/cancellation worker termination and lease cleanup tests |
| Boundary preservation | No route/network/subprocess/persistence/model/patch and scanner invariants |
| Whole-repository quality | Ruff, strict mypy, pytest, compileall, OpenAPI, Compose |
| Container boundary | Fresh build, no-mount/no-network health, scanner 2.4.0 when applicable |

## 13. Risk register

| Risk | Planned control | Stop condition |
| --- | --- | --- |
| Huge directory requires unbounded sort | Bounded stable-directory enumeration; discard on overflow | Cannot make selection deterministic within memory cap |
| Lexer accepts malformed syntax as a fact | Balanced token state, explicit ambiguity, no raw fallback | Fixture produces a false positive from malformed input |
| Python package/import mapping is misleading | Generic mapping marked incomplete; catalog exact mapping required for non-observation | Mapping completeness cannot be justified |
| Context graph is interpreted as reachability | Lexical vocabulary and schema prohibit runtime claims | A field/enum implies execution or data flow |
| Secret leaks before redaction | Raw bytes stay internal; redaction before model construction | Secret appears in any outward/log/error artifact |
| Shared Phase 4 refactor changes identities | Golden canonical fixtures before sharing | Any Phase 4 byte or ID changes |
| Cancellation races cleanup | Await worker termination before propagation | Any active descriptor/raw buffer survives lease exit |
| New dependency expands supply chain | No new parser dependency under current authority | Safe implementation requires a new dependency |
| Rule catalog becomes caller-controlled search | Code-native catalog; no settings/service injection | Caller or repository can choose search semantics |

## 14. Mandatory pause and escalation conditions

Implementation pauses for explicit review before:

- adding any runtime or development parser dependency;
- using Tree-sitter, a native extension, compiler, interpreter, language server,
  Git command, shell, or subprocess;
- adding an outbound destination, repository fetch, persistence/cache, telemetry,
  model call, public route, CLI workflow, UI, or patch path;
- accepting caller/repository paths, rules, regexes, symbols, keys, or weights;
- changing Phase 3 inventory/scanner semantics, OSV-Scanner 2.4.0, scanner input,
  arguments, environment, or egress;
- changing Phase 4 models, canonical output, evidence eligibility, or IDs;
- broadening extensions/configuration formats or weakening failure/coverage
  semantics; or
- emitting a runtime reachability, exploitability, exposure, or affected status.

If an authorized recognizer cannot be made safe without one of these changes,
that recognizer remains unsupported until a separately approved amendment.

## 15. Preliminary readiness checklist

- [x] User authorization recorded.
- [x] Phase 4 baseline and remote commit verified.
- [x] Authorized work order reviewed and converted from proposal status.
- [x] Separate-service and staged-ecosystem strategy frozen.
- [x] Catalog trust and mapping-completeness rules frozen.
- [x] Descriptor traversal memory/depth/path constraints added.
- [x] Work packages, gates, tests, risks, and stop conditions defined.
- [x] Architecture, threat model, evidence policy, index, and canonical record
      synchronized without claiming planned controls are implemented.
- [x] Production implementation started and completed within the authorized boundary.

Work Package 0 was the historical readiness gate. Work Packages 1–9 subsequently
completed under the same frozen boundary.

## 16. Work Package 0 verification

Completed July 28, 2026:

- the change set contains authorization and planning documentation only;
- Ruff formatting and lint pass;
- strict mypy passes for 81 source files;
- pytest passes 177 deterministic tests, with the bounded live OSV contract
  intentionally opt-in;
- application/test bytecode compilation passes;
- OpenAPI remains exactly `/health` and
  `/api/v1/advisories/{identifier}`; and
- Docker Compose configuration validates.

No Phase 5 module, setting, dependency, file read, route, subprocess, network,
persistence, model, classification, or patch behavior was added during
preliminary work.

## 17. Phase 5 completion definition

Phase 5 is complete only when Work Packages 1–9 pass their exit gates, every
authorized observation/signal links to canonical redacted evidence, partial
coverage is explicit, repeated bundles are deterministic, lease cleanup is
verified, Phase 3/4 behavior is unchanged, and no deferred capability has been
introduced. Authorization or partial module availability alone is not
completion.

## 18. Completion verification

Completed July 28, 2026 and reverified July 29, 2026:

- Work Packages 1–8 delivered the strict context domain and configuration,
  trusted catalog and target derivation, descriptor-relative discovery, bounded
  Python/JavaScript/TypeScript/Go and JSON/TOML recognition, redacted context
  evidence, lexical graph/ranking, and the lease-scoped `ContextService`;
- 243 deterministic tests pass, with the bounded live OSV scanner contract still
  intentionally opt-in;
- Ruff formatting/lint, strict mypy over 108 source files, application/test
  bytecode compilation, exact OpenAPI paths, and Docker Compose validation pass;
- a fresh standalone image builds on Docker Engine 29.6.2, starts without a
  repository mount or external network, returns HTTP 200 from `/health`, and
  reports OSV-Scanner 2.4.0;
- scanner code/input/arguments, the scanner image pin, Phase 4 models and
  canonical evidence implementation, and public routes remain unchanged; and
- no parser dependency, subprocess, new egress, persistence, model, public
  route, CLI/web workflow, exposure classification, or patch path was added.

The final boundary audit also proved fail-closed omission at Phase 5 display
limits, literal-only configuration observations, supported-form-only JavaScript
imports, explicit-alias-only Go selector facts, and strict semantic binding from
observations, graph relationships, signals, and file outcomes to their cited
context evidence.

The completed output remains lexical context, not runtime/data-flow
reachability, exploitability, deployment exposure, or repository
affected/not-affected status.
