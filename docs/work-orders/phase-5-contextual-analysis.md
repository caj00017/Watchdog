# Phase 5 Authorized Work Order — Deterministic Contextual Analysis

**Status:** Completed within the authorized boundary

**Prepared:** July 28, 2026

**Authorized:** July 28, 2026

**Completed:** July 29, 2026, after final boundary audit and reverification

**Formal plan:** [Phase 5 implementation plan](../plans/phase-5-implementation-plan.md)

**Completion record:** [Phase 5 final verification recap](../archive/recaps/development-recap-2026-07-29-phase-5-verification.md)

**Authority:** The user explicitly authorized Phase 5 commencement on July 28,
2026. This work order, the canonical project record, and repository `AGENTS.md`
jointly define the authorized boundary. Authorization does not waive any trust
boundary below. A capability outside this document requires a separate explicit
review and synchronized authority update before implementation.

## Objective

Add an internal, deterministic, lease-scoped contextual-analysis service that
collects narrowly relevant source and configuration observations for Phase 3
dependency matches and links them to Phase 4 evidence. Phase 5 may distinguish
dependency presence from observed import, explicit call-site, target-specific
configuration, and nearby endpoint signals. It does not decide exploitability,
runtime reachability, deployment exposure, or whether a repository is affected.

All discovery, reads, parsing, redaction, evidence construction, heuristic
evaluation, and bundle construction must finish before the existing repository
lease exits. Unredacted repository content remains transient bounded process
memory and must not cross the service boundary.

## Why this phase is separate

Phase 4 intentionally reads only files already named by Phase 3 source
references. Contextual analysis requires a new ability to discover and inspect
allowlisted source and configuration files. That is a material trust-boundary
change and must not be implemented by broadening `EvidenceService` or weakening
its caller-selected-path protections.

Phase 5 therefore introduces a separate service, producer version, configuration
digest, coverage model, rule catalog, and evidence kind. Phase 4 dependency
evidence remains immutable input and keeps its existing identity and semantics.

## Authorized boundary

The service may:

- accept an active `AcquiredRepository`, `DependencyInventory`,
  `DependencyMatchReport`, and Phase 4 `EvidenceBundle` for the same snapshot;
- derive analysis targets only from validated Phase 3 component identities,
  match links, and a trusted versioned rule catalog shipped with Watchdog;
- discover allowlisted source and configuration files inside the acquired root
  using descriptor-relative, no-follow traversal;
- tokenize or parse those files with bounded data-only parsers that never import
  or execute repository code;
- record exact import declarations, explicit symbol references and call sites,
  target-specific configuration entries, and allowlisted endpoint declarations;
- build a bounded local context graph from explicit lexical relationships;
- apply versioned deterministic ranking and heuristic rules to those
  observations;
- return strict immutable evidence, signals, coverage, warnings, and a canonical
  internal context bundle.

The service may not:

- accept caller-supplied paths, globs, regular expressions, symbols, package-to-
  import mappings, configuration keys, endpoint rules, or ranking weights;
- inspect files outside the acquired repository, follow any symlink, or use
  `Path.resolve()` or string-prefix containment as a traversal defense;
- execute or import repository code, load repository plugins, evaluate templates,
  deserialize executable formats, run a build, or invoke package/ecosystem tools;
- resolve or install dependencies, generate an SBOM, or change Phase 3 inventory
  or scanner inputs;
- use Tree-sitter, language servers, compilers, interpreters, Git, shell commands,
  subprocesses, native parser extensions, or new third-party parser dependencies
  in the initial boundary;
- add network access, persistence, cache files, telemetry containing repository
  data, a model call, a public route, a CLI workflow, or an evidence browser;
- infer data flow from untrusted input to a vulnerable sink, evaluate dynamic
  dispatch/reflection, claim runtime reachability, or produce an exposure
  classification;
- generate or apply a patch.

Tree-sitter or another parser framework may be considered later only through a
separate dependency, grammar-version, resource-limit, malformed-input, and
supply-chain review recorded as a boundary amendment.

## Trusted target and rule generation

Phase 5 must not expose a general search API. `ContextTarget` objects are
generated internally from canonical match ordinals and their validated inventory
components. A target contains only:

- match ordinal and component ID;
- ecosystem and normalized package/module identity;
- exact or preserved component version state;
- trusted import-root candidates and optional symbol/configuration/endpoint rules
  from a checked-in `ContextRuleCatalog`;
- explicit limitations when a package-to-import mapping is incomplete or
  unavailable.

Initial generic import-root rules are intentionally conservative:

- npm uses the exact normalized package name and permits a syntactic package
  subpath beneath that name;
- Go uses the exact component module path or resolved replacement module prefix;
- Python uses a normalized hyphen-to-underscore candidate only when syntactically
  valid, plus explicit reviewed exceptions in the trusted catalog.

Generic name conversion is a candidate mapping, not proof that a distribution
exports that import. The output must preserve `import_mapping_incomplete` when
the catalog cannot establish a complete mapping. Vulnerable symbols,
configuration keys, and framework rules are never taken from repository text,
advisory prose, or a caller. If the trusted catalog has no such rule, Phase 5
does not invent one.

The rule catalog must have a strict frozen schema, canonical ordering, an
explicit version and SHA-256, bounded entries, unique rule IDs, and tests for
ambiguous or conflicting rules. Changing rules or ranking weights changes the
context configuration and bundle identity.

## Initial discovery allowlist

Discovery is sorted, descriptor-relative, and no-follow. It may inspect only:

- Python: `.py` and `.pyi`;
- npm/JavaScript: `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, and `.tsx`;
- Go: `.go`;
- target-specific data configuration: `.json` and `.toml` files whose normalized
  paths or keys are explicitly named by the trusted rule catalog.

The initial boundary excludes Markdown, documentation, arbitrary text, YAML,
XML, templates, notebooks, minified/generated bundles, source maps, archives,
binaries, vendored trees, dependency caches, virtual environments, VCS data,
test snapshots, coverage output, and files selected solely by repository
instructions. Test source may be included only when it is an otherwise
allowlisted language file; its path classification must remain visible.

Directory exclusions begin with the Phase 3 generated/VCS/vendor exclusions and
add common build/output/cache trees such as `dist`, `build`, `target`, `.next`,
`.cache`, and `coverage`. Exclusion is a coverage limitation, not evidence that
usage is absent. Any allowlist or exclusion change requires security tests and
documentation.

## Descriptor-relative traversal and reads

Phase 5 must implement a dedicated descriptor walker or a reviewed shared
primitive; it must not use `os.walk` as the security boundary. The algorithm:

1. Opens the acquired repository root as a no-follow directory descriptor.
2. Enumerates entries from an already-open directory descriptor in sorted
   repository-relative POSIX order.
3. Rejects control characters, empty/dot/parent segments, backslashes, paths over
   the configured length, duplicate/case-colliding identities, and all symlinks.
4. Opens every child relative to its parent descriptor with close-on-exec and
   no-follow flags.
5. Descends only into real directories and reads only allowlisted regular files.
6. Uses nonblocking final opens, bounded chunks, and pre/post `fstat` identity
   checks.
7. Hashes the complete permitted file and records its SHA-256 before extracting
   contextual spans.
8. Stops cooperatively on cancellation or the shared monotonic deadline.

A missing, replaced, changed, unreadable, unsafe, oversized, ambiguous, or
over-limit path produces an explicit warning and partial coverage. No failure is
translated into “not used,” “unreachable,” or “not affected.”

## Data-only language analysis

All parsers operate on bounded in-memory bytes from the safe reader. UTF-8 is
strict; invalid text omits analysis for that file. Newlines are normalized only
for safe display after positions are established.

### Python

Use the standard-library tokenizer and a separately bounded syntax recognizer.
Do not import modules or evaluate annotations, decorators, literals, f-strings,
or constants. Collect only:

- `import` and `from ... import ...` declarations with aliases;
- explicit name/attribute references bound by those declarations;
- syntactic call expressions whose callee is an observed bound name/attribute;
- allowlisted route decorators/calls from the trusted catalog;
- target-specific literal configuration assignments named by catalog rules.

### JavaScript and TypeScript

Use a reviewed bounded lexical recognizer, not regular-expression search over raw
text. It must understand comments, quoted strings, template-literal boundaries,
and balanced delimiters sufficiently to reject ambiguity. Collect only:

- static `import` declarations;
- literal `require("package")` and `import("package")` forms;
- explicit member/name references bound to those imports;
- syntactic calls on those bound names;
- allowlisted route registration calls and target-specific literal
  configuration properties from catalog rules.

Nonliteral imports, computed properties, template interpolation, re-exports,
bundler aliases, and malformed or unsupported syntax remain explicit
limitations.

### Go

Use a reviewed bounded lexical recognizer for package/import declarations,
comments, quoted/raw strings, selectors, calls, and balanced delimiters. Collect
only:

- exact import paths and aliases;
- selector references and calls bound to imported package aliases;
- allowlisted `net/http` or framework registration calls from catalog rules;
- target-specific literal configuration values named by catalog rules.

Dot imports, blank imports, build tags, generated files, cgo, reflection, and
interface/dynamic dispatch must remain explicit limitations where relevant.

Malformed or ambiguous syntax never falls back to substring or regex matching.

## Context graph and deterministic signals

The graph is an observation graph, not a runtime call graph. Versioned node and
edge kinds are limited to directly parsed facts such as:

- source file and syntactic scope;
- dependency target;
- import declaration;
- bound identifier;
- explicit reference or call site;
- target-specific configuration entry;
- endpoint declaration;
- `imports`, `binds`, `references`, `calls`, `configures`, and
  `declared_near_endpoint` edges.

Every node and edge must link to canonical redacted context evidence. No edge may
assert that user input reaches a call, that a call is executed, or that two files
are runtime-reachable merely because one imports the other.

Deterministic match-level signals use a controlled non-classification vocabulary:

- `explicit_target_call_observed`;
- `target_reference_observed`;
- `dependency_import_observed`;
- `target_configuration_observed`;
- `endpoint_proximity_observed`;
- `target_usage_not_observed_within_coverage`;
- `context_incomplete`;
- `context_not_applicable`.

`target_usage_not_observed_within_coverage` is permitted only when the target had
a usable import mapping, every eligible file completed analysis, no relevant
limit or parser warning occurred, and the result carries the fixed limitation:
“Static non-observation does not establish runtime absence or non-exposure.” It
must never become a vulnerability or exposure-negative finding.

Ranking is deterministic and auditable. Exact catalog symbol calls rank above
generic package references; import declarations rank below explicit calls;
endpoint proximity and target-specific configuration are independent supporting
signals. Path order, rule ID, source position, and evidence ID provide stable
tie-breaks. File length, secret content, comments, prose, and model-generated
scores must not influence ranking.

## Evidence and domain contract

Add strict frozen source-neutral models for:

- producer and rule-catalog metadata;
- context targets and target limitations;
- source-file analysis outcomes;
- context observations, graph nodes, and graph edges;
- deterministic signals and their supporting evidence IDs;
- per-match context links;
- warnings, coverage, configuration, and `ContextBundle`.

Phase 5 context evidence uses a new evidence kind and producer identity. Each
item anchors the exact repository URL, commit/tree SHA, normalized path,
complete Phase 5 file digest, one-based inclusive line range, parser/rule
versions, and trust level `untrusted_repository`. It links back to the Phase 4
dependency evidence ID and canonical match ordinal that caused the file to be
considered.

Only content passed through the existing versioned redaction policy may enter an
outward model. The selected complete syntactic span is redacted before the
display-budget decision. If the complete redacted display does not fit the item
or remaining bundle budget, it is `content_omitted` with partial coverage rather
than truncated. Redaction failure has the same fail-closed behavior. Raw spans,
secret hashes, offsets of redacted values, parser exception text, temporary
paths, and operational timing must not enter the bundle.

Context IDs and bundle IDs use canonical JSON and SHA-256. The bundle excludes
timestamps and temporary paths and sorts targets, file outcomes, evidence,
observations, graph data, signals, links, and warnings by documented stable keys.
The same snapshot, Phase 3/4 inputs, source bytes, producer/parser/rule/redaction
versions, and configuration must serialize byte-for-byte identically.

No Phase 4 model or evidence ID may be rewritten in place. Shared reader,
redaction, or identity code may be extracted only when tests prove Phase 4 output
is byte-for-byte unchanged.

## Authorized initial limits

Add `WATCHDOG_CONTEXT_` settings and a strict `ContextLimits` model:

| Limit | Authorized default | Meaning |
| --- | ---: | --- |
| Deadline | 120 seconds | Complete discovery, analysis, and bundle deadline |
| Directories | 5,000 | Maximum real directories enumerated |
| Candidate paths | 10,000 | Maximum entries considered before filtering |
| Directory depth | 64 | Maximum descriptor-relative traversal depth |
| Path length | 4,096 UTF-8 bytes | Maximum normalized repository-relative path |
| Source files | 2,000 | Maximum allowlisted regular files opened |
| Bytes per file | 2 MiB | Maximum bytes read from one source/config file |
| Total source bytes | 50 MiB | Maximum unique contextual bytes read |
| Lexical tokens per file | 100,000 | Maximum tokens emitted by one recognizer |
| Lexical tokens | 1,000,000 | Maximum tokens across all files |
| Nesting depth | 256 | Maximum recognized delimiter/syntax depth |
| Observations | 50,000 | Maximum canonical parsed observations |
| Graph nodes | 50,000 | Maximum observation graph nodes |
| Graph edges | 100,000 | Maximum observation graph edges |
| Context evidence items | 10,000 | Maximum canonical context items |
| Line span | 100 lines | Maximum selected syntactic span |
| Display bytes per item | 16 KiB | Maximum redacted display per item |
| Bundle display bytes | 5 MiB | Maximum total redacted display |
| Redactions per item | 100 | Maximum recorded replacements |
| Warnings | 1,000 | Maximum warnings including overflow summary |

Capacity is reserved for terminal overflow summaries. Canonical input order
determines every limit outcome. Item or observation overflow remains visible in
bounded per-file and per-match outcomes; it is never silently dropped or
converted into non-observation.

Directory enumeration must also remain memory-bounded before sorting. An open
directory is scanned into at most the remaining candidate-path capacity plus one
entry. If that capacity is exceeded, the buffered names are discarded, discovery
stops, and partial coverage records `candidate_path_limit_exceeded`; no
filesystem enumeration order is allowed to choose a nondeterministic subset.
Pre/post directory identity and metadata disagreement similarly discards the
enumeration and limits coverage.

## Async lifecycle and cancellation

`ContextService.collect(...)` runs blocking traversal, parsing, redaction, and
bundle work in a cancellable worker thread under one monotonic deadline. On
caller cancellation it sets the worker cancellation event, awaits worker
termination, and only then propagates cancellation. Repository lease cleanup
must never race an active Phase 5 descriptor, parser, or raw-content buffer.

All normal failure, deadline, redaction-failure, limit, and cancellation paths
require integration tests proving verified lease cleanup. A process crash remains
outside in-process cleanup guarantees.

## Planned modules

```text
watchdog/domain/context.py
watchdog/context/catalog.py
watchdog/context/identifiers.py
watchdog/context/limits.py
watchdog/context/targets.py
watchdog/context/discovery.py
watchdog/context/python.py
watchdog/context/javascript.py
watchdog/context/go.py
watchdog/context/configuration.py
watchdog/context/evidence.py
watchdog/context/graph.py
watchdog/context/ranking.py
watchdog/context/service.py
```

Shared Phase 4 primitives remain under `watchdog/evidence/` only when their
contracts remain evidence-generic and unchanged. Phase 5 must not create a
general-purpose filesystem or search API for other callers.

## Staged implementation sequence

1. Freeze target generation, rule-catalog schema, context domain models,
   canonical identities, limits, and negative-semantics tests.
2. Add descriptor-relative sorted discovery and hostile filesystem tests without
   parsing source content.
3. Add bounded language lexical recognizers one ecosystem at a time, with Python
   first and independent security review before JavaScript/TypeScript and Go.
4. Add target-specific configuration and endpoint rules only through the trusted
   catalog.
5. Add context graph construction, deterministic signals/ranking, and explicit
   partial-coverage aggregation.
6. Integrate redacted context evidence and prove Phase 4 canonical output remains
   unchanged.
7. Add lease-scoped service, cancellation/cleanup tests, unchanged-boundary
   assertions, and synchronized architecture/threat/evidence documentation.

Each ecosystem slice should remain independently reviewable. A language must
stay unsupported rather than using a generic textual fallback.

## Required tests

### Schema and identity

- extra-field rejection, immutability, string/collection bounds, status/content
  invariants, duplicate IDs, broken evidence links, and snapshot disagreement;
- deterministic target, rule-catalog, observation, graph, signal, evidence, and
  bundle IDs;
- canonical ordering and byte-for-byte repeatability;
- rejection of caller-selected paths, rules, symbols, patterns, and weights;
- validation that no Phase 5 model emits an exposure classification.

### Discovery and reader security

- absolute/traversal/backslash/control paths, final and parent symlinks,
  contained symlinks, directories, FIFOs, devices, sockets, missing files,
  concurrent replacement, identity changes, case collisions, oversized files,
  long paths, deadlines, cancellation, and every traversal/read limit;
- exclusions for VCS, dependencies, vendors, virtual environments, generated
  output, caches, source maps, binaries, archives, and unsupported extensions;
- proof that every open is descriptor-relative and no repository path reaches a
  subprocess, network client, parser plugin, or import mechanism.

### Language recognizers

- valid and malformed import forms, aliases, multiline syntax, comments, escaped
  strings, Unicode, CRLF, invalid UTF-8, nesting, and long-line limits;
- Python relative/star imports, decorators, attribute calls, shadowing, and
  unsupported dynamic import forms;
- JavaScript/TypeScript ESM, literal CommonJS/dynamic imports, templates,
  computed properties, re-exports, comments, JSX/TS syntax boundaries, and
  unsupported nonliteral imports;
- Go grouped/aliased/dot/blank imports, raw strings, selectors, build tags,
  generated-file markers, and unsupported dynamic/interface behavior;
- malformed or unsupported syntax omits analysis instead of falling back to raw
  search.

### Rules, graph, and semantics

- npm/Go generic mappings, Python conservative mapping and exception catalog,
  missing/ambiguous mappings, catalog conflicts, and catalog-version identity;
- exact evidence support for every observation, graph edge, signal, and rank;
- deterministic tie-breaking and independence from prose/comments/secret text;
- package presence without import, import without call, explicit call without
  endpoint proximity, and endpoint proximity without data-flow claims;
- non-observation only under complete eligible coverage with its mandatory
  limitation;
- no signal can become `affected`, `not_affected`, `reachable`, `unreachable`,
  `exposed`, or `not_exposed`.

### Redaction and confidentiality

- synthetic credentials for every Phase 4 detector in imports, strings,
  configuration, endpoints, and malformed files;
- redaction overlap, display omission after full-span redaction, detector
  failure, and replacement limits;
- raw synthetic secrets absent from models, canonical JSON, warnings,
  exceptions, captured logs, snapshots, and failed-parser diagnostics.

### Integration and boundary

- Phase 3 match → Phase 4 dependency evidence → Phase 5 context links for the
  same exact snapshot;
- successful, partial, malformed, deadline, overflow, redaction-failure, and
  cancellation paths preserve verified lease cleanup;
- parser/scanner/evidence incomplete states remain incomplete and cannot become
  negative context;
- repeated collection is byte-for-byte deterministic;
- Phase 4 bundle bytes and IDs remain unchanged by shared-code refactoring;
- no package install, repository execution, subprocess, network call,
  persistence, public route, model call, exposure classification, or patch path;
- OpenAPI remains exactly health and advisory retrieval;
- OSV-Scanner remains pinned to 2.4.0 with unchanged arguments, generated input,
  trusted configuration, environment, and network behavior.

## Acceptance criteria

Phase 5 may be marked complete only when:

1. Every contextual observation and deterministic signal links to canonical
   redacted evidence for the exact snapshot and target match.
2. All eligible paths originate from internal descriptor-based discovery and all
   search semantics originate from the trusted versioned catalog.
3. Python, JavaScript/TypeScript, and Go recognizers fail closed without generic
   substring fallback or repository execution.
4. Results visibly distinguish dependency presence, import, reference, explicit
   call, target configuration, endpoint proximity, non-observation, and
   incomplete coverage.
5. No result claims exploitability, data-flow reachability, runtime execution,
   deployment exposure, or affected/not-affected repository status.
6. Unredacted repository content never crosses the service boundary or enters a
   log, exception, persisted file, export, network request, or model call.
7. Limits, ambiguity, unsupported syntax, mapping gaps, stale inputs, and failure
   remain explicit and cannot create a negative conclusion.
8. Cancellation waits for worker termination and verified lease cleanup succeeds
   on every tested path.
9. Phase 3 scanner and Phase 4 evidence identities/behavior remain unchanged.
10. Formatting, lint, strict mypy, deterministic tests, compilation, OpenAPI,
    Compose, documentation, and relevant environment-dependent verification pass.

## Explicitly deferred

Tree-sitter/native parsers, YAML/XML/templates/notebooks, arbitrary search,
repository instructions, source-to-sink taint analysis, interprocedural or
runtime call graphs, reflection/dynamic-dispatch resolution, build tags or
conditional compilation evaluation, container/deployment analysis, SBOMs,
dependency installation, package resolution, source execution, exploitability,
exposure classifications, LLM investigation, persistence, jobs, public evidence
or repository routes, CLI/web workflows, remediation, and patch previews remain
outside this authorized Phase 5 boundary.
