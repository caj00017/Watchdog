# Phase 4 Work Order — Evidence Engine

**Status:** Completed July 28, 2026; retained as the reviewed implementation contract

**Prepared:** July 27, 2026

**Authority:** The canonical project record and repository `AGENTS.md` take
precedence if this work order conflicts with either one.

## Objective

Add a deterministic internal evidence engine that converts Watchdog-generated
Phase 3 dependency source references into bounded, redacted repository evidence
items and a canonical evidence bundle. All repository access and evidence work
must finish inside the existing Phase 2 lease.

Phase 4 establishes evidence identity, safe extraction, redaction, and linkage.
It does not decide whether source code is reachable or whether a repository is
affected.

## Authorized boundary

The service may:

- accept an `AcquiredRepository`, `DependencyInventory`, and
  `DependencyMatchReport` produced for the same exact snapshot;
- read only files already named by Watchdog-generated Phase 3 source references;
- locate the referenced structured value or line using allowlisted dependency
  formats;
- produce bounded redacted display content, hashes, coverage warnings, and
  deterministic evidence links;
- return immutable source-neutral domain models to its in-process caller.

The service may not:

- accept arbitrary caller-supplied repository paths, globs, selectors, or line
  ranges;
- walk the repository for new source files or perform general source,
  configuration, call, import, endpoint, reachability, or exposure analysis;
- follow symlinks, execute repository code, import repository modules, invoke
  package managers or repository tools, or install dependencies;
- start a subprocess, add an outbound network destination, persist evidence,
  send content to a model, expose a public route, or generate a patch;
- modify the Phase 3 scanner input, version, configuration, or network behavior.

The historical Phase 4 plan mentioned an evidence-browser endpoint. That route
is not part of this work order. Public repository or evidence APIs require a
separate orchestration, retention, authorization, and threat-model decision.

## Domain contract

All Phase 4 models must use strict schema validation, reject extra fields, and be
immutable after validation. Strings and collections must have explicit bounds.
No model may contain a filesystem-absolute path or unredacted secret.

### Evidence producer

`EvidenceProducer` identifies the Watchdog component that located and rendered
the evidence:

- stable producer name;
- explicit producer version;
- selector-resolver version;
- redaction-policy version.

Changing any producer version changes evidence and bundle identity.

### Evidence source

`EvidenceSource` anchors one item to:

- canonical repository URL;
- exact commit SHA and tree SHA;
- repository-relative normalized POSIX path;
- original Phase 3 structured selector;
- optional validated one-based inclusive line range;
- complete source-file SHA-256;
- trust level `untrusted_repository`.

The repository snapshot and source-file digest are mandatory. A snippet hash
alone is not sufficient evidence of its repository context.

### Evidence content

`EvidenceContent` contains only safe display material:

- UTF-8 text after deterministic newline normalization and redaction;
- SHA-256 of the final redacted UTF-8 display bytes;
- final display byte count;
- `redacted` and `truncated` flags;
- ordered redaction records.

An evidence item must never retain raw selected bytes, a raw secret, or a hash of
an individual secret. The complete source-file digest plus selector and line
range anchor the source. Redacted-display hashing anchors exactly what a later
consumer is permitted to see.

### Redaction record

`RedactionRecord` contains:

- a stable redaction category;
- detector name and version;
- occurrence ordinal;
- constant replacement marker.

It must not contain matched text, secret hashes, surrounding raw content, or
secret-derived exception messages. Initial deterministic detector categories are
private-key blocks, credential-bearing URI user information, recognized token
formats, and values assigned to allowlisted credential-like keys such as
`password`, `token`, `api_key`, `secret`, and `client_secret`.

### Evidence item

`EvidenceItem` contains:

- deterministic evidence ID;
- kind `dependency_source`;
- `EvidenceProducer` and `EvidenceSource`;
- status `extracted`, `redacted`, or `content_omitted`;
- optional safe `EvidenceContent`;
- explicit omission or coverage codes when content is unavailable.

An omitted-content item still records the exact source reference and limitation;
it must not be represented as successfully extracted content.

### Match link

`MatchEvidenceLink` contains:

- the stable match ordinal within the canonical match report;
- advisory component index and optional dependency component ID;
- ordered evidence IDs;
- explicit limitation codes.

Every dependency match with Phase 3 source references must receive a link. A
failed extraction links an omitted-content item and marks the bundle partial;
the reference must not silently disappear.

### Evidence bundle

`EvidenceBundle` contains:

- deterministic bundle ID;
- exact `InventorySnapshot`;
- evidence configuration and its SHA-256;
- sorted evidence items and match links;
- structured warnings and coverage state;
- `partial` status.

The canonical bundle contains no wall-clock timestamp or temporary path. The
same snapshot, Phase 3 inputs, source bytes, producer versions, and configuration
must serialize to the same canonical JSON and bundle ID. Operational timing may
be observed by the caller but is not evidence-bundle data.

## Initial limits

The first implementation must add `WATCHDOG_EVIDENCE_` settings and a strict
`EvidenceLimits` model with these defaults:

| Limit | Default | Meaning |
| --- | ---: | --- |
| Deadline | 60 seconds | Complete evidence collection deadline |
| Source files | 200 | Maximum unique referenced files opened |
| Bytes per source file | 5 MiB | Maximum bytes read from one file |
| Total source bytes | 25 MiB | Maximum unique source bytes read |
| Evidence items | 10,000 | Maximum canonical evidence items |
| Line span | 200 lines | Maximum selected lines before omission |
| Display bytes per item | 16 KiB | Maximum redacted display bytes |
| Bundle display bytes | 5 MiB | Maximum total redacted display bytes |
| Redactions per item | 100 | Maximum recorded replacements |
| Warnings | 1,000 | Maximum retained structured warnings |

Limit exhaustion marks coverage partial. It must not return a clean empty bundle
or change a dependency match into negative evidence. Truncation may occur only
after redaction; if the complete selected content cannot be safely redacted under
the configured limit, content is omitted.

## Safe-read algorithm

1. Reject snapshot disagreement among the acquired repository, inventory, and
   match report before opening any file.
2. Deduplicate and sort Phase 3 source references. Do not accept an independent
   path or selector argument.
3. Open the repository root and walk each relative path component with directory
   file descriptors and no-follow flags. Reject empty, dot, parent, absolute,
   backslash, symlink, non-directory parent, and non-regular final targets.
4. Read from the already-open final descriptor in bounded chunks. Enforce the
   per-file and aggregate budgets against observed bytes, not only metadata.
5. Hash the complete bytes read and require equality with the Phase 3
   `file_sha256`. A missing, changed, oversized, or unreadable source becomes an
   omitted item and explicit partial coverage.
6. Resolve the existing selector with the allowlisted positional resolver. Do
   not use `eval`, imports, repository code, or ecosystem tools.
7. Decode selected display bytes as strict UTF-8. Invalid encoding omits display
   content while preserving the source anchor and limitation.
8. Apply deterministic redaction before constructing any domain model, log
   field, diagnostic, or exception visible outside the redactor.
9. Enforce display and redaction limits, construct immutable items, sort them,
   link every match, and calculate canonical IDs.
10. Finish before the repository lease exits. Cleanup verification remains the
    caller's correctness boundary.

The implementation must not use `Path.resolve()` or a string-prefix containment
check as its symlink defense. Every opened path component must be checked through
the descriptor-based no-follow walk.

## Selector resolution

Phase 4 supports only selectors already emitted by the Phase 3 allowlisted
dependency parsers:

- line selectors from requirements and Go data are revalidated against the
  selected source line;
- JSON Pointer selectors use a bounded data-only JSON tokenizer that records
  exact token spans and rejects duplicate or ambiguous mappings;
- TOML selectors use a bounded data-only positional lexer for the supported
  Phase 3 structures and reject ambiguous mappings;
- unsupported, stale, ambiguous, or unresolvable selectors produce
  `content_omitted` evidence and explicit partial coverage.

Resolvers return the smallest complete syntactic entry that supports the Phase 3
claim, plus only configured bounded context lines. They do not inspect unrelated
source files or infer code behavior. New selector kinds or source formats are a
boundary change and require tests and documentation.

## Redaction and failure rules

- Redaction runs on the smallest selected source span, never the whole repository.
- Synthetic test secrets are required; real credentials must never enter
  fixtures, snapshots, logs, or golden files.
- Detector failure, excessive matches, invalid text, or an unsafe replacement
  state omits content and marks coverage partial.
- Warnings contain stable codes and safe generic messages only. They may name a
  normalized repository-relative path and selector but must not include source
  text.
- No exception raised by the evidence boundary may include source bytes.
- Missing or omitted evidence lowers coverage. It cannot support a negative
  repository or exposure conclusion.

## Planned modules

```text
watchdog/domain/evidence.py
watchdog/evidence/identifiers.py
watchdog/evidence/limits.py
watchdog/evidence/reader.py
watchdog/evidence/selectors.py
watchdog/evidence/redaction.py
watchdog/evidence/service.py
```

`watchdog/domain/evidence.py` stays source-neutral. Filesystem operations remain
in `watchdog/evidence/reader.py`; format positioning remains in selectors;
redaction remains isolated so unredacted values cannot cross into models or
diagnostics.

## Implementation sequence

1. Add strict domain models, canonical identity functions, configuration, and
   validator tests without reading a repository.
2. Add the descriptor-based bounded reader and hostile filesystem security
   tests.
3. Add supported positional selector resolvers and deterministic fixture tests.
4. Add redaction with tests proving raw synthetic secrets are absent from
   models, serialized output, warnings, exceptions, and captured logs.
5. Add the lease-scoped evidence service, match linkage, coverage aggregation,
   and cleanup integration tests.
6. Update all current documentation and record the completed verification
   snapshot before marking Phase 4 complete.

Each step should remain a small reviewable change. A later step must not weaken a
control established by an earlier one.

## Required tests

### Unit and schema

- strict extra-field rejection, immutability, bounds, cross-field validation;
- deterministic evidence/configuration/bundle IDs and canonical ordering;
- rejection of invalid paths, digests, line ranges, status/content combinations,
  duplicate item IDs, broken links, and snapshot mismatches;
- stable partial coverage and warning aggregation.

### Extraction

- every supported Phase 3 selector and manifest format;
- LF and CRLF input, Unicode, invalid UTF-8, long lines, multiline values,
  duplicate/ambiguous structured keys, empty files, and stale selectors;
- digest mismatch, concurrent replacement, missing file, directory, FIFO,
  symlink final target, symlink parent, and contained symlink;
- all byte, file, item, line, display, redaction, warning, deadline, and
  cancellation limits.

### Redaction

- each detector with synthetic placeholders;
- multiple and overlapping candidates with deterministic precedence;
- no raw synthetic secret in returned objects, JSON, warnings, exceptions, or
  captured logs;
- detector failure and redaction-limit exhaustion omit content without fallback.

### Integration and security

- evidence collection succeeds only while the repository lease is active;
- success, extraction failure, deadline, cancellation, and redaction failure all
  preserve verified lease cleanup;
- every Phase 3 match source reference maps to an evidence item and link;
- parser/scanner incomplete states remain incomplete and never become negative;
- repeated collection for the same commit and configuration is byte-for-byte
  deterministic;
- OpenAPI remains limited to health and advisory retrieval;
- the evidence engine performs no subprocess or outbound-network operation.

## Acceptance criteria

Phase 4 is complete only when:

1. Every Phase 3 dependency match with a source reference links to canonical
   evidence, including explicit omitted-content evidence for failures.
2. Evidence is bound to the exact snapshot, verified file digest, selector, and
   smallest supported line range.
3. No unredacted repository content crosses the evidence service boundary.
4. Sensitive synthetic fixtures are redacted before any future model-facing
   bundle could consume them.
5. Evidence bundles are byte-for-byte deterministic for the same commit, inputs,
   source bytes, producer versions, and configuration.
6. Coverage loss, limits, stale references, and failures remain explicit and
   cannot become negative findings.
7. All repository reads and evidence work finish inside the lease and cleanup is
   verified on every tested exit path.
8. No repository code, package tool, subprocess, new egress, persistence, LLM,
   exposure classification, patch, or public route is added.
9. Formatting, lint, strict type checking, deterministic tests, bytecode
   compilation, OpenAPI checks, and Compose validation pass.
10. `AGENTS.md`, the canonical record, architecture, threat model, evidence
    policy, root README, and dated completion recap describe the implemented
    boundary before Phase 4 is marked complete.

## Explicitly deferred

SBOM generation, arbitrary file evidence, general source/configuration analysis,
imports/calls/endpoints, reachability, deployment context, exposure
classification, LLM investigation, persistence, jobs, evidence browsing, public
repository routes, CLI/web workflows, remediation, and patch previews remain
outside Phase 4.
