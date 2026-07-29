# Evidence Policy

> Supporting detail. The canonical project status and roadmap are maintained in
> `../Nexura_Watchdog_Project_Design_and_Implementation_Record.md`.

## Purpose

Watchdog must show what it knows, how it knows it, and what remains uncertain.
The current phases provide external advisory evidence, acquisition provenance
for an exact repository snapshot, source-linked dependency inventory, and
exact-coordinate scanner matches. They make no source-reachability or runtime
exposure claim.

## Evidence categories in this phase

### Normalized advisory values

Identifiers, descriptions, severity entries, affected packages or Git-only
components and ranges, CWEs, references, and remediation entries are normalized
facts reported by a source.
They are not Watchdog observations of a target repository.

Fixed-version remediation is a deterministic rendering of OSV `fixed` range
events. It means the source marks that range boundary as fixed; it is not a
compatibility guarantee or a claim that every later version is safe in every
range.

### Field provenance

Every normalized field that comes from the upstream record has a
`field_provenance` entry. The normalized path maps to one or more objects with:

- source adapter name;
- upstream record identifier;
- exact retrieval URL and UTC timestamp;
- upstream JSON path supporting the field.

Empty lists receive collection-level provenance. This distinguishes “the source
reported no items” from “the normalizer did not inspect this field.” Domain
metadata such as `partial`, `warnings`, and `conflicts` describes Watchdog
processing and does not pretend to have upstream field provenance.

### Raw source records

The complete parsed OSV JSON object is retained in `sources[].raw` by default.
Operators may disable response inclusion with
`WATCHDOG_INCLUDE_RAW_SOURCE_RECORDS=false`. Retrieval metadata remains even when
raw inclusion is disabled.

Raw content is evidence for debugging and audit. It is never executable content
or an instruction to Watchdog.

### Dependency inventory evidence

Every inventory occurrence records an exact commit-anchored deterministic ID,
repository-relative POSIX path, structured JSON Pointer/TOML/line selector, and
SHA-256 of the parsed file. Relationship (`direct`, `transitive`, `unknown`),
scope, exact/constraint/unknown version kind, source type, and preserved
conditions state only what the format supports. Constraints are not installed
versions; `go.sum` is integrity metadata; local/editable/Git dependencies remain
visible but scanner-ineligible.

Scanned-file status and coverage distinguish complete, partial, empty valid,
absent, all-malformed, and unsupported-only inputs. Oversized, excluded,
ambiguous, malformed, unresolved, and limit-stopped structures carry structured
warnings. An empty component list without this coverage state is not a valid
negative result.

### Scanner and match evidence

Scanner evidence retains the pinned version, logical fixed arguments, UTC times,
exit code, generated-input and validated-output digests, bounded validated JSON,
and sanitized diagnostics. Temporary paths are replaced by logical labels. Only
validated exit 0/1 results can support `affected`, `affected_conditional`, or
`not_reported_affected`; target IDs and aliases are matched explicitly and the
result maps back to every inventory source occurrence.

`not_reported_affected` means only that this successful pinned scan did not
report the target advisory for one exact coordinate. It is not a statement that
the repository, deployment, feature, or code path is unaffected. Scanner
failure is `scanner_incomplete`; constraints/local sources are
`version_unknown`; package-less Git or unsupported ecosystems are
`unsupported_advisory_component`. Conditional results remain conditional without
making the report partial solely for that reason.

## Alias policy

Input identifiers are canonicalized for syntax and case. An alias is accepted as
resolved only when the returned record uses it as the primary ID or explicitly
includes it in its alias list. The adapter rejects unrelated responses. Watchdog
does not infer alias equivalence from similar titles or affected packages.

## Conflict policy

Related records may be merged only when their primary identifiers and aliases
overlap. Additive collections are deduplicated. Differing scalar values remain in
`conflicts` with the complete competing values and provenance.

The first source value is used for the normalized display field to keep exports
deterministic. This is presentation precedence, not a hidden assertion that the
value is more accurate. Consumers making security decisions must inspect
`conflicts`.

## Failure and partial-result policy

- Invalid identifiers are input errors.
- A 404 states only that the configured source has no matching record.
- Timeouts and HTTP failures are source failures, not empty advisories.
- Invalid JSON, schema mismatches, invalid timestamps, and identity mismatches are
  malformed-source failures.
- Partial results must set `partial=true`, state limitations in `warnings`, or use
  the explicit `partial_result` error when no validated record can be returned.

No failure mode may be translated into “not vulnerable” or “not affected.” This
phase does not produce exposure classifications at all.

## Export policy

JSON is the canonical lossless export and includes provenance, raw sources,
conflicts, warnings, and partial status. Markdown is a human-readable projection:
it includes source metadata and conflict notices but omits raw source JSON.
Untrusted source text is escaped before Markdown rendering.

## Repository acquisition provenance

`RepositorySnapshot` is immutable metadata about one successful, temporary
acquisition. It records:

- canonical public GitHub owner, name, and URL;
- the caller's optional ref and the ref used for resolution;
- the exact commit SHA and tree SHA reported by GitHub;
- UTC retrieval time;
- SHA-256 and byte count of the downloaded archive;
- extracted regular-file bytes, file count, and symlink count.

This supports reproducibility and identifies the bytes handed to a later
deterministic consumer. The archive digest proves equality with the downloaded
archive, not authorship, signature validity, or independent equivalence to the
reported Git tree. Those values currently trust GitHub's public API and archive
service.

The repository root exists only during its lease. After exit,
`CleanupResult` records when cleanup ran, whether the archive and workspace are
absent, and whether deletion was verified. Cleanup state is operational
provenance; it is not evidence that a vulnerability is present or absent.

Repository filenames, symlink targets, and contents are untrusted data. They are
not normalized advisory facts, instructions, findings, or safe input to an LLM.
No content evidence is persisted or exported in this phase.

## Failure policy for repository intake

- Invalid GitHub URLs and refs are input failures.
- A missing or inaccessible repository/ref means only that intake could not
  resolve that public object.
- GitHub timeouts, rate limits, and HTTP failures are source failures.
- Malformed metadata or archives, unsafe members, limit violations, and deadline
  expiration are explicit intake failures.
- Cleanup is successful only when both archive and workspace absence are
  verified. A cleanup failure carries its status and must be surfaced.

None of these states may be translated into “not affected,” and a partially
created workspace never yields a repository snapshot.

## Phase 4 repository evidence

Phase 4 is complete under `../work-orders/phase-4-evidence-engine.md`. The
implemented service converts only Watchdog-generated Phase 3 source references
into internal evidence while the exact repository lease is active.

Every evidence item must identify:

- the canonical repository and exact commit/tree snapshot;
- a normalized repository-relative source path;
- the original structured selector and optional validated line range;
- the complete Phase 3 source-file digest;
- explicit producer, selector-resolver, and redaction-policy versions;
- trust level `untrusted_repository`;
- extraction status and any safe coverage or omission codes;
- only redacted display content and its SHA-256 when content is included.

Evidence identity is computed from canonical source and producer data. Evidence
bundles sort items and match links, include their complete configuration and
configuration digest, omit temporary paths and wall-clock values, and must be
byte-for-byte deterministic for the same snapshot, Phase 3 inputs, source bytes,
producer versions, and configuration.

Unredacted selected bytes may exist only transiently within bounded evidence
collection. They must never enter a domain model, serialized bundle, log,
warning, exception, persistent store, export, or model call. Redaction records
identify detector categories and replacement ordinals but contain no matched
text, individual-secret hash, or raw context. Redaction failure, invalid text,
ambiguity, stale content, or a limit produces `content_omitted` evidence and
partial coverage, never a raw fallback.

Every Phase 3 dependency match with source references receives a deterministic
match-evidence link. If content cannot be safely extracted, the link points to
an omitted-content evidence item carrying the exact reference and limitation so
the source does not silently disappear. Evidence status and bundle coverage must
be inspected before a later consumer relies on a link.

The evidence-item limit is absolute. References beyond that cap remain visible
as canonical match-source outcomes with `item_limit_exceeded` and no evidence
ID. This is the bounded resolution of the item-cap conflict: Phase 4 does not
create unlimited omitted items, silently drop references, or fail the whole
bundle solely because item capacity is exhausted.

Phase 4 evidence is an observed repository artifact, not an exposure inference.
It cannot by itself establish imports, calls, runtime reachability, deployment
applicability, exploitability, or an affected/not-affected classification.
There is no public evidence browser, persistence layer, or model-facing transfer
in Phase 4.

## Future finding evidence

Later repository evidence must identify the exact commit, tool version, file,
line range, content hash, trust level, and any redactions. Facts, external
evidence, inferences, assumptions, and recommendations must remain visibly
separate. Every repository claim and final finding must link to evidence; missing
coverage must lower confidence rather than create a negative conclusion.

## Phase 5 context evidence

The completed `../work-orders/phase-5-contextual-analysis.md` and formal
`../plans/phase-5-implementation-plan.md` define a separate context-evidence
contract implemented by the internal lease-scoped `ContextService`.

Context evidence identifies the exact snapshot, complete contextual
source-file digest, normalized path, smallest supported syntactic span,
recognizer/catalog/redaction versions, causing match ordinal, and supporting
Phase 4 dependency evidence ID. Only redacted display content may enter a
context model. Phase 4 evidence and identities remain immutable inputs rather
than being rewritten as context evidence.

The complete selected span is redacted before applying display budgets. If its
redacted display exceeds the per-item or remaining bundle budget, the content is
omitted rather than truncated. Strict bundle validation also requires each
observation, graph relationship, signal, and file outcome to cite evidence for
the same target, match, kind, source anchor, and digest as applicable.

Context observations distinguish imports, explicit references/calls, reviewed
target configuration, and reviewed endpoint proximity. They are lexical facts,
not evidence of execution, data flow, runtime reachability, exploitability,
deployment exposure, or repository affected status. Guarded static non-
observation requires complete eligible coverage, a complete target mapping, no
relevant limit/ambiguity, and a mandatory limitation explaining that static
non-observation does not establish runtime absence or non-exposure.

Discovery, recognizer, ambiguity, mapping, deadline, cancellation, redaction, or
capacity failure must remain explicit partial coverage. Missing context evidence
can never be converted into a negative conclusion.

## Phase 6 model input and inference

The completed Phase 6 work order implements a model-facing envelope and strict
inference boundary. It does not add a model evidence category: model output is
always inference over existing evidence.

The envelope is a deterministic bounded view of
validated normalized advisory facts, relevant Phase 3 matches, safe Phase 4
evidence, Phase 5 context evidence/signals, and their complete visible coverage
state. It excludes raw OSV records, unrelated inventory, omitted/raw
content, repository access, temporary paths, environment data, credentials, and
operational diagnostics. Reaching an input limit produces explicit omitted
counts and incomplete input rather than silent loss.

Model output never becomes evidence. A validated investigation result remains
an inference artifact that cites immutable evidence IDs. Every claim requires
an included evidence link, while facts, model inference,
assumptions, gaps, and controlled human-validation actions remain distinct.
Unknown, omitted, cross-snapshot, or fabricated links invalidate the whole
response instead of being repaired.

The exact validated output receives a canonical content identity, but that
identity attests only to those validated bytes and producer/configuration
versions. It does not claim that a nondeterministic model repeats the result.
Raw provider responses, opaque provider IDs, prompts, headers, and evidence text
remain transient and absent from logs, exceptions, persistence, and the
canonical result.

The implemented initial dispositions cannot express affected/not-affected status,
runtime/data-flow reachability, exploitability, or deployment exposure. Missing
or partial evidence, gateway failure, invalid output, and policy failure remain
explicit incomplete run states and never negative findings.

## Phase 7 reporting boundary

The completed Phase 7 presentation boundary consumes only revalidated Phase 1–6
artifacts. Its canonical report preserves the exact distinction between target
metadata, deterministic fact, model inference, assumption, gap, limitation, and
controlled validation action. Every deterministic finding and inference retains
its existing evidence, signal, or provenance IDs; rendering creates no new
evidence category.

The report assembler proves same-advisory and same-snapshot agreement, rebuilds
the deterministic Phase 6 envelope to verify the result link, and rejects
unknown, fabricated, omitted, stale, or cross-linked support. It selects bounded
evidence deterministically and records upstream-envelope and report omissions.
Report identity covers canonical renderer-independent content, configuration,
producer, and wording policy but does not imply repeatability of a future model
run.

Summary/technical and JSON/escaped-Markdown outputs are projections of the same
canonical report and share status, coverage, findings, inference, and
limitations. They cannot hide partial coverage, turn scanner non-reporting or
lexical non-observation into a repository negative, promote model prose to fact,
or broaden Phase 6 vocabulary. The first human-readable line states that the
report is evidence-bound and is not an affected/not-affected or runtime-exposure
determination.

Reports contain only allowlisted projections and already-redacted display
content. They exclude raw source/provider payloads, omitted/raw repository
content, operational paths, prompts/responses, headers, credentials, and logs.
Phase 7 permits no arbitrary evidence browsing, server persistence,
affected/not-affected classification, reachability/exposure conclusion,
remediation, command, or patch.

## Phase 8 remediation planning boundary

The Phase 8 work order is planning-only and creates no current remediation
artifact or behavior. It proposes that a future canonical plan treat an
advisory `fixed` event or remediation entry only as a source-reported fact with
exact Phase 1 provenance. Such a value would not prove compatibility,
availability, safety, or completed remediation, and ambiguity or conflicts would
remain explicit.

A future patch preview would be a separate deterministic review artifact linked
to one eligible exact dependency match, its Phase 4 evidence, the exact source
reference and digest, and a source-reported candidate. It could not become
evidence that a change was applied or that the repository was fixed. The
proposal requires bounded no-follow reads inside the lease, in-memory-only
single-token replacement, semantic reparse, fail-closed redaction, verified
cleanup, and a permanent human-approval boundary. No Phase 8 repository read,
candidate selection, plan, command, preview, write, or apply behavior is
currently implemented or authorized.
