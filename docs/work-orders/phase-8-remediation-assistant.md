# Phase 8 Work Order — Evidence-Bound Remediation Assistant

**Status:** Complete; implementation and release gates passed July 29, 2026

**Prepared:** July 29, 2026

**Required baseline:** Completed Phase 7 commit
`60079274ea4ea9784391b3b34712fd3b3d8ad519`

**Planning authority:** On July 29, 2026, the user requested a Phase 8 work order after
the completed Phase 7 implementation was fully documented, committed, and
prepared for push. That request authorizes this planning artifact and its
documentation links only. It does not authorize remediation models, repository
reads, version-selection logic, workflow changes, interface changes, commands,
patch generation, patch application, or any other Phase 8 runtime behavior.

**Implementation authority:** On July 29, 2026, the user supplied and explicitly
directed implementation of the formal staged Phase 8 plan in
`../plans/phase-8-implementation-plan.md`. Before runtime work began, commit
`8d5df91f672a2dfe027169da40c6abc9faa9909f` was verified to descend from the
immutable Phase 7 baseline and its complete post-baseline delta was verified as
documentation-only.

**Completion finding:** All staged packages and release gates passed. The exact
results, environment-dependent container evidence, retained live-scanner
coverage limitation, and permanent deferrals are recorded in
`../archive/recaps/development-recap-2026-07-29-phase-8.md`.

## Readiness finding

The Phase 7 baseline provides the strict inputs needed to design a remediation
boundary: normalized advisory remediation and fixed-version facts with
provenance, exact source-linked dependency coordinates, match states, canonical
repository evidence, lexical context, validated model inference, a canonical
report, lease-safe orchestration, and local-only interfaces.

Those inputs do not establish general runtime/data-flow reachability,
exploitability, deployment exposure, compatibility of an upgrade, or an
affected/not-affected repository classification. Phase 8 therefore cannot
truthfully promise that a proposed change is necessary, sufficient, safe, or a
complete fix. Its initial boundary must remain an evidence-linked remediation
*candidate* and preview service with explicit human validation.

Phase 8 was approved for staged implementation against the exact Phase 7
baseline. Each package remains subject to the gates and permanent deferrals in
the formal plan; authorization does not extend beyond this work order.

## Objective

Help a local maintainer move from a supported vulnerable dependency observation
to a reviewable next action without crossing into autonomous remediation. The
implemented initial Phase 8 boundary adds:

- a strict canonical `RemediationPlan` that references, but never rewrites, a
  validated Phase 7 report and its Phase 1–6 artifacts;
- deterministic fixed-version candidates derived only from provenance-linked
  advisory data for the same package and advisory;
- controlled, non-executable human validation actions and compatibility
  limitations;
- bounded, redacted, in-memory patch previews for a narrow allowlist of
  unambiguous direct exact-version declarations;
- separate JSON and hostile-text-safe Markdown projections;
- an opt-in direct CLI command and opt-in extension to the existing disabled
  literal-loopback application; and
- no repository write, package-manager invocation, dependency installation,
  test execution, command generation, persistence, or automatic patch apply.

The service answers only:

> What source-reported upgrade candidates exist for this exact dependency
> observation, what evidence supports them, what narrow edit could a maintainer
> review, and what must a human validate?

It does not answer:

> Is this repository definitely affected, will the upgrade be compatible, or
> has the vulnerability been fully remediated?

## Why this phase is separate

Remediation introduces a new integrity boundary. Earlier phases observe and
present hostile data; a patch preview describes a change to source bytes and can
be mistaken for an approved action. Version ordering differs by ecosystem,
advisories can contain conflicting or incomplete fixed-version information,
lockfiles can be generated artifacts, and apparently small upgrades can contain
breaking changes.

Keeping Phase 8 separate allows independent review of:

- authoritative remediation provenance and fixed-version ambiguity;
- ecosystem version-comparison correctness;
- source-edit eligibility and exact byte-span selection;
- the no-write and no-execution guarantees;
- preview redaction and hostile-output handling;
- human-approval semantics;
- lease, cancellation, and cleanup ordering; and
- local-interface expansion.

## Frozen Phase 1–7 invariants

Phase 8 must consume the completed Phase 7 baseline as immutable validated
input. It must not change:

- advisory normalization, provenance, conflicts, or OSV-only source behavior;
- public-GitHub-only repository validation, exact-commit acquisition, or lease
  cleanup;
- Phase 3 inventory coverage, parser behavior, matching semantics, scanner
  invocation, or the OSV-Scanner 2.4.0 pin;
- Phase 4 source eligibility, selectors, redaction, evidence identity, or
  canonical bundles;
- Phase 5 discovery, lexical recognizers, target catalogs, signals, evidence,
  graph semantics, or canonical identities;
- Phase 6 prompts, schemas, gateway, model policy, dispositions, evidence links,
  or canonical identities;
- Phase 7 request/report schema version 1, report identities, wording,
  renderers, CLI investigation behavior, or behavior of its existing local
  routes; or
- the existing public advisory application and its OpenAPI surface.

A Phase 8 artifact may reference these identities. It may not silently rerun,
repair, reinterpret, downgrade, or replace them.

## Implemented trust and data classification

Phase 8 receives three classes of input:

1. **Validated deterministic artifacts:** Phase 1 advisory facts and provenance,
   Phase 3 inventory/matches, Phase 4/5 evidence and context, and the Phase 7
   canonical report. These remain data, not instructions.
2. **Validated model inference:** the Phase 6 result as projected by Phase 7.
   This remains untrusted inference and may explain context, but it cannot select
   a version or authorize a preview.
3. **Repository bytes inside the lease:** hostile source bytes from an exact
   Phase 3 source reference. They may be read only by the Phase 8 preview
   collector under no-follow, digest, size, selector, and mutation checks.

Every remediation candidate, preview, limitation, and validation action must
carry its supporting advisory provenance, dependency evidence, and source
identity. A recommendation without valid support must be rejected.

## Implemented eligibility gate

A remediation candidate may be created only when all of the following are true:

1. Before any lease-scoped preview collection, the advisory, repository
   snapshot, inventory, match report, and Phase 4/5 evidence bundles pass their
   existing strict validation and same-snapshot/advisory linkage checks.
2. Before final plan assembly, the Phase 6 result and Phase 7 report also pass
   strict validation; the report ID and every referenced artifact identity must
   agree with the supplied canonical artifacts and any collected preview.
3. The relevant Phase 3 match state is `affected` or
   `affected_conditional` for an exact scanner-eligible package coordinate.
4. The candidate fixed version is reported by the normalized advisory for the
   same ecosystem and package, either as a `fixed` range event or an explicit
   remediation `fixed_version`.
5. The fixed-version value has exact Phase 1 field provenance.
6. Conflicts, incomplete advisory data, package ambiguity, and conditional
   applicability are preserved rather than resolved by preference.

`not_reported_affected`, `version_unknown`, `scanner_incomplete`, unsupported
components, lexical non-observation, model inference, or an incomplete report
cannot independently authorize a candidate or preview.

## Advisory remediation and version policy

Phase 8 must distinguish source facts from Watchdog choices:

- A source-reported fixed version is an advisory fact, not proof that it is the
  minimum compatible or currently available upgrade.
- Multiple fixed events remain multiple candidates unless a reviewed
  ecosystem-specific rule can establish which event applies to the exact
  current coordinate.
- Conflicting fixed versions or remediation records remain explicit conflicts.
- No package registry, release feed, Git tag, changelog, or compatibility
  service may be queried.
- No version may be invented, normalized into a different meaning, or selected
  by a model.

The implementation compares versions only through reviewed,
fixture-backed, ecosystem-specific deterministic comparators. PyPI may use the
already installed `packaging` library. npm and Go require code-native parsers
whose accepted grammars and ordering behavior are frozen before use. If a value
is outside the supported grammar, ordering is ambiguous, or comparator coverage
is incomplete, Phase 8 must list the source value for human review and omit a
patch preview.

The words `safe`, `compatible`, `resolved`, `fixed`, and `not affected` must not
describe a proposed target version as a Watchdog conclusion. Controlled wording
uses `source-reported fixed-version candidate` and always states that ecosystem,
compatibility, availability, lockfile, deployment, and test validation remain
the maintainer's responsibility.

## Canonical remediation plan

The `RemediationPlan` is a strict, frozen, extra-field-forbidden,
source-neutral artifact with a deterministic identity. It contains only bounded
allowlisted projections:

- schema, producer, candidate-policy, preview-policy, redaction-policy, wording,
  and renderer versions;
- exact advisory ID, repository URL, commit/tree/archive identities, and Phase 7
  report ID;
- plan status: `unavailable`, `manual_review_required`,
  `candidates_available`, or `previews_available`;
- remediation candidates with current exact coordinate, match ordinal/state,
  source-reported target value, advisory provenance IDs, evidence IDs, selection
  status, and limitations;
- patch-preview records with a source reference, original file digest,
  hypothetical file digest, structured edit operation, bounded redacted
  zero-context diff, and semantic reparse result;
- controlled validation-action codes;
- conflicts, omissions, warnings, coverage, and partial state; and
- configuration identity and canonical plan ID.

Plan identity is SHA-256 over canonical JSON excluding only the ID itself. Wall
clock time, temporary paths, process IDs, input ordering, provider metadata, and
interface choice are excluded. Candidate, preview, warning, provenance, and
support collections are uniquely keyed and canonically sorted.

The plan remains separate from Phase 7 `InvestigationReport` schema version 1.
It references the report ID but must not add fields to, re-identify, or replace
that report. JSON and Markdown are projections of the plan, not new analytical
artifacts.

## Candidate classifications

The candidate vocabulary is intentionally operational and narrower
than vulnerability classification:

- `source_reported`: an advisory supplied the candidate with provenance;
- `comparator_supported`: the value passed a reviewed ecosystem comparator;
- `ambiguous`: multiple or conflicting source facts prevent deterministic
  selection;
- `manual_only`: the candidate may be reviewed but no preview is eligible;
- `preview_eligible`: all preview gates pass; and
- `preview_unavailable`: one or more explicit preview limitations apply.

These labels must not be reused as repository affected status, risk, confidence,
compatibility, or remediation success.

## Implemented patch-preview boundary

Patch previews are optional, disabled by default, and available only for direct,
human-authored, exact-version declarations recognized by the existing data-only
parsers. The initial allowlist is limited to reviewed exact declarations in:

- `requirements*.txt` using an unambiguous exact `==` version token;
- PEP 621 dependency values in `pyproject.toml` with one unambiguous exact
  version;
- direct exact dependency values in `package.json`; and
- direct `require` entries in `go.mod` with a supported semantic version.

Generated lockfiles, transitive entries, local/editable/path/Git dependencies,
constraints, ranges, markers whose applicability is unresolved, replacements,
workspace files, and unsupported syntax are manual-only. Phase 8 does not edit
`uv.lock`, `package-lock.json`, or `go.sum`, and it must state when companion
generated files may need an operator-controlled update outside Watchdog.

The preview collector must:

1. Run only inside the existing Phase 2 lease after the relevant Phase 3–5
   artifacts exist.
2. Accept only a Phase 3 source reference reached through an eligible match and
   Phase 4 evidence link; it accepts no caller-selected path or selector.
3. Open every path component without following symlinks, require a regular file,
   verify pre/post identity, and verify the Phase 3 file SHA-256 before parsing.
4. Resolve exactly one version token through a trusted versioned locator for the
   allowlisted format. Zero or multiple matches fail closed.
5. Construct the hypothetical bytes in bounded memory without writing them to
   the repository, workspace, temporary file, cache, or subprocess.
6. Require unchanged byte-for-byte prefix and suffix around the target token.
7. Reparse original and hypothetical bytes with the same data-only parser and
   prove that exactly the intended component version changed while other
   normalized dependency facts remain equal. Parser warnings or semantic drift
   make the preview unavailable.
8. Produce an original digest, hypothetical digest, structured replacement, and
   zero-context diff; run all display text through fail-closed redaction and
   hostile-output escaping before it can leave the service.
9. Finish before lease exit and cooperate with cancellation so cleanup is joined
   and verified before any stop is reported.

The collector must never write a changed file, invoke Git, call `patch`, produce
an apply command, change file modes, follow repository instructions, or retain
unredacted repository content.

## Human approval and validation contract

Every plan must state that no change has been applied. A patch preview is a
review artifact, not approval and not a command.

Validation actions use a fixed allowlisted vocabulary such as:

- review the cited advisory fixed-version provenance;
- assess target-version compatibility and release notes independently;
- review the cited declaration and preview;
- update generated lock or checksum files using the maintainer's trusted normal
  workflow;
- run the project's trusted tests outside Watchdog;
- confirm deployment and conditional dependency applicability; and
- rerun the Watchdog investigation against a separately acquired new commit.

Actions are human-readable descriptions only. They contain no shell fragment,
package-manager command, script, URL supplied by repository content, arbitrary
path, or model-generated instruction. Watchdog never executes a validation
action or interprets its completion as fact.

## Implemented workflow placement

Patch preview collection requires exact source bytes and therefore must finish
inside the repository lease. Plan assembly and rendering require no repository
capability and occur only after verified cleanup:

```text
validate request
  -> Phase 1 advisory
  -> enter Phase 2 repository lease
     -> Phase 3 inventory and matching
     -> Phase 4 evidence
     -> Phase 5 context
     -> optional Phase 8 preview collection
  -> verified lease cleanup
  -> Phase 6 investigation
  -> Phase 7 report
  -> Phase 8 plan assembly and rendering
```

The implementation uses one shared internal workflow core that preserves the
existing Phase 7 behavior and exposes the Phase 8 hook only when explicitly
requested and enabled. A default Phase 7 investigation does not perform Phase 8
reads or create a remediation artifact.

The outer deadline includes admission, preview collection, cleanup, plan
assembly, and rendering. Timeout, cancellation, or client disconnect must cancel
and join child work, wait for verified cleanup, and emit no partial preview
bytes.

## Implemented local user boundary

Phase 8 remains local-only and opt-in. The implementation adds:

- `python -m apps.cli remediate` with the same advisory, public GitHub
  repository, optional ref, view, and format inputs as the investigation CLI;
  and
- one exact `POST /api/v1/remediations` route in the separate local application,
  available only when both local interfaces and remediation are enabled.

The Phase 7 investigation CLI and `POST /api/v1/investigations` remain unchanged.
The public advisory application remains unchanged. The Phase 8 CLI writes only
the fully buffered selected plan to stdout, accepts no output path, and uses
fixed diagnostics on stderr. The local route remains synchronous,
non-persistent, exact-Host/same-origin, bounded, and protected by the existing
custom-header and security-header policy.

The UI may add a fixed remediation mode only after the schema, workflow, CLI,
and local HTTP security tests pass. Hostile values reach text-only sinks. No
browser storage, remote asset, automatic download, clipboard write, file-system
API, or auto-apply control is permitted.

## Implemented renderers

Summary and technical JSON plus escaped Markdown project the same canonical
plan. Every renderer:

- fully buffers and byte-checks output before emission;
- includes plan/report IDs, exact snapshot, candidate source/provenance,
  preview eligibility, limitations, partial state, and validation actions;
- labels source-reported facts, Watchdog deterministic selection, and human
  actions separately;
- begins human-readable output with a fixed statement that no change was applied
  and the preview does not establish compatibility or completed remediation;
- escapes Markdown, HTML, terminal controls, bidirectional controls, paths, and
  header values as hostile data; and
- omits content rather than truncating through a code point, token, escape, or
  redaction boundary.

Raw advisory records, raw repository files, unredacted content, provider
requests/responses, prompts, environment values, temporary paths, and logs never
enter the plan.

## Implemented settings and absolute limits

Phase 8 adds a strict `WATCHDOG_REMEDIATION_` configuration boundary. The
implemented ceilings are:

| Limit | Default | Absolute maximum | Meaning |
| --- | ---: | ---: | --- |
| Remediation enabled | `false` | n/a | No Phase 8 collection or interface unless explicitly enabled |
| Preview generation enabled | `false` | n/a | Guidance can remain enabled while source previews stay off |
| Concurrent remediation workflows | `1` | `1` | Per-process admission |
| End-to-end remediation deadline | `180 s` | `600 s` | Admission through cleanup and rendering |
| Candidates | `64` | `256` | Canonical source-reported candidate records |
| Candidate versions per match | `16` | `64` | Preserved ambiguity bound |
| Preview source files | `16` | `64` | Unique validated referenced files |
| Bytes per preview source file | `5 MiB` | `5 MiB` | Read ceiling; existing smaller phase limit still controls |
| Total preview source bytes | `20 MiB` | `25 MiB` | Aggregate source-read ceiling |
| Patch previews | `16` | `64` | Canonical in-memory preview records |
| Changed tokens per preview | `1` | `1` | One exact version-token replacement |
| Diff bytes per preview | `16 KiB` | `64 KiB` | Redacted zero-context display ceiling |
| Total preview display bytes | `256 KiB` | `1 MiB` | Aggregate redacted display ceiling |
| Warnings | `128` | `512` | Structured safe warnings |
| Validation actions | `32` | `64` | Controlled human actions |
| JSON/Markdown output | `1 MiB` | `1 MiB` | Fully buffered final output |

All Phase 1–7 limits remain independently controlling. A Phase 8 value cannot
raise an earlier service's allowance. Limit exhaustion produces explicit partial
coverage or an unavailable preview, never an unsafe fallback or a negative
finding.

## Failure semantics

Expected typed states include:

- remediation disabled;
- no eligible affected exact coordinate;
- no source-reported fixed-version candidate;
- advisory remediation conflict or ambiguity;
- unsupported ecosystem version grammar;
- candidate not greater than the observed exact version;
- direct declaration unavailable or not preview-eligible;
- source reference missing, stale, changed, ambiguous, or symlinked;
- digest or semantic-reparse mismatch;
- redaction or display omission;
- preview/source/candidate/output limit exhausted;
- workflow timeout or cancellation;
- cleanup failure; and
- rendering or interface failure.

Scanner failure, incomplete analysis, unavailable remediation, invalid preview,
or cancellation must never become `no remediation needed`, `already fixed`, or
any equivalent negative conclusion. Cleanup failure remains an operational
failure and no plan may imply that the repository lease completed successfully.

## Logging and confidentiality

Logs and exceptions may contain only fixed event names, stable error codes,
bounded counts, durations, phase names, and canonical IDs known to be safe. They
must not contain advisory prose, repository URL/ref/path, dependency values,
source bytes, diffs, target versions, model content, headers, request bodies,
credentials, environment values, or temporary paths.

Plans are intentionally visible to the requesting local operator but are not
copied to logs, telemetry, caches, history, or server files. Operator-directed
stdout redirection or browser download creates an operator-owned copy outside
Watchdog's retention boundary.

## Implemented modules

```text
watchdog/domain/remediation.py
watchdog/remediation/__init__.py
watchdog/remediation/identifiers.py
watchdog/remediation/limits.py
watchdog/remediation/candidates.py
watchdog/remediation/versions.py
watchdog/remediation/preview.py
watchdog/remediation/assembler.py
watchdog/remediation/report_json.py
watchdog/remediation/report_markdown.py
watchdog/workflow/service.py                # reviewed shared-core integration only
apps/cli/__main__.py                        # additive remediate command only
apps/web/routes.py                          # one guarded local route only
apps/web/static/*                           # fixed local mode only
```

The domain artifact remains independent from filesystem, FastAPI, terminal, and
HTML code. Version comparison, source preview, plan assembly, rendering,
orchestration, and adapters remain separate.

## Required staged implementation plan

After explicit authorization, implementation must still begin with a formal plan
and pass these gates sequentially:

1. **Baseline and vocabulary:** record authorization, verify exact Phase 7
   baseline, freeze schemas, statuses, wording, limits, and support-link rules.
2. **Candidate facts:** implement advisory-to-match candidate derivation without
   repository reads; prove provenance, ambiguity, and non-classification policy.
3. **Ecosystem comparators:** implement and fixture-test one ecosystem at a time;
   unsupported grammar fails closed before preview work.
4. **Preview reader and locator:** implement descriptor-based no-follow reads,
   digest/mutation checks, exact token location, no-write proof, and semantic
   reparse for one manifest format at a time.
5. **Canonical plan:** assemble deterministic IDs, coverage, warnings,
   limitations, and fixed validation actions after cleanup.
6. **Renderers:** add bounded JSON and escaped Markdown with adversarial output
   fixtures.
7. **Workflow integration:** introduce the optional lease hook without changing
   default Phase 7 behavior; prove cancellation and cleanup ordering.
8. **CLI and local API:** expose only after internal acceptance passes; keep both
   flags disabled by default.
9. **UI, documentation, and release gate:** add the fixed text-sink mode, update
   architecture/threat/evidence/operator records, run all container and
   regression checks, and publish a dated recap.

No ecosystem or interface proceeds merely because another ecosystem passes.
Each preview format requires its own ambiguity, parser, redaction, mutation,
semantic-diff, and cleanup tests.

## Required tests

### Schema, identity, and linkage

- strict extra-forbidden models reject unknown or malformed fields;
- plan, candidate, preview, configuration, and rendered output identities are
  deterministic;
- input revalidation rejects stale, cross-advisory, cross-snapshot, fabricated,
  omitted, or broken support links;
- every candidate cites exact advisory provenance and dependency evidence;
- every preview cites one eligible candidate and one validated source reference;
- Phase 7 report ID and schema version remain unchanged.

### Candidate and version policy

- only affected/affected-conditional exact coordinates are eligible;
- non-reporting, unknown, unsupported, and scanner-incomplete states are not
  remediation authorization;
- fixed events map only to the exact ecosystem/package component;
- conflicts and multiple fixed events remain visible and prevent unsafe
  selection;
- PyPI, npm, and Go comparator fixtures cover valid ordering, prereleases,
  build/pseudo-version forms where supported, invalid syntax, and limits;
- unsupported comparison omits preview instead of guessing;
- model output cannot introduce or select a target version.

### Repository preview security

- caller-selected paths/selectors and references outside the eligible match are
  rejected before filesystem access;
- absolute/traversal/control/backslash paths, symlinks in every component,
  non-regular files, digest drift, file replacement, and mutation fail closed;
- source byte and deadline limits apply before full materialization;
- zero or multiple token locations make a preview unavailable;
- hypothetical bytes exist only in bounded memory and the workspace remains
  byte-for-byte unchanged on success and every failure;
- prefix/suffix identity and semantic reparse prove one intended version change;
- parser warnings, unrelated dependency changes, formatting-wide rewrites, and
  lockfile edits are rejected;
- redaction failure omits diff content and never falls back to raw bytes;
- repository content never enters logs, errors, prompts, or model input.

### Rendering and interface safety

- summary/technical JSON/Markdown views agree on IDs, status, candidates,
  preview state, coverage, and limitations;
- Markdown/HTML/ANSI/bidirectional/control/path/header payloads remain inert;
- output exceeding a byte ceiling is not partially emitted;
- CLI stdout contains only a complete plan and stderr contains fixed diagnostics;
- no CLI output path, command, template, model, endpoint, or patch-apply option
  exists;
- the local remediation route is absent or rejects use while disabled;
- exact Host, same-origin, Fetch Metadata, custom-header, JSON, request-size,
  security-header, disconnect, and no-CORS/no-cookie rules remain enforced;
- the UI makes no external request, uses no storage, and has no apply/execute
  control.

### Workflow, cleanup, and regression

- Phase 8 source reads occur only inside the existing lease;
- Phase 6, Phase 7 report assembly, Phase 8 plan assembly, and rendering occur
  only after verified cleanup;
- success, source failure, parser failure, redaction failure, timeout,
  cancellation, disconnect, render failure, and cleanup failure all join active
  workers and preserve cleanup semantics;
- default Phase 7 investigations perform no Phase 8 work and remain byte-for-byte
  stable for fixed fixtures;
- the public advisory OpenAPI remains exactly its existing two paths;
- dependencies, OSV source behavior, repository intake, parser behavior,
  scanner arguments/version/input/network boundary, evidence/context/model
  identities, and existing routes remain unchanged;
- formatting, lint, strict typing, deterministic tests, compileall, Compose,
  package assets, standalone image, no-mount health, scanner 2.4.0, and relevant
  no-network/local-loopback container checks pass.

## Acceptance criteria

Phase 8 may be marked complete only when:

1. The exact Phase 7 baseline and separate implementation authority are recorded.
2. One strict canonical plan references but does not mutate Phase 1–7 artifacts.
3. Every candidate is source-reported, same-package, provenance-linked, and
   derived only from an eligible exact affected match.
4. Ambiguous, conflicting, unsupported, incomplete, or conditional data remains
   explicit and cannot silently authorize a preview.
5. A preview can change only one unambiguous direct exact-version token in
   bounded memory and semantic reparse proves no other dependency fact changed.
6. No repository byte is written and no repository/package/build/test command is
   generated or executed.
7. All repository reads finish inside the lease; plan/model/report/interface work
   occurs only after verified cleanup.
8. Every preview is redacted, bounded, evidence-linked, clearly unapplied, and
   accompanied by compatibility and validation limitations.
9. Summary/technical JSON/Markdown views preserve the same status, support,
   ambiguity, coverage, and limitations.
10. The CLI and local route are opt-in, synchronous, local-only, non-persistent,
    and share one validated service boundary.
11. Phase 7 default behavior, report identity, public API, dependencies, scanner,
    egress, and Phase 1–6 identities remain unchanged.
12. Security-boundary tests and synchronized architecture, threat-model,
    evidence-policy, operator, canonical-record, AGENTS, and recap documentation
    are complete.

## Mandatory pause and escalation conditions

Implementation must pause for a separate explicit decision before:

- automatically applying, writing, staging, committing, pushing, opening a pull
  request, or uploading any proposed change;
- generating or executing a shell, package-manager, Git, build, test, validation,
  deployment, migration, or rollback command;
- installing dependencies, resolving packages, contacting a registry or release
  feed, invoking ecosystem tooling, or executing repository code;
- accepting arbitrary files, local repositories, uploaded archives, caller-
  selected paths/selectors/rules/templates, or general source-edit requests;
- editing lockfiles, checksums, generated files, multiple tokens, multiple files,
  source code, configuration unrelated to the exact dependency declaration, or
  unsupported formats;
- using a model to choose a version, generate a patch, generate validation
  instructions, reinterpret evidence, or approve remediation;
- claiming affected/not-affected status, runtime/data-flow reachability,
  exploitability, deployment exposure, upgrade compatibility, availability,
  remediation completeness, or risk reduction;
- adding persistence, history, caches, jobs/queues, report/plan retrieval,
  authentication, credentials, private repositories, telemetry, remote providers,
  external assets, or a production/non-loopback interface;
- adding a dependency, parser, executable, outbound destination, retry/fallback,
  advisory source, repository source, scanner change, or OSV-Scanner version
  change; or
- changing any Phase 1–7 canonical model, identity, prompt, policy, source
  eligibility, route, or default behavior rather than adding a separate Phase 8
  artifact and explicitly gated adapter.

## Explicitly deferred

Automatic patch application, repository writes, general code-remediation
patches, multi-file changes, lockfile regeneration, dependency resolution,
package-manager/build/test execution, generated commands/scripts, model-generated
patches or instructions, pull requests, commits, uploads, remote registries,
compatibility analysis, changelog/release-note analysis, affected/not-affected or
reachability/exposure classification, production/hosted service, authentication,
private repositories, persistence, jobs/history, and remote providers remain
outside this implemented initial Phase 8 boundary.

Completion of this bounded Phase 8 work finishes the currently enumerated Phase
0–8 feature roadmap. It does not by itself make Watchdog a production hosted
service or complete the still-deferred classification, ecosystem breadth,
release-engineering, and operational-hardening work. Those decisions require
separate planning rather than being silently folded into remediation.
