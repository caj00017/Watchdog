# Development Recap — Phase 9 Completion

**Date:** July 29, 2026

**Immutable Phase 8 baseline:**
`87ea89a5313c3dcb9cdc349a27691f91d83e623d`

**Phase 9 planning and authority commit:**
`81763ffd84aef418c49793e9059b3bb16492e93c`

**Phase 9 implementation commit:**
`5c8be6cb732ef46bb43b62675b8d4276eba91723`

**Operator-review fixes:**

- `7dfc26f9b3a99219a7934d5481aa1a4b29fad781` — admit only the fixed guided
  top-level Firefox navigation tuple;
- `366503ecf549b807a487a3cd9e5e05b3006ecc32` — make cancellation status final
  and honest about disconnected cleanup;
- `dc6e4785648482af34d75a7fa9093fdcf50595a9` — group repeated text and improve
  desktop result layout; and
- `a6f0f12cacafe96bd248aa277515727ba36ffffc` — summarize opaque evidence
  identities while retaining the complete canonical list.

**Documentation closeout commit:**
`d665a5b90153476531ff464aaf9a3fd802a984a1`

## Completed boundary

Implemented the separately authorized local-first guided experience without
changing any Phase 1–8 canonical artifact, renderer bytes, scanner scan
arguments/input/network behavior, OSV-Scanner 2.4.0, existing route default,
legacy module asset/command bytes, repository access, egress destination, or
analytical vocabulary.

The completed boundary adds:

- one installed `watchdog` dispatcher with `ui`, `doctor`, `investigate`, and
  `remediate` commands;
- direct delegation of investigation/remediation commands to the unchanged
  legacy CLI implementation;
- bounded cross-field configuration validation and a non-repository scanner
  preflight using only exact `--version`, a private control directory, minimal
  proxy-free environment, 10-second/64-KiB ceilings, argument arrays, and
  process-group cleanup;
- fixed safe doctor output and one controlled guided readiness projection;
- trusted per-process UI enabling, forced preview-off default, optional explicit
  model/previews, fixed literal-loopback URL validation, bind-before-open,
  environment-template-independent browser selection, and verified listener
  cleanup;
- separately selected guided HTML/CSS/JavaScript with two-field first run,
  collapsed advanced controls, readiness guidance, non-streaming progress,
  cancellation, counted duplicate grouping, wider independent result rows,
  explained evidence-type summaries with a complete collapsed identifier list,
  structured text-only JSON projection, visually separate model inference, raw
  canonical output, and separate no-apply remediation review; and
- guided scanner admission before body parsing or workflow activity while
  preserving all legacy scanner-failure semantics.

Phase 9 adds no model/scanner installation, hosted/non-loopback interface,
authentication, credential, private repository, persistence, telemetry,
history/job, upload, download, clipboard, arbitrary path, external browser
asset, command, write, apply, new dependency, or new outbound destination.

## Verification

- `ruff format --check .`: pass across 195 files
- `ruff check .`: pass
- strict `mypy`: pass across 177 source/test files
- `python -m compileall`: pass
- deterministic pytest after operator-review fixes: 362 passed, 1 opt-in live
  scanner test skipped
- Docker Compose parse: pass
- public OpenAPI regression: exactly `/health` and
  `/api/v1/advisories/{identifier}`
- guided checked-in asset total: 26,159 bytes, inside the 256 KiB limit
- standalone image build: pass
- image: `sha256:1f9334892518e47df0611d1668e63c3e1d63a60b2803fbde5d7f3090f117d859`,
  79,631,529 bytes
- installed wheel: all four `watchdog` commands invoke; invalid direct command
  stdout/stderr/exit results are byte-identical to both legacy module commands
- installed package: all Phase 7, Phase 8, and Phase 9 assets present
- embedded scanner and `watchdog doctor`: exactly OSV-Scanner 2.4.0 ready
- public no-mount/no-network health:
  `{"status":"ok","version":"0.1.0"}`
- guided no-mount/no-network health: `{"status":"ok"}`
- guided readiness: HTTP 200, no-store,
  `{"scanner":"ready","ai":"off","remediation":"enabled","previews":"disabled"}`
- both verification containers: network mode `none`, mounts `[]`
- SIGTERM: guided and public application shutdown completed with exit 0; the
  two disposable verification containers were then removed
- final-image SIGINT: guided shutdown completed without traceback, exited 0,
  retained network mode `none` and mounts `[]`, and the disposable container was
  removed

The image and installed-wheel checks above describe the initial implementation
commit. The four operator-review fixes changed only guided security/projection
code, tests, and documentation. Current checked-in guided assets total 26,159
bytes and pass the full deterministic/package-selection gates, but the
environment image was not rebuilt after those revisions. Release hardening must
build its candidate from the reviewed closeout commit and must not reuse the
initial Phase 9 image as a release artifact.

The live OSV scanner contract remains opt-in because it requires outbound OSV
network access. Its skipped state is an explicit coverage limitation and is not
interpreted as a negative finding. Browser opener behavior was deterministically
tested with injected controllers; the container smoke used `--no-open` because
it has no desktop session.

Two bounded headless Firefox visual-check attempts used isolated profiles, a
forced software-rendering attempt, and a 20-second timeout. The sandboxed browser
failed during graphics initialization and produced no screenshot. Only the
headless processes started by verification were terminated; the existing user
browser was left untouched, and temporary scanner/profile artifacts were
removed.

The user subsequently performed the desktop Firefox review with the native
launcher module and a temporary scanner copied from the already verified Phase
9 image. The stale development `.venv` had neither pip nor the newly generated
console script, so this session used `python -m watchdog.launcher`; installed-
wheel `watchdog` invocation remains separately verified above. The operator
confirmed the initial visual design and capability states, exercised Cancel,
and completed a live summary/JSON investigation of `GO-2021-0053` against
`https://github.com/google/osv-scanner`. The report resolved `main` to exact
commit `b159db4b508431e4b3ca752887db97e47bda462e`, retained `incomplete`, showed
scanner 2.4.0 completion, five controlled coordinate findings, evidence,
coverage gaps, limitations, and raw canonical access.

The review exposed the four issues listed with the review-fix commits above.
After the navigation fix, the operator reached and used the page. After the
layout/deduplication fix, the operator reported that the result presentation was
great. The evidence wall then prompted the final controlled type/count summary
and collapsed full-ID disclosure. The user accepted the resulting state as the
Phase 9 stopping point and asked for complete closeout documentation.

The final evidence-summary revision passed the full deterministic suite and
static hostile-text/browser-boundary checks, but no new screenshot after that
last revision was reported before close. The remediation-candidate action,
keyboard-only traversal, and a narrow responsive viewport were also not
explicitly reported as manually exercised. They retain automated/static
coverage; this recap does not claim unreported manual observations.

## Permanent deferrals

Hosted operation, authentication, credentials, private inputs, persistence,
telemetry, jobs/history, scanner/model installation, remote model providers,
repository writes/apply, commands, classification, runtime/data-flow
reachability, exposure, compatibility/availability claims, new dependencies or
destinations, release governance, locking, CI, release-candidate production,
and publication remain outside Phase 9. Release hardening resumes at item 2 of
`~/TODO.txt` under a separate work order.

For release one, model synthesis remains optional and local through the existing
operator-managed literal-loopback OpenAI-compatible adapter; Watchdog does not
install a model or model server. The user recorded a version-two direction of an
AWS-hosted service using a candidate DeepSeek V3 API provider with rate limits.
That is deferred planning context, not implementation authority. It requires a
new security/privacy/operations work order covering remote evidence transfer,
credentials, authentication and authorization, tenant isolation, provider data
handling and retention, encryption, rate/abuse/cost controls, persistence and
logging, availability/fallback, monitoring, and incident response.
