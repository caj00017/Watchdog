# Nexura Watchdog

Nexura Watchdog is an evidence-driven vulnerability investigation project. The
current implementation provides advisory intelligence plus bounded internal
services for safely acquiring public GitHub repository snapshots,
deterministically inventorying allowlisted dependency files, matching exact
coordinates, collecting redacted dependency-source evidence, and producing
bounded evidence-linked lexical context. The API accepts
a CVE, GHSA, or OSV database identifier, retrieves
the corresponding OSV record, and returns a source-neutral advisory with
field-level provenance.

Repository intake, inventory, and matching are not exposed through HTTP routes.
Intake resolves a branch, tag, or commit to an immutable commit SHA, downloads
that SHA's GitHub archive, extracts only validated data into a disposable
workspace, and verifies deletion when its context closes. Inside that lease,
Phase 3 reads bounded dependency data without invoking package managers or
repository code. Exact PyPI, npm, and Go coordinates can be sent to pinned
OSV-Scanner 2.4.0 through a generated custom input. SBOMs, runtime/data-flow
reachability, remote model providers, and patch generation remain out of scope.

Phase 4 implements the reviewed internal evidence-engine work order. It turns
only Watchdog-generated Phase 3 source references into bounded, redacted,
deterministic evidence while the repository lease remains active. It adds no
arbitrary repository browsing, general source/reachability analysis, subprocess,
new network access, persistence, model call, exposure classification, or public
route.

Phase 5 implements a separate internal `ContextService`. It validates the same
Phase 3/4 snapshot and evidence links, discovers only allowlisted Python,
JavaScript/TypeScript, Go, and catalog-selected JSON/TOML files with bounded
descriptor-relative no-follow reads, and emits deterministic redacted lexical
observations, graph edges, and non-classification signals. It adds no route,
subprocess, dependency, network client, persistence, model call, runtime
reachability, exposure classification, or patch behavior.

Phase 6 implements a separate internal `InvestigationService` over validated
Phase 1 and Phase 3–5 artifacts after repository cleanup. It builds a canonical
bounded envelope, uses fixed versioned instructions and strict JSON Schema,
requires exact evidence links plus deterministic disposition gates, and has one
disabled-by-default credential-free literal-loopback OpenAI-compatible adapter.
It adds no route, interface, persistence, remote provider, affected/not-affected
classification, reachability/exposure claim, remediation, command, or patch.

Phases 0–9 are complete as of July 29, 2026.

Phase 7 adds deterministic evidence-safe reports, a bounded end-to-end workflow,
a direct stdout-only CLI, and a separate disabled-by-default literal-loopback
UI/API. It preserves all Phase 1–6 identities, keeps repository work inside the
verified lease, invokes Phase 6 only after cleanup, and adds no persistence,
remote destination, classification, remediation, command, or patch behavior.

Phase 8 adds a disabled-by-default evidence-bound remediation assistant against
immutable Phase 7 commit `6007927`. It emits provenance-linked source-reported
upgrade candidates, controlled human validation actions, and optional narrowly
bounded in-memory previews of one direct exact-version token. It never writes or
applies repository bytes, generates commands, executes repository or ecosystem
tools, resolves versions, or claims compatibility or completed remediation.

Phase 9 adds the installed `watchdog` launcher, bounded scanner readiness, and a
separately selected guided literal-loopback experience. It changes no Phase
1–8 artifact, renderer, scanner, route default, or analytical claim. The guided
launcher enables the local UI and candidate planning only for its process;
previews remain explicit opt-in, AI remains optional and literal-loopback, and
no repository byte is written or retained.

Release 1 hardening adds Apache-2.0 licensing, governance and security-reporting
policy, exact hash-checked dependency locks, least-privilege CI, bounded package
inspection, a digest-pinned multi-stage container build, and a human-gated PyPI
Trusted Publishing workflow. It changes no Phase 1–9 runtime behavior,
destination, default, canonical artifact, or analytical claim. `v0.1.0` remains
unpublished until the final external release gate is approved.

Release 1 is local terminal-first: bare `watchdog` and explicit `watchdog tui`
launch a keyboard-first Textual TUI, while the existing `watchdog ui` web
experience remains unchanged for side-by-side comparison. Textual 8.2.8 and its
pure-Python graph are exact hash-locked trusted-project dependencies. Publication
of the validated pre-TUI candidate remains paused in favor of a replacement
candidate. Hosted operation and SSH access are deferred to a separately reviewed
Version 2 product.

## Requirements

- Python 3.12, 3.13, or 3.14
- `pip` and `venv` for native development, or Docker Compose
- Network access to `https://api.osv.dev` when resolving live advisories
- Network access to `https://api.github.com` and GitHub's allowlisted codeload
  host when acquiring a repository
- OSV-Scanner 2.4.0 at an absolute configured path for native matching; the
  Docker image embeds the pinned multi-architecture scanner binary
- Network access to OSV for exact-coordinate scanner lookups

## Development install

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements/dev.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
```

The lock is generated from trusted Watchdog metadata in a clean Python 3.12
environment. It is never generated from, or used to install, an analyzed
repository. For a release artifact, install `requirements/runtime.lock` first
and then install the reviewed wheel with `--no-deps`.

Check prerequisites and start the guided local experience:

```bash
watchdog doctor
watchdog
```

`doctor` validates configuration and invokes only the configured scanner's
bounded `--version` operation. It requires exactly OSV-Scanner 2.4.0 and never
contacts an advisory, GitHub, OSV, registry, repository, or model endpoint. It
prints only fixed readiness text and does not reveal configured paths or
environment values.

Bare `watchdog` and `watchdog tui` require interactive stdin/stdout and a
supported terminal of at least 60 columns by 20 rows. They perform scanner
readiness before workflow-runtime construction. The TUI offers Summary,
Evidence, Remediation, and display-safe Canonical JSON views without receiving a
repository, scanner, filesystem, HTTP, or model-provider capability. Dynamic
values are plain text under the versioned terminal display policy; original
bounded canonical JSON bytes remain unchanged in memory. `Ctrl+C` cancels active
work through cleanup verification, while `Ctrl+Q` requests a clean exit.

For side-by-side comparison, `watchdog ui` prints the exact literal-loopback URL
after binding and opens it in the system browser. Use `--no-open` to leave browser opening to
the operator. The initial page needs only an advisory ID and a public GitHub
URL; optional ref, view, and artifact format are under Advanced. The page stores
no investigation, uses no external assets, and offers remediation candidate
review only after an investigation completes. Repeated result text is grouped
with explicit counts. Evidence is explained and summarized by identity type,
with every canonical identifier and the unchanged raw artifact retained under
collapsed disclosures.

AI is `Off` by default. `watchdog tui --model MODEL` or
`watchdog ui --model MODEL` enables the existing
credential-free literal-loopback OpenAI-compatible adapter for that process;
the existing explicit investigation settings remain supported. A model outage,
timeout, malformed response, or schema/policy rejection leaves the deterministic
report available with a controlled limitation. `watchdog tui --enable-previews`
or `watchdog ui --enable-previews` independently opts into the existing bounded one-token
in-memory preview behavior. No option installs a scanner or model, persists a
result, generates a command, or applies a change.

Release one retains only this optional operator-managed local model path so the
evidence envelope and synthesis can remain on the operator's machine. A future
AWS-hosted service and remote model provider require a separate authorized
security/privacy/operations boundary; no remote provider or hosted listener is
implemented by this release.

Configuration is read from environment variables prefixed with `WATCHDOG_`.
Useful settings include:

| Variable | Default | Purpose |
| --- | --- | --- |
| `WATCHDOG_ENVIRONMENT` | `development` | `development`, `test`, or `production` |
| `WATCHDOG_OSV_BASE_URL` | `https://api.osv.dev/v1` | OSV API base URL |
| `WATCHDOG_UPSTREAM_TIMEOUT_SECONDS` | `10` | OSV request timeout, greater than 0 and at most 60 seconds |
| `WATCHDOG_INCLUDE_RAW_SOURCE_RECORDS` | `true` | Retain the raw OSV object in the response |
| `WATCHDOG_GITHUB_API_VERSION` | `2026-03-10` | GitHub REST API version header |
| `WATCHDOG_REPOSITORY_NETWORK_TIMEOUT_SECONDS` | `30` | Timeout for each GitHub request, at most 120 seconds |
| `WATCHDOG_REPOSITORY_MAX_DURATION_SECONDS` | `600` | End-to-end intake deadline, including concurrency wait |
| `WATCHDOG_REPOSITORY_MAX_ARCHIVE_BYTES` | `262144000` | Maximum compressed archive bytes |
| `WATCHDOG_REPOSITORY_MAX_EXTRACTED_BYTES` | `262144000` | Maximum regular-file bytes extracted |
| `WATCHDOG_REPOSITORY_MAX_FILES` | `25000` | Maximum unique extracted paths, including directories |
| `WATCHDOG_REPOSITORY_MAX_PATH_LENGTH` | `1024` | Maximum relative path length after stripping the archive root |
| `WATCHDOG_REPOSITORY_MAX_CONCURRENT_INTAKES` | `1` | Concurrent leases per intake-service instance |
| `WATCHDOG_REPOSITORY_WORKSPACE_ROOT` | system temporary directory | Optional parent for mode-0700 workspaces |
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
| `WATCHDOG_EVIDENCE_DEADLINE_SECONDS` | `60` | End-to-end evidence deadline |
| `WATCHDOG_EVIDENCE_MAX_SOURCE_FILES` | `200` | Maximum unique referenced files opened |
| `WATCHDOG_EVIDENCE_MAX_BYTES_PER_SOURCE_FILE` | `5242880` | Maximum bytes read from one evidence source file |
| `WATCHDOG_EVIDENCE_MAX_TOTAL_SOURCE_BYTES` | `26214400` | Maximum total unique evidence-source bytes read |
| `WATCHDOG_EVIDENCE_MAX_ITEMS` | `10000` | Maximum canonical evidence items |
| `WATCHDOG_EVIDENCE_MAX_LINE_SPAN` | `200` | Maximum selected source lines per item |
| `WATCHDOG_EVIDENCE_MAX_DISPLAY_BYTES_PER_ITEM` | `16384` | Maximum redacted display bytes per item |
| `WATCHDOG_EVIDENCE_MAX_BUNDLE_DISPLAY_BYTES` | `5242880` | Maximum redacted display bytes per bundle |
| `WATCHDOG_EVIDENCE_MAX_REDACTIONS_PER_ITEM` | `100` | Maximum replacements recorded per item |
| `WATCHDOG_EVIDENCE_MAX_WARNINGS` | `1000` | Maximum retained evidence warnings, including overflow summary |
| `WATCHDOG_CONTEXT_DEADLINE_SECONDS` | `120` | Whole Phase 5 contextual-analysis deadline |
| `WATCHDOG_CONTEXT_MAX_DIRECTORIES` | `5000` | Maximum source directories enumerated |
| `WATCHDOG_CONTEXT_MAX_CANDIDATE_PATHS` | `10000` | Maximum directory entries considered before filtering |
| `WATCHDOG_CONTEXT_MAX_DIRECTORY_DEPTH` | `64` | Maximum descriptor-relative traversal depth |
| `WATCHDOG_CONTEXT_MAX_PATH_BYTES` | `4096` | Maximum UTF-8 bytes in a normalized relative path |
| `WATCHDOG_CONTEXT_MAX_SOURCE_FILES` | `2000` | Maximum allowlisted source/configuration files opened |
| `WATCHDOG_CONTEXT_MAX_BYTES_PER_SOURCE_FILE` | `2097152` | Maximum bytes read from one contextual source file |
| `WATCHDOG_CONTEXT_MAX_TOTAL_SOURCE_BYTES` | `52428800` | Maximum total contextual source bytes read |
| `WATCHDOG_CONTEXT_MAX_TOKENS_PER_FILE` | `100000` | Maximum lexical tokens per file |
| `WATCHDOG_CONTEXT_MAX_TOTAL_TOKENS` | `1000000` | Maximum lexical tokens across the bundle |
| `WATCHDOG_CONTEXT_MAX_NESTING_DEPTH` | `256` | Maximum recognized delimiter depth |
| `WATCHDOG_CONTEXT_MAX_OBSERVATIONS` | `50000` | Maximum canonical lexical observations |
| `WATCHDOG_CONTEXT_MAX_GRAPH_NODES` | `50000` | Maximum lexical graph nodes |
| `WATCHDOG_CONTEXT_MAX_GRAPH_EDGES` | `100000` | Maximum lexical graph edges |
| `WATCHDOG_CONTEXT_MAX_EVIDENCE_ITEMS` | `10000` | Maximum redacted context evidence items |
| `WATCHDOG_CONTEXT_MAX_LINE_SPAN` | `100` | Maximum source lines selected per item |
| `WATCHDOG_CONTEXT_MAX_DISPLAY_BYTES_PER_ITEM` | `16384` | Maximum redacted display bytes per item |
| `WATCHDOG_CONTEXT_MAX_BUNDLE_DISPLAY_BYTES` | `5242880` | Maximum redacted display bytes per context bundle |
| `WATCHDOG_CONTEXT_MAX_REDACTIONS_PER_ITEM` | `100` | Maximum redactions per context item |
| `WATCHDOG_CONTEXT_MAX_WARNINGS` | `1000` | Maximum retained context warnings |
| `WATCHDOG_INVESTIGATION_ENABLED` | `false` | Explicitly enable the internal model request |
| `WATCHDOG_INVESTIGATION_LOOPBACK_HOST` | `127.0.0.1` | Literal loopback only: `127.0.0.1` or `::1` |
| `WATCHDOG_INVESTIGATION_LOOPBACK_PORT` | `11434` | Explicit loopback model-server port |
| `WATCHDOG_INVESTIGATION_MODEL` | unset | Required bounded model identifier when enabled |
| `WATCHDOG_INVESTIGATION_DEADLINE_SECONDS` | `60` | Concurrency, request, response, validation, and result deadline |
| `WATCHDOG_INVESTIGATION_MAX_CONCURRENT_REQUESTS` | `1` | Requests per service instance; fixed maximum of one |
| `WATCHDOG_INVESTIGATION_MAX_INPUT_BYTES` | `262144` | Maximum canonical envelope bytes |
| `WATCHDOG_INVESTIGATION_MAX_OUTPUT_BYTES` | `65536` | Maximum provider response bytes |
| `WATCHDOG_INVESTIGATION_MAX_EVIDENCE_ITEMS` | `256` | Maximum Phase 4/5 evidence items in the envelope |
| `WATCHDOG_INVESTIGATION_MAX_CLAIMS` | `64` | Maximum validated model claims |
| `WATCHDOG_INVESTIGATION_MAX_EVIDENCE_LINKS_PER_CLAIM` | `32` | Maximum citations per claim |
| `WATCHDOG_INVESTIGATION_MAX_ASSUMPTIONS` | `32` | Maximum controlled assumption codes |
| `WATCHDOG_INVESTIGATION_MAX_MISSING_EVIDENCE_CODES` | `64` | Maximum controlled gap codes |
| `WATCHDOG_INVESTIGATION_MAX_VALIDATION_ACTIONS` | `32` | Maximum controlled human-validation actions |
| `WATCHDOG_INVESTIGATION_MAX_RATIONALE_BYTES_PER_CLAIM` | `2048` | Maximum UTF-8 rationale bytes per claim |
| `WATCHDOG_INVESTIGATION_MAX_OUTPUT_TOKENS` | `4096` | Requested provider output ceiling |
| `WATCHDOG_WORKFLOW_MAX_CONCURRENT_REQUESTS` | `1` | Whole workflows per process; fixed maximum of one |
| `WATCHDOG_WORKFLOW_DEADLINE_SECONDS` | `180` | Admission through report assembly and cleanup |
| `WATCHDOG_WORKFLOW_MAX_ADVISORY_IDENTIFIER_BYTES` | `128` | Maximum advisory identifier bytes |
| `WATCHDOG_WORKFLOW_MAX_REPOSITORY_URL_BYTES` | `2048` | Maximum repository URL bytes before strict validation |
| `WATCHDOG_WORKFLOW_MAX_REPOSITORY_REF_BYTES` | `255` | Maximum optional repository-ref bytes |
| `WATCHDOG_WORKFLOW_MAX_REPORT_JSON_BYTES` | `1048576` | Maximum canonical JSON/report bytes |
| `WATCHDOG_WORKFLOW_MAX_MARKDOWN_BYTES` | `1048576` | Maximum fully rendered Markdown bytes |
| `WATCHDOG_WORKFLOW_MAX_REPORT_ENTRIES` | `1024` | Maximum entries in either report projection |
| `WATCHDOG_WORKFLOW_MAX_EVIDENCE_REFERENCES` | `2048` | Maximum report evidence/provenance references |
| `WATCHDOG_WORKFLOW_MAX_REPORT_DIAGNOSTICS` | `512` | Maximum retained report diagnostics |
| `WATCHDOG_LOCAL_INTERFACES_ENABLED` | `false` | Explicitly enable the separate local listener |
| `WATCHDOG_LOCAL_INTERFACES_HOST` | `127.0.0.1` | Literal `127.0.0.1` or `::1` only |
| `WATCHDOG_LOCAL_INTERFACES_PORT` | `8765` | Local application port |
| `WATCHDOG_LOCAL_INTERFACES_MAX_REQUEST_BYTES` | `8192` | Maximum investigation request body |
| `WATCHDOG_LOCAL_INTERFACES_MAX_STATIC_ASSET_BYTES` | `262144` | Total checked-in UI asset ceiling |
| `WATCHDOG_REMEDIATION_ENABLED` | `false` | Explicitly enable candidate/plan workflows and the direct CLI |
| `WATCHDOG_REMEDIATION_PREVIEW_ENABLED` | `false` | Independently enable lease-scoped in-memory previews |
| `WATCHDOG_REMEDIATION_MAX_CONCURRENT_REQUESTS` | `1` | Whole remediation workflows per process; fixed maximum one |
| `WATCHDOG_REMEDIATION_DEADLINE_SECONDS` | `180` | Admission through cleanup, plan assembly, and rendering |
| `WATCHDOG_REMEDIATION_MAX_CANDIDATES` | `64` | Canonical candidate records; hard maximum 256 |
| `WATCHDOG_REMEDIATION_MAX_CANDIDATE_VERSIONS_PER_MATCH` | `16` | Preserved targets per match; hard maximum 64 |
| `WATCHDOG_REMEDIATION_MAX_PREVIEW_SOURCE_FILES` | `16` | Internally selected source files; hard maximum 64 |
| `WATCHDOG_REMEDIATION_MAX_BYTES_PER_PREVIEW_SOURCE_FILE` | `5242880` | Per-file preview read ceiling |
| `WATCHDOG_REMEDIATION_MAX_TOTAL_PREVIEW_SOURCE_BYTES` | `20971520` | Aggregate preview-read ceiling; hard maximum 25 MiB |
| `WATCHDOG_REMEDIATION_MAX_PREVIEWS` | `16` | Canonical preview records; hard maximum 64 |
| `WATCHDOG_REMEDIATION_MAX_DIFF_BYTES_PER_PREVIEW` | `16384` | Redacted zero-context display ceiling |
| `WATCHDOG_REMEDIATION_MAX_TOTAL_PREVIEW_DISPLAY_BYTES` | `262144` | Aggregate redacted preview display ceiling |
| `WATCHDOG_REMEDIATION_MAX_WARNINGS` | `128` | Controlled structured warning ceiling |
| `WATCHDOG_REMEDIATION_MAX_VALIDATION_ACTIONS` | `32` | Controlled non-executable action ceiling |
| `WATCHDOG_REMEDIATION_MAX_JSON_BYTES` | `1048576` | Fully buffered JSON output ceiling |
| `WATCHDOG_REMEDIATION_MAX_MARKDOWN_BYTES` | `1048576` | Fully buffered Markdown output ceiling |

Investigation settings are consumed when a trusted workflow creates
`InvestigationService`; the existing advisory FastAPI application still does not
instantiate or expose it. The Phase 7 CLI/local app create it only behind the
bounded workflow and after repository cleanup. Enabling requires an explicit
model identifier and a same-host server that
supports strict OpenAI-compatible JSON Schema responses at the fixed
`/v1/chat/completions` path. No API key is accepted or sent.

Phase 9 adds no environment setting. Guided mode is selected only by the
installed `watchdog ui` launcher. It uses immutable per-process overrides to
enable the local interface and candidate planning, forces previews off unless
`--enable-previews` is present, and retains the validated configured loopback
host and port. This does not change the disabled defaults used by `python -m
apps.cli` or `python -m apps.web`.

## Run locally

The primary native first-run path is:

```bash
watchdog doctor
watchdog ui
```

The installed launcher also exposes the unchanged direct workflows as
`watchdog investigate ...` and `watchdog remediate ...`. They delegate to the
same implementation as the legacy module commands and preserve stdout, stderr,
and exit behavior.

The public advisory API remains available separately for development:

```bash
uvicorn apps.api.main:app --reload
```

The API and interactive OpenAPI documentation are then available at
`http://127.0.0.1:8000` and `http://127.0.0.1:8000/docs`.

Docker Compose builds and starts the standalone image without a source bind mount:

```bash
docker compose up --build
```

The Phase 7 CLI calls the workflow directly and writes only the selected report
to standard output. Watchdog accepts no output path; shell redirection is an
operator-controlled persistence decision.

```bash
python -m apps.cli investigate \
  --advisory CVE-2021-44228 \
  --repository https://github.com/owner/repository \
  --ref main \
  --view technical \
  --format json
```

Exit `0` means a complete report, `4` means a valid analytically incomplete
report, `2` is invalid input, `3` is advisory/repository acquisition failure,
`5` is cancellation/deadline, and `1` is cleanup/report/internal failure.

The Phase 8 command has the same request shape and no output-path, apply,
command, path, selector, or replacement option. `WATCHDOG_REMEDIATION_ENABLED`
must be explicit. Preview generation remains off unless its separate flag is
also enabled.

```bash
WATCHDOG_REMEDIATION_ENABLED=true \
python -m apps.cli remediate \
  --advisory CVE-2021-44228 \
  --repository https://github.com/owner/repository \
  --ref main \
  --view technical \
  --format markdown
```

Remediation exit `0` means a candidate or complete preview is available, `4`
means a valid unavailable/manual plan, `6` means the feature is disabled, `2`
is invalid input, `3` is advisory/repository failure, `5` is cancellation or
deadline, and `1` is cleanup, validation, assembly, render, or internal failure.
Stdout receives exactly one complete plan; fixed diagnostics use stderr.

The legacy separate local web application is still disabled by default. Start
it explicitly; the launcher refuses hostnames, wildcards, and non-loopback
addresses and does not launch a browser or enable access logs.

```bash
WATCHDOG_LOCAL_INTERFACES_ENABLED=true python -m apps.web
```

The fixed local surface at `http://127.0.0.1:8765` contains `/health`, `/`, two
exact asset routes, and synchronous `POST /api/v1/investigations`. The POST
requires `Content-Type: application/json` and
`X-Watchdog-Local-Request: 1`. There is no OpenAPI UI, CORS, cookie, job,
history, upload, evidence browser, arbitrary static path, or retained report.

When both `WATCHDOG_LOCAL_INTERFACES_ENABLED=true` and
`WATCHDOG_REMEDIATION_ENABLED=true`, the checked-in remediation UI variant and
synchronous `POST /api/v1/remediations` are added. The variant uses text-only
sinks and has no apply, command, clipboard, upload, filesystem, persistence, or
download control. The same Host, origin, Fetch Metadata, custom-header, JSON,
request-size, no-store, no-CORS, no-cookie, and disconnect-cleanup controls
apply.

The guided launcher adds only `/api/v1/readiness` to its own local process. The
bounded response contains controlled scanner, AI, remediation, and preview
states. When the scanner is unavailable, the page remains available with fixed
guidance, but both workflows are rejected before request parsing, advisory
lookup, network access, or repository lease acquisition. The route and guided
assets do not exist in legacy mode. A browser-opened guided root accepts only
the exact top-level document-navigation Fetch Metadata tuple for the fixed root
URL; assets and API calls retain same-origin admission, and API calls still
require the fixed local-request header.

## Standalone container verification

The deterministic test suite does not require a live scanner or Docker daemon.
The following operator checks reproduce the environment-dependent Phase 3
acceptance gates; the latest verified snapshot is recorded in the canonical
implementation record. Docker access must work from the shell running these
commands. If an account was just added to the `docker` group, start a new login
session or run `newgrp docker` first. Docker group membership grants root-level
privileges. Do not work around socket permissions by making the Docker socket
world-writable.

Validate Compose and build the standalone image:

```bash
docker compose config --quiet
docker build --pull --tag nexura-watchdog:0.1.0-rc1 .
docker image inspect nexura-watchdog:0.1.0-rc1 --format '{{.Id}} {{.Size}}'
```

The build fetches the scanner from the digest-pinned multi-architecture
OSV-Scanner image. Record the resulting application image ID and size as a local
verification snapshot, not as a stable release identifier.

Verify that the embedded binary's `osv-scanner version:` line reports exactly
`2.4.0`. Additive lines may report versions for separately bundled tools:

```bash
docker run --rm \
  --entrypoint /usr/local/bin/osv-scanner \
  nexura-watchdog:0.1.0-rc1 \
  --version
```

Start the image without a volume mount and check its standalone health endpoint:

```bash
docker run --detach \
  --name nexura-watchdog-phase3-health \
  --publish 127.0.0.1:18000:8000 \
  nexura-watchdog:0.1.0-rc1

curl --fail --silent --show-error http://127.0.0.1:18000/health
docker logs nexura-watchdog-phase3-health
docker rm --force nexura-watchdog-phase3-health
```

The expected response is `{"status":"ok","version":"0.1.0"}` with HTTP 200.

The live OSV contract smoke is intentionally opt-in. To exercise the Python
pipeline with the same binary embedded in the image, copy that binary to a
temporary host path and run only the bounded contract test:

```bash
docker create --name nexura-watchdog-scanner-copy nexura-watchdog:0.1.0-rc1
docker cp \
  nexura-watchdog-scanner-copy:/usr/local/bin/osv-scanner \
  /tmp/nexura-watchdog-osv-scanner-2.4.0
docker rm nexura-watchdog-scanner-copy
chmod 0755 /tmp/nexura-watchdog-osv-scanner-2.4.0
/tmp/nexura-watchdog-osv-scanner-2.4.0 --version

WATCHDOG_RUN_LIVE_SCANNER_TEST=1 \
WATCHDOG_OSV_SCANNER_PATH=/tmp/nexura-watchdog-osv-scanner-2.4.0 \
.venv/bin/pytest -q \
  tests/integration/test_phase3_pipeline.py::test_live_osv_contract_gogo_protobuf

rm /tmp/nexura-watchdog-osv-scanner-2.4.0
```

This smoke requires outbound HTTPS access to OSV. It checks the exact coordinate
`github.com/gogo/protobuf@1.3.1` against `GO-2021-0053` and verifies lease
cleanup. Success is `1 passed`; a network or scanner failure is an incomplete
check, never a negative vulnerability result.

## Quality checks

```bash
ruff format --check .
ruff check .
mypy
pytest
python scripts/verify_release.py --expected-version 0.1.0
```

Apply automatic formatting with `ruff format .`.

## API usage

Check service health:

```bash
curl --fail http://127.0.0.1:8000/health
```

Retrieve a normalized JSON advisory:

```bash
curl --fail \
  http://127.0.0.1:8000/api/v1/advisories/CVE-2021-44228
```

Export the same record as Markdown with a query parameter:

```bash
curl --fail \
  'http://127.0.0.1:8000/api/v1/advisories/CVE-2021-44228?format=markdown'
```

Content negotiation is also supported:

```bash
curl --fail \
  -H 'Accept: text/markdown' \
  http://127.0.0.1:8000/api/v1/advisories/CVE-2021-44228
```

Expected client and upstream failures use a stable envelope:

```json
{
  "error": {
    "code": "advisory_not_found",
    "message": "No advisory record was found for 'CVE-2026-12345'."
  }
}
```

The defined error codes are `invalid_identifier`, `advisory_not_found`,
`source_unavailable`, `malformed_source_response`, and `partial_result`.

## Internal repository intake

The repository service is the internal async lifecycle boundary used by Phase 3;
there is intentionally no repository API endpoint or persistence layer. A caller
must keep inventory, matching, and all other read-only processing inside the
lease:

```python
import httpx

from watchdog.config.settings import Settings
from watchdog.domain.repositories import RepositoryRequest
from watchdog.repository.github import GitHubRepositorySource
from watchdog.repository.intake import RepositoryIntakeService
from watchdog.repository.limits import RepositoryLimits

settings = Settings()
limits = RepositoryLimits.from_settings(settings)

async with httpx.AsyncClient() as client:
    source = GitHubRepositorySource(
        client,
        api_version=settings.github_api_version,
        network_timeout_seconds=limits.network_timeout_seconds,
    )
    intake = RepositoryIntakeService(source, limits)
    lease = intake.acquire(
        RepositoryRequest(
            repository_url="https://github.com/octocat/Hello-World",
            ref="main",
        )
    )
    async with lease as repository:
        exact_commit = repository.snapshot.commit_sha
        source_root = repository.root  # valid only inside this block

    assert lease.cleanup_result.verified
```

Only canonical public `https://github.com/{owner}/{repository}` URLs are
accepted. Authentication, private repositories, Git clones, submodules, archive
retention, and repository execution are unsupported. The archive approach means
Git hooks and `.git` metadata never enter the workspace. Symlinks are accepted
only when their lexical target remains inside the extracted tree; hardlinks,
devices, FIFOs, sparse files, traversal, case collisions, and malformed archives
are rejected.

## Internal dependency inventory and matching

`DependencyInventoryService.build(acquired)` must run before the repository
lease exits. Discovery is sorted and does not follow symlinks. It supports PEP
621/standard dependency groups, `requirements*.txt`, uv lock schema 1, npm
`package.json` and package-lock v2/v3, plus `go.mod`/`go.sum`. Recognized excluded,
unsupported, malformed, oversized, or unresolved structures produce source-linked
coverage warnings; an empty valid manifest is distinct from absent or malformed
coverage.

`AdvisoryMatchService.match(advisory, inventory)` selects only ecosystem/name
candidates. Exact registry coordinates are placed in a generated
`osv-scanner.json`; original repository manifests and configuration are never
passed to the subprocess. OSV-Scanner runs with `--no-resolve`, a trusted empty
configuration, bounded output, and a proxy-free minimal environment. Its normal
OSV lookup requires outbound network access and increases the Docker image size.

Match states distinguish `affected`, `affected_conditional`,
`not_reported_affected`, `version_unknown`, `scanner_incomplete`, and
`unsupported_advisory_component`. `not_reported_affected` says only that a
successful pinned scan did not report the target advisory for that exact
coordinate. It is never a repository-level not-affected result, and Phase 3 does
not establish source reachability or runtime exposure.

## Internal lease-scoped evidence

`EvidenceService.collect(acquired, inventory, report)` must run before the same
repository lease exits. It validates snapshot agreement, derives all eligible
paths and selectors from the Phase 3 match report, opens every path component
relative to directory descriptors without following links, rehashes complete
bounded files, and requires the Phase 3 digest before selecting content.

The resolver supports only Phase 3 line, npm JSON Pointer, PEP 621/dependency
group TOML, and uv package/dependency selectors. Selected content is redacted
before UTF-8-safe display truncation. The outward bundle contains only immutable
redacted display content or `content_omitted` items with stable limitation codes;
raw selected bytes, individual-secret hashes, temporary paths, timestamps, and
operational timing are excluded. Canonical JSON and SHA-256 bind configuration,
items, and bundles deterministically.

Every canonical match ordinal receives a link that preserves its Phase 3 state
and limitations. The 10,000-item cap is absolute: overflow references remain
visible as bounded source outcomes with `item_limit_exceeded` and no evidence ID.
Missing, stale, ambiguous, unsafe, over-limit, deadline-stopped, or redaction-
failed content makes coverage partial and never supports a negative repository
conclusion. The service has no route, persistence, subprocess, network client,
model call, exposure classification, or patch behavior.

## Internal deterministic contextual analysis

`ContextService.collect(acquired, inventory, report, evidence)` must run inside
the same active repository lease. Before discovery it requires exact snapshot
agreement and canonical Phase 3 match-to-Phase 4 evidence linkage. Targets and
all search semantics come only from those validated inputs and the checked-in,
digest-bound catalog.

Discovery is sorted, descriptor-relative, no-follow, extension-allowlisted, and
bounded before sorting or reading. Data-only recognizers cover reviewed lexical
Python, JavaScript/TypeScript, Go, JSON, and TOML forms. Selected spans are
redacted before entering immutable models; failures and unsupported forms produce
explicit partial coverage with no raw fallback.

Configuration facts require supported literal values. JavaScript import facts
require a supported import form, Go selector facts require an explicit import
alias, and Phase 5 display content is omitted rather than truncated when an item
or bundle display budget is exhausted. Bundle validation binds observations,
graph relationships, signals, and file digests to the exact related evidence.

The resulting `ContextBundle` distinguishes dependency imports, references,
explicit calls, reviewed configuration, and reviewed endpoint declarations. Its
graph is lexical only. A guarded usage-not-observed signal requires complete
mapping and complete eligible coverage and always states that static
non-observation does not establish runtime absence or non-exposure. The service
does not classify reachability, exposure, exploitability, or repository affected
status and has no public route.

## Evidence model

Normalized fields stay convenient to consume while `field_provenance` maps each
normalized JSON path to the upstream record, URL, retrieval time, and source path
that supports it. `sources` retains the raw source record by default. When
multiple normalized source records disagree, `conflicts` retains every competing
value and its provenance; choosing a display value does not erase the conflict.

In this repository, the
[Project Design and Implementation Record](../Nexura_Watchdog_Project_Design_and_Implementation_Record.md)
is the canonical status and roadmap. Supporting detail is organized under
[architecture](../architecture/architecture.md),
[threat model](../security/threat-model.md), and
[evidence policy](../security/evidence-policy.md). The complete `docs/` tree is
tracked with the implementation. The completed implementation contract is the
[Phase 4 evidence engine work order](../work-orders/phase-4-evidence-engine.md).
The completed [Phase 5 contextual-analysis work order](../work-orders/phase-5-contextual-analysis.md)
and [formal plan](../plans/phase-5-implementation-plan.md) define the current
bounded internal contextual-analysis contract. The completed
[Phase 6 evidence-bound model-investigation work order](../work-orders/phase-6-evidence-bound-model-investigation.md)
and [formal plan](../plans/phase-6-implementation-plan.md) define the internal
model-inference boundary. The completed
[Phase 7 reporting and local-interfaces work order](../work-orders/phase-7-reporting-and-local-interfaces.md)
and [formal plan](../plans/phase-7-implementation-plan.md) define the current
report, workflow, terminal, browser, and literal-loopback interface boundary.
The completed
[Phase 8 remediation-assistant work order](../work-orders/phase-8-remediation-assistant.md)
and [formal plan](../plans/phase-8-implementation-plan.md) define the current
candidate, comparator, no-write preview, plan, CLI, and opt-in local-interface
boundary.
The completed
[Phase 9 guided-experience work order](../work-orders/phase-9-local-first-guided-experience.md)
and [formal plan](../plans/phase-9-implementation-plan.md) define the installed
launcher, readiness, browser-open, guided-projection, and legacy-regression
boundary.
The completed
[Release 1 hardening work order](../work-orders/release-1-hardening.md),
[implementation plan](../plans/release-1-hardening-implementation-plan.md),
and [release process](../release/release-process.md) define dependency, CI,
artifact, container, governance, and publication controls without changing the
product runtime boundary.
The completed
[Release 1 local terminal UI work order](../work-orders/release-1-tui-and-ssh-trial.md)
and [formal plan](../plans/release-1-local-tui-implementation-plan.md) define the
local terminal, unchanged-web, workflow-observer, display, lifecycle, and
replacement-candidate boundary. Hosted operation and SSH access are explicitly
deferred to Version 2.

## License and security

Nexura Watchdog is licensed under the [Apache License 2.0](../../LICENSE).
Vulnerabilities should be reported through the private process in
[SECURITY.md](../../SECURITY.md), never through a public issue containing sensitive
details.
