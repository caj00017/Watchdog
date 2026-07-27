# Nexura Watchdog

Nexura Watchdog is an evidence-driven vulnerability investigation project. The
current implementation provides advisory intelligence plus bounded internal
services for safely acquiring public GitHub repository snapshots,
deterministically inventorying allowlisted dependency files, and matching exact
coordinates. The API accepts a CVE, GHSA, or OSV database identifier, retrieves
the corresponding OSV record, and returns a source-neutral advisory with
field-level provenance.

Repository intake, inventory, and matching are not exposed through HTTP routes.
Intake resolves a branch, tag, or commit to an immutable commit SHA, downloads
that SHA's GitHub archive, extracts only validated data into a disposable
workspace, and verifies deletion when its context closes. Inside that lease,
Phase 3 reads bounded dependency data without invoking package managers or
repository code. Exact PyPI, npm, and Go coordinates can be sent to pinned
OSV-Scanner 2.4.0 through a generated custom input. SBOMs, source/reachability
analysis, LLM calls, and patch generation remain out of scope.

## Requirements

- Python 3.12 or newer
- `pip` and `venv` for native development, or Docker Compose
- Network access to `https://api.osv.dev` when resolving live advisories
- Network access to `https://api.github.com` and GitHub's allowlisted codeload
  host when acquiring a repository
- OSV-Scanner 2.4.0 at an absolute configured path for native matching; the
  Docker image embeds the pinned multi-architecture scanner binary
- Network access to OSV for exact-coordinate scanner lookups

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

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

## Run locally

```bash
uvicorn apps.api.main:app --reload
```

The API and interactive OpenAPI documentation are then available at
`http://127.0.0.1:8000` and `http://127.0.0.1:8000/docs`.

Docker Compose builds and starts the standalone image without a source bind mount:

```bash
docker compose up --build
```

## Phase 3 operator verification

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
docker build --pull --tag nexura-watchdog:phase3 .
docker image inspect nexura-watchdog:phase3 --format '{{.Id}} {{.Size}}'
```

The build fetches the scanner from the digest-pinned multi-architecture
OSV-Scanner image. Record the resulting application image ID and size as a local
verification snapshot, not as a stable release identifier.

Verify that the embedded binary's `osv-scanner version:` line reports exactly
`2.4.0`. Additive lines may report versions for separately bundled tools:

```bash
docker run --rm \
  --entrypoint /usr/local/bin/osv-scanner \
  nexura-watchdog:phase3 \
  --version
```

Start the image without a volume mount and check its standalone health endpoint:

```bash
docker run --detach \
  --name nexura-watchdog-phase3-health \
  --publish 127.0.0.1:18000:8000 \
  nexura-watchdog:phase3

curl --fail --silent --show-error http://127.0.0.1:18000/health
docker logs nexura-watchdog-phase3-health
docker rm --force nexura-watchdog-phase3-health
```

The expected response is `{"status":"ok","version":"0.1.0"}` with HTTP 200.

The live OSV contract smoke is intentionally opt-in. To exercise the Python
pipeline with the same binary embedded in the image, copy that binary to a
temporary host path and run only the bounded contract test:

```bash
docker create --name nexura-watchdog-scanner-copy nexura-watchdog:phase3
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

## Evidence model

Normalized fields stay convenient to consume while `field_provenance` maps each
normalized JSON path to the upstream record, URL, retrieval time, and source path
that supports it. `sources` retains the raw source record by default. When
multiple normalized source records disagree, `conflicts` retains every competing
value and its provenance; choosing a display value does not erase the conflict.

In this local working tree, the
[Project Design and Implementation Record](docs/Nexura_Watchdog_Project_Design_and_Implementation_Record.md)
is the canonical status and roadmap. Supporting detail is organized under
[architecture](docs/architecture/architecture.md),
[threat model](docs/security/threat-model.md), and
[evidence policy](docs/security/evidence-policy.md). The complete `docs/` tree is
intentionally ignored by Git and requires a separate backup.
