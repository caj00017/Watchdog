# Development Recap — July 27, 2026

> Archived Phase 1 session record. The canonical current state is maintained in
> `../../Nexura_Watchdog_Project_Design_and_Implementation_Record.md`.

## Session objective

This session completed Nexura Watchdog's first work order: establish the project
foundation and implement the advisory-intelligence layer without introducing
repository analysis or LLM functionality.

The resulting service accepts CVE, GHSA, and OSV database identifiers, retrieves
OSV data, and returns a validated source-neutral advisory with raw source data,
field-level provenance, visible conflicts, and JSON or Markdown output.

## Delivered

### Project foundation

- Created the planned application, domain, adapter, reporting, test, and deferred
  feature directory structure.
- Added Python 3.12+ packaging and dependencies in `pyproject.toml`.
- Configured Ruff formatting and linting, strict mypy checks, pytest, and
  pytest-asyncio.
- Added a Dockerfile and reload-enabled Docker Compose development service.
- Added validated `WATCHDOG_`-prefixed settings for environment, OSV URL,
  upstream timeout, and raw-record inclusion.
- Added repository-wide security and development rules in `AGENTS.md`.

### Advisory domain and normalization

- Added immutable, source-neutral models for advisories, severity, affected
  components, ranges, version events, references, remediation, source records,
  provenance, conflicts, warnings, and partial status.
- Kept OSV response models isolated inside the source adapter rather than
  coupling them to the normalized domain.
- Retained the complete parsed OSV record by default for audit and debugging.
- Mapped normalized JSON paths to source name, record ID, retrieval URL and time,
  and exact upstream JSON path.
- Added provenance for nested range events, versions, references, and derived
  remediation fields, not only top-level collections.
- Added a source-neutral merger that deduplicates additive values, remaps their
  provenance, and exposes competing scalar values through explicit conflict
  records.

### Identifier and OSV support

- Added bounded validation for CVE, GHSA, and OSV database identifiers.
- Canonicalized CVE and OSV identifiers to uppercase while preserving the
  lowercase GHSA suffix required by OSV's case-sensitive endpoint.
- Required the returned OSV record to identify the requested value as either its
  primary ID or an explicit alias.
- Normalized aliases supplied by OSV without inferring equivalence from advisory
  text or affected packages.
- Supported OSV records that describe a Git repository and range without an
  `affected[].package` object.
- Converted OSV fixed events into deterministic remediation entries while
  retaining their precise source paths.

### API and exports

- Added `GET /health` with service status and version.
- Added `GET /api/v1/advisories/{identifier}` with validated JSON output.
- Added Markdown output through `?format=markdown` or
  `Accept: text/markdown`.
- Escaped external text in Markdown and excluded raw source JSON from the
  human-readable export.
- Added stable error envelopes for invalid identifiers, missing records,
  unavailable sources, malformed responses, and partial results.
- Added application-lifespan ownership of the asynchronous HTTP client and a
  replaceable dependency boundary for deterministic integration tests.

### Documentation

- Expanded `README.md` with native and Docker installation, configuration,
  development, quality-check, and API examples.
- Added `docs/architecture.md` describing the current runtime flow and deferred
  components.
- Added `docs/threat-model.md` covering the client, OSV network, and export trust
  boundaries.
- Added `docs/evidence-policy.md` defining provenance, aliases, conflicts,
  failures, partial results, and export behavior.

## Important implementation decisions

1. **Normalized values remain easy to consume.** Provenance is stored in a
   parallel `field_provenance` map keyed by normalized JSON paths instead of
   wrapping every value in a source-specific object.
2. **Raw records do not replace validation.** OSV objects are retained for audit,
   but only validated and normalized fields drive API behavior.
3. **Conflicts remain data.** A deterministic first-source value may be used for
   display, but every competing scalar value and its provenance remains visible
   in `conflicts`.
4. **Failures never become negative findings.** Upstream timeouts, HTTP failures,
   malformed data, identity mismatches, and normalization failures have distinct
   error paths.
5. **Repository functionality remains absent.** Deferred directories are
   placeholders only; no cloning, dependency installation, scanner execution,
   source analysis, or model calls were introduced.

## Issues found through validation

Live testing identified several cases that the initial mocked fixtures did not
cover:

- Some OSV CVE records contain Git ranges without package metadata. The domain
  now preserves these as repository-identified affected components.
- OSV's advisory-by-ID endpoint is case-sensitive for GHSA suffixes. Identifier
  canonicalization now handles each identifier family separately.
- Collection-level provenance alone was insufficient for the evidence policy.
  Provenance was extended to normalized nested leaves and corrected during
  multi-record deduplication.
- The host provided Python 3.14 without pip. An isolated `.venv` was created and
  pip was bootstrapped into it; no system Python packages were modified.
- Current Python 3.14 test-client compatibility required pytest-asyncio 1.x and
  the `httpx2` development dependency. Updating those removed all test warnings.
- The original `docs` ignore rule hid required documentation. It was narrowed so
  the supplied prompt and formal plan remain ignored while project-authored
  documentation is commit-visible.

## Verification completed

The final code state passed:

- `ruff format --check .` — 37 files already formatted
- `ruff check .` — all checks passed
- `mypy` — no issues across 32 source files
- `pytest` — 25 tests passed without warnings
- OpenAPI schema generation and required-route assertions
- Docker Compose YAML parsing
- `git diff --check`

A live Uvicorn process was also exercised against OSV:

- `/health` returned HTTP 200.
- `CVE-2021-44228` returned validated JSON with its raw record and 211 normalized
  provenance paths.
- `GHSA-JFH8-C2JP-5V3Q` returned Markdown successfully after family-specific case
  canonicalization.
- `OSV-2020-1113` returned validated JSON successfully.

## Current limitations

- OSV is the only active advisory source. The merger can represent cross-source
  conflicts, but no second adapter supplies them yet.
- The adapter has a bounded request timeout but no cache, retry policy, hosted
  rate controls, or configurable upstream response-size limit.
- Docker was not installed in the session environment, so the Compose file was
  validated but the container image was not built or started.
- No persistence layer or background job system exists yet.
- Repository intake, dependency inventory, scanning, evidence extraction,
  reachability analysis, LLM investigation, UI, and patch previews remain out of
  scope.
- An open-source license has not yet been selected.

## Recommended next work order

Proceed with Phase 2, safe public-repository intake, while keeping it separate
from dependency scanning. The work order should cover:

1. Strict public GitHub URL and ref validation.
2. Exact commit-SHA resolution.
3. Disposable workspaces with configurable size, file-count, and time limits.
4. Disabled Git hooks and no package installation or repository code execution.
5. Path and symlink escape protections.
6. Verifiable cleanup and security-focused tests for malformed and hostile
   repositories.

Before a public release, select a license and add hosted-service controls for
upstream response size, concurrency, and retry behavior.
