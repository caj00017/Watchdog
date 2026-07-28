# Development Recap — July 27, 2026 — Phase 2

> Archived Phase 2 session record. The canonical current state is maintained in
> `../../Nexura_Watchdog_Project_Design_and_Implementation_Record.md`.

## Session objective

This session implemented Phase 2, safe public-repository intake, while preserving
the separation between acquisition and repository analysis. Nexura Watchdog can
now resolve and temporarily acquire an exact public GitHub revision without Git,
authentication, persistence, package installation, or repository code execution.

The capability is an internal context-managed service. No repository HTTP route,
scanner, dependency parser, exposure classification, LLM call, or patch behavior
was added.

## Delivered

### Repository domain and input boundary

- Added immutable models for repository requests, canonical GitHub identity,
  resolved revisions, acquisition snapshots, acquired roots, and cleanup results.
- Added strict public GitHub URL parsing. Accepted URLs use HTTPS and contain only
  an owner and repository; optional `.git` and one trailing slash are normalized.
- Rejected credentials, nonstandard or explicit ports, query strings, fragments,
  percent encoding, extra path segments, invalid owner/repository syntax, and
  non-GitHub destinations.
- Added bounded optional ref validation and typed errors for invalid input,
  missing or unavailable sources, malformed metadata, unsafe or empty archives,
  limits, timeouts, and failed cleanup.
- Added validated settings for request and total duration, compressed and
  extracted bytes, unique workspace paths, path length, per-service concurrency, and an
  optional workspace parent.

### Exact public-GitHub resolution and download

- Added a public GitHub adapter behind a source-neutral repository protocol.
- Resolved GitHub's default branch or a caller-supplied branch, tag, or commit to
  a full immutable commit SHA and tree SHA.
- Verified the returned canonical identity matches the requested repository and
  rejected private metadata.
- Requested the archive by exact commit SHA rather than by a mutable ref.
- Fixed outbound API access to `https://api.github.com`; followed archive
  redirects manually only on HTTPS GitHub API or codeload hosts.
- Streamed the archive into a mode-0600 file, enforcing both declared
  `Content-Length` and observed bytes, and recorded a SHA-256 digest.
- Used no token, Git process, hook, submodule operation, shell, or credential
  helper. Archive-only acquisition means `.git` metadata and executable Git hooks
  never enter the workspace.

### Defensive workspace extraction

- Added a custom tar member loop instead of using a general extraction call.
- Required a single archive root and removed it from exposed paths.
- Rejected absolute paths, traversal, empty path segments, backslashes, control
  characters, duplicates, Unicode case-fold collisions, and excessive path
  lengths.
- Allowed only directories, regular files, and relative symlinks whose lexical
  target remains inside the extracted tree.
- Rejected hardlinks, sparse files, devices, FIFOs, unsupported entries, and any
  member nested beneath a previously created symlink.
- Enforced regular-file bytes, unique materialized paths (including implicit
  directories), and the shared end-to-end deadline while copying in bounded
  chunks.
- Created workspace directories as mode 0700 and regular files as mode 0600.

### Lease lifecycle and verified cleanup

- Added a single-use async lease that owns the complete lifecycle from semaphore
  acquisition through deletion verification.
- Included semaphore wait, metadata resolution, download, and extraction in the
  total duration limit.
- Removed the compressed archive before yielding the extracted root.
- Returned an immutable snapshot with repository/ref identity, exact commit and
  tree, retrieval time, archive digest and byte count, extracted byte and file
  counts, and symlink count.
- Removed and verified the archive and workspace on normal exit, caller failure,
  source failure, unsafe input, limit breach, timeout, and cancellation.
- Ensured cancellation waits for extraction termination and cleanup before the
  concurrency slot is released.
- Refused cleanup when a workspace path has been replaced by a symlink or
  non-directory, surfacing a typed result instead of following it.

### Tests and documentation

- Added GitHub adapter tests for ref encoding, exact-SHA archive requests,
  redirect restrictions, status mapping, malformed SHAs, declared and streamed
  byte limits, hashing, and empty responses.
- Added hostile-archive tests for traversal, absolute and Windows-like paths,
  control characters, multiple roots, duplicates, case collisions, escaping or
  traversed symlinks, hardlinks, FIFOs, malformed gzip, empty archives, and every
  extraction limit.
- Added lifecycle tests for successful snapshots, consumer exceptions, unsafe
  archives, deadline expiry, task cancellation, shared concurrency, cleanup
  verification, and single-use leases.
- Updated the README, architecture, threat model, evidence policy, repository
  rules, settings reference, and current/deferred boundaries.

## Important implementation decisions

1. **Use GitHub archives, not Git clone.** Phase 2 needs immutable source bytes,
   not repository history. Archive acquisition removes the hook, checkout-filter,
   submodule, credential-helper, and command-injection surface of invoking Git.
2. **Resolve first, download by SHA.** Mutable branches and tags are useful input,
   but the acquired artifact and snapshot are anchored to the full resolved
   commit.
3. **Keep intake internal.** An HTTP route would introduce admission, distributed
   rate, abuse, job-lifecycle, and retention concerns that are unnecessary before
   an investigation orchestrator exists.
4. **Make cleanup part of correctness.** A lease is not complete merely because
   analysis stopped. Deletion must run for every exit path and both paths must be
   absent before cleanup is verified.
5. **Allow only contained symlinks.** Some real repositories use relative links,
   so they are retained as data when lexical resolution stays inside the root.
   Hardlinks and link-parent traversal are rejected because they add ambiguity
   without Phase 2 value.
6. **Separate provenance from findings.** A repository snapshot establishes what
   was acquired; it does not establish dependency presence, reachability, or
   vulnerability exposure.

## Issues found through validation

- Cancellation-safe deletion requires shielding a concrete cleanup task and then
  awaiting it after cancellation. Shielding a bare thread coroutine would allow
  control and the semaphore slot to return while deletion still ran.
- A branch name containing `/` must be encoded as one GitHub path parameter. The
  adapter's request test now asserts that boundary.
- Header-only download limits are insufficient. The adapter also measures the
  actual streamed bytes, including responses without `Content-Length`.
- Archive and extracted limits can coexist on disk during extraction. The
  architecture now documents that peak storage may approach their sum.
- A cleanup path can be locally replaced with a symlink. Cleanup fails closed
  rather than following that path, and the behavior has a targeted security test.

## Verification completed

The final code state passed:

- `ruff format --check .` — 54 files already formatted
- `ruff check .` — all checks passed
- `mypy` — no issues across 47 source files
- `pytest` — 87 tests passed without warnings
- bytecode compilation for application, library, and test modules
- OpenAPI generation with exactly the existing health and advisory routes
- Docker Compose YAML parsing
- Docker Engine 29.6.2 / Compose build using the pulled `python:3.12-slim`
  base image
- Compose development-container startup and HTTP 200 health response
- standalone built-image startup without the source bind mount and HTTP 200
  health response
- `git diff --check`

A live smoke test acquired `https://github.com/octocat/Hello-World` without
executing its content:

- resolved ref: `master`
- commit: `7fd1a60b01f91b314f59955a4e4d4e80d8edf11d`
- tree: `b4eecafa9be2f2006ce1b709d6857b07069b4608`
- downloaded archive: 265 bytes,
  SHA-256 `9f40b519431e9754a1680244b820877ca975aa969ea4ae72798bfe3f67d0f139`
- extracted: one regular file and 13 bytes
- archive absent before the lease yielded and workspace deletion verified after
  exit

The retained `watchdog-api:latest` image is Linux/amd64, 57,331,464 bytes, with
image ID `sha256:b7a80729e4495f97e293b17833291a3358ab98554a0d213a58ca4afc699feff3`.
Temporary validation containers and their Compose network were removed after the
checks.

## Current limitations

- Intake supports unauthenticated public GitHub repositories only. GitHub
  Enterprise, private repositories, tokens, submodules, Git history, and archive
  retention are unsupported.
- The source trusts GitHub to associate the returned tarball with the requested
  commit. It records the archive digest but does not reconstruct the Git tree or
  verify a commit signature.
- Concurrency is shared within one `RepositoryIntakeService` instance, not across
  processes or hosts. There is no distributed admission control or queue.
- Limits are enforced in application code; there is no filesystem quota,
  compression-ratio cap, or independent CPU/memory sandbox yet.
- A process crash or host termination can bypass normal cleanup. There is no
  startup scavenger for stale workspaces.
- GitHub metadata responses have time and schema bounds but no explicit response
  byte cap, cache, retry policy, or hosted rate-limit coordination.
- Contained symlinks remain untrusted. Future consumers must use safe read-only
  traversal and must not execute, import, build, or install repository content.
- No repository input is exposed through the API, and no acquired content is
  persisted or exported.

## Next work order — Phase 3 dependency inventory and matching

Phase 3 should operate only inside the Phase 2 lease and should produce
deterministic component and match records. It must not add source execution, an
LLM, reachability conclusions, or a public investigation endpoint yet.

### 1. Lock the inventory and match contracts

- Add source-neutral immutable models for ecosystem, package identity, version,
  dependency relationship, inventory component, graph edge, source reference,
  raw tool record, parser/tool warning, and advisory-component match.
- Give every component a stable inventory ID. Link it to repository-relative
  manifest or lockfile paths and structured selectors such as JSON Pointer or
  TOML key paths; do not introduce the full Phase 4 evidence schema early.
- Represent relationship as direct, transitive, or unknown. Never infer
  transitivity when a file format cannot prove it.
- Distinguish exact resolved versions from declared constraints and retain the
  original value. An unresolved constraint must not be evaluated as an installed
  version.
- Define partial status and warnings so parser or tool failure cannot become an
  empty, clean inventory.

### 2. Add bounded, data-only ecosystem detection

- Walk the acquired root without following symlinks and locate only allowlisted
  manifest and lockfile names.
- Reuse snapshot counts, then add manifest-count, per-file byte, total parsed
  byte, parser-depth, and inventory-duration limits.
- Detect Python, JavaScript/TypeScript, and Go from manifests, not file
  extensions or executable probing.
- Record unsupported lockfiles and malformed supported files as explicit
  warnings with paths.

### 3. Implement parsers behind source-neutral protocols

- Python first slice: PEP 621 `pyproject.toml` dependencies and optional groups,
  `requirements*.txt`, plus one lock format capable of proving resolved
  transitive versions. Treat includes, editable installs, URLs, markers, hashes,
  and unsupported requirement syntax explicitly; never fetch or install them.
- JavaScript/TypeScript first slice: `package.json` declarations and npm
  `package-lock.json` v2/v3. Build package identities and dependency edges from
  lock data; warn on unsupported Yarn or pnpm lockfiles rather than guessing.
- Go first slice: `go.mod` requirements and `// indirect` state, with `go.sum` as
  integrity metadata rather than a dependency graph. Do not invoke `go list` or
  download modules.
- Use standard-library data parsers where practical and validate every parser
  result into the common domain at the boundary.

### 4. Add a bounded OSV-Scanner adapter

- Confirm and pin a supported OSV-Scanner release and JSON schema at the start of
  the phase; record tool name, version, arguments, timestamps, exit status, and
  raw validated output.
- Invoke it with an argument array, never a shell; set a hard timeout and stdout,
  stderr, and output-size caps; terminate the process tree on timeout.
- Run with a sanitized environment and no repository-dependent configuration,
  hooks, package installation, or build steps. Define the scanner's outbound OSV
  network policy explicitly before enabling it.
- Treat nonzero exit, malformed JSON, timeout, unsupported ecosystem, and partial
  coverage as typed warnings or failures, never as “no vulnerabilities.”
- Keep Syft optional and deferred unless it closes a documented inventory gap;
  adding it requires the same boundary and output validation.

### 5. Match advisories deterministically

- Normalize package names according to ecosystem rules and create candidate
  matches only when advisory ecosystem and name agree.
- Use exact resolved versions and OSV-Scanner's validated range result for
  vulnerable-version decisions. Do not apply lexical version comparisons or
  assume that a declared constraint is installed.
- Link each match to advisory affected-package provenance and one or more
  inventory component IDs/source references.
- Emit explicit states for matched, version-not-in-range, version-unknown,
  ecosystem-unsupported, and scanner-incomplete. None is yet a reachability or
  repository exposure classification.

### 6. Build representative and hostile fixtures

- Add small Python, npm, and Go repositories with known direct and transitive
  dependency graphs, including vulnerable and fixed versions.
- Add malformed, oversized, deeply nested, duplicate, unusual-name, URL-based,
  marker-heavy, workspace/monorepo, and unsupported-lockfile fixtures.
- Include filenames and package values containing shell metacharacters to prove
  they remain arguments/data and cannot alter scanner invocation.
- Test symlink behavior, scanner timeout and truncation, nonzero exit, malformed
  output, cancellation, and lease cleanup after every parser or scanner failure.
- Add end-to-end internal tests from exact acquired snapshot through inventory and
  match records, asserting direct/transitive distinction, provenance links, and
  explicit coverage warnings.

### 7. Document and gate completion

- Update architecture, threat model, evidence policy, settings, and `AGENTS.md`
  for parser and scanner boundaries before exposing any new route.
- Keep tool versions and fixture expectations reproducible. Add container
  resource limits if the scanner becomes part of Docker development.
- Require formatting, lint, strict typing, all unit/integration/security tests,
  scanner contract tests, OpenAPI no-expansion assertions, Compose validation,
  and a live data-only smoke against a small public repository.
- Phase 3 is complete only when known fixtures produce correct package matches,
  direct and transitive dependencies remain distinguishable, unsupported formats
  create visible warnings, failures never create clean negative results, and the
  Phase 2 workspace is still verifiably removed.
