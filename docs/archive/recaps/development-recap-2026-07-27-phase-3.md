# Development Recap — July 27, 2026 — Phase 3

> Archived Phase 3 session record. The canonical current state is maintained in
> `../../Nexura_Watchdog_Project_Design_and_Implementation_Record.md`.

## Objective and boundary

This session implemented deterministic dependency inventory and target-advisory
matching strictly inside the Phase 2 repository lease. It added no public route,
repository execution, dependency installation, package resolution, SBOM, source
analysis, LLM call, persistence, exposure classification, or patch behavior.
Package version remains 0.1.0 and OpenAPI remains the health/advisory API.

## Delivered

- Restored `docs/` to `.gitignore`; no documentation path is Git-tracked.
- Added immutable source-neutral inventory, graph, coverage, scanner, and match
  contracts with deterministic commit-anchored IDs and source hashes/selectors.
- Added sorted no-follow discovery with limits for time, manifest count,
  per-file/total bytes, nesting, requirements includes, components, edges, and
  warnings.
- Added data-only parsers for PEP 621/dependency groups/requirements, uv lock
  schema 1, npm declarations/package-lock v2/v3, and bounded `go.mod`; `go.sum`
  remains integrity metadata.
- Preserved exact/constraint/unknown versions, direct/transitive/unknown
  relationships, scope, markers, npm OS/CPU conditions, uv variants/workspaces,
  npm package locations/workspaces, and Go replacements/exclusions/tools.
- Added explicit malformed, unsupported, excluded, ambiguous, local-source,
  unresolved, and limit coverage warnings.
- Embedded OSV-Scanner 2.4.0 from the locked multi-architecture digest and added
  an absolute native path setting.
- Generated custom intermediate input from exact normalized coordinates only;
  repository paths/configuration never enter the subprocess.
- Added lazy exact version checking, trusted empty configuration, fixed argument
  arrays, `--no-resolve`, private controls, proxy-free environment, bounded
  concurrent output, process-group termination, strict-known-field JSON
  validation, output hashing, and sanitized diagnostics.
- Added target primary-ID/alias matching and explicit `affected`, conditional,
  narrow negative, unknown-version, scanner-incomplete, and unsupported states.

## Security decisions

1. Scanner input is generated inventory, never original repository data.
2. Constraints and local sources are visible evidence but not exact scan inputs.
3. Conditions are preserved and never evaluated against the analysis host.
4. Exit 0 and 1 are success only when JSON validates; all other outcomes are
   incomplete and cannot become negative evidence.
5. `not_reported_affected` applies only to the exact coordinate scanned. It does
   not establish repository reachability, deployment applicability, or exposure.
6. Inventory and matching remain lease-scoped internal services.

## Verification snapshot

The deterministic local suite covers Python/npm/Go happy paths and hostile
inputs, normalization and conditions, limits, unsupported/malformed coverage,
scanner argument/environment/output contracts, version mismatch, failure state
mapping, candidate/alias matching, and verified lease cleanup after parser and
scanner failures. It passes 118 deterministic tests; the live
`github.com/gogo/protobuf@1.3.1` / `GO-2021-0053` lookup is an explicit opt-in
contract test because it requires the pinned binary and OSV network access.

Final operator verification commands are maintained in the root `README.md`.
After Docker group access was refreshed, Docker Engine 29.6.2 built the Phase 3
image at 78,462,929 bytes with image ID
`sha256:9fd43a0d9e4e7057e4af1dca2d39c1e7be00537e66c4501ae4db36a69a6afa3d`.
The embedded binary reported OSV-Scanner 2.4.0, and its extracted SHA-256 was
`15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0`.
The standalone container had no mounts and returned HTTP 200 with
`{"status":"ok","version":"0.1.0"}`.

The first live attempt exposed a strict version-parser defect because the pinned
binary reports an additional osv-scalibr version. The adapter was corrected to
validate only the explicit `osv-scanner version:` line, with a regression test
covering the real additive output. After rebuilding, the opt-in live contract
passed with the binary extracted from the final image. This completed Phase 3
operator acceptance without weakening the exact scanner-version requirement.

## Deferred

Syft, SBOM generation, additional ecosystems/lock formats, source evidence,
reachability, exposure, LLM reasoning, persistence, public repository routes,
hosted isolation, and patch previews remain deferred security-boundary changes.
