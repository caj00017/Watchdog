# Development Recap — Phase 9 Completion

**Date:** July 29, 2026

**Immutable Phase 8 baseline:**
`87ea89a5313c3dcb9cdc349a27691f91d83e623d`

**Phase 9 planning and authority commit:**
`81763ffd84aef418c49793e9059b3bb16492e93c`

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
  cancellation, structured text-only JSON projection, visually separate model
  inference, raw canonical output, and separate no-apply remediation review; and
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
- deterministic pytest: 361 passed, 1 opt-in live scanner test skipped
- Docker Compose parse: pass
- public OpenAPI regression: exactly `/health` and
  `/api/v1/advisories/{identifier}`
- guided checked-in asset total: 22,389 bytes, inside the 256 KiB limit
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

The live OSV scanner contract remains opt-in because it requires outbound OSV
network access. Its skipped state is an explicit coverage limitation and is not
interpreted as a negative finding. Browser opener behavior was deterministically
tested with injected controllers; the container smoke used `--no-open` because
it has no desktop session.

Two bounded headless Firefox visual-check attempts used isolated profiles, a
forced software-rendering attempt, and a 20-second timeout. The sandboxed browser
failed during graphics initialization and produced no screenshot. Only the
headless processes started by this verification were terminated; the existing
user browser was left untouched, and temporary scanner/profile artifacts were
removed. The five-minute first-time desktop visual/usability sign-off remains an
explicit operator coverage limitation. This is not interpreted as a UI failure:
the real guided server/readiness and disabled-scanner paths ran, HTTP controls
passed, SIGINT cleanup completed without traceback after the discovered launcher
fix, and responsive/accessibility/text-sink behavior has deterministic coverage.

## Permanent deferrals

Hosted operation, authentication, credentials, private inputs, persistence,
telemetry, jobs/history, scanner/model installation, remote model providers,
repository writes/apply, commands, classification, runtime/data-flow
reachability, exposure, compatibility/availability claims, new dependencies or
destinations, release governance, locking, CI, release-candidate production,
and publication remain outside Phase 9. Release hardening resumes at item 2 of
`~/TODO.txt` under a separate work order.
