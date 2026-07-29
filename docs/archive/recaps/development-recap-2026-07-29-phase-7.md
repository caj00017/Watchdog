# Development Recap — Phase 7 Completion

**Date:** July 29, 2026

**Baseline:** Phase 6 commit `02abea580723461e0a8b02a07a93cc5438d9a63b`

## Completed boundary

Implemented the authorized Phase 7 evidence-safe reporting and local-interface
boundary without changing dependencies, the existing advisory API, repository
inputs, OSV-Scanner 2.4.0, Phase 4/5 eligibility or identities, or the Phase 6
prompt/policy/gateway.

The implementation adds:

- strict frozen request/report/configuration models and deterministic report IDs;
- bounded evidence-linked summary/technical JSON and escaped-Markdown views;
- fixed-order Phase 1 → lease-scoped Phase 2–5 → verified cleanup → Phase 6 →
  report orchestration with shared admission/deadline and cancellation joining;
- a direct stdout-only `python -m apps.cli investigate` adapter;
- a separate disabled-by-default `python -m apps.web` literal-loopback launcher,
  five exact routes, Host/origin/custom-header/resource controls, security
  headers, and generic errors; and
- checked-in dependency-free UI assets using same-origin fetches, text sinks,
  transient download blobs, and no browser persistence.

Phase 7 remains a presentation boundary. Reports preserve deterministic fact,
model inference, assumptions, gaps, limitations, and validation actions as
separate categories and cannot express affected/not-affected status, runtime or
data-flow reachability, exploitability, deployment exposure, remediation,
commands, code generation, or patches.

## Verification

- `ruff format --check .`: pass (`166 files already formatted` at the final
  pre-documentation gate)
- `ruff check .`: pass
- strict `mypy`: pass across 152 source/test files
- `python -m compileall`: pass
- deterministic pytest: 280 passed, 1 opt-in live scanner test skipped
- Docker Compose parse: pass
- standalone image build: pass
- image: `sha256:9e3be5ba9799c4b9004532a9d42e600ad2b6b5fe9fb991a22cd79ab5feb03bfd`,
  79,365,135 bytes
- installed wheel includes `index.html`, `watchdog.css`, and `watchdog.js`
- embedded scanner: `osv-scanner version: 2.4.0`
- default no-mount advisory health: `{"status":"ok","version":"0.1.0"}`
- local launcher disabled by default: pass
- explicitly enabled unpublished loopback health: `{"status":"ok"}`

The live OSV scanner contract remained opt-in because it requires external OSV
network access. Its absence is a coverage limitation, not a negative result.

## Deferred

Public/remote or production interfaces, proxy/container publication,
authentication, private repositories, persistence, jobs/history, report lookup,
remote providers/credentials, new inputs or dependencies, classification,
reachability/exposure, remediation, executable validation, commands, code
generation, and patches remain unapproved.
