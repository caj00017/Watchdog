# Development Recap — Phase 8 Completion

**Date:** July 29, 2026

**Immutable baseline:** Phase 7 commit
`60079274ea4ea9784391b3b34712fd3b3d8ad519`

**Verified planning commit:**
`8d5df91f672a2dfe027169da40c6abc9faa9909f`, a documentation-only descendant
of the immutable baseline

## Completed boundary

Implemented the separately authorized evidence-bound remediation assistant
without changing dependencies, the public advisory API, scanner input or
network behavior, OSV-Scanner 2.4.0, or any Phase 1–7 canonical artifact.

The completed boundary adds:

- strict frozen support, candidate, preview, coverage, plan, request, rendered
  output, configuration, and typed identity contracts;
- provenance-complete, evidence-linked source-reported candidate derivation for
  eligible exact affected or conditional observations;
- bounded fail-closed PyPI, npm SemVer 2.0.0, and Go semantic/pseudo-version
  comparison without registry or release lookups;
- optional lease-scoped descriptor-safe reads and one-token in-memory previews
  for requirements files, PEP 621 direct dependencies, the reviewed npm
  same-root lockfile-to-direct-declaration bridge, and direct non-replaced
  `go.mod` requirements;
- exact digest and file-identity checks, byte-identical prefix/suffix proof,
  data-only semantic reparse, redacted zero-context display, and no repository
  write capability;
- canonical bounded JSON and escaped-Markdown remediation-plan projections with
  fixed no-change and human-validation wording;
- one shared private Phase 1–7 workflow core, a separately admitted and disabled
  Phase 8 service, a direct stdout-only `remediate` CLI, and a doubly gated
  literal-loopback route/UI variant; and
- deterministic Phase 1–7 identity/render regression fixtures plus Phase 8
  schema, comparator, candidate, preview, bridge, no-write, workflow, CLI, HTTP,
  rendering, and UI security coverage.

Phase 8 never applies or writes a change, generates a command, invokes repository
or package-manager code, installs analyzed dependencies, resolves a version,
persists a plan, or claims compatibility, availability, affectedness,
reachability/exposure, successful remediation, or completed testing.

## Verification

- `ruff format --check .`: pass across 188 files
- `ruff check .`: pass
- strict `mypy`: pass across 172 source/test files
- `python -m compileall`: pass
- deterministic pytest: 339 passed, 1 opt-in live scanner test skipped
- Docker Compose parse: pass
- dependency regression: `pyproject.toml` remains byte-identical with SHA-256
  `eafe9a470a3c8b81f19e20d10fb305c7df721a961879bb529b0181f36994a922`
- standalone image build: pass
- image:
  `sha256:4a59f7e1fdd4493e53f36ed3f17e98abac3b8a95796c89d0d7196c0e5de231ae`,
  79,573,979 bytes
- installed package assets: Phase 7 and Phase 8 HTML/CSS/JavaScript present and
  inside the configured byte boundary
- embedded scanner: `osv-scanner version: 2.4.0`
- public no-mount/no-network health:
  `{"status":"ok","version":"0.1.0"}`
- explicitly enabled remediation local-app no-mount/no-network health:
  `{"status":"ok"}`
- both health containers: Docker network mode `none`, mounts `[]`
- public OpenAPI regression: exactly `/health` and
  `/api/v1/advisories/{identifier}`
- remediation route registration: absent by default and present only when both
  local-interface and remediation settings are enabled

The live OSV scanner contract remains opt-in because it requires external OSV
network access. Its skipped state is an explicit coverage limitation and is not
interpreted as a negative finding.

## Permanent human-approval boundary

Repository writes/apply, commands, generated lock/checksum changes, multi-token
or multi-file previews, source-code patches, model-selected versions or
instructions, registry queries, dependency resolution or installation,
repository/package/build/test execution, compatibility or success claims,
classification, remote/private interfaces, credentials, persistence, jobs,
authentication, telemetry, new dependencies or destinations, and any Phase 1–7
identity/default change remain deferred pending a separate work order and
explicit authorization.
