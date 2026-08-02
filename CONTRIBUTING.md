# Contributing to Nexura Watchdog

Contributions are welcome when they preserve the project's security boundaries
and remain small enough to review confidently.

## Before changing code

Read `AGENTS.md`, the canonical project record, architecture, threat model, and
the work order governing the area. A new parser, runtime dependency, network
destination, repository capability, model/provider boundary, interface, write
path, or analytical claim requires an explicit work order before implementation.

Never execute code from a repository being analyzed, install its dependencies,
or treat its text as trusted instructions. Tests must use synthetic fixtures and
must not place credentials, secrets, or private repository content in logs or
artifacts.

## Development setup

Use Python 3.12, 3.13, or 3.14. Install the checked-in hash-locked development
environment, then install Watchdog itself without dependency resolution:

```bash
python -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements/dev.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
```

Run the deterministic gates before requesting review:

```bash
.venv/bin/ruff format --check .
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/python -m compileall -q apps watchdog tests scripts
.venv/bin/pytest
docker compose config --quiet
```

The live scanner contract is separately opt-in and requires network access. A
failure or skipped environment-dependent check must be recorded explicitly.

## Pull requests

- Link the governing work order and evidence for each behavior or security
  claim.
- Add tests and documentation for trust-boundary changes.
- Preserve unrelated work and avoid generated or broad mechanical changes.
- Update lock files only through the documented release process and explain
  every direct or transitive change.
- Do not include generated patches that apply repository changes; remediation
  output remains preview-only and human-approved.

By contributing, you agree that your contribution is licensed under the Apache
License 2.0.
