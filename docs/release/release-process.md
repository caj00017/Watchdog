# Release Process

This process implements the Release 1 hardening work order. It applies to the
trusted Watchdog repository only and must never be used to build or install an
analyzed repository.

## 1. Prepare

1. Start from a clean `main` that matches the intended reviewed commit.
2. Confirm the version agrees in `pyproject.toml`, `watchdog/__init__.py`, and
   `CHANGELOG.md`.
3. Confirm all direct and transitive dependency changes are reviewed and the
   three lock files were regenerated in the documented clean Python 3.12
   environment.
4. Run `python scripts/verify_release.py --expected-version 0.1.0`.
5. Run the complete deterministic quality gates and record every skipped or
   environment-dependent check.

## 2. Build once

Create a clean release environment from `requirements/release.lock`, install the
project without dependency resolution or build isolation, and build both
artifacts with a fixed source timestamp:

```bash
python -m venv .release-venv
.release-venv/bin/python -m pip install --require-hashes -r requirements/release.lock
.release-venv/bin/python -m pip install --no-deps --no-build-isolation -e .
SOURCE_DATE_EPOCH=1785628800 \
  .release-venv/bin/python -m build --no-isolation
.release-venv/bin/python scripts/normalize_sdist.py \
  --epoch 1785628800 \
  dist/nexura_watchdog-0.1.0.tar.gz
.release-venv/bin/python -m twine check --strict dist/*
python scripts/verify_release.py --expected-version 0.1.0 --dist-dir dist
sha256sum dist/*
```

The candidate record must contain the exact commit, filenames, and checksums.
Do not rebuild between validation and publication.

`1785628800` is the fixed UTC release epoch for `v0.1.0`. Changing it changes
the artifact contract and requires a new candidate record.

## 3. Validate artifacts

- Inspect wheel and source-distribution member names; reject absolute paths,
  traversal, links, unexpected generated files, and omitted license, changelog,
  security policy, package assets, or release metadata.
- Install the wheel and source distribution independently in clean Python
  environments using `requirements/runtime.lock` and `--no-deps`.
- Exercise `watchdog --help` and controlled `watchdog doctor` behavior without
  contacting advisory, repository, registry, or model services.
- Build the standalone container from the exact candidate commit, confirm its
  embedded OSV-Scanner reports exactly 2.4.0, and run the no-mount health check.
- Retain explicit limitations for the opt-in live scanner/network contract and
  any unperformed manual UI checks.

## 4. Configure remote release controls

Before the first publication, verify the remote controls listed in
`GOVERNANCE.md`. PyPI Trusted Publishing must identify this repository, the
`release.yml` workflow, and the protected `pypi` environment. No API token is
stored in repository settings or workflow files.

## 5. Final go/no-go and publication

1. Review the candidate record and ensure no tracked or untracked changes exist.
2. Create an annotated stable tag whose value is exactly `v` plus the package
   version.
3. Push only that reviewed commit and tag.
4. Approve the protected `pypi` environment after the workflow's build and
   validation jobs pass.
5. Verify the published filenames and SHA-256 digests equal the candidate.
6. Create the GitHub release from the matching changelog section and attach the
   checksums. Never upload a rebuilt artifact.

Publication, tag push, environment approval, and repository-setting changes are
human release actions and are not performed by candidate preparation.

## Lock regeneration

Locks are generated in a clean `python:3.12-slim` container using exactly
`pip==26.0` and `pip-tools==7.6.0`. The resolver pip is pinned because a newer
pip internals API is not implicitly accepted. The container receives only the
trusted Watchdog checkout.
Run pip-compile once for runtime dependencies, once with the `dev` extra, and
once with the `release` extra. The development and release locks also consume
`requirements/build.in`, whose exact backend pins mirror `pyproject.toml`.
Always use backtracking resolution, hashes, annotation, and the trusted public
package index. Review the complete diff and then prove all three files install
with `--require-hashes`.

The exact regeneration commands are recorded at the top of each generated lock
file. A resolver or index failure blocks lock refresh; it must not be treated as
evidence that dependencies are current or unaffected.
