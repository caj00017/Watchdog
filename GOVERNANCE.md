# Governance

Nexura Watchdog is maintained by Christopher Jones / Nexura. The maintainer is
responsible for scope decisions, work-order authorization, release approval,
security response, and repository administration.

## Change control

- `main` is the integration branch and should require pull-request review and
  passing CI before merge.
- Security-boundary changes require an authorized work order, tests,
  architecture and threat-model updates, and explicit review of residual risk.
- Runtime dependencies, external destinations, scanner changes, and canonical
  identity/schema changes receive the same boundary review as application code.
- Documentation-only planning commits precede implementation when they grant a
  new security or release boundary.
- Release automation cannot waive a failed or incomplete security gate.

## Releases

The maintainer acts as release manager unless another person is explicitly
delegated in the release record. Stable releases use SemVer tags, immutable
artifacts with checksums, reviewed release notes, a protected publication
environment, and PyPI Trusted Publishing. The tag, package metadata, changelog,
and application version must agree exactly.

The release manager makes the final go/no-go decision, approves publication,
and may yank a package when a severe defect creates material user or security
risk. Published files are never replaced in place. Corrections use a new
version, and any yank or rollback reason is recorded publicly when disclosure is
safe.

## Repository settings required before publication

- Protect `main`; require pull requests, CI, and resolution of review comments.
- Enable private vulnerability reporting.
- Create a protected `pypi` environment with required reviewer approval.
- Configure the `release.yml` workflow as a PyPI Trusted Publisher for the
  `nexura-watchdog` project.
- Restrict tag creation for stable `v*` releases to the release manager.

These remote controls are verified during the final release go/no-go. Checked-in
files document the policy but do not claim that remote settings are active.
