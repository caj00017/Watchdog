## Governing work order and scope

<!-- Link the work order or explain why the change is within an existing boundary. -->

## Evidence and behavior

<!-- Describe the evidence supporting each behavior, compatibility, or security claim. -->

## Verification

- [ ] Ruff format and lint
- [ ] Strict mypy
- [ ] Compileall
- [ ] Deterministic pytest suite
- [ ] Documentation and security-boundary review
- [ ] Environment-dependent checks recorded as passed, failed, skipped, or unavailable

## Trust-boundary review

- [ ] No analyzed repository code or dependencies are executed or installed
- [ ] No new runtime dependency, destination, credential, persistence, or write path
- [ ] Findings retain evidence links and explicit coverage limitations
- [ ] Generated remediation remains preview-only and human-approved
