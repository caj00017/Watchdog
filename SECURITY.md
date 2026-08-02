# Security Policy

Nexura Watchdog processes hostile repository and vulnerability data. Security
reports that could expose a bypass, secret, private data, or a working exploit
must not be filed in a public issue.

## Supported versions

Until `v0.1.0` is published, security fixes are made on `main`. After release,
the latest `0.1.x` version and `main` are supported. Older prerelease builds and
mutable development container tags are not supported release identifiers.

## Reporting a vulnerability

Use the repository's GitHub **Report a vulnerability** private-reporting flow to
open a private security advisory. Include:

- the affected version or commit;
- the trust boundary and expected behavior;
- minimal reproduction steps using synthetic data;
- the security impact and any known preconditions; and
- whether details or proof-of-concept material require extra handling.

Do not include real credentials, tokens, unredacted secrets, private repository
content, or personal data. Do not attach or link to a repository whose code must
be executed to reproduce the issue.

If private reporting is unavailable, do not publish the details. Open a public
issue containing only a request for a private reporting channel and no security-
sensitive information.

## Response process

The maintainer will acknowledge a usable private report, assess severity and
affected versions, preserve evidence, and coordinate a fix and disclosure plan.
There is no guaranteed response-time SLA for this local-first alpha release.
Scanner failure, unavailable reproduction infrastructure, or incomplete
coverage will be reported as limitations rather than treated as evidence that a
report is not applicable.
