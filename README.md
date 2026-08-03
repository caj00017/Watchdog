# Nexura Watchdog

Nexura Watchdog helps you investigate a known security advisory in a public
GitHub repository. You give it an advisory ID, such as a CVE, GHSA, or OSV ID,
and a repository URL. Watchdog gathers the advisory, checks supported dependency
files, and returns a report with the evidence behind its findings.

Watchdog is designed to be careful with unfamiliar code. It reads a bounded
archive of the repository; it does not run repository code, install the
repository's dependencies, or change the repository. A result can be incomplete
when information is unavailable or unsupported, so an incomplete result is not a
clean bill of health.

## Quick start

The current command-line workflow runs from a source checkout.

### 1. Get the project

You need Python 3.12, 3.13, or 3.14, plus network access to OSV and public GitHub repositories.

```bash
git clone https://github.com/caj00017/Watchdog.git
cd Watchdog
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements/dev.lock
python -m pip install --no-deps --no-build-isolation -e .
```

These commands install Watchdog's development dependencies from the checked-in,
hash-locked files. They do not install anything from a repository being
investigated.

### 2. Make the scanner available

Watchdog needs OSV-Scanner 2.4.0 for exact dependency matching. Install or
otherwise obtain that version separately, then point Watchdog at its absolute
path:

```bash
export WATCHDOG_OSV_SCANNER_PATH=/absolute/path/to/osv-scanner
watchdog doctor
```

The doctor command checks the configuration and scanner version without
contacting an advisory, GitHub, or repository. Continue only when it reports
`scanner: ready (OSV-Scanner 2.4.0)`.

### 3. Launch the local TUI

Run Watchdog in an interactive terminal:

```bash
watchdog
```

The guided TUI shows readiness, accepts one advisory ID and one public GitHub
URL, reports data-free workflow progress, and separates Summary, Evidence,
Remediation, and Canonical JSON views. `watchdog tui` is the explicit equivalent.
Use `--enable-previews` only when you want the existing bounded one-token
in-memory remediation previews. The terminal must be at least 60 columns by 20
rows; redirected or unsupported terminal invocations fail with plain text before
Textual or workflow services start.

### 4. Use the direct command when needed

Provide a CVE, GHSA, or OSV identifier and the public GitHub repository you want to review:

```bash
watchdog investigate \
  --advisory CVE-2021-44228 \
  --repository https://github.com/owner/repository \
  --ref main \
  --format markdown
```

The report is written to standard output. Add `> report.md` if you want your
shell to save it. Omit `--ref` to let GitHub use the repository's default
branch. Use `--format json` for machine-readable output.

## How to read the result

Watchdog keeps different kinds of information separate:

- facts found by the deterministic checks;
- optional model inferences, when explicitly enabled;
- assumptions and missing coverage;
- validation actions for a person to perform.

Pay attention to warnings about unknown versions, unsupported files, scanner failures, or partial coverage. Watchdog does not turn those cases into a repository-level affected or not-affected answer.

## Web comparison interface

The existing literal-loopback web UI remains available unchanged for
side-by-side comparison:

```bash
watchdog ui
```

Use `watchdog ui --no-open` to print the local URL without opening a browser.
The TUI and web interface are local, transient projections over the same
canonical models. Hosted operation, SSH, and remote access remain deferred to
Version 2.

## Need the full details?

The [technical reference](docs/reference/README-technical.md) preserves the
complete configuration, API, container, internal-service, security, and
verification documentation.

The [project design and implementation record](docs/Nexura_Watchdog_Project_Design_and_Implementation_Record.md)
is the canonical record of the project's current status and boundaries.
Watchdog is licensed under the [Apache License 2.0](LICENSE); security issues
should follow [SECURITY.md](SECURITY.md).
