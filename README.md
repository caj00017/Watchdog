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

Watchdog is not published yet, so the current way to use it is from a source
checkout. You need:

- Python 3.12, 3.13, or 3.14;
- OSV-Scanner exactly 2.4.0;
- network access to OSV and the public GitHub repository you want to inspect;
- an interactive terminal at least 60 columns wide and 20 rows tall.

### 1. Download and install Watchdog

Clone the trusted Watchdog project, create an isolated Python environment, and
install its checked-in dependencies:

```bash
git clone https://github.com/caj00017/Watchdog.git
cd Watchdog
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements/dev.lock
python -m pip install --no-deps --no-build-isolation -e .
```

The commands above are for Bash on Linux or macOS. In PowerShell, activate the
environment with `.venv\Scripts\Activate.ps1` instead. The dependency file is
hash-locked and belongs to Watchdog itself. Watchdog never installs dependencies
from a repository you ask it to investigate.

### 2. Make the scanner available

Watchdog uses OSV-Scanner for exact dependency matching, but deliberately does
not download it for you. Install or otherwise obtain version 2.4.0, confirm that
it reports that exact version, and give Watchdog its absolute path:

```bash
/absolute/path/to/osv-scanner --version
export WATCHDOG_OSV_SCANNER_PATH=/absolute/path/to/osv-scanner
watchdog doctor
```

In PowerShell, set the same variable with
`$env:WATCHDOG_OSV_SCANNER_PATH = "C:\absolute\path\to\osv-scanner.exe"`.

The doctor command checks the configuration and scanner version without
contacting an advisory, GitHub, or repository. Continue only when it reports
`scanner: ready (OSV-Scanner 2.4.0)`.

### 3. Start Watchdog

Run Watchdog in an interactive terminal:

```bash
watchdog
```

The start screen confirms whether the scanner is ready. Enter one advisory ID
(a CVE, GHSA, or OSV ID), one public GitHub URL, and optionally a branch, tag, or
commit in the ref field. Press Tab to move between controls and Enter to start.

The result workspace keeps Summary, Evidence, Remediation, and Canonical JSON in
separate views. Press Escape to close a detail view, Ctrl+C to cancel active work,
or Ctrl+Q to leave cleanly. `watchdog tui` is the explicit equivalent of bare
`watchdog`.

Remediation suggestions are plans only: Watchdog never writes to the repository
or applies a change. One-token preview generation is also off unless you start
the TUI with `watchdog tui --enable-previews`. Optional model synthesis remains
off unless you explicitly configure the existing local loopback model boundary.

If the TUI does not start, run `watchdog doctor` first. A scanner error means the
configured executable is missing or is not exactly version 2.4.0. A terminal
error means stdin or stdout is redirected, the terminal type is unsupported, or
the window is smaller than 60x20. Neither preflight failure starts an
investigation.

### 4. Optional: produce a report without the TUI

Provide a CVE, GHSA, or OSV identifier and the public GitHub repository you want
to review:

```bash
watchdog investigate \
  --advisory CVE-2021-44228 \
  --repository https://github.com/owner/repository \
  --ref main \
  --format markdown
```

The direct command writes the report to standard output. Add `> report.md` if
you want your shell to save it. Omit `--ref` to use the repository's default
branch, or use `--format json` for machine-readable output. Unlike the TUI, this
command is suitable for redirected output.

## How to read the result

Watchdog keeps different kinds of information separate:

- facts found by the deterministic checks;
- optional model inferences, when explicitly enabled;
- assumptions and missing coverage;
- validation actions for a person to perform.

Pay attention to warnings about unknown versions, unsupported files, scanner
failures, or partial coverage. Watchdog does not turn those cases into a
repository-level affected or not-affected answer.

Watchdog keeps no investigation history. Save the canonical JSON or direct CLI
output yourself if you need a durable record.

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
