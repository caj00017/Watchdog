# Textual 8.2.8 Dependency Review

**Reviewed:** August 4, 2026

**Scope:** Trusted Watchdog Release 1 local-TUI runtime only. This review does
not authorize Textual Web, `textual-serve`, the development console, syntax
extras, telemetry, remote operation, or any use inside analyzed repositories.

## Selected distribution and ownership

Watchdog directly constrains `textual>=8.2.8,<9`; all three checked-in locks
select exactly `textual==8.2.8`. PyPI identifies Will McGugan as the package
owner and Textualize's GitHub organization as the source repository. The release
was uploaded June 30, 2026 and declares Python `>=3.9,<4.0`, including Python
3.12, 3.13, and 3.14 and Linux, macOS, and Windows classifiers.

Textual 8.2.8 is MIT licensed. MIT is permissive and compatible with Watchdog's
Apache-2.0 distribution. The Textual license remains included by its installed
distribution; Watchdog does not copy Textual source into its own package.

Trusted PyPI distribution identities:

- `textual-8.2.8-py3-none-any.whl`: 731,418 bytes; SHA-256
  `267375fd402dc8d981457212efa71f0e3365fd17bba144ba9bb3ed7563cb374a`
- `textual-8.2.8.tar.gz`: 1,860,502 bytes; SHA-256
  `3f106a9fbc73e39dd266c9712432087de78a6d644084c7c241d6a25c3169115b`

## Runtime graph and excluded features

The base distribution declares these dependencies:

- `markdown-it-py[linkify]>=2.1.0`
- `mdit-py-plugins`
- `platformdirs>=3.6.0,<5`
- `pygments>=2.19.2,<3`
- `rich>=14.2.0`
- `typing-extensions>=4.4.0,<5`

The generated Python 3.12 locks resolve the complete base graph, including the
linkify support requested by Textual. Every selected artifact is hash checked.
The reviewed graph is Python-only and adds no native extension. Textual's
optional `syntax` extra is not requested, so no Tree-sitter package enters any
lock. `textual-dev`, Textual Web, `textual-serve`, browser-serving components,
remote features, snapshot tools, and development-console packages are absent.

The package exposes generic Markdown, syntax, link, command-palette, clipboard,
mouse, focus, title, and web capabilities. Watchdog does not use those dynamic
rendering features and disables or avoids them in its TUI boundary. Their
presence in the toolkit is not authority to activate them.

## Security and maintenance observation

PyPI's release JSON reported no vulnerability entries for Textual 8.2.8 when
reviewed on August 4, 2026. A separate point-in-time OSV package review likewise
found no OSV-listed vulnerability affecting `PyPI/textual` version 8.2.8. This
is point-in-time evidence, not a guarantee of future safety or complete advisory
coverage. Dependency refreshes and any Textual major-version change require a
new review.

Textual was actively maintained at review time and 8.2.8 was a current 8.x
release. Watchdog pins the selected version in locks even though project metadata
retains a bounded 8.x constraint, so an upstream release cannot enter a trusted
build without an explicit lock change and review.

## Acceptance and rollback

The dependency is acceptable only while hostile-terminal tests, headless state
tests, Python 3.12–3.14 tests, packaging checks, licensing, and the pure-Python
graph pass. Unsupported manual platforms remain coverage limitations and are not
inferred as passing. If a gate fails, revert the no-argument/TUI launcher,
remove the Textual constraint and TUI package, regenerate all three locks from
the pre-TUI metadata, and retain `watchdog ui` plus direct commands as the
Release 1 interface.

Sources reviewed: trusted PyPI 8.2.8 JSON metadata and distributions, Textual's
upstream project metadata/documentation, generated hash-checked Python 3.12 lock
graph, and OSV's package database on the review date.
