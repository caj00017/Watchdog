# Threat Model

> Supporting detail. The canonical project status and roadmap are maintained in
> `../Nexura_Watchdog_Project_Design_and_Implementation_Record.md`.

## Scope and security objectives

This model covers the advisory API, internal public-GitHub intake, bounded Phase
3 dependency parsing, exact-coordinate OSV-Scanner matching, and the implemented
Phase 4 evidence boundary.
The repository boundary assumes every byte, filename, link, and metadata value in
an acquired project is hostile. The scanner boundary trusts only the pinned
binary and Watchdog-generated controls; it does not trust repository manifests,
configuration, or environment variables.

The current objectives are to:

- accept bounded identifiers and canonical public GitHub URLs rather than
  caller-controlled upstream destinations;
- preserve advisory provenance and exact repository acquisition metadata;
- acquire repository data without Git, credentials, package installation, or
  execution;
- bound network time, total intake time, archive size, extracted bytes, file
  count, path length, and per-service concurrency;
- prevent archive paths and links from escaping the disposable workspace;
- delete temporary data verifiably on success, failure, timeout, and
  cancellation;
- ensure missing data and tool failure never become negative security findings.
- parse only allowlisted bounded dependency data without repository or package
  execution;
- provide the scanner only generated exact coordinates, bound its process and
  output, and preserve its failures as incomplete coverage.
- constrain Phase 4 evidence reads to Watchdog-generated source references,
  redact before content crosses the service boundary, and fail closed when safe
  extraction cannot complete.

## Assets

- Integrity of normalized advisory records and provenance
- Integrity of the resolved repository identity, commit, tree, and archive digest
- Host filesystem content outside the workspace
- Availability, disk space, memory, and CPU of the API process
- Operator environment variables and network credentials
- Confidential repository content accidentally present in a public archive
- Accuracy of errors, partial-result state, and cleanup status
- Integrity of inventory source links, deterministic IDs, exact coordinates, and
  scanner evidence
- Confidentiality of unredacted repository snippets and integrity of Phase 4
  evidence identities, match links, redactions, and coverage state

## Trust boundaries

### API client boundary

The current API accepts only advisory identifiers. Identifier syntax is
allowlisted and canonicalized before any outbound request. There is no public
repository-intake route, upload, retention option, or arbitrary URL proxy.

### Advisory network boundary

OSV responses and failures are external and untrusted. Strict boundary models,
identity checks, and typed errors prevent malformed, missing, or unavailable data
from becoming an empty advisory. The configured OSV base URL is operator trust,
not request data.

### Internal repository request boundary

The repository URL and ref remain untrusted even though a trusted internal caller
invokes the service. URLs must use HTTPS, host `github.com`, and contain exactly
an owner and repository. Credentials, custom ports, query strings, fragments,
percent encoding, and extra path segments fail closed. Refs are bounded and may
not contain controls or surrounding whitespace.

### GitHub network boundary

The adapter sends unauthenticated requests only to the fixed public GitHub API.
Archive redirects are handled manually and restricted to HTTPS GitHub API and
codeload hosts without credentials, nonstandard ports, or fragments. Repository
identity is compared case-insensitively with GitHub metadata, private metadata is
rejected, and commit/tree identifiers must be full lowercase SHA-1 values.

### Archive and workspace boundary

GitHub archive bytes and tar metadata are fully hostile. A private mode-0700
workspace and mode-0600 archive limit other local users. The archive is streamed
with a compressed byte cap, then enumerated by a custom validator before each
member is created. No general tar extraction, subprocess, shell, Git command,
hook, package manager, importer, or repository binary is used.

Contained symlinks remain untrusted filesystem objects even when they cannot
lexically escape. Future consumers must not follow them outside their intended
read-only operations and must continue to treat file contents as data.

### Dependency-parser boundary

Manifest filenames, bytes, selectors, package names, versions, includes, and
conditions are hostile data. Sorted discovery does not follow symlinks and skips
generated/VCS/vendor trees. Recognized files are opened without following links,
read under per-file and total caps, and parsed in a worker with deadline,
nesting, include, component, edge, and warning limits. Requirements includes are
local-only and cannot be absolute, URLs, cyclic, missing silently, or escape the
lease. No package manager, interpreter import, Go/npm/Python tool, build, or
dependency installation is invoked.

### OSV-Scanner subprocess and network boundary

OSV-Scanner 2.4.0 is pinned in the image and native paths must be absolute. The
lazy version boundary requires the explicit `osv-scanner version:` line to be
exactly 2.4.0 while allowing additive metadata about separately bundled tools.
The binary receives only generated normalized exact coordinates plus a trusted
empty configuration in a private control directory—not repository files or
paths. The argument array is fixed; recursive scanning, call analysis,
remediation, repository configuration, resolution, and plugins are absent. A
minimal proxy-free environment uses disposable home/cache/temp locations.

Stdout and stderr are drained concurrently under byte caps. Timeout, overflow,
cancellation, or reader failure terminates the new process group, escalates to
kill, and reaps it. Exit 0/1 still requires strict validation of known JSON types.
The scanner's normal OSV lookup is the sole Phase 3 egress; `--no-resolve`
prevents dependency-resolution lookups such as deps.dev. CA/DNS, the pinned
scanner implementation, and OSV availability remain trusted dependencies.

### Phase 4 evidence boundary

The evidence service receives only an acquired repository,
inventory, and match report that agree on the exact snapshot. Its file targets
come exclusively from Watchdog-generated Phase 3 source references; a caller
cannot supply an arbitrary path, selector, or line range.

Every path component is opened relative to a repository directory descriptor
with no-follow semantics. The final target must be a bounded regular file, and
its complete digest must match the Phase 3 reference before content is used.
Selector resolution is limited to the dependency formats already supported by
Phase 3. Ambiguous, stale, changed, invalid, or unsupported references produce
omitted-content evidence and explicit partial coverage.

Selected raw bytes remain hostile and may exist only transiently in bounded
memory inside the reader and redactor. Only deterministic redacted display text
may cross into an immutable evidence item. Redaction errors, invalid encoding,
or resource limits omit content rather than returning raw data. Models,
warnings, exceptions, and logs may not contain unredacted repository content.

The service is in-process and has no subprocess, network client, persistence, or
public route. All work must finish inside the Phase 2 lease so existing cleanup
verification remains the lifecycle boundary.

### Export boundary

Advisory text is untrusted. JSON uses the framework serializer. Markdown escapes
HTML and Markdown control characters and omits raw source objects. Repository
content has no export path in this phase.

## Threats and controls

| Threat | Current control | Residual risk or follow-up |
| --- | --- | --- |
| SSRF through repository URL | Exact HTTPS `github.com` URL grammar; fixed API destination; redirect host allowlist | DNS and TLS depend on the runtime and CA trust store |
| Credentials leak to GitHub or redirect | No authentication support; userinfo rejected; redirect hosts and ports constrained | Hosted private-repository support would require a new credential design |
| Mutable branch changes during intake | Ref resolves to a full commit; tarball request uses that commit; snapshot records commit and tree | Archive contents trust GitHub; the tarball is not independently reconstructed into a Git tree |
| Compressed download exhausts disk | Header and streamed-byte caps; partial files are lease-owned and cleaned | Peak space includes compressed plus extracted data; filesystem quotas are not enforced here |
| Archive bomb exhausts disk | Declared and observed extracted regular-file bytes are capped | CPU/memory hard limits and compression-ratio limits require process/container isolation before hosted use |
| Path traversal or absolute write | Root stripping plus rejection of absolute paths, `..`, empty segments, backslashes, and controls | Python tar parsing remains in the trusted computing base |
| Symlink or hardlink escape | Only contained relative symlinks; no parent traversal through earlier symlinks; hardlinks rejected | Trusted future consumers must avoid unsafe link-following behavior |
| Device, FIFO, sparse, or special member abuse | All unsupported member types are rejected | New archive formats require an equivalent reviewed validator |
| Cross-platform overwrite or ambiguity | Duplicate and Unicode case-fold collisions rejected; relative path length bounded | Filesystem normalization differences beyond case folding may need platform-specific tests |
| Git hooks, submodules, or checkout filters execute | Archive-only acquisition; no Git process or `.git` metadata | None within current intake path |
| Repository code or dependency execution | Data-only allowlisted parsers; no imports, builds, package tools, dependency installs, or repository-path scanner input | Parser libraries and the pinned scanner remain trusted code |
| Manifest resource exhaustion | Per-file/total bytes, file count, nesting, include, graph, warning, and deadline limits | Python process has no independent CPU/memory cgroup in native development |
| Requirements traversal or fetch | Only contained local relative includes; URLs, absolute paths, escapes, cycles, and missing files warn | Included content remains hostile and can still exhaust configured budgets |
| Scanner argument/config injection | Fixed argument array; generated controls; trusted empty config; no repository paths or config | Operator controls the absolute executable setting |
| Scanner hangs or forks | Timeout, bounded concurrent output, new session, process-group terminate/kill/reap | Host crash and adversarial kernel behavior are outside application cleanup |
| Scanner leaks credentials | New minimal environment omits proxies and credentials; diagnostics are bounded and sanitized | OSV requests use host CA/DNS; no application-layer destination pin exists inside scanner |
| Scanner/network failure becomes negative | Only validated exit 0/1 supports exact-coordinate results; all other states are `scanner_incomplete` | A successful lookup can still reflect stale/incomplete OSV data |
| Host-dependent condition evaluation | PEP 508 markers and npm OS/CPU expressions are preserved, never evaluated | Deployment applicability remains unknown until a later user-context phase |
| Intake stalls or consumes all workers | End-to-end deadline, per-request timeout, and semaphore | Semaphore is per service instance; distributed/global rate controls are deferred |
| Cancellation leaves data behind | Extraction cooperatively stops; cleanup is awaited and verified before slot release | Process termination or host crash can leave a workspace; startup scavenging is deferred |
| Workspace deletion is redirected | Cleaner refuses a workspace path replaced by a symlink or non-directory | A same-UID local attacker with workspace access is outside the primary deployment assumption |
| Cleanup failure is hidden | Typed failure includes archive/workspace removal flags and verification state | Operator alerting and stale-workspace recovery are not implemented |
| Public repository contains secrets | No content logging/persistence/model transmission; scanner receives coordinates only; mandatory deletion | Parsed package strings and source paths can still contain surprising hostile text |
| Large GitHub metadata response | Network timeout and strict schema | Metadata response-byte cap and retry/rate policy are required before hosted exposure |
| Upstream outage becomes “not affected” | Source and intake failures are typed; neither flow emits an exposure classification | Later orchestration must preserve this distinction |
| Advisory Markdown injects active content | HTML and Markdown metacharacters escaped | Renderer-specific defense in depth remains necessary |

## Phase 4 implemented controls

These controls are implemented and covered by schema, selector, redaction,
hostile-filesystem, cancellation, determinism, and lease-cleanup tests:

| Threat | Implemented control | Failure behavior or residual risk |
| --- | --- | --- |
| Caller chooses an unrelated or escaping file | Accept only Watchdog-generated Phase 3 source references; validate matching snapshots and normalized relative paths | Reject the request before a file opens |
| Symlink or parent-component traversal during evidence reads | Descriptor-relative component walk with no-follow flags; regular-file final target; no `Path.resolve()` containment shortcut | Omit content, mark partial, and preserve cleanup |
| Source changes between inventory and evidence | Hash the complete bounded file opened by descriptor and compare it with the Phase 3 digest | Omit stale evidence; never relabel the changed bytes |
| Evidence extraction exhausts resources | Deadline plus source-file, per-file, total-byte, item, line-span, display, redaction, and warning caps | Stop bounded work and return explicit partial coverage |
| Repository secret enters a model, export, log, or exception | Redact the smallest selected span before model construction; no persistence/export/model path; safe generic diagnostics | Redaction failure omits content with no raw fallback |
| Secret-derived hashes enable guessing | Hash the complete source file and final redacted display only; never hash an individual secret | Small public files may still be guessable from the full-file digest because the digest is repository evidence |
| Prompt injection is mistaken for instruction | Mark all repository evidence `untrusted_repository`; treat content as quoted data; no model call in Phase 4 | A later model phase must preserve trust labels and validate evidence links |
| Nondeterministic evidence cannot be audited | Version producer/resolver/redaction policy; canonical JSON; stable sort; exclude time and temporary paths from identity | Implementation/library changes require a producer-version change |
| Extraction failure becomes negative evidence | Omitted-content items, structured warnings, and partial bundle coverage; no exposure classification | Consumers must inspect evidence status and bundle coverage |

## Explicitly absent capabilities

There is currently no repository API endpoint, GitHub authentication, private
repository support, Git clone, archive retention, SBOM tool,
source/static/reachability analysis beyond dependency selectors, LLM call,
exposure classification, or patch application. Phase 3 inventory and
exact-coordinate matching are internal only and do not assert runtime exposure.
Phase 4 evidence extraction remains internal and has no persistence or public
export path.

Prompt injection in source and configuration becomes operationally relevant only
when model analysis exists. That phase must quote repository data, redact
secrets, bound evidence, require a strict output schema, and validate every model
claim against evidence IDs. Generated patches remain previews until explicit
human approval.

## Security change process

Any new outbound destination, input type, source adapter, persistence mechanism,
repository operation, scanner, public intake endpoint, retention option, or model
provider changes a trust boundary. It requires targeted abuse-case tests and
synchronized updates to `AGENTS.md`, this threat model, and the architecture
documentation.

The proposed `../work-orders/phase-5-contextual-analysis.md` would add a new
hostile-source discovery and parsing boundary. It is review material only. No
Phase 5 control is active or authorized until this threat model, `AGENTS.md`, and
the canonical record explicitly approve implementation.
