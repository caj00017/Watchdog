from __future__ import annotations

import argparse
import ast
import re
import stat
import tarfile
import tomllib
import zipfile
from collections.abc import Sequence
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any, cast

_ROOT = Path(__file__).resolve().parents[1]
_STABLE_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_ACTION_PIN = re.compile(r"^\s*uses:\s*([^\s@]+)@([0-9a-f]{40})(?:\s*#.*)?$", re.MULTILINE)
_USES_LINE = re.compile(r"^\s*uses:\s*([^\s]+)", re.MULTILINE)
_LOCK_ENTRY = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)==(?P<version>[^\s;]+)"
    r"(?:\s*;\s*.+)?$"
)
_DIRECT_DEPENDENCY = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)")
_EXPECTED_LOCKS = ("runtime.lock", "dev.lock", "release.lock")
_RELEASE_EPOCH = 1_785_628_800
_RELEASE_ZIP_DATETIME = (2026, 8, 2, 0, 0, 0)
_REQUIRED_WHEEL_ASSETS = {
    "apps/web/static/guided-index.html",
    "apps/web/static/guided-watchdog.css",
    "apps/web/static/guided-watchdog.js",
    "apps/web/static/index.html",
    "apps/web/static/remediation-index.html",
    "apps/web/static/remediation-watchdog.js",
    "apps/web/static/watchdog.css",
    "apps/web/static/watchdog.js",
}
_REQUIRED_WHEEL_TUI_MODULES = {
    "watchdog/tui/__init__.py",
    "watchdog/tui/app.py",
    "watchdog/tui/backend.py",
    "watchdog/tui/display.py",
    "watchdog/tui/driver.py",
    "watchdog/tui/projection.py",
    "watchdog/tui/runner.py",
    "watchdog/workflow/observer.py",
}
_REQUIRED_SDIST_FILES = {
    "AGENTS.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "pyproject.toml",
    "docs/release/release-process.md",
    "docs/release/textual-8.2.8-dependency-review.md",
    "docs/plans/release-1-local-tui-implementation-plan.md",
    "docs/work-orders/release-1-hardening.md",
    "docs/work-orders/release-1-tui-and-ssh-trial.md",
    "requirements/runtime.lock",
    "requirements/dev.lock",
    "requirements/release.lock",
    "scripts/normalize_sdist.py",
    "scripts/verify_release.py",
}


class ReleaseVerificationError(ValueError):
    """Raised when trusted release inputs or artifacts violate the contract."""


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _project(root: Path) -> dict[str, Any]:
    document = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = document.get("project")
    if not isinstance(project, dict):
        raise ReleaseVerificationError("pyproject.toml has no static project table")
    return cast(dict[str, Any], project)


def _module_version(root: Path) -> str:
    tree = ast.parse((root / "watchdog/__init__.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__version__"
                for target in node.targets
            )
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            return node.value.value
    raise ReleaseVerificationError("watchdog.__version__ is not one static string")


def _direct_dependency_names(project: dict[str, Any]) -> set[str]:
    dependencies = project.get("dependencies")
    if not isinstance(dependencies, list) or not all(
        isinstance(dependency, str) for dependency in dependencies
    ):
        raise ReleaseVerificationError("project dependencies are not a static string list")
    names: set[str] = set()
    for dependency in dependencies:
        match = _DIRECT_DEPENDENCY.match(dependency)
        if match is None:
            raise ReleaseVerificationError("a direct dependency has unsupported syntax")
        names.add(_canonical_name(match.group("name")))
    return names


def _lock_entries(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    forbidden = ("--trusted-host", "--extra-index-url", "git+", " @ ", "-e ", "--editable")
    if any(value in text for value in forbidden):
        raise ReleaseVerificationError(f"{path.name} contains a forbidden requirement source")

    entries: dict[str, str] = {}
    current_name: str | None = None
    current_hashed = False

    def finish() -> None:
        nonlocal current_name, current_hashed
        if current_name is not None and not current_hashed:
            raise ReleaseVerificationError(f"{path.name} has an unhashed pin: {current_name}")
        current_name = None
        current_hashed = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if stripped.startswith("--hash"):
            if current_name is None:
                raise ReleaseVerificationError(f"{path.name} has a detached hash")
            normalized_hash = stripped.removesuffix("\\").rstrip()
            if re.fullmatch(r"--hash=sha256:[0-9a-f]{64}", normalized_hash) is None:
                raise ReleaseVerificationError(f"{path.name} has a malformed SHA-256 hash")
            current_hashed = True
            continue
        if not line or line.lstrip().startswith("#") or line[:1].isspace():
            continue
        if line.startswith("--"):
            raise ReleaseVerificationError(f"{path.name} has an unsupported global option")
        finish()
        requirement = line.removesuffix("\\").rstrip()
        match = _LOCK_ENTRY.fullmatch(requirement)
        if match is None:
            raise ReleaseVerificationError(f"{path.name} contains a non-exact requirement")
        current_name = _canonical_name(match.group("name"))
        if current_name in entries:
            raise ReleaseVerificationError(f"{path.name} repeats {current_name}")
        entries[current_name] = match.group("version")
    finish()
    if not entries:
        raise ReleaseVerificationError(f"{path.name} contains no package pins")
    return entries


def _verify_locks(root: Path, project: dict[str, Any]) -> None:
    locks = {name: _lock_entries(root / "requirements" / name) for name in _EXPECTED_LOCKS}
    direct = _direct_dependency_names(project)
    missing = direct - locks["runtime.lock"].keys()
    if missing:
        raise ReleaseVerificationError(f"runtime.lock omits direct dependencies: {sorted(missing)}")
    for name in ("dev.lock", "release.lock"):
        missing_runtime = locks["runtime.lock"].keys() - locks[name].keys()
        if missing_runtime:
            raise ReleaseVerificationError(f"{name} omits runtime pins: {sorted(missing_runtime)}")
        for backend in ("setuptools", "wheel"):
            if backend not in locks[name]:
                raise ReleaseVerificationError(f"{name} omits build backend {backend}")
    for tool in ("build", "twine"):
        if tool not in locks["release.lock"]:
            raise ReleaseVerificationError(f"release.lock omits {tool}")
    for name, entries in locks.items():
        if entries.get("textual") != "8.2.8":
            raise ReleaseVerificationError(f"{name} does not select reviewed Textual 8.2.8")
        forbidden = sorted(package for package in entries if package.startswith("tree-sitter"))
        if forbidden or "textual-dev" in entries:
            raise ReleaseVerificationError(f"{name} contains an unreviewed Textual feature")


def _verify_workflow_action_pins(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    uses = _USES_LINE.findall(text)
    pins = _ACTION_PIN.findall(text)
    if len(uses) != len(pins):
        raise ReleaseVerificationError(f"{path.name} has an action without a full SHA pin")


def _verify_workflows(root: Path) -> None:
    ci_path = root / ".github/workflows/ci.yml"
    release_path = root / ".github/workflows/release.yml"
    for path in (ci_path, release_path):
        _verify_workflow_action_pins(path)
    ci = ci_path.read_text(encoding="utf-8")
    release = release_path.read_text(encoding="utf-8")
    if "pull_request_target" in ci or "id-token: write" in ci or "secrets." in ci:
        raise ReleaseVerificationError("CI has an elevated pull-request boundary")
    if "permissions:\n  contents: read" not in ci:
        raise ReleaseVerificationError("CI does not declare read-only contents permission")
    if "permissions:\n  contents: read" not in release:
        raise ReleaseVerificationError("release workflow does not default to read-only contents")
    for expected in ("id-token: write", "name: pypi", "environment:", "--require-hashes"):
        if expected not in release:
            raise ReleaseVerificationError(f"release workflow omits {expected}")
    if "password:" in release or "secrets." in release or "pull_request_target" in release:
        raise ReleaseVerificationError("release workflow contains a long-lived credential boundary")
    before_publish, separator, publish = release.partition("\n  publish:\n")
    if (
        not separator
        or "id-token: write" in before_publish
        or publish.count("id-token: write") != 1
    ):
        raise ReleaseVerificationError("OIDC authority is not isolated to the publish job")


def _verify_container(root: Path) -> None:
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    required = (
        "ghcr.io/google/osv-scanner:v2.4.0@sha256:",
        "python:3.12-slim@sha256:",
        "--require-hashes",
        "--no-deps",
        "--no-isolation",
    )
    for value in required:
        if value not in dockerfile:
            raise ReleaseVerificationError(f"Dockerfile omits release control: {value}")
    ignored = set((root / ".dockerignore").read_text(encoding="utf-8").splitlines())
    for value in (".git", ".env", ".venv", "dist", "tests"):
        if value not in ignored:
            raise ReleaseVerificationError(f".dockerignore omits sensitive build input: {value}")


def _safe_archive_name(name: str) -> PurePosixPath:
    if (
        "\\" in name
        or not name
        or name.startswith("/")
        or len(name) > 1_024
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise ReleaseVerificationError("artifact contains a non-relative member")
    path = PurePosixPath(name)
    if (
        any(part in {"", ".", ".."} or len(part) > 255 for part in path.parts)
        or ":" in path.parts[0]
    ):
        raise ReleaseVerificationError("artifact contains traversal or ambiguous member syntax")
    return path


def _verify_metadata(
    content: bytes,
    expected_version: str,
    expected_dependencies: set[str],
) -> None:
    message = BytesParser(policy=policy.default).parsebytes(content)
    expected = {
        "Name": "nexura-watchdog",
        "Version": expected_version,
        "License-Expression": "Apache-2.0",
        "Requires-Python": ">=3.12",
    }
    for key, value in expected.items():
        if message.get(key) != value:
            raise ReleaseVerificationError(f"artifact metadata {key} does not equal {value}")
    requirements = message.get_all("Requires-Dist", [])
    if not requirements:
        raise ReleaseVerificationError("artifact metadata contains no runtime dependencies")
    runtime_dependencies: set[str] = set()
    for requirement in requirements:
        if 'extra == "' in requirement:
            continue
        match = _DIRECT_DEPENDENCY.match(requirement)
        if match is None:
            raise ReleaseVerificationError("artifact metadata has an invalid dependency")
        runtime_dependencies.add(_canonical_name(match.group("name")))
    if runtime_dependencies != expected_dependencies:
        raise ReleaseVerificationError("artifact runtime dependencies do not match project policy")


def _verify_wheel(path: Path, expected_version: str, expected_dependencies: set[str]) -> None:
    expected_name = f"nexura_watchdog-{expected_version}-py3-none-any.whl"
    if path.name != expected_name:
        raise ReleaseVerificationError(f"unexpected wheel filename: {path.name}")
    with zipfile.ZipFile(path) as archive:
        if len(archive.infolist()) > 500:
            raise ReleaseVerificationError("wheel member limit exceeded")
        names: set[str] = set()
        total_size = 0
        metadata_name: str | None = None
        license_present = False
        for item in archive.infolist():
            member = str(_safe_archive_name(item.filename))
            mode = item.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ReleaseVerificationError("wheel contains a symbolic link")
            if item.date_time != _RELEASE_ZIP_DATETIME:
                raise ReleaseVerificationError("wheel member has a non-release timestamp")
            if member in names:
                raise ReleaseVerificationError("wheel repeats an archive member")
            total_size += item.file_size
            if item.file_size > 5_000_000 or total_size > 20_000_000:
                raise ReleaseVerificationError("wheel content size limit exceeded")
            names.add(member)
            if member.endswith(".dist-info/METADATA"):
                metadata_name = member
            if member.endswith(".dist-info/licenses/LICENSE"):
                license_present = True
        if not _REQUIRED_WHEEL_ASSETS.issubset(names):
            raise ReleaseVerificationError("wheel omits guided or legacy interface assets")
        if not _REQUIRED_WHEEL_TUI_MODULES.issubset(names):
            raise ReleaseVerificationError("wheel omits local TUI boundary modules")
        if metadata_name is None or not license_present:
            raise ReleaseVerificationError("wheel omits metadata or Apache license")
        _verify_metadata(archive.read(metadata_name), expected_version, expected_dependencies)


def _verify_sdist(path: Path, expected_version: str, expected_dependencies: set[str]) -> None:
    expected_name = f"nexura_watchdog-{expected_version}.tar.gz"
    if path.name != expected_name:
        raise ReleaseVerificationError(f"unexpected sdist filename: {path.name}")
    prefix = f"nexura_watchdog-{expected_version}/"
    names: set[str] = set()
    metadata: bytes | None = None
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 800:
            raise ReleaseVerificationError("sdist member limit exceeded")
        total_size = 0
        archive_names: set[str] = set()
        for item in members:
            member = str(_safe_archive_name(item.name))
            if not (item.isfile() or item.isdir()):
                raise ReleaseVerificationError("sdist contains a non-file member")
            expected_mode = 0o644 if item.isfile() else 0o755
            if (
                item.mtime != _RELEASE_EPOCH
                or item.uid != 0
                or item.gid != 0
                or item.uname
                or item.gname
                or item.mode != expected_mode
            ):
                raise ReleaseVerificationError("sdist member metadata is not normalized")
            if member in archive_names:
                raise ReleaseVerificationError("sdist repeats an archive member")
            archive_names.add(member)
            total_size += item.size
            if item.size > 5_000_000 or total_size > 50_000_000:
                raise ReleaseVerificationError("sdist content size limit exceeded")
            if member == prefix.removesuffix("/"):
                continue
            if not member.startswith(prefix):
                raise ReleaseVerificationError("sdist member is outside the package prefix")
            relative = member.removeprefix(prefix)
            if relative:
                names.add(relative)
            if relative == "PKG-INFO":
                extracted = archive.extractfile(item)
                if extracted is None:
                    raise ReleaseVerificationError("sdist PKG-INFO is unreadable")
                metadata = extracted.read(1_000_001)
                if len(metadata) > 1_000_000:
                    raise ReleaseVerificationError("sdist PKG-INFO exceeds its bound")
    if not _REQUIRED_SDIST_FILES.issubset(names):
        missing = sorted(_REQUIRED_SDIST_FILES - names)
        raise ReleaseVerificationError(f"sdist omits release files: {missing}")
    if metadata is None:
        raise ReleaseVerificationError("sdist omits PKG-INFO")
    _verify_metadata(metadata, expected_version, expected_dependencies)


def verify_distribution(dist_dir: Path, expected_version: str) -> None:
    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ReleaseVerificationError("dist must contain exactly one wheel and one sdist")
    expected_dependencies = _direct_dependency_names(_project(_ROOT))
    _verify_wheel(wheels[0], expected_version, expected_dependencies)
    _verify_sdist(sdists[0], expected_version, expected_dependencies)


def verify_repository(root: Path, expected_version: str, *, tag: str | None = None) -> None:
    if _STABLE_VERSION.fullmatch(expected_version) is None:
        raise ReleaseVerificationError("expected version is not stable SemVer")
    project = _project(root)
    project_version = project.get("version")
    if project_version != expected_version or _module_version(root) != expected_version:
        raise ReleaseVerificationError("project and module versions do not agree")
    if project.get("license") != "Apache-2.0":
        raise ReleaseVerificationError("project license metadata is not Apache-2.0")
    if f"## [{expected_version}]" not in (root / "CHANGELOG.md").read_text(encoding="utf-8"):
        raise ReleaseVerificationError("changelog omits the release version")
    if tag is not None and tag != f"v{expected_version}":
        raise ReleaseVerificationError("tag does not exactly match the package version")
    _verify_locks(root, project)
    _verify_workflows(root)
    _verify_container(root)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify trusted Watchdog release inputs.")
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--tag")
    parser.add_argument("--dist-dir", type=Path)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    namespace = _parser().parse_args(arguments)
    try:
        verify_repository(_ROOT, namespace.expected_version, tag=namespace.tag)
        if namespace.dist_dir is not None:
            verify_distribution(namespace.dist_dir.resolve(), namespace.expected_version)
    except (OSError, ReleaseVerificationError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"release verification failed: {exc}")
        return 1
    print(f"release verification passed: v{namespace.expected_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
