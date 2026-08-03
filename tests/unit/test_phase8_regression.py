from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path

from tests.report_fixtures import build_report
from watchdog.domain.reports import ReportFormat, ReportView
from watchdog.reporting.renderers import ReportRenderer

_PHASE7_REPORT_ID = "report:sha256:675ff4aa38cbfd775d3ceb6d40e57c947929dbff5f31f740d67ffba9374e180a"
_PHASE7_RENDER_SHA256 = {
    (ReportView.SUMMARY, ReportFormat.JSON): (
        "8ca79fdc0a04f8be6c053162d8a27646639a6adb37af010df785bedb7b89d3f6"
    ),
    (ReportView.SUMMARY, ReportFormat.MARKDOWN): (
        "f60c09ea149364b7d594c6bdaab8e5300a4e5e99f512025e115951e024d30929"
    ),
    (ReportView.TECHNICAL, ReportFormat.JSON): (
        "f03b949cd06e4d34300b3ca8be02f48682f7298d31e94303d383cfdad42aecb9"
    ),
    (ReportView.TECHNICAL, ReportFormat.MARKDOWN): (
        "db7be558343c0fff7ebb01fa3c9d5b5b4bdca8f11f4cc2f9cb00c64bcd9c6735"
    ),
}


async def test_phase7_report_identity_and_rendered_bytes_remain_frozen(
    tmp_path: Path,
) -> None:
    report, configuration, _investigation = await build_report(tmp_path)
    renderer = ReportRenderer(configuration)

    assert report.id == _PHASE7_REPORT_ID
    for (view, format), expected in _PHASE7_RENDER_SHA256.items():
        rendered = renderer.render(report, view=view, format=format)
        assert hashlib.sha256(rendered.body).hexdigest() == expected


def test_release_one_tui_adds_only_reviewed_runtime_dependency_and_keeps_scanner_pin() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text())
    dockerfile = Path("Dockerfile").read_text()
    scanner = Path("watchdog/scanners/osv_scanner.py").read_text()

    assert project["project"]["dependencies"] == [
        "fastapi>=0.115,<1",
        "httpx>=0.27,<1",
        "packaging>=24.2,<26",
        "pydantic>=2.10,<3",
        "pydantic-settings>=2.7,<3",
        "textual>=8.2.8,<9",
        "uvicorn[standard]>=0.34,<1",
    ]
    assert "ghcr.io/google/osv-scanner:v2.4.0@sha256:" in dockerfile
    assert 'OSV_SCANNER_VERSION = "2.4.0"' in scanner
