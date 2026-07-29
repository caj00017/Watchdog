from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Never

from pydantic import ValidationError

from watchdog.config import Settings
from watchdog.domain.errors import (
    AdvisoryNotFoundError,
    InvalidIdentifierError,
    MalformedSourceResponseError,
    SourceUnavailableError,
)
from watchdog.domain.remediation import RemediationPlanStatus, RemediationWorkflowRequest
from watchdog.domain.reports import (
    InvestigationWorkflowRequest,
    ReportFormat,
    ReportStatus,
    ReportView,
)
from watchdog.domain.repositories import RepositoryRequest
from watchdog.remediation.assembler import RemediationAssemblyError
from watchdog.remediation.candidates import CandidateDerivationError
from watchdog.remediation.preview import PreviewCollectionError
from watchdog.remediation.report_json import RemediationRenderError
from watchdog.reporting.assembler import ReportAssemblyError
from watchdog.reporting.report_json import ReportRenderError
from watchdog.repository.errors import (
    InvalidRepositoryRefError,
    InvalidRepositoryUrlError,
    RepositoryIntakeError,
)
from watchdog.workflow.errors import (
    RemediationDisabledError,
    WorkflowCancelledError,
    WorkflowCleanupError,
    WorkflowTimeoutError,
)
from watchdog.workflow.runtime import workflow_runtime


class CliUsageError(ValueError):
    pass


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> Never:
        raise CliUsageError


def _parser() -> SafeArgumentParser:
    parser = SafeArgumentParser(prog="python -m apps.cli", add_help=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    investigate = subparsers.add_parser("investigate")
    investigate.add_argument("--advisory", required=True)
    investigate.add_argument("--repository", required=True)
    investigate.add_argument("--ref")
    investigate.add_argument(
        "--view", choices=tuple(item.value for item in ReportView), default="summary"
    )
    investigate.add_argument(
        "--format", choices=tuple(item.value for item in ReportFormat), default="json"
    )
    remediate = subparsers.add_parser("remediate")
    remediate.add_argument("--advisory", required=True)
    remediate.add_argument("--repository", required=True)
    remediate.add_argument("--ref")
    remediate.add_argument(
        "--view", choices=tuple(item.value for item in ReportView), default="summary"
    )
    remediate.add_argument(
        "--format", choices=tuple(item.value for item in ReportFormat), default="json"
    )
    return parser


def _diagnostic(code: str, message: str) -> None:
    sys.stderr.write(f"{code}: {message}\n")


async def _investigate(namespace: argparse.Namespace) -> int:
    try:
        request = InvestigationWorkflowRequest(
            advisory_identifier=namespace.advisory,
            repository=RepositoryRequest(
                repository_url=namespace.repository,
                ref=namespace.ref,
            ),
            view=ReportView(namespace.view),
            format=ReportFormat(namespace.format),
        )
    except ValidationError:
        _diagnostic("invalid_request", "The investigation request is invalid.")
        return 2

    try:
        async with workflow_runtime(Settings()) as runtime:
            rendered = await runtime.workflow.run_rendered(request, runtime.renderer)
    except (
        InvalidIdentifierError,
        InvalidRepositoryUrlError,
        InvalidRepositoryRefError,
    ):
        _diagnostic("invalid_request", "The investigation request is invalid.")
        return 2
    except (ReportAssemblyError, ReportRenderError):
        _diagnostic("report_failed", "The validated report could not be produced.")
        return 1
    except (AdvisoryNotFoundError, SourceUnavailableError, MalformedSourceResponseError):
        _diagnostic("upstream_failure", "The advisory source did not produce a usable record.")
        return 3
    except RepositoryIntakeError as exc:
        if exc.code == "repository_cleanup_failed":
            _diagnostic("cleanup_failed", "Repository cleanup could not be verified.")
            return 1
        _diagnostic(
            "repository_failure", "The repository source did not produce a usable snapshot."
        )
        return 3
    except (WorkflowTimeoutError, WorkflowCancelledError):
        _diagnostic("workflow_stopped", "The workflow stopped after repository cleanup.")
        return 5
    except WorkflowCleanupError:
        _diagnostic("cleanup_failed", "Repository cleanup could not be verified.")
        return 1
    except ValidationError:
        _diagnostic("workflow_failed", "The investigation failed validation internally.")
        return 1
    except Exception:
        _diagnostic("workflow_failed", "The investigation failed without producing a report.")
        return 1

    try:
        sys.stdout.buffer.write(rendered.body)
        sys.stdout.buffer.flush()
    except (BrokenPipeError, OSError):
        return 1
    return 4 if rendered.status is ReportStatus.INCOMPLETE else 0


async def _remediate(namespace: argparse.Namespace) -> int:
    try:
        request = RemediationWorkflowRequest(
            advisory_identifier=namespace.advisory,
            repository=RepositoryRequest(
                repository_url=namespace.repository,
                ref=namespace.ref,
            ),
            view=ReportView(namespace.view),
            format=ReportFormat(namespace.format),
        )
    except ValidationError:
        _diagnostic("invalid_request", "The remediation request is invalid.")
        return 2

    try:
        async with workflow_runtime(Settings()) as runtime:
            if runtime.remediation_workflow is None or runtime.remediation_renderer is None:
                raise RemediationDisabledError("remediation runtime is unavailable")
            rendered = await runtime.remediation_workflow.run_rendered(
                request, runtime.remediation_renderer
            )
    except RemediationDisabledError:
        _diagnostic("remediation_disabled", "The remediation feature is disabled.")
        return 6
    except (
        InvalidIdentifierError,
        InvalidRepositoryUrlError,
        InvalidRepositoryRefError,
    ):
        _diagnostic("invalid_request", "The remediation request is invalid.")
        return 2
    except (AdvisoryNotFoundError, SourceUnavailableError, MalformedSourceResponseError):
        _diagnostic("upstream_failure", "The advisory source did not produce a usable record.")
        return 3
    except RepositoryIntakeError as exc:
        if exc.code == "repository_cleanup_failed":
            _diagnostic("cleanup_failed", "Repository cleanup could not be verified.")
            return 1
        _diagnostic(
            "repository_failure", "The repository source did not produce a usable snapshot."
        )
        return 3
    except (WorkflowTimeoutError, WorkflowCancelledError):
        _diagnostic("workflow_stopped", "The workflow stopped after repository cleanup.")
        return 5
    except WorkflowCleanupError:
        _diagnostic("cleanup_failed", "Repository cleanup could not be verified.")
        return 1
    except (
        CandidateDerivationError,
        PreviewCollectionError,
        RemediationAssemblyError,
        RemediationRenderError,
        ValidationError,
    ):
        _diagnostic("remediation_failed", "The validated remediation plan could not be produced.")
        return 1
    except Exception:
        _diagnostic("workflow_failed", "The remediation workflow failed without producing a plan.")
        return 1

    try:
        sys.stdout.buffer.write(rendered.body)
        sys.stdout.buffer.flush()
    except (BrokenPipeError, OSError):
        return 1
    return (
        0
        if rendered.status
        in {
            RemediationPlanStatus.CANDIDATES_AVAILABLE,
            RemediationPlanStatus.PREVIEWS_AVAILABLE,
        }
        else 4
    )


async def _async_main(arguments: list[str]) -> int:
    try:
        namespace = _parser().parse_args(arguments)
    except CliUsageError:
        _diagnostic("invalid_arguments", "The command arguments are invalid.")
        return 2
    if namespace.command == "investigate":
        return await _investigate(namespace)
    if namespace.command == "remediate":
        return await _remediate(namespace)
    _diagnostic("invalid_arguments", "The command arguments are invalid.")
    return 2


def main() -> int:
    return asyncio.run(_async_main(sys.argv[1:]))


if __name__ == "__main__":
    raise SystemExit(main())
