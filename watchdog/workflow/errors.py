class WorkflowError(RuntimeError):
    code = "workflow_failed"


class WorkflowTimeoutError(WorkflowError):
    code = "workflow_timed_out"


class WorkflowCancelledError(WorkflowError):
    code = "workflow_cancelled"


class WorkflowCleanupError(WorkflowError):
    code = "workflow_cleanup_failed"


class WorkflowObserverError(WorkflowError):
    code = "workflow_observer_failed"


class RemediationDisabledError(WorkflowError):
    code = "remediation_disabled"
