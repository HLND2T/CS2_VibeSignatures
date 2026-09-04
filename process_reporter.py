"""Domain models and backend abstraction for process reporting."""

import secrets
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Protocol


class RunStatus(str, Enum):
    QUEUED = "queued"
    STARTING = "starting"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ABORTED = "aborted"
    STALE = "stale"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    ABORTED = "aborted"


class ProcessPhase(str, Enum):
    PREFLIGHT = "preflight"
    WAITING_FOR_MCP = "waiting_for_mcp"
    VALIDATING_BINARY = "validating_binary"
    VALIDATING_INPUTS = "validating_inputs"
    PREPROCESSING = "preprocessing"
    VALIDATING_OUTPUTS = "validating_outputs"
    AGENT_FALLBACK = "agent_fallback"
    VCALL_EXPORT = "vcall_export"
    POSTPROCESSING = "postprocessing"
    FINISHED = "finished"


class ProcessEventType(str, Enum):
    RUN_INITIALIZED = "run.initialized"
    RUN_STATUS_CHANGED = "run.status_changed"
    TASK_STATUS_CHANGED = "task.status_changed"
    SKILL_PROGRESS = "skill.progress"
    HEARTBEAT = "heartbeat"


class ProcessReason(str, Enum):
    EXISTING_OUTPUTS = "existing_outputs"
    SKIP_IF_EXISTS = "skip_if_exists"
    PLATFORM_MISMATCH = "platform_mismatch"
    MISSING_BINARY = "missing_binary"
    MISSING_INPUT = "missing_input"
    INVALID_INPUT = "invalid_input"
    INVALID_OUTPUT = "invalid_output"
    PREPROCESS_ABSENT = "preprocess_absent"
    OPTIONAL_OUTPUT_ABSENT = "optional_output_absent"
    PREPROCESS_FAILED = "preprocess_failed"
    AGENT_FAILED = "agent_failed"
    MCP_UNAVAILABLE = "mcp_unavailable"
    BINARY_VERIFICATION_FAILED = "binary_verification_failed"
    UPSTREAM_ABORTED = "upstream_aborted"
    GRAPH_INVALID = "graph_invalid"
    UNKNOWN_ERROR = "unknown_error"


class EdgeType(str, Enum):
    ARTIFACT = "artifact"
    OPTIONAL_INPUT = "optional_input"
    PREREQUISITE = "prerequisite"
    ALTERNATIVE_ORDER = "alternative_order"
    CROSS_STAGE_ARTIFACT = "cross_stage_artifact"
    STAGE_ORDER = "stage_order"


class PlanNodeType(str, Enum):
    SKILL = "skill"
    VCALL_TARGET = "vcall_target"
    POST_PROCESS = "post_process"


@dataclass(frozen=True)
class SkillEdge:
    source: str
    target: str
    edge_type: EdgeType
    artifact: str | None = None


@dataclass(frozen=True)
class SkillGraph:
    nodes: dict[str, dict[str, Any]]
    edges: list[SkillEdge]
    order: list[str]
    layers: dict[str, int]
    cycles: list[list[str]]
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ExecutionStage:
    id: str
    stage_index: int
    module_name: str
    description: str | None = None


@dataclass(frozen=True)
class ExecutionJob:
    id: str
    stage_id: str
    stage_index: int
    module_name: str
    platform: str
    binary_path: str | None


@dataclass(frozen=True)
class ExecutionNode:
    id: str
    job_id: str
    stage_id: str
    name: str
    node_type: PlanNodeType
    order: int
    layer: int
    description: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExecutionEdge:
    source: str
    target: str
    edge_type: EdgeType
    artifact: str | None = None


@dataclass(frozen=True)
class ExecutionPlan:
    stages: list[ExecutionStage] = field(default_factory=list)
    jobs: list[ExecutionJob] = field(default_factory=list)
    nodes: list[ExecutionNode] = field(default_factory=list)
    edges: list[ExecutionEdge] = field(default_factory=list)
    warnings: list[str | ProcessReason] = field(default_factory=list)
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Return the stable JSON-compatible API representation."""
        return _serialize(asdict(self))


@dataclass(frozen=True)
class ProcessEvent:
    run_id: str
    event_type: ProcessEventType
    task_id: str | None = None
    status: RunStatus | TaskStatus | None = None
    phase: ProcessPhase | None = None
    reason: ProcessReason | str | None = None
    message: str | None = None
    error: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    occurred_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


class ProcessReporter(Protocol):
    def initialize_run(self, plan: dict[str, Any], run_id: str | None = None) -> str: ...

    def emit(self, event: ProcessEvent) -> None: ...

    def heartbeat(self, run_id: str) -> None: ...

    def finalize_run(self, run_id: str, status: RunStatus, summary: dict[str, int]) -> None: ...

    def flush(self) -> None: ...

    def close(self) -> None: ...


class ProcessReporterError(RuntimeError):
    """Base error raised by process reporter implementations."""


class ProcessReporterConfigurationError(ProcessReporterError):
    """Raised when the configured reporter backend cannot be constructed."""


class NullProcessReporter:
    """Default reporter that preserves the existing local CLI behavior."""

    def initialize_run(self, plan: dict[str, Any], run_id: str | None = None) -> str:
        del plan
        return run_id or generate_run_id()

    def emit(self, event: ProcessEvent) -> None:
        del event

    def heartbeat(self, run_id: str) -> None:
        del run_id

    def finalize_run(self, run_id: str, status: RunStatus, summary: dict[str, int]) -> None:
        del run_id, status, summary

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


class BestEffortProcessReporter:
    """Prevent observability failures from changing Analyzer results."""

    def __init__(self, delegate: ProcessReporter, warning_callback: Callable[[str], None] = print):
        self._delegate = delegate
        self._warning_callback = warning_callback

    def _call(self, method_name: str, *args):
        try:
            return getattr(self._delegate, method_name)(*args)
        except Exception as exc:
            self._warning_callback(f"Warning: Process reporter {method_name} failed: {exc}")
            return None

    def initialize_run(self, plan: dict[str, Any], run_id: str | None = None) -> str:
        initialized_run_id = self._call("initialize_run", plan, run_id)
        return initialized_run_id or run_id or generate_run_id()

    def emit(self, event: ProcessEvent) -> None:
        self._call("emit", event)

    def heartbeat(self, run_id: str) -> None:
        self._call("heartbeat", run_id)

    def finalize_run(self, run_id: str, status: RunStatus, summary: dict[str, int]) -> None:
        self._call("finalize_run", run_id, status, summary)

    def flush(self) -> None:
        self._call("flush")

    def close(self) -> None:
        self._call("close")


def _serialize(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {key: _serialize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialize(item) for item in value]
    return value


_CROCKFORD_BASE32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def generate_run_id() -> str:
    """Generate a dependency-free ULID-compatible run identifier."""
    value = (int(time.time() * 1000) << 80) | secrets.randbits(80)
    encoded = []
    for _ in range(26):
        value, remainder = divmod(value, 32)
        encoded.append(_CROCKFORD_BASE32[remainder])
    return "".join(reversed(encoded))


def _validate_id_part(value: object, label: str) -> str:
    normalized = str(value).strip()
    if not normalized or "/" in normalized:
        raise ValueError(f"{label} must be non-empty and cannot contain '/'")
    return normalized


def build_stage_id(stage_index: int, module_name: str) -> str:
    """Build an ID that remains unique when module names repeat."""
    if stage_index < 0:
        raise ValueError("stage_index must be non-negative")
    return f"stage-{stage_index:04d}-{_validate_id_part(module_name, 'module_name')}"


def build_job_id(stage_id: str, platform: str) -> str:
    return f"{_validate_id_part(stage_id, 'stage_id')}-{_validate_id_part(platform, 'platform')}"


def build_task_id(job_id: str, task_name: str) -> str:
    return f"{_validate_id_part(job_id, 'job_id')}/{_validate_id_part(task_name, 'task_name')}"


def build_vcall_task_id(job_id: str, target_name: str) -> str:
    job_part = _validate_id_part(job_id, "job_id")
    return f"{job_part}/vcall/{_validate_id_part(target_name, 'target_name')}"


def build_post_process_task_id(job_id: str) -> str:
    return f"{_validate_id_part(job_id, 'job_id')}/post-process"


_TASK_TRANSITIONS = {
    TaskStatus.PENDING: {
        TaskStatus.RUNNING,
        TaskStatus.SKIPPED,
        TaskStatus.ABORTED,
    },
    TaskStatus.RUNNING: {
        TaskStatus.SUCCEEDED,
        TaskStatus.FAILED,
        TaskStatus.SKIPPED,
        TaskStatus.ABORTED,
    },
}

_RUN_TRANSITIONS = {
    RunStatus.QUEUED: {RunStatus.STARTING, RunStatus.FAILED, RunStatus.ABORTED},
    RunStatus.STARTING: {RunStatus.RUNNING, RunStatus.FAILED, RunStatus.ABORTED, RunStatus.STALE},
    RunStatus.RUNNING: {RunStatus.SUCCEEDED, RunStatus.FAILED, RunStatus.ABORTED, RunStatus.STALE},
    RunStatus.STALE: {RunStatus.RUNNING, RunStatus.FAILED, RunStatus.ABORTED},
}


def is_valid_task_transition(current: TaskStatus, target: TaskStatus) -> bool:
    """Accept idempotent writes and reject transitions out of terminal states."""
    return current == target or target in _TASK_TRANSITIONS.get(current, set())


def is_valid_run_transition(current: RunStatus, target: RunStatus) -> bool:
    """Accept idempotent writes and allow a stale run to recover."""
    return current == target or target in _RUN_TRANSITIONS.get(current, set())
