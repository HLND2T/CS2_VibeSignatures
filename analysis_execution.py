"""Local execution plans and evidence for Analyzer and platform workers."""

import os
import secrets
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    ABORTED = "aborted"


class ExecutionReason(str, Enum):
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
    warnings: list[str | ExecutionReason] = field(default_factory=list)
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-compatible execution plan."""
        return _serialize(asdict(self))


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


def is_valid_task_transition(current: TaskStatus, target: TaskStatus) -> bool:
    """Accept idempotent writes and reject transitions out of terminal states."""
    return current == target or target in _TASK_TRANSITIONS.get(current, set())


class AnalysisExecutionState:
    """Keep local task lifecycle and artifact evidence for execution contracts."""

    def __init__(self, run_id: str, plan: ExecutionPlan):
        self.run_id = run_id
        self.plan = plan
        self._node_ids = {node.id for node in plan.nodes}
        self._nodes_by_job = {job.id: [] for job in plan.jobs}
        for node in plan.nodes:
            self._nodes_by_job[node.job_id].append(node.id)
        self._states = {task_id: TaskStatus.PENDING for task_id in self._node_ids}
        self._states.update({job.id: TaskStatus.PENDING for job in plan.jobs})
        self._attempted = set()
        self._output_attempts = {task_id: set() for task_id in self._node_ids}
        self._output_produced = {task_id: set() for task_id in self._node_ids}
        self._terminal_details = {}

    def record_task_status(
        self,
        task_id: str,
        status: TaskStatus,
        *,
        attempted: bool = False,
        reason: ExecutionReason | None = None,
        error: str | None = None,
        payload: dict | None = None,
    ) -> None:
        current = self._states.get(task_id, TaskStatus.PENDING)
        terminal_statuses = {
            TaskStatus.SUCCEEDED,
            TaskStatus.FAILED,
            TaskStatus.SKIPPED,
            TaskStatus.ABORTED,
        }
        if current in terminal_statuses:
            return
        if not is_valid_task_transition(current, status):
            return
        if task_id in self._node_ids and status == TaskStatus.RUNNING and attempted:
            self._attempted.add(task_id)
        self._states[task_id] = status
        if status in terminal_statuses and task_id in self._node_ids:
            self._terminal_details[task_id] = {
                "reason": reason.value if isinstance(reason, ExecutionReason) else reason,
                "error": error,
                "payload": payload or {},
            }

    def abort_job_tasks(self, job_id: str, reason: ExecutionReason) -> None:
        self.finish_job_tasks(job_id, TaskStatus.ABORTED, reason)

    def finish_job_tasks(
        self,
        job_id: str,
        status: TaskStatus,
        reason: ExecutionReason,
    ) -> None:
        self.finish_tasks(self._nodes_by_job.get(job_id, []), status, reason)

    def finish_tasks(self, task_ids, status: TaskStatus, reason: ExecutionReason) -> None:
        for task_id in task_ids:
            self.record_task_status(task_id, status, reason=reason)

    def abort_pending(self, reason: ExecutionReason) -> None:
        for task_id in list(self._states):
            self.record_task_status(task_id, TaskStatus.ABORTED, reason=reason)

    def summary(self) -> dict[str, int]:
        counts = {status.value: 0 for status in TaskStatus}
        for task_id in self._node_ids:
            counts[self._states[task_id].value] += 1
        counts["total"] = len(self._node_ids)
        return counts

    def record_output_attempts(self, task_id: str, paths) -> None:
        if task_id in self._output_attempts:
            self._output_attempts[task_id].update(os.fspath(path) for path in paths)

    def record_output_produced(self, task_id: str, paths) -> None:
        if task_id in self._output_produced:
            self._output_produced[task_id].update(os.fspath(path) for path in paths)

    def task_record(self, task_id: str) -> dict:
        details = self._terminal_details.get(task_id, {})
        return {
            "task_id": task_id,
            "status": self._states.get(task_id, TaskStatus.PENDING).value,
            "attempted": task_id in self._attempted,
            "reason": details.get("reason"),
            "error": details.get("error"),
            "payload": details.get("payload", {}),
            "attempted_outputs": sorted(self._output_attempts.get(task_id, set())),
            "produced_outputs": sorted(self._output_produced.get(task_id, set())),
        }

    def import_task_record(self, record: dict) -> None:
        """Restore a validated platform worker's terminal evidence."""
        task_id = record["task_id"]
        if task_id not in self._states:
            raise ValueError(f"Unknown worker task: {task_id}")
        status = TaskStatus(record["status"])
        self.record_task_status(task_id, TaskStatus.RUNNING, attempted=True)
        if not record["attempted"]:
            self._attempted.discard(task_id)
        self.record_output_attempts(task_id, record["attempted_outputs"])
        self.record_output_produced(task_id, record["produced_outputs"])
        self.record_task_status(
            task_id,
            status,
            reason=record["reason"],
            error=record["error"],
            payload=record["payload"],
        )
