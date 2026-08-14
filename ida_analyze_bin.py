#!/usr/bin/env python3
"""
IDA Binary Analysis Script for CS2_VibeSignatures

Analyzes CS2 binary files using IDA Pro MCP and Claude, Codex, or OpenCode agents.
Sequentially processes modules and symbols defined in configs/<GAMEVER>.yaml.

Usage:
    python ida_analyze_bin.py -gamever=14134 [-platform=windows,linux] [-skill=SKILL]
        [-agent=claude/codex/opencode] [-agent_model=MODEL]

    -gamever: Game version subdirectory name (required)
    -oldgamever: Old game version for signature reuse (default: gamever - 1)
    -configyaml: Analysis config path (default: configs/<GAMEVER>.yaml)
    -bindir: Directory containing downloaded binaries (default: bin)
    -platform: Platforms to analyze, comma-separated (default: windows,linux)
    -skill: Exact skill name to run; all other skills are skipped
    -agent: Agent to use for analysis: claude, codex, or opencode (default: claude)
    -agent_model: Optional model override; OpenCode requires provider/model format
    -ida_args: Additional arguments for idalib-mcp (optional)
    -debug: Enable debug output
    -skip_error: Continue analysis after skill or preprocessor failures
    -skip_pp: Skip preprocessing scripts and run Agent Skills directly

Requirements:
    uv sync
    uv (for running idalib-mcp)
    claude CLI, codex CLI, or opencode CLI

Output:
    bin/14134/engine/CServerSideClient_IsHearingClient.linux.yaml
    bin/14134/engine/CServerSideClient_IsHearingClient.windows.yaml
    ...and more
"""

import argparse
import inspect
import json
import os
import posixpath
import socket
import subprocess
import sys
import time

from binary_hashing import hash_file
from pathlib import Path

from dotenv import load_dotenv

from agent_runner import DEFAULT_AGENT_MODEL, run_skill
from analysis_config import AnalysisConfigError, resolve_analysis_config

try:
    import yaml
    import asyncio
    from mcp.types import TextContent
except ImportError as e:
    print(f"Error: Missing required dependency: {e.name}")
    print("Please install required dependencies with: uv sync")
    sys.exit(1)

from ida_skill_preprocessor import (
    PREPROCESS_STATUS_ABSENT_OK,
    PREPROCESS_STATUS_FAILED,
    PREPROCESS_STATUS_NO_SCRIPT,
    PREPROCESS_STATUS_SUCCESS,
    preprocess_single_skill_via_mcp,
    report_preprocess_exception,
)
from ida_mcp_session import (
    McpConnectionError,
    McpContractError,
    McpDatabaseSelectionError,
    McpDatabaseUnavailableError,
    McpToolCallError,
    check_ida_mcp_supervisor_health,
    normalize_binary_identity_path,
    open_ida_mcp_session,
)
from ida_vcall_finder import (
    aggregate_vcall_results_for_object,
    export_object_xref_details_via_mcp,
)
from process_reporter import (
    BestEffortProcessReporter,
    EdgeType,
    ExecutionEdge,
    ExecutionJob,
    ExecutionNode,
    ExecutionPlan,
    ExecutionStage,
    PlanNodeType,
    ProcessEvent,
    ProcessEventType,
    ProcessPhase,
    ProcessReason,
    ProcessReporter,
    ProcessReporterConfigurationError,
    RunStatus,
    SkillEdge,
    SkillGraph,
    TaskStatus,
    build_job_id,
    build_post_process_task_id,
    build_stage_id,
    build_task_id,
    build_vcall_task_id,
    is_valid_task_transition,
)
from process_reporter_factory import create_process_reporter
from trusted_yaml import load_yaml, load_yaml_file

load_dotenv()

DEFAULT_DOWNLOAD_FILE = "download.yaml"
DEFAULT_BIN_DIR = "bin"
DEFAULT_PLATFORM = "windows,linux"
DEFAULT_MODULES = "*"
DEFAULT_AGENT = "claude"
DEFAULT_LLM_MODEL = "gpt-4o"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13337
POST_PROCESS_FUNC_RENAME_BATCH_SIZE = 50
MCP_STARTUP_TIMEOUT = 1200  # seconds to wait for MCP server
MCP_SHUTDOWN_TIMEOUT = 10.0
QEXIT_CONNECTION_RESET_MARKER = "[WinError 10054]"
OPENED_BINARY_VERIFY_TIMEOUT = 60.0
OPENED_BINARY_VERIFY_RETRY_INTERVAL = 2.0
_BINARY_HASH_CACHE = {}
_PE_STYLE_BASE_ADDRESS = 0x180000000


class McpRecoveryBudget:
    """Limit lifecycle-owner MCP restarts for one binary processing run."""

    def __init__(self, restart_limit=1):
        self.remaining_restarts = max(0, int(restart_limit))

    def consume_restart(self):
        if self.remaining_restarts <= 0:
            return False
        self.remaining_restarts -= 1
        return True


class AnalysisReporting:
    """Track local lifecycle state while forwarding events to a reporter backend."""

    def __init__(self, reporter: ProcessReporter, run_id: str, plan: ExecutionPlan):
        self.reporter = (
            reporter if isinstance(reporter, BestEffortProcessReporter) else BestEffortProcessReporter(reporter)
        )
        self.run_id = run_id
        self._node_ids = {node.id for node in plan.nodes}
        self._nodes_by_job = {job.id: [] for job in plan.jobs}
        for node in plan.nodes:
            self._nodes_by_job[node.job_id].append(node.id)
        self._states = {task_id: TaskStatus.PENDING for task_id in self._node_ids}
        self._states.update({job.id: TaskStatus.PENDING for job in plan.jobs})

    def emit_run_status(self, status: RunStatus, *, message: str | None = None) -> None:
        self.reporter.emit(
            ProcessEvent(
                run_id=self.run_id,
                event_type=ProcessEventType.RUN_STATUS_CHANGED,
                status=status,
                message=message,
            )
        )

    def emit_task_status(
        self,
        task_id: str,
        status: TaskStatus,
        phase: ProcessPhase,
        *,
        reason: ProcessReason | None = None,
        message: str | None = None,
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
        self.reporter.emit(
            ProcessEvent(
                run_id=self.run_id,
                event_type=ProcessEventType.TASK_STATUS_CHANGED,
                task_id=task_id,
                status=status,
                phase=phase,
                reason=reason,
                message=message,
                error=error,
                payload=payload or {},
            )
        )
        self._states[task_id] = status

    def emit_agent_progress(self, task_id: str, **progress) -> None:
        self.reporter.emit(
            ProcessEvent(
                run_id=self.run_id,
                event_type=ProcessEventType.SKILL_PROGRESS,
                task_id=task_id,
                status=TaskStatus.RUNNING,
                phase=ProcessPhase.AGENT_FALLBACK,
                payload=progress,
            )
        )

    def abort_job_tasks(self, job_id: str, reason: ProcessReason, message: str) -> None:
        self.finish_job_tasks(job_id, TaskStatus.ABORTED, reason, message)

    def finish_job_tasks(
        self,
        job_id: str,
        status: TaskStatus,
        reason: ProcessReason,
        message: str,
    ) -> None:
        self.finish_tasks(self._nodes_by_job.get(job_id, []), status, reason, message)

    def finish_tasks(self, task_ids, status: TaskStatus, reason: ProcessReason, message: str) -> None:
        for task_id in task_ids:
            self.emit_task_status(task_id, status, ProcessPhase.FINISHED, reason=reason, message=message)

    def abort_pending(self, reason: ProcessReason, message: str) -> None:
        for task_id in list(self._states):
            self.emit_task_status(task_id, TaskStatus.ABORTED, ProcessPhase.FINISHED, reason=reason, message=message)

    def summary(self) -> dict[str, int]:
        counts = {status.value: 0 for status in TaskStatus}
        for task_id in self._node_ids:
            counts[self._states[task_id].value] += 1
        counts["total"] = len(self._node_ids)
        return counts


def _absolute_path_preserve_spelling(path):
    """Make a local path absolute without resolving 8.3 names or junction targets."""
    return os.path.abspath(os.path.normpath(os.fspath(path)))


SURVEY_CURRENT_IDB_PATH_PY_EVAL = (
    "import json\n"
    "path = ''\n"
    "input_sha256 = ''\n"
    "try:\n"
    "    import idaapi\n"
    "    path = idaapi.get_path(idaapi.PATH_TYPE_IDB) or ''\n"
    "except Exception:\n"
    "    pass\n"
    "if not path:\n"
    "    try:\n"
    "        import idc\n"
    "        path = idc.get_idb_path() or ''\n"
    "    except Exception:\n"
    "        pass\n"
    "try:\n"
    "    import ida_nalt\n"
    "    raw_sha256 = ida_nalt.retrieve_input_file_sha256()\n"
    "    if isinstance(raw_sha256, (bytes, bytearray)):\n"
    "        input_sha256 = bytes(raw_sha256).hex()\n"
    "    elif isinstance(raw_sha256, str):\n"
    "        input_sha256 = raw_sha256.strip()\n"
    "except Exception:\n"
    "    pass\n"
    "metadata = {'path': path}\n"
    "if input_sha256:\n"
    "    metadata['input_sha256'] = input_sha256\n"
    "result = json.dumps({'metadata': metadata})\n"
)


def _parse_tool_json_content(result):
    if not result or not getattr(result, "content", None):
        return None

    item = result.content[0]
    raw = getattr(item, "text", None)
    if not isinstance(raw, str):
        raw = item.text if isinstance(item, TextContent) else str(item)
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def _resolve_config_path(config_path):
    return Path(config_path).expanduser().resolve()


def _artifact_symbol_category_map_from_document(config_data):
    category_map = {}
    for module_entry in config_data.get("modules", []):
        if not isinstance(module_entry, dict):
            continue
        for symbol_entry in module_entry.get("symbols", []):
            if not isinstance(symbol_entry, dict):
                continue
            symbol_name = str(symbol_entry.get("name", "")).strip()
            category = str(symbol_entry.get("category", "")).strip()
            if symbol_name and category and symbol_name not in category_map:
                category_map[symbol_name] = category
    return category_map


def _symbol_alias_map_from_document(config_data):
    aliases = {}
    for module_entry in config_data.get("modules", []):
        if not isinstance(module_entry, dict):
            continue
        for symbol_entry in module_entry.get("symbols", []):
            if not isinstance(symbol_entry, dict):
                continue
            symbol_name = str(symbol_entry.get("name", "")).strip()
            if not symbol_name:
                continue
            values = symbol_entry.get("alias")
            raw_aliases = values if isinstance(values, (list, tuple)) else [values]
            aliases[symbol_name] = tuple(alias for value in raw_aliases if (alias := str(value or "").strip()))
    return aliases


def _load_config_document(config_path):
    return load_yaml_file(_resolve_config_path(config_path), cache=True, copy_result=False) or {}


def _load_artifact_symbol_category_map(config_path):
    try:
        return _artifact_symbol_category_map_from_document(_load_config_document(config_path))
    except Exception:
        return {}


def _load_symbol_alias_map(config_path):
    try:
        return _symbol_alias_map_from_document(_load_config_document(config_path))
    except Exception:
        return {}


def _derive_artifact_symbol_name(artifact_path, platform):
    basename = os.path.basename(str(artifact_path or ""))
    platform_suffix = f".{platform}.yaml"
    if basename.endswith(platform_suffix):
        return basename[: -len(platform_suffix)]
    if basename.endswith(".yaml"):
        return basename[:-5]
    return basename


def _lookup_expected_input_artifact_category(
    artifact_path,
    platform,
    config_path=None,
    category_map=None,
):
    symbol_name = _derive_artifact_symbol_name(artifact_path, platform)
    if not symbol_name:
        return None
    if category_map is None:
        category_map = _load_artifact_symbol_category_map(config_path) if config_path else {}
    return category_map.get(symbol_name)


def _is_current_module_artifact_path(artifact_path, binary_dir):
    """Return whether artifact addresses can be checked in this binary's IDB."""
    if not binary_dir:
        return True

    try:
        artifact_resolved = Path(artifact_path).resolve()
        binary_dir_resolved = Path(binary_dir).resolve()
        return os.path.commonpath([os.fspath(artifact_resolved), os.fspath(binary_dir_resolved)]) == os.fspath(
            binary_dir_resolved
        )
    except (OSError, ValueError):
        return True


def _parse_py_eval_result_json(result):
    payload = _parse_tool_json_content(result)
    if not isinstance(payload, dict):
        return None

    result_text = payload.get("result", "")
    if not isinstance(result_text, str) or not result_text:
        return None

    try:
        parsed = json.loads(result_text)
    except (json.JSONDecodeError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


async def _inspect_func_va_via_session(session, func_va_text):
    py_code = (
        "import ida_funcs, ida_segment, idaapi, json\n"
        f"raw_func_va = {json.dumps(str(func_va_text))}\n"
        "payload = {\n"
        "    'has_segment': False,\n"
        "    'segment_name': '',\n"
        "    'has_function': False,\n"
        "    'function_start': '',\n"
        "    'is_function_start': False,\n"
        "}\n"
        "try:\n"
        "    ea = int(raw_func_va, 0)\n"
        "except Exception:\n"
        "    result = json.dumps(payload)\n"
        "else:\n"
        "    seg = None\n"
        "    try:\n"
        "        seg = ida_segment.getseg(ea)\n"
        "    except Exception:\n"
        "        try:\n"
        "            seg = idaapi.getseg(ea)\n"
        "        except Exception:\n"
        "            seg = None\n"
        "    if seg is not None:\n"
        "        payload['has_segment'] = True\n"
        "        try:\n"
        "            payload['segment_name'] = ida_segment.get_segm_name(seg) or ''\n"
        "        except Exception:\n"
        "            payload['segment_name'] = ''\n"
        "    func = ida_funcs.get_func(ea)\n"
        "    if func is None:\n"
        "        # A valid .text thunk may be left un-analyzed as a bare loc_ (code\n"
        "        # but not a function); promote it so its func_va resolves for\n"
        "        # downstream consumers. add_func no-ops on non-code addresses.\n"
        "        try:\n"
        "            idaapi.add_func(ea)\n"
        "        except Exception:\n"
        "            pass\n"
        "        func = ida_funcs.get_func(ea)\n"
        "    if func is not None:\n"
        "        func_start = int(func.start_ea)\n"
        "        payload['has_function'] = True\n"
        "        payload['function_start'] = hex(func_start)\n"
        "        payload['is_function_start'] = (func_start == ea)\n"
        "    result = json.dumps(payload)\n"
    )
    try:
        eval_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
    except Exception:
        return None
    return _parse_py_eval_result_json(eval_result)


async def validate_expected_input_artifacts_via_session(
    session,
    expected_inputs,
    platform,
    binary_dir=None,
    debug=False,
    config_path=None,
    category_map=None,
):
    invalid_artifacts = []

    for artifact_path in expected_inputs or []:
        category = _lookup_expected_input_artifact_category(
            artifact_path,
            platform,
            config_path=config_path,
            category_map=category_map,
        )
        if category not in {"func", "vfunc"}:
            continue

        try:
            with open(artifact_path, "r", encoding="utf-8") as handle:
                artifact_payload = load_yaml(handle)
        except Exception as exc:
            invalid_artifacts.append(f"{artifact_path}: failed to read YAML ({exc})")
            continue

        if not isinstance(artifact_payload, dict):
            invalid_artifacts.append(f"{artifact_path}: invalid YAML payload (expected mapping)")
            continue

        issues = []
        raw_func_va = artifact_payload.get("func_va")
        func_va_text = str(raw_func_va or "").strip()
        should_require_func_va = category == "func"
        should_inspect_func_va = _is_current_module_artifact_path(
            artifact_path,
            binary_dir,
        )

        if should_require_func_va and not func_va_text:
            issues.append("missing required field func_va")

        # func_sig is intentionally NOT required here: a func artifact may be consumed
        # only as an xref/exclude anchor (located by func_va for same-binary xref
        # computation), in which case its YAML legitimately omits func_sig.

        if func_va_text:
            try:
                int(func_va_text, 0)
            except (TypeError, ValueError):
                issues.append(f"invalid func_va value {func_va_text!r}")
            else:
                if should_inspect_func_va:
                    inspect_payload = await _inspect_func_va_via_session(
                        session,
                        func_va_text,
                    )
                    if inspect_payload is not None:
                        has_segment = bool(inspect_payload.get("has_segment"))
                        segment_name = str(inspect_payload.get("segment_name", "")).strip()
                        if not has_segment:
                            issues.append(f"func_va={func_va_text} is not mapped to any segment")
                        elif segment_name != ".text":
                            issues.append(
                                f"func_va={func_va_text} resolves to segment {segment_name!r} instead of '.text'"
                            )
                        elif not inspect_payload.get("has_function"):
                            issues.append(f"func_va={func_va_text} does not resolve to a function")
                        elif not inspect_payload.get("is_function_start"):
                            function_start = str(inspect_payload.get("function_start", "")).strip() or "<unknown>"
                            issues.append(
                                f"func_va={func_va_text} resolves inside function "
                                f"{function_start} instead of a function start"
                            )
                    elif debug:
                        print(
                            "  Warning: unable to inspect expected_input func_va via MCP: "
                            f"{artifact_path} ({func_va_text})"
                        )

        if issues:
            invalid_artifacts.append(f"{artifact_path}: {'; '.join(issues)}")

    return invalid_artifacts


def _merge_metadata_path(payload, path_payload):
    if not isinstance(path_payload, dict):
        return payload

    path_metadata = path_payload.get("metadata")
    if not isinstance(path_metadata, dict):
        return payload

    resolved_path = path_metadata.get("path")
    if not isinstance(resolved_path, str) or not resolved_path:
        return payload

    if not isinstance(payload, dict):
        merged_metadata = {"path": resolved_path}
        input_sha256 = path_metadata.get("input_sha256")
        if isinstance(input_sha256, str) and input_sha256.strip():
            merged_metadata["input_sha256"] = input_sha256.strip()
        return {"metadata": merged_metadata}

    metadata = payload.get("metadata")
    merged_payload = dict(payload)
    merged_metadata = dict(metadata) if isinstance(metadata, dict) else {}
    merged_metadata["path"] = resolved_path
    input_sha256 = path_metadata.get("input_sha256")
    if isinstance(input_sha256, str) and input_sha256.strip():
        merged_metadata["input_sha256"] = input_sha256.strip()
    merged_payload["metadata"] = merged_metadata
    return merged_payload


async def _survey_current_idb_path_via_py_eval(session):
    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": SURVEY_CURRENT_IDB_PATH_PY_EVAL},
        )
    except (McpConnectionError, McpContractError, McpDatabaseSelectionError, McpToolCallError):
        raise
    except Exception:
        return None
    return _parse_py_eval_result_json(result)


async def survey_binary_via_session(session, detail_level="minimal"):
    parsed = None
    try:
        result = await session.call_tool(
            name="survey_binary",
            arguments={"detail_level": detail_level},
        )
    except (McpConnectionError, McpContractError, McpDatabaseSelectionError, McpToolCallError):
        raise
    except Exception:
        pass
    else:
        parsed = _parse_tool_json_content(result)

    current_idb_path = await _survey_current_idb_path_via_py_eval(session)
    if isinstance(current_idb_path, dict):
        return _merge_metadata_path(parsed, current_idb_path)

    return parsed


async def check_mcp_supervisor_health(host=DEFAULT_HOST, port=DEFAULT_PORT):
    return await check_ida_mcp_supervisor_health(host, port)


async def check_mcp_worker_health(host, port, expected_binary):
    try:
        async with open_ida_mcp_session(host, port, expected_binary=expected_binary) as session:
            await session.call_tool(name="py_eval", arguments={"code": "1"})
            return True
    except Exception:
        return False


async def check_mcp_health(host=DEFAULT_HOST, port=DEFAULT_PORT):
    return await check_mcp_supervisor_health(host, port)


async def survey_binary_via_mcp(
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    detail_level="minimal",
    expected_binary=None,
    explicit_database=None,
):
    """
    Retrieve a compact overview of the binary currently loaded in IDA.

    Args:
        host: MCP server host
        port: MCP server port
        detail_level: 'standard' or 'minimal' (use 'minimal' for binaries with >10k functions)
    Returns:
        Parsed survey dict on success, None otherwise.

    Note:
        When available, metadata.path is replaced with the current IDB path so callers
        can infer targets from the moved .i64 location instead of the original input binary path.

    Example result (detail_level='minimal'):
        {
            "metadata": {
                "path": "D:\\CS2_VibeSignatures\\bin\\14141c\\engine\\engine2.dll.i64",
                "module": "engine2.dll",
                "arch": "64",
                "base_address": "0x180000000",
                "image_size": "0x95c000",
                "md5": "11092707508ae325cfdbcfb5ff200423",
                "sha256": "2f48108e724bdb389d0102bc673d762405d39f222d84f4ac56ce86bbe4d61c28"
            },
            "statistics": {
                "total_functions": 15504,
                "named_functions": 317,
                "library_functions": 248,
                "unnamed_functions": 14939,
                "total_strings": 14531,
                "total_segments": 6
            },
            "segments": [
                {"name": ".text",  "start": "0x180001000", "end": "0x180481000", "size": "0x480000", "permissions": "rx"},
                {"name": ".idata", "start": "0x180481000", "end": "0x180482bf0", "size": "0x1bf0",   "permissions": "r"},
                {"name": ".rdata", "start": "0x180482bf0", "end": "0x180604000", "size": "0x181410", "permissions": "r"},
                {"name": ".data",  "start": "0x180604000", "end": "0x180916000", "size": "0x312000", "permissions": "rw"},
                {"name": ".pdata", "start": "0x180916000", "end": "0x180950000", "size": "0x3a000",  "permissions": "r"},
                {"name": "_RDATA", "start": "0x180950000", "end": "0x180951000", "size": "0x1000",   "permissions": "r"}
            ],
            "entrypoints": [
                {"addr": "0x1802523d0", "name": "BinaryProperties_GetValue", "ordinal": 1},
                {"addr": "0x180400100", "name": "CreateInterface",           "ordinal": 2},
                {"addr": "0x180219430", "name": "Source2Main",               "ordinal": 7},
                ...
            ],
            "_note": "Binary has 15504 functions; xref analysis was limited to the first 10000 for performance."
        }
    """
    session_kwargs = {}
    if expected_binary is not None:
        session_kwargs["expected_binary"] = expected_binary
    if explicit_database is not None:
        session_kwargs["explicit_database"] = explicit_database
    async with open_ida_mcp_session(host, port, **session_kwargs) as session:
        return await survey_binary_via_session(session, detail_level=detail_level)


def _hash_file(path):
    absolute_path = _absolute_path_preserve_spelling(path)
    stat = os.stat(absolute_path)
    cache_key = (absolute_path, stat.st_size, stat.st_mtime_ns)
    cached = _BINARY_HASH_CACHE.get(cache_key)
    if cached:
        return cached

    hashes = hash_file(absolute_path)
    _BINARY_HASH_CACHE[cache_key] = hashes
    return hashes


def _metadata_hash(metadata, key):
    value = metadata.get(key)
    if not isinstance(value, str):
        return ""
    normalized = value.strip().lower()
    if normalized in {"", "unavailable", "unknown", "none", "null"}:
        return ""
    return normalized


def _is_ida_database_path(path):
    if not isinstance(path, str):
        return False
    lowered = path.strip().lower()
    return lowered.endswith((".i64", ".idb"))


def _parse_metadata_int(metadata, key):
    value = metadata.get(key)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return int(value.strip(), 0)
        except ValueError:
            return None
    return None


def validate_opened_binary_identity(binary_path, platform, survey_payload):
    if not isinstance(survey_payload, dict):
        return False, ["survey_binary returned no metadata"]

    metadata = survey_payload.get("metadata")
    if not isinstance(metadata, dict):
        return False, ["survey_binary returned no metadata"]

    reasons = []
    if platform == "linux":
        base_address = _parse_metadata_int(metadata, "base_address")
        if base_address is not None and base_address >= _PE_STYLE_BASE_ADDRESS:
            reasons.append(f"PE-style base_address for linux target: {hex(base_address)}")

    opened_path = metadata.get("path")
    opened_sha256 = _metadata_hash(metadata, "sha256")
    input_sha256 = _metadata_hash(metadata, "input_sha256")
    # survey_binary may not hash a reused IDB, while ida_nalt still exposes
    # the hash of the original input binary recorded in that database.
    opened_is_ida_database = _is_ida_database_path(opened_path)
    if opened_is_ida_database and not input_sha256:
        reasons.append("IDB input sha256 is unavailable")
    effective_sha256 = input_sha256 if opened_is_ida_database else (opened_sha256 or input_sha256)
    opened_md5 = _metadata_hash(metadata, "md5")
    expected_hashes = None
    if effective_sha256 or opened_md5:
        try:
            expected_hashes = _hash_file(binary_path)
        except OSError as exc:
            reasons.append(f"could not hash expected binary: {exc}")

    if effective_sha256 and expected_hashes:
        expected_sha256 = expected_hashes["sha256"]
        if effective_sha256 != expected_sha256:
            label = "opened" if opened_sha256 else "IDB input"
            reasons.append(f"sha256 mismatch: expected {expected_sha256}, {label} {effective_sha256}")
        return not reasons, reasons

    if opened_md5 and expected_hashes:
        expected_md5 = expected_hashes["md5"]
        if opened_md5 != expected_md5:
            reasons.append(f"md5 mismatch: expected {expected_md5}, opened {opened_md5}")
        return not reasons, reasons

    expected_path = normalize_binary_identity_path(_absolute_path_preserve_spelling(binary_path))
    normalized_opened_path = normalize_binary_identity_path(opened_path) if isinstance(opened_path, str) else ""
    if not normalized_opened_path:
        reasons.append("path mismatch: opened metadata path is missing")
    elif normalized_opened_path != expected_path:
        reasons.append(f"path mismatch: expected {expected_path}, opened {normalized_opened_path}")

    return not reasons, reasons


def verify_opened_binary_via_mcp(
    binary_path,
    platform,
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    debug=False,
    verify_timeout=OPENED_BINARY_VERIFY_TIMEOUT,
    retry_interval=OPENED_BINARY_VERIFY_RETRY_INTERVAL,
):
    deadline = time.monotonic() + max(0.0, verify_timeout)
    while True:
        try:
            survey = asyncio.run(
                survey_binary_via_mcp(
                    host=host,
                    port=port,
                    detail_level="minimal",
                    expected_binary=binary_path,
                )
            )
        except McpDatabaseUnavailableError:
            raise
        except (McpConnectionError, McpContractError, McpDatabaseSelectionError, McpToolCallError) as exc:
            print("  Failed: opened binary verification failed")
            print(f"    Expected: {_absolute_path_preserve_spelling(binary_path)}")
            print(f"    Reason: {exc}")
            return False
        ok, reasons = validate_opened_binary_identity(binary_path, platform, survey)
        if ok:
            return True
        retryable = reasons in (
            ["survey_binary returned no metadata"],
            ["path mismatch: opened metadata path is missing"],
        )
        if not retryable or time.monotonic() >= deadline:
            break
        if debug:
            print("  Opened binary metadata is not ready; retrying verification...")
        time.sleep(max(0.0, retry_interval))

    metadata = survey.get("metadata") if isinstance(survey, dict) else {}
    opened_path = metadata.get("path") if isinstance(metadata, dict) else None
    base_address = metadata.get("base_address") if isinstance(metadata, dict) else None
    opened_sha256 = metadata.get("sha256") if isinstance(metadata, dict) else None
    input_sha256 = metadata.get("input_sha256") if isinstance(metadata, dict) else None
    opened_md5 = metadata.get("md5") if isinstance(metadata, dict) else None

    print("  Failed: opened binary verification failed")
    print(f"    Expected: {_absolute_path_preserve_spelling(binary_path)}")
    print(f"    Opened: {opened_path or '(unknown)'}")
    print(f"    Platform: {platform}")
    if base_address:
        print(f"    Opened base_address: {base_address}")
    if opened_sha256:
        print(f"    Opened sha256: {opened_sha256}")
    if input_sha256:
        print(f"    IDB input sha256: {input_sha256}")
    if opened_md5:
        print(f"    Opened md5: {opened_md5}")
    for reason in reasons:
        print(f"    Reason: {reason}")
    return False


async def validate_expected_input_artifacts_via_mcp(
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    expected_inputs=None,
    platform="",
    binary_dir=None,
    expected_binary=None,
    explicit_database=None,
    debug=False,
    config_path=None,
    category_map=None,
):
    if not expected_inputs:
        return []

    try:
        session_kwargs = {}
        if expected_binary is not None:
            session_kwargs["expected_binary"] = expected_binary
        if explicit_database is not None:
            session_kwargs["explicit_database"] = explicit_database
        async with open_ida_mcp_session(host, port, **session_kwargs) as session:
            return await validate_expected_input_artifacts_via_session(
                session,
                expected_inputs=expected_inputs,
                platform=platform,
                binary_dir=binary_dir,
                debug=debug,
                config_path=config_path,
                category_map=category_map,
            )
    except Exception:
        if debug:
            print("  Warning: expected_input artifact validation via MCP failed")
        return []


def _run_validate_expected_input_artifacts_via_mcp(
    *,
    host,
    port,
    expected_inputs,
    platform,
    binary_dir=None,
    expected_binary=None,
    explicit_database=None,
    debug=False,
    config_path=None,
    category_map=None,
):
    return asyncio.run(
        validate_expected_input_artifacts_via_mcp(
            host=host,
            port=port,
            expected_inputs=expected_inputs,
            platform=platform,
            binary_dir=binary_dir,
            expected_binary=expected_binary,
            explicit_database=explicit_database,
            debug=debug,
            config_path=config_path,
            category_map=category_map,
        )
    )


def _run_post_process_expected_outputs_via_mcp(
    *,
    host,
    port,
    yaml_items,
    expected_binary=None,
    explicit_database=None,
    debug=False,
):
    """Run post_process for collected expected output YAML mappings."""
    if not yaml_items:
        return True
    return asyncio.run(
        post_process_expected_outputs_via_mcp(
            host=host,
            port=port,
            yaml_items=yaml_items,
            expected_binary=expected_binary,
            explicit_database=explicit_database,
            debug=debug,
        )
    )


async def post_process_expected_outputs_via_mcp(
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    yaml_items=None,
    expected_binary=None,
    explicit_database=None,
    debug=False,
):
    """Connect to IDA MCP and execute post_process actions."""
    yaml_items = list(yaml_items or [])
    if not yaml_items:
        return True

    try:
        session_kwargs = {}
        if expected_binary is not None:
            session_kwargs["expected_binary"] = expected_binary
        if explicit_database is not None:
            session_kwargs["explicit_database"] = explicit_database
        async with open_ida_mcp_session(host, port, **session_kwargs) as session:
            return await post_process_expected_outputs_via_session(
                session,
                yaml_items,
                debug=debug,
            )
    except Exception as exc:
        if debug:
            print(f"  Post-process: MCP connection failed: {exc}")
        return False


async def preprocess_single_vcall_object_via_mcp(
    host,
    port,
    output_root,
    gamever,
    module_name,
    platform,
    object_name,
    expected_binary=None,
    explicit_database=None,
    debug=False,
):
    """Export xref detail YAMLs for a single vcall_finder object via MCP."""
    session_kwargs = {}
    if expected_binary is not None:
        session_kwargs["expected_binary"] = expected_binary
    if explicit_database is not None:
        session_kwargs["explicit_database"] = explicit_database
    async with open_ida_mcp_session(host, port, **session_kwargs) as session:
        return await export_object_xref_details_via_mcp(
            session,
            output_root=output_root,
            gamever=gamever,
            module_name=module_name,
            platform=platform,
            object_name=object_name,
            debug=debug,
        )


def ensure_mcp_available(
    process,
    binary_path,
    host,
    port,
    ida_args,
    debug,
    recovery_budget=None,
):
    """
    Ensure idalib-mcp is running and responsive. Restart if necessary.

    Checks the process status first, then performs a real MCP health check.
    If the server is unresponsive, kills the old process and starts a new one.

    Args:
        process: Current subprocess.Popen object (may be None)
        binary_path: Path to binary file for restarting idalib-mcp
        host: MCP server host
        port: MCP server port
        ida_args: Additional arguments for idalib-mcp
        debug: Enable debug output

    Returns:
        Tuple of (new_process, ok) where new_process may be the same object
        if no restart was needed, and ok indicates whether MCP is available.
    """
    restart_authorized = False

    # Step 1: check if the process has already exited
    if process is not None and process.poll() is not None:
        if debug:
            print(f"  idalib-mcp process exited with code {process.returncode}")
        process = None

    # Step 2: if process appears alive, do a real MCP health check
    if process is not None:
        healthy = asyncio.run(check_mcp_worker_health(host, port, binary_path))
        if healthy:
            return process, True
        print("  MCP health check failed")
        if recovery_budget is not None:
            restart_authorized = recovery_budget.consume_restart()
            if not restart_authorized:
                print("  MCP recovery restart already used; not restarting idalib-mcp again")
                return process, False
        quit_ida_gracefully(process, host, port, expected_binary=binary_path, debug=debug)
        process = None

    # Step 3: restart idalib-mcp
    if recovery_budget is not None and not restart_authorized:
        if not recovery_budget.consume_restart():
            print("  MCP recovery restart already used; not restarting idalib-mcp again")
            return process, False
    if is_port_in_use(host, port):
        if debug:
            print(f"  Waiting for MCP port {host}:{port} to be released before restart...")
        if not wait_for_port_release(host, port):
            print(f"  Failed: MCP port {host}:{port} remained in use; recovery restart aborted")
            return None, False
    print("  Restarting idalib-mcp...")
    new_process = start_idalib_mcp(binary_path, host, port, ida_args, debug)
    if new_process is None:
        return None, False
    return new_process, True


def verify_owned_mcp_with_single_recovery(
    process,
    binary_path,
    platform,
    host,
    port,
    ida_args,
    debug,
    recovery_budget=None,
):
    """Verify the opened binary and recover an unavailable owned worker once."""
    try:
        return process, verify_opened_binary_via_mcp(binary_path, platform, host, port, debug=debug)
    except McpDatabaseUnavailableError as exc:
        print("  Opened binary verification found an unavailable MCP worker; checking recovery...")
        print(f"    Expected: {_absolute_path_preserve_spelling(binary_path)}")
        print(f"    Reason: {exc}")

    original_process = process
    process, mcp_ok = ensure_mcp_available(
        process,
        binary_path,
        host,
        port,
        ida_args,
        debug,
        recovery_budget=recovery_budget,
    )
    if not mcp_ok:
        print("  Failed: unable to recover the unavailable MCP worker")
        return process, False

    if process is original_process and debug:
        print("  MCP worker recovered without a restart; re-verifying opened binary...")
    elif process is not original_process:
        print("  Re-verifying opened binary after the single MCP recovery restart...")

    try:
        verified = verify_opened_binary_via_mcp(binary_path, platform, host, port, debug=debug)
    except McpDatabaseUnavailableError as exc:
        print("  Failed: MCP worker remained unavailable after recovery")
        print(f"    Expected: {_absolute_path_preserve_spelling(binary_path)}")
        print(f"    Reason: {exc}")
        verified = False
    return process, verified


async def quit_ida_via_mcp(host, port, *, expected_binary, auto_started):
    """Quit only the worker owned by this auto-started flow."""
    try:
        async with open_ida_mcp_session(
            host,
            port,
            expected_binary=expected_binary,
            auto_started=auto_started,
        ) as session:
            if not session.binding.should_auto_quit:
                return False
            try:
                await session.call_tool("py_eval", {"code": "import idc; idc.qexit(0)"})
            except McpToolCallError as exc:
                if QEXIT_CONNECTION_RESET_MARKER not in str(exc):
                    return False
            return True
    except Exception:
        return False


async def quit_ida_gracefully_async(process, host, port, *, expected_binary, debug=False):
    """Close an owned worker when safe, then stop the supplied supervisor."""
    if process is None:
        return
    if process.poll() is not None:
        return

    if debug:
        print("  Quitting IDA gracefully via MCP...")

    try:
        await asyncio.wait_for(
            quit_ida_via_mcp(
                host,
                port,
                expected_binary=expected_binary,
                auto_started=True,
            ),
            timeout=5,
        )
    except Exception:
        pass

    await asyncio.to_thread(stop_idalib_mcp_process, process, debug=debug)
    released = await asyncio.to_thread(
        wait_for_port_release,
        host,
        port,
        MCP_SHUTDOWN_TIMEOUT,
    )
    if debug and not released:
        print(f"  MCP port {host}:{port} remained in use after shutdown")


def quit_ida_gracefully(process, host, port, *, expected_binary, debug=False):
    """Run targeted worker cleanup and stop the supplied supervisor."""
    if process is None:
        return

    if process.poll() is not None:
        return

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(
            quit_ida_gracefully_async(
                process,
                host,
                port,
                expected_binary=expected_binary,
                debug=debug,
            )
        )
        return

    raise RuntimeError(
        "quit_ida_gracefully() cannot run inside an active event loop; use await quit_ida_gracefully_async() instead"
    )


def stop_idalib_mcp_process(process, debug=False):
    """Stop only the subprocess started by this runner, without using the MCP port."""
    if process is None or process.poll() is not None:
        return
    if debug:
        print("  Stopping the current idalib-mcp process...")
    try:
        process.terminate()
        process.wait(timeout=10)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    if process.poll() is None:
        try:
            process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _ida_database_paths(binary_path):
    """Return the IDA database and lock/side files associated with a binary."""
    base = os.fspath(binary_path)
    database_paths = [
        f"{base}.i64",
        f"{base}.idb",
        f"{base}.id0",
        f"{base}.id1",
        f"{base}.id2",
        f"{base}.nam",
        f"{base}.til",
    ]
    for database_path in (f"{base}.i64", f"{base}.idb"):
        database_paths.extend(f"{database_path}{suffix}" for suffix in (".id0", ".id1", ".id2", ".nam", ".til"))
    return database_paths


def _invalidate_ida_database(binary_path, debug=False):
    removed = []
    for database_path in _ida_database_paths(binary_path):
        try:
            if os.path.isfile(database_path):
                os.remove(database_path)
                removed.append(database_path)
        except OSError as exc:
            if debug:
                print(f"  Warning: unable to remove stale IDA database file {database_path}: {exc}")
    return removed


def _has_ida_database(binary_path):
    return any(os.path.isfile(path) for path in _ida_database_paths(binary_path)[:2])


def resolve_oldgamever(gamever, bin_dir):
    """
    Resolve the best oldgamever by searching for the most recent existing version
    directory under bin_dir.

    Version ordering (descending):
        14141z > 14141y > ... > 14141b > 14141a > 14141 > 14140

    Args:
        gamever: Current game version string (e.g., "14142", "14141a")
        bin_dir: Base binary directory to check for existing version subdirectories

    Returns:
        Best matching oldgamever string, or None if no candidate directory exists
    """
    if not gamever:
        return None

    # Parse gamever into (base_number, optional_suffix)
    if gamever[-1].islower() and gamever[-1].isalpha():
        suffix = gamever[-1]
        base_str = gamever[:-1]
    else:
        suffix = None
        base_str = gamever

    try:
        base = int(base_str)
    except ValueError:
        return None

    # Generate candidates in descending version order
    candidates = []

    if suffix:
        # E.g., gamever="14141c" -> try 14141b, 14141a, 14141, 14140z..14140a, 14140
        for c in range(ord(suffix) - 1, ord("a") - 1, -1):
            candidates.append(f"{base}{chr(c)}")
        candidates.append(str(base))
        prev_base = base - 1
        for c in range(ord("z"), ord("a") - 1, -1):
            candidates.append(f"{prev_base}{chr(c)}")
        candidates.append(str(prev_base))
    else:
        # E.g., gamever="14142" -> try 14141z..14141a, 14141, 14140
        prev_base = base - 1
        for c in range(ord("z"), ord("a") - 1, -1):
            candidates.append(f"{prev_base}{chr(c)}")
        candidates.append(str(prev_base))
        candidates.append(str(prev_base - 1))

    # Return the first candidate whose directory exists
    for candidate in candidates:
        candidate_dir = os.path.join(bin_dir, candidate)
        if os.path.isdir(candidate_dir):
            return candidate

    return None


def _is_major_update_gamever(gamever, download_path=DEFAULT_DOWNLOAD_FILE):
    """
    Check whether `gamever` is flagged as a major update in download.yaml.

    A major update means cross-version signature reuse is unreliable, so
    oldgamever auto-resolution should be skipped for that version.

    Args:
        gamever: Target game version string (matched against downloads[].tag)
        download_path: Path to download.yaml; resolved relative to this script
            when not absolute

    Returns:
        True only when the matching download entry sets a truthy `major_update`.
        Returns False when gamever is empty, the file is missing/unreadable, or
        the version is not flagged, preserving the default auto-resolve behavior.
    """
    if not gamever:
        return False

    path = Path(download_path)
    if not path.is_absolute():
        path = Path(__file__).resolve().parent / path

    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = load_yaml(handle) or {}
    except Exception:
        return False

    downloads = data.get("downloads")
    if not isinstance(downloads, list):
        return False

    target = str(gamever).strip()
    for entry in downloads:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("tag", "")).strip() == target:
            return bool(entry.get("major_update", False))

    return False


def parse_vcall_finder_filter(raw_value):
    """
    Parse vcall finder selector into normalized filter structure.

    Args:
        raw_value: Raw selector string from CLI, e.g. "a,b" or None

    Returns:
        None if selector is not provided; otherwise:
        {"names": list[str]}

    Raises:
        ValueError: If selector is empty or has invalid format.
    """
    if raw_value is None:
        return None

    if not isinstance(raw_value, str):
        raise ValueError("selector must be a string")

    selector = raw_value.strip()
    if not selector:
        raise ValueError("selector cannot be empty")

    names = []
    seen_names = set()
    for name in selector.split(","):
        normalized_name = name.strip()
        if not normalized_name:
            raise ValueError("selector contains empty object name")
        if normalized_name == "*":
            raise ValueError("wildcard is not supported; specify object names explicitly")
        if normalized_name not in seen_names:
            seen_names.add(normalized_name)
            names.append(normalized_name)

    return {"names": names}


def _parse_optional_llm_temperature(raw_value, parser):
    if raw_value is None:
        return None
    raw_text = str(raw_value).strip()
    if not raw_text:
        return None
    try:
        return float(raw_text)
    except ValueError:
        parser.error("Invalid LLM temperature: must be a number")


def _parse_optional_llm_fake_as(raw_value, parser):
    if raw_value is None:
        return None
    normalized_value = str(raw_value).strip().lower()
    if not normalized_value:
        return None
    if normalized_value != "codex":
        parser.error("Invalid LLM fake_as: must be 'codex'")
    return normalized_value


def _parse_optional_llm_effort(raw_value, parser):
    if raw_value is None:
        return "medium"
    normalized_value = str(raw_value).strip().lower()
    if not normalized_value:
        return "medium"

    valid_efforts = {"none", "minimal", "low", "medium", "high", "xhigh"}
    if normalized_value not in valid_efforts:
        parser.error("Invalid LLM effort: must be one of none, minimal, low, medium, high, xhigh")
    return normalized_value


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Analyze CS2 binary files using IDA Pro MCP and Claude, Codex, or OpenCode agents"
    )
    parser.add_argument(
        "-configyaml",
        default=None,
        help="Analysis config path; defaults to configs/<GAMEVER>.yaml",
    )
    parser.add_argument(
        "-bindir",
        default=DEFAULT_BIN_DIR,
        help=f"Directory containing downloaded binaries (default: {DEFAULT_BIN_DIR})",
    )
    parser.add_argument(
        "-gamever",
        default=os.environ.get("CS2VIBE_GAMEVER"),
        required="CS2VIBE_GAMEVER" not in os.environ,
        help="Game version subdirectory name (required, or set CS2VIBE_GAMEVER env var)",
    )
    parser.add_argument(
        "-platform",
        default=DEFAULT_PLATFORM,
        help=f"Platforms to analyze, comma-separated (default: {DEFAULT_PLATFORM})",
    )
    parser.add_argument(
        "-agent",
        default=os.environ.get("CS2VIBE_AGENT", DEFAULT_AGENT),
        help=(
            "Agent executable to use for analysis, e.g., claude, claude.cmd, codex, "
            f"codex.cmd, opencode, opencode.cmd (default: {DEFAULT_AGENT}, or set CS2VIBE_AGENT env var)"
        ),
    )
    parser.add_argument(
        "-agent_model",
        default=os.environ.get("CS2VIBE_AGENT_MODEL", DEFAULT_AGENT_MODEL),
        help="Custom model for the selected agent (default: agent default, or set CS2VIBE_AGENT_MODEL env var)",
    )
    parser.add_argument(
        "-modules",
        default=DEFAULT_MODULES,
        help=f"Modules to analyze, comma-separated (default: {DEFAULT_MODULES} for all). E.g., server,engine",
    )
    parser.add_argument(
        "-skill",
        default=None,
        help="Exact skill name to run; all other skills are skipped",
    )
    parser.add_argument("-vcall_finder", default=None, help="Comma-separated vcall_finder object names")
    parser.add_argument(
        "-llm_model",
        default=os.environ.get("CS2VIBE_LLM_MODEL", DEFAULT_LLM_MODEL),
        help=f"OpenAI-compatible model for preprocessing and vcall_finder workflow (default: {DEFAULT_LLM_MODEL}, or set CS2VIBE_LLM_MODEL env var)",
    )
    parser.add_argument(
        "-llm_apikey",
        default=os.environ.get("CS2VIBE_LLM_APIKEY"),
        help="OpenAI-compatible API key used by preprocessing and vcall_finder aggregation (or set CS2VIBE_LLM_APIKEY env var)",
    )
    parser.add_argument(
        "-llm_baseurl",
        default=os.environ.get("CS2VIBE_LLM_BASEURL"),
        help="Optional custom compatible base URL used by preprocessing and vcall_finder aggregation (required when -llm_fake_as=codex; or set CS2VIBE_LLM_BASEURL env var)",
    )
    parser.add_argument(
        "-llm_temperature",
        default=os.environ.get("CS2VIBE_LLM_TEMPERATURE"),
        help="Optional OpenAI-compatible temperature used by preprocessing and vcall_finder aggregation (or set CS2VIBE_LLM_TEMPERATURE env var)",
    )
    parser.add_argument(
        "-llm_fake_as",
        default=os.environ.get("CS2VIBE_LLM_FAKE_AS"),
        help="Optional OpenAI-compatible fake_as override (only supports 'codex'; or set CS2VIBE_LLM_FAKE_AS env var)",
    )
    parser.add_argument(
        "-llm_effort",
        default=os.environ.get("CS2VIBE_LLM_EFFORT"),
        help="Optional OpenAI-compatible reasoning effort for preprocessing and vcall_finder aggregation (default: medium; or set CS2VIBE_LLM_EFFORT env var)",
    )
    parser.add_argument("-ida_args", default="", help="Additional arguments for idalib-mcp (optional)")
    parser.add_argument("-debug", action="store_true", help="Enable debug output")
    parser.add_argument(
        "-skip_error",
        action="store_true",
        help="Continue analysis after skill or preprocessor failures",
    )
    parser.add_argument(
        "-skip_pp",
        action="store_true",
        help="Skip preprocessing scripts and run Agent Skills directly",
    )
    parser.add_argument(
        "-rename",
        action="store_true",
        help="Run post_process rename/comment pass for existing expected output YAML files",
    )
    parser.add_argument(
        "-process_reporter",
        choices=("none", "redis"),
        default=os.environ.get("CS2VIBE_PROCESS_REPORTER", "none"),
        help="Process reporter backend (default: none, or set CS2VIBE_PROCESS_REPORTER)",
    )
    parser.add_argument(
        "-redis_url",
        default=os.environ.get("CS2VIBE_REDIS_URL", "redis://127.0.0.1:6379/0"),
        help="Redis URL for the process reporter (or set CS2VIBE_REDIS_URL)",
    )
    parser.add_argument(
        "-redis_prefix",
        default=os.environ.get("CS2VIBE_REDIS_PREFIX", "cs2vibe:analysis:v1"),
        help="Redis key prefix for the process reporter (or set CS2VIBE_REDIS_PREFIX)",
    )
    parser.add_argument(
        "-run_id",
        default=os.environ.get("CS2VIBE_RUN_ID"),
        help="Existing scheduler-created run ID (or set CS2VIBE_RUN_ID)",
    )
    parser.add_argument(
        "-maxretry", type=int, default=3, help="Maximum number of retry attempts for skill execution (default: 3)"
    )
    parser.add_argument(
        "-oldgamever",
        default=None,
        help="Old game version for signature reuse (default: gamever - 1, "
        "auto-disabled when gamever is a major_update in download.yaml). Set to 'none' to disable.",
    )

    args = parser.parse_args()

    # Parse platforms
    args.platforms = [p.strip() for p in args.platform.split(",") if p.strip()]
    valid_platforms = {"windows", "linux"}
    for p in args.platforms:
        if p not in valid_platforms:
            parser.error(f"Invalid platform: {p}. Must be one of: {', '.join(valid_platforms)}")

    # Parse modules filter
    if args.modules == "*":
        args.module_filter = None  # None means all modules
    else:
        args.module_filter = [m.strip() for m in args.modules.split(",") if m.strip()]

    if args.skill is not None:
        args.skill = args.skill.strip()
        if not args.skill:
            parser.error("-skill cannot be empty")

    # Parse vcall_finder selector
    try:
        args.vcall_finder_filter = parse_vcall_finder_filter(args.vcall_finder)
    except ValueError as e:
        parser.error(f"Invalid -vcall_finder: {e}")
    if args.vcall_finder_filter is not None:
        if args.module_filter is None or not args.module_filter or "*" in args.module_filter:
            parser.error("-vcall_finder requires explicit -modules without '*'")

    # Resolve oldgamever
    if args.oldgamever is None:
        # Auto-resolve only when this gamever is NOT a major update. Major
        # updates break cross-version signature reuse, so leave oldgamever
        # disabled unless it was explicitly provided.
        if _is_major_update_gamever(args.gamever):
            args.oldgamever = None
        else:
            args.oldgamever = resolve_oldgamever(args.gamever, args.bindir)
    elif args.oldgamever.lower() == "none":
        args.oldgamever = None

    args.llm_temperature = _parse_optional_llm_temperature(
        args.llm_temperature,
        parser,
    )
    args.llm_fake_as = _parse_optional_llm_fake_as(args.llm_fake_as, parser)
    args.llm_effort = _parse_optional_llm_effort(args.llm_effort, parser)

    return args


def _run_preprocess_single_skill_via_mcp(
    *,
    host,
    port,
    skill_name,
    expected_outputs,
    expected_inputs=None,
    optional_inputs=None,
    old_yaml_map,
    new_binary_dir,
    platform,
    debug,
    llm_model,
    llm_apikey,
    llm_baseurl,
    llm_temperature,
    llm_effort,
    llm_fake_as,
    symbol_aliases=None,
    llm_max_retries=None,
    expected_binary=None,
    explicit_database=None,
):
    preprocess_kwargs = {
        "host": host,
        "port": port,
        "skill_name": skill_name,
        "expected_outputs": expected_outputs,
        "expected_inputs": expected_inputs,
        "optional_inputs": optional_inputs,
        "old_yaml_map": old_yaml_map,
        "new_binary_dir": new_binary_dir,
        "platform": platform,
        "expected_binary": expected_binary,
        "explicit_database": explicit_database,
        "debug": debug,
        "llm_model": llm_model,
        "llm_apikey": llm_apikey,
        "llm_baseurl": llm_baseurl,
        "llm_temperature": llm_temperature,
        "llm_effort": llm_effort,
        "llm_fake_as": llm_fake_as,
        "llm_max_retries": llm_max_retries,
        "symbol_aliases": symbol_aliases,
    }

    return asyncio.run(preprocess_single_skill_via_mcp(**preprocess_kwargs))


def _optional_config_description(value, owner):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"Invalid description for {owner}: expected string or null, got {type(value).__name__}")
    description = value.strip()
    return description or None


def _parse_config_skill(skill, module_name):
    skill_name = skill.get("name")
    if not skill_name:
        return None
    return {
        "name": skill_name,
        "description": _optional_config_description(
            skill.get("description"), f"skill '{skill_name}' in module '{module_name}'"
        ),
        "expected_output": skill.get("expected_output", []) or [],
        "expected_output_windows": skill.get("expected_output_windows", []) or [],
        "expected_output_linux": skill.get("expected_output_linux", []) or [],
        "optional_output": skill.get("optional_output", []) or [],
        "expected_input": skill.get("expected_input", []),
        "expected_input_windows": skill.get("expected_input_windows", []) or [],
        "expected_input_linux": skill.get("expected_input_linux", []) or [],
        "optional_input": skill.get("optional_input", []) or [],
        "optional_input_windows": skill.get("optional_input_windows", []) or [],
        "optional_input_linux": skill.get("optional_input_linux", []) or [],
        "skip_if_exists": skill.get("skip_if_exists", []) or [],
        "prerequisite": skill.get("prerequisite", []) or [],
        "max_retries": skill.get("max_retries"),
        "platform": skill.get("platform"),
    }


def _config_artifact_key(module_name, artifact_path):
    normalized_artifact = artifact_path.replace("\\", "/")
    return posixpath.normpath(posixpath.join("_artifacts", module_name, normalized_artifact))


def _config_skill_platform_paths(skill, base_key, platform):
    paths = list(skill.get(base_key, []) or [])
    paths.extend(skill.get(f"{base_key}_{platform}", []) or [])
    return [path.replace("{platform}", platform) for path in paths]


def find_module_skill_dependency_gaps(modules, platform):
    """Return config inputs that are unavailable when their consumer would run."""
    available_artifacts = set()
    gaps = []
    for module_index, module in enumerate(modules):
        module_name = module["name"]
        skills = module.get("skills") or []
        skill_map = {skill["name"]: skill for skill in skills}
        for skill_name in topological_sort_skills(skills, platform=platform):
            skill = skill_map[skill_name]
            skill_platform = skill.get("platform")
            if skill_platform and skill_platform != platform:
                continue
            missing = [
                key
                for key in (
                    _config_artifact_key(module_name, path)
                    for path in _config_skill_platform_paths(skill, "expected_input", platform)
                )
                if key not in available_artifacts
            ]
            if missing:
                gaps.append(
                    f"{platform} module[{module_index}] {module_name}/{skill_name} missing: {', '.join(missing)}"
                )
            for output in _config_skill_platform_paths(skill, "expected_output", platform):
                available_artifacts.add(_config_artifact_key(module_name, output))
    return gaps


def validate_module_skill_dependencies(modules):
    """Reject analysis modules whose required inputs are unavailable at execution time."""
    dependency_gaps = []
    for platform in ("windows", "linux"):
        dependency_gaps.extend(find_module_skill_dependency_gaps(modules, platform))
    if dependency_gaps:
        raise ValueError("analysis config dependency gaps:\n" + "\n".join(dependency_gaps))


def parse_config_document(config):
    """Transform an already loaded analysis config into executable modules."""
    config = config or {}
    if not isinstance(config, dict):
        raise TypeError("analysis config top level must be a mapping")
    modules = []
    for stage_index, module in enumerate(config.get("modules", [])):
        name = module.get("name")
        if not name:
            print("  Warning: Skipping module without name")
            continue

        skills = [
            parsed
            for skill in module.get("skills", []) or []
            if (parsed := _parse_config_skill(skill, name)) is not None
        ]
        modules.append(
            {
                "stage_index": stage_index,
                "name": name,
                "description": _optional_config_description(module.get("description"), f"module '{name}'"),
                "path_windows": module.get("path_windows"),
                "path_linux": module.get("path_linux"),
                "skills": skills,
            }
        )

    return modules


def parse_config(config_path, config_document=None):
    """Parse an analysis config and extract module information."""
    config = _load_config_document(config_path) if config_document is None else config_document
    return parse_config_document(config)


def resolve_module_vcall_targets(module, selector):
    """Return explicitly requested vcall_finder targets for a selected module."""
    del module
    if selector is None:
        return []
    return list(selector.get("names", []))


def _select_skills_by_name(skills, selected_skill_name):
    """Return only skills whose name exactly matches the requested name."""
    if selected_skill_name is None:
        return skills

    normalized_name = str(selected_skill_name).strip()
    return [skill for skill in skills if skill.get("name") == normalized_name]


def _select_modules_by_skill(modules, selected_skill_name, module_filter=None):
    """Filter modules to exact skill matches within the active module filter."""
    if selected_skill_name is None:
        return modules

    selected_modules = []
    available_skill_names = []
    for module in modules:
        module_name = module.get("name")
        if module_filter is not None and module_name not in module_filter:
            continue

        module_skills = module.get("skills", [])
        available_skill_names.extend(skill.get("name") for skill in module_skills if skill.get("name"))
        selected_skills = _select_skills_by_name(module_skills, selected_skill_name)
        if not selected_skills:
            continue

        selected_module = dict(module)
        selected_module["skills"] = selected_skills
        selected_modules.append(selected_module)

    if selected_modules:
        return selected_modules

    available_label = ", ".join(sorted(set(available_skill_names))) or "(none)"
    raise ValueError(f"Skill '{selected_skill_name}' not found; available skills: {available_label}")


def _skill_artifact_paths(skill, base_key, platform=None):
    paths = list(skill.get(base_key, []) or [])
    if platform is None:
        paths.extend(skill.get(f"{base_key}_windows", []) or [])
        paths.extend(skill.get(f"{base_key}_linux", []) or [])
    else:
        paths.extend(skill.get(f"{base_key}_{platform}", []) or [])
    return [path for path in paths if path]


def _normalized_artifact_keys(path):
    normalized_path = os.path.normcase(os.path.normpath(path))
    normalized_name = os.path.normcase(os.path.normpath(os.path.basename(path)))
    return normalized_path, normalized_name


def _build_artifact_producers(skills, platform=None):
    producers = {}
    for skill in skills:
        producer_name = skill["name"]
        for output_key in ("expected_output", "optional_output"):
            for output_path in _skill_artifact_paths(skill, output_key, platform):
                for key in _normalized_artifact_keys(output_path):
                    producers.setdefault(key, set()).add(producer_name)
    return producers


def _build_skill_dependencies(skills, platform=None):
    skill_names = {skill["name"] for skill in skills}
    producers = _build_artifact_producers(skills, platform)
    dependencies = {name: set() for name in skill_names}
    edges = []
    edge_keys = set()
    for skill in skills:
        consumer = skill["name"]
        for input_key, edge_type in (
            ("expected_input", EdgeType.ARTIFACT),
            ("optional_input", EdgeType.OPTIONAL_INPUT),
        ):
            for input_path in _skill_artifact_paths(skill, input_key, platform):
                path_key, name_key = _normalized_artifact_keys(input_path)
                inferred = set(producers.get(path_key, set()))
                if not inferred:
                    inferred.update(producers.get(name_key, set()))
                for producer in sorted(inferred):
                    dependencies[consumer].add(producer)
                    edge_key = (producer, consumer, edge_type, input_path)
                    if edge_key not in edge_keys:
                        edges.append(SkillEdge(producer, consumer, edge_type, input_path))
                        edge_keys.add(edge_key)
        for prerequisite in skill.get("prerequisite", []) or []:
            if prerequisite in skill_names and prerequisite != consumer:
                dependencies[consumer].add(prerequisite)
                edge_key = (prerequisite, consumer, EdgeType.PREREQUISITE, None)
                if edge_key not in edge_keys:
                    edges.append(SkillEdge(prerequisite, consumer, EdgeType.PREREQUISITE))
                    edge_keys.add(edge_key)
    return dependencies, edges


def _topological_order_with_fallback(dependencies, skills):
    in_degree = {name: len(prerequisites) for name, prerequisites in dependencies.items()}
    dependents = {name: [] for name in dependencies}
    for consumer, prerequisites in dependencies.items():
        for prerequisite in prerequisites:
            dependents[prerequisite].append(consumer)

    queue = sorted(name for name, degree in in_degree.items() if degree == 0)
    order = []
    while queue:
        current = queue.pop(0)
        order.append(current)
        for dependent in sorted(dependents[current]):
            in_degree[dependent] -= 1
            if in_degree[dependent] == 0:
                queue.append(dependent)
        queue.sort()

    blocked = set(dependencies) - set(order)
    for skill in skills:
        if skill["name"] in blocked and skill["name"] not in order:
            order.append(skill["name"])
    return order, blocked


def _find_dependency_cycles(dependencies):
    index = 0
    indexes = {}
    lowlinks = {}
    stack = []
    on_stack = set()
    cycles = []

    def visit(node):
        nonlocal index
        indexes[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for dependency in sorted(dependencies[node]):
            if dependency not in indexes:
                visit(dependency)
                lowlinks[node] = min(lowlinks[node], lowlinks[dependency])
            elif dependency in on_stack:
                lowlinks[node] = min(lowlinks[node], indexes[dependency])
        if lowlinks[node] != indexes[node]:
            return
        component = []
        while stack:
            member = stack.pop()
            on_stack.remove(member)
            component.append(member)
            if member == node:
                break
        if len(component) > 1:
            cycles.append(sorted(component))

    for node in sorted(dependencies):
        if node not in indexes:
            visit(node)
    return sorted(cycles)


def _calculate_skill_layers(dependencies, cycles):
    cycle_components = {member: frozenset(cycle) for cycle in cycles for member in cycle}
    components = {cycle_components.get(node, frozenset([node])) for node in dependencies}
    component_dependencies = {component: set() for component in components}
    for node, prerequisites in dependencies.items():
        component = cycle_components.get(node, frozenset([node]))
        for prerequisite in prerequisites:
            dependency_component = cycle_components.get(prerequisite, frozenset([prerequisite]))
            if dependency_component != component:
                component_dependencies[component].add(dependency_component)

    component_layers = {}

    def resolve_layer(component):
        if component not in component_layers:
            dependency_layers = [resolve_layer(item) for item in component_dependencies[component]]
            component_layers[component] = 1 + max(dependency_layers) if dependency_layers else 0
        return component_layers[component]

    return {node: resolve_layer(cycle_components.get(node, frozenset([node]))) for node in dependencies}


def _build_skill_graph(skills, platform=None):
    dependencies, edges = _build_skill_dependencies(skills, platform)
    order, blocked = _topological_order_with_fallback(dependencies, skills)
    cycles = _find_dependency_cycles(dependencies)
    warnings = []
    if blocked:
        warnings.append(f"Circular dependency detected among skills: {sorted(blocked)}")
    return SkillGraph(
        nodes={skill["name"]: dict(skill) for skill in skills},
        edges=edges,
        order=order,
        layers=_calculate_skill_layers(dependencies, cycles),
        cycles=cycles,
        warnings=warnings,
    )


def build_skill_graph(skills):
    """Build the complete skill DAG without changing legacy ordering semantics."""
    return _build_skill_graph(skills)


def _raise_for_artifact_dependency_cycles(graph):
    self_dependencies = sorted(
        edge.source
        for edge in graph.edges
        if edge.source == edge.target and edge.edge_type in {EdgeType.ARTIFACT, EdgeType.OPTIONAL_INPUT}
    )
    if self_dependencies:
        raise ValueError(f"Artifact dependency cycle detected: self-dependencies={self_dependencies}")

    invalid_cycles = []
    for cycle in graph.cycles:
        members = set(cycle)
        if any(
            edge.edge_type in {EdgeType.ARTIFACT, EdgeType.OPTIONAL_INPUT}
            and edge.source in members
            and edge.target in members
            for edge in graph.edges
        ):
            invalid_cycles.append(cycle)
    if invalid_cycles:
        raise ValueError(f"Artifact dependency cycle detected: {invalid_cycles}")


def topological_sort_skills(skills, platform=None):
    """Return dependency-first skill names and reject artifact input cycles."""
    graph = _build_skill_graph(skills, platform)
    _raise_for_artifact_dependency_cycles(graph)
    for warning in graph.warnings:
        print(f"  Warning: {warning}")
    return graph.order


def _skill_runs_on_platform(skill, platform):
    configured_platform = skill.get("platform")
    return configured_platform is None or configured_platform == platform


def _build_execution_skill_nodes(*, stage, job, skills, order_graph, platform_graph):
    skill_map = {skill["name"]: skill for skill in skills}
    nodes = []
    for order, skill_name in enumerate(order_graph.order):
        skill = skill_map[skill_name]
        nodes.append(
            ExecutionNode(
                id=build_task_id(job.id, skill_name),
                job_id=job.id,
                stage_id=stage.id,
                name=skill_name,
                node_type=PlanNodeType.SKILL,
                order=order,
                layer=platform_graph.layers.get(skill_name, 0),
                description=skill.get("description"),
                data={key: value for key, value in skill.items() if key != "description"},
            )
        )
    return nodes


def _append_execution_auxiliary_nodes(
    nodes,
    *,
    module,
    stage,
    job,
    vcall_finder_selector,
    include_post_process,
):
    next_order = len(nodes)
    next_layer = max((node.layer for node in nodes), default=-1) + 1
    for target_name in resolve_module_vcall_targets(module, vcall_finder_selector):
        nodes.append(
            ExecutionNode(
                id=build_vcall_task_id(job.id, target_name),
                job_id=job.id,
                stage_id=stage.id,
                name=target_name,
                node_type=PlanNodeType.VCALL_TARGET,
                order=next_order,
                layer=next_layer,
            )
        )
        next_order += 1
    if include_post_process and module.get("skills"):
        nodes.append(
            ExecutionNode(
                id=build_post_process_task_id(job.id),
                job_id=job.id,
                stage_id=stage.id,
                name="post-process",
                node_type=PlanNodeType.POST_PROCESS,
                order=next_order,
                layer=next_layer + 1,
            )
        )
    return nodes


def _build_execution_job_edges(job, platform_graph, nodes):
    edges = [
        ExecutionEdge(
            source=build_task_id(job.id, edge.source),
            target=build_task_id(job.id, edge.target),
            edge_type=edge.edge_type,
            artifact=edge.artifact,
        )
        for edge in platform_graph.edges
    ]
    edges.extend(
        ExecutionEdge(source=source.id, target=target.id, edge_type=EdgeType.STAGE_ORDER)
        for source, target in zip(nodes, nodes[1:])
    )
    return edges


def _build_execution_job_nodes(
    module,
    *,
    stage,
    job,
    platform,
    vcall_finder_selector,
    include_post_process,
):
    skills = module.get("skills", []) or []
    order_graph = build_skill_graph(skills)
    active_skills = [skill for skill in skills if _skill_runs_on_platform(skill, platform)]
    platform_graph = _build_skill_graph(active_skills, platform)
    _raise_for_artifact_dependency_cycles(platform_graph)
    nodes = _build_execution_skill_nodes(
        stage=stage,
        job=job,
        skills=skills,
        order_graph=order_graph,
        platform_graph=platform_graph,
    )
    nodes = _append_execution_auxiliary_nodes(
        nodes,
        module=module,
        stage=stage,
        job=job,
        vcall_finder_selector=vcall_finder_selector,
        include_post_process=include_post_process,
    )
    edges = _build_execution_job_edges(job, platform_graph, nodes)
    warnings = [f"{job.id}: {warning}" for warning in order_graph.warnings]
    return nodes, edges, warnings, active_skills


def _resolve_execution_artifacts(job, active_skills, platform):
    binary_dir = os.path.dirname(job.binary_path) if job.binary_path else None
    producers = []
    consumers = []
    warnings = []
    if binary_dir is None:
        return producers, consumers, warnings

    for skill in active_skills:
        node_id = build_task_id(job.id, skill["name"])
        path_groups = (
            ("expected_output", producers, None),
            ("optional_output", producers, None),
            ("expected_input", consumers, EdgeType.CROSS_STAGE_ARTIFACT),
            ("optional_input", consumers, EdgeType.OPTIONAL_INPUT),
        )
        for base_key, records, edge_type in path_groups:
            for artifact_path in _skill_artifact_paths(skill, base_key, platform):
                try:
                    resolved_path = resolve_artifact_path(binary_dir, artifact_path, platform)
                except ValueError as exc:
                    warnings.append(f"{node_id}: {exc}")
                    continue
                records.append(
                    {
                        "key": os.path.normcase(os.path.normpath(resolved_path)),
                        "artifact": resolved_path,
                        "job_id": job.id,
                        "stage_id": job.stage_id,
                        "stage_index": job.stage_index,
                        "node_id": node_id,
                        "edge_type": edge_type,
                    }
                )
    return producers, consumers, warnings


def _build_cross_stage_artifact_edges(producers, consumers, job_positions):
    producers_by_path = {}
    for producer in producers:
        producers_by_path.setdefault(producer["key"], []).append(producer)

    edges = []
    warnings = []
    seen_edges = set()
    for consumer in consumers:
        for producer in producers_by_path.get(consumer["key"], []):
            if producer["stage_id"] == consumer["stage_id"]:
                continue
            edge_key = (producer["node_id"], consumer["node_id"], consumer["key"])
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            edges.append(
                ExecutionEdge(
                    source=producer["node_id"],
                    target=consumer["node_id"],
                    edge_type=consumer["edge_type"],
                    artifact=consumer["artifact"],
                )
            )
            if job_positions[producer["job_id"]] > job_positions[consumer["job_id"]]:
                warnings.append(
                    "Cross-stage artifact dependency conflicts with execution order: "
                    f"{producer['node_id']} -> {consumer['node_id']}"
                )
    return edges, warnings


def _build_execution_job_plan(
    module,
    *,
    stage,
    platform,
    bin_dir,
    gamever,
    vcall_finder_selector,
    include_post_process,
):
    module_path = module.get(f"path_{platform}")
    binary_path = get_binary_path(bin_dir, gamever, module["name"], module_path) if module_path else None
    job = ExecutionJob(
        id=build_job_id(stage.id, platform),
        stage_id=stage.id,
        stage_index=stage.stage_index,
        module_name=module["name"],
        platform=platform,
        binary_path=binary_path,
    )
    nodes, edges, warnings, active_skills = _build_execution_job_nodes(
        module,
        stage=stage,
        job=job,
        platform=platform,
        vcall_finder_selector=vcall_finder_selector,
        include_post_process=include_post_process,
    )
    producers, consumers, artifact_warnings = _resolve_execution_artifacts(job, active_skills, platform)
    warnings.extend(artifact_warnings)
    return job, nodes, edges, warnings, producers, consumers


def _build_execution_control_edges(stages, jobs):
    edges = [
        ExecutionEdge(source=source.id, target=target.id, edge_type=EdgeType.STAGE_ORDER)
        for source, target in zip(stages, stages[1:])
    ]
    edges.extend(
        ExecutionEdge(source=source.id, target=target.id, edge_type=EdgeType.STAGE_ORDER)
        for source, target in zip(jobs, jobs[1:])
    )
    return edges


def _build_execution_stage(module, fallback_index):
    stage_index = module.get("stage_index", fallback_index)
    return ExecutionStage(
        id=build_stage_id(stage_index, module["name"]),
        stage_index=stage_index,
        module_name=module["name"],
        description=module.get("description"),
    )


def build_execution_plan(
    modules,
    *,
    platforms,
    bin_dir,
    gamever,
    vcall_finder_selector=None,
    include_post_process=False,
):
    """Build the immutable task hierarchy and dependency graph before execution."""
    stages = []
    jobs = []
    nodes = []
    edges = []
    warnings = []
    artifact_producers = []
    artifact_consumers = []

    for fallback_index, module in enumerate(modules):
        stage = _build_execution_stage(module, fallback_index)
        stages.append(stage)
        for platform in platforms:
            job, job_nodes, job_edges, job_warnings, producers, consumers = _build_execution_job_plan(
                module,
                stage=stage,
                platform=platform,
                bin_dir=bin_dir,
                gamever=gamever,
                vcall_finder_selector=vcall_finder_selector,
                include_post_process=include_post_process,
            )
            jobs.append(job)
            nodes.extend(job_nodes)
            edges.extend(job_edges)
            warnings.extend(job_warnings)
            artifact_producers.extend(producers)
            artifact_consumers.extend(consumers)

    edges.extend(_build_execution_control_edges(stages, jobs))
    job_positions = {job.id: position for position, job in enumerate(jobs)}
    cross_edges, cross_warnings = _build_cross_stage_artifact_edges(
        artifact_producers,
        artifact_consumers,
        job_positions,
    )
    edges.extend(cross_edges)
    warnings.extend(cross_warnings)
    return ExecutionPlan(stages=stages, jobs=jobs, nodes=nodes, edges=edges, warnings=warnings)


def should_start_binary_processing(
    skills_to_process,
    vcall_targets,
    post_process_yaml_items=None,
):
    """Start IDA when skills, vcall_finder, or post_process still has work to do."""
    return bool(skills_to_process or vcall_targets or post_process_yaml_items)


def _pending_binary_work_count(
    skills_to_process=None,
    skill_index=0,
    vcall_targets=None,
    vcall_index=0,
    post_process_yaml_items=None,
):
    remaining_skills = max(0, len(skills_to_process or []) - skill_index)
    remaining_vcalls = max(0, len(vcall_targets or []) - vcall_index)
    post_process_count = 1 if post_process_yaml_items else 0
    return remaining_skills + remaining_vcalls + post_process_count


def resolve_artifact_path(binary_dir, artifact_path, platform):
    """Resolve one artifact path under the current gamever root."""
    if not artifact_path:
        raise ValueError("artifact path is empty")

    expanded = artifact_path.replace("{platform}", platform)
    module_dir = _absolute_path_preserve_spelling(binary_dir)
    candidate = _absolute_path_preserve_spelling(os.path.join(module_dir, expanded))
    real_module_dir = Path(binary_dir).resolve()
    real_gamever_dir = real_module_dir.parent.resolve()
    real_candidate = (real_module_dir / expanded).resolve()

    if os.path.commonpath([str(real_candidate), str(real_gamever_dir)]) != str(real_gamever_dir):
        raise ValueError(f"artifact path escapes gamever root: {artifact_path}")

    return candidate


def expand_expected_paths(binary_dir, paths, platform):
    """Expand {platform} placeholders and resolve artifact paths under a binary directory."""
    return [resolve_artifact_path(binary_dir, path, platform) for path in paths]


def all_expected_outputs_exist(expected_outputs):
    """Return True when every expected output already exists on disk."""
    return bool(expected_outputs) and all(os.path.exists(path) for path in expected_outputs)


def expand_skill_output_paths(binary_dir, skill, platform):
    """Return required, optional, and preprocessor output paths for one skill."""
    platform_output_key = f"expected_output_{platform}"
    combined_outputs = list(skill.get("expected_output", []) or [])
    combined_outputs += list(skill.get(platform_output_key, []) or [])
    required_outputs = expand_expected_paths(
        binary_dir,
        combined_outputs,
        platform,
    )
    optional_outputs = expand_expected_paths(
        binary_dir,
        skill.get("optional_output", []) or [],
        platform,
    )
    return required_outputs, optional_outputs, required_outputs + optional_outputs


def should_skip_skill_for_existing_outputs(required_outputs, optional_outputs):
    """Return True when configured output artifacts make processing unnecessary."""
    if required_outputs:
        return all_expected_outputs_exist(required_outputs)
    return all_expected_outputs_exist(optional_outputs)


def _load_post_process_yaml_mapping(path, debug=False):
    """Load one post_process YAML file and return a mapping payload or None."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = load_yaml(handle)
    except Exception as exc:
        if debug:
            print(f"  Post-process: skipping unreadable YAML {path}: {exc}")
        return None

    if not isinstance(payload, dict):
        if debug:
            print(f"  Post-process: skipping non-mapping YAML {path}")
        return None
    return payload


def _collect_post_process_yaml_mappings(
    binary_dir,
    sorted_skill_names,
    skill_map,
    platform,
    debug=False,
):
    """Collect existing expected output YAML mappings in stable skill/output order."""
    yaml_items = []
    seen_paths = set()

    for skill_name in sorted_skill_names:
        skill = skill_map[skill_name]
        skill_platform = skill.get("platform")
        if skill_platform and skill_platform != platform:
            continue
        try:
            platform_output_key = f"expected_output_{platform}"
            combined_outputs = list(skill.get("expected_output", []) or [])
            combined_outputs += list(skill.get(platform_output_key, []) or [])
            expected_outputs = expand_expected_paths(
                binary_dir,
                combined_outputs,
                platform,
            )
        except ValueError as exc:
            if debug:
                print(f"  Post-process: skipping {skill_name}: {exc}")
            continue

        for output_path in expected_outputs:
            artifact_path = _absolute_path_preserve_spelling(output_path)
            if not _is_current_module_artifact_path(artifact_path, binary_dir):
                if debug:
                    print(f"  Post-process: skipping YAML outside current module dir {artifact_path}")
                continue
            seen_key = os.path.normcase(artifact_path)
            if seen_key in seen_paths:
                continue
            seen_paths.add(seen_key)
            if not os.path.exists(artifact_path):
                continue
            payload = _load_post_process_yaml_mapping(artifact_path, debug=debug)
            if payload is None:
                continue
            yaml_items.append((artifact_path, payload))

    return yaml_items


def _empty_post_process_actions():
    return {
        "func_renames": [],
        "data_renames": [],
        "sig_comments": [],
    }


def _extend_post_process_actions(target, source):
    target["func_renames"].extend(source["func_renames"])
    target["data_renames"].extend(source["data_renames"])
    target["sig_comments"].extend(source["sig_comments"])


def _parse_post_process_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            return int(raw, 0)
        except ValueError:
            return None
    return None


def _parse_post_process_addr(value):
    parsed = _parse_post_process_int(value)
    if parsed is None or parsed < 0:
        return None
    return f"0x{parsed:x}"


def _post_process_text(value):
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _format_post_process_offset_comment(offset_value, label):
    return f"0x{offset_value:X} = {offset_value}LL = {label}"


def _build_post_process_actions_from_yaml(payload, source_path, debug=False):
    actions = _empty_post_process_actions()
    if not isinstance(payload, dict):
        return actions

    vtable_class = _post_process_text(payload.get("vtable_class"))
    vtable_addr = _parse_post_process_addr(payload.get("vtable_va"))
    if vtable_class and vtable_addr:
        actions["data_renames"].append(
            {
                "addr": vtable_addr,
                "name": f"{vtable_class}_vtable",
                "kind": "vtable",
            }
        )
    elif debug and (payload.get("vtable_class") is not None or payload.get("vtable_va") is not None):
        print(f"  Post-process: skipped invalid vtable rename in {source_path}")

    func_name = _post_process_text(payload.get("func_name"))
    func_addr = _parse_post_process_addr(payload.get("func_va"))
    if func_name and func_addr:
        actions["func_renames"].append({"addr": func_addr, "name": func_name})
    elif debug and (payload.get("func_name") is not None or payload.get("func_va") is not None):
        print(f"  Post-process: skipped invalid function rename in {source_path}")

    gv_name = _post_process_text(payload.get("gv_name"))
    gv_addr = _parse_post_process_addr(payload.get("gv_va"))
    if gv_name and gv_addr:
        actions["data_renames"].append(
            {
                "addr": gv_addr,
                "name": gv_name,
                "kind": "global",
            }
        )
    elif debug and (payload.get("gv_name") is not None or payload.get("gv_va") is not None):
        print(f"  Post-process: skipped invalid global rename in {source_path}")

    vfunc_sig = _post_process_text(payload.get("vfunc_sig"))
    vfunc_offset = _parse_post_process_int(payload.get("vfunc_offset"))
    has_vfunc_sig_disp = "vfunc_sig_disp" in payload
    raw_vfunc_sig_disp = payload.get("vfunc_sig_disp")
    vfunc_sig_disp = _parse_post_process_int(raw_vfunc_sig_disp)
    if not has_vfunc_sig_disp:
        vfunc_sig_disp = 0
    if (
        func_name
        and vfunc_sig
        and vfunc_offset is not None
        and vfunc_offset >= 0
        and vfunc_sig_disp is not None
        and vfunc_sig_disp >= 0
    ):
        actions["sig_comments"].append(
            {
                "pattern": vfunc_sig,
                "disp": vfunc_sig_disp,
                "comment": _format_post_process_offset_comment(vfunc_offset, func_name),
                "source_path": source_path,
                "kind": "vfunc_sig",
            }
        )
    elif debug and (payload.get("vfunc_sig") is not None or payload.get("vfunc_offset") is not None):
        print(f"  Post-process: skipped invalid vfunc_sig comment in {source_path}")

    struct_name = _post_process_text(payload.get("struct_name"))
    member_name = _post_process_text(payload.get("member_name"))
    offset_sig = _post_process_text(payload.get("offset_sig"))
    offset_value = _parse_post_process_int(payload.get("offset"))
    has_offset_sig_disp = "offset_sig_disp" in payload
    raw_offset_sig_disp = payload.get("offset_sig_disp")
    offset_sig_disp = _parse_post_process_int(raw_offset_sig_disp)
    if not has_offset_sig_disp:
        offset_sig_disp = 0
    if (
        struct_name
        and member_name
        and offset_sig
        and offset_value is not None
        and offset_value >= 0
        and offset_sig_disp is not None
        and offset_sig_disp >= 0
    ):
        actions["sig_comments"].append(
            {
                "pattern": offset_sig,
                "disp": offset_sig_disp,
                "comment": _format_post_process_offset_comment(
                    offset_value,
                    f"{struct_name}::{member_name}",
                ),
                "source_path": source_path,
                "kind": "offset_sig",
            }
        )
    elif debug and (payload.get("offset_sig") is not None or payload.get("offset") is not None):
        print(f"  Post-process: skipped invalid offset_sig comment in {source_path}")

    return actions


def _parse_post_process_match_addr(value):
    parsed = _parse_post_process_int(value)
    if parsed is None or parsed < 0:
        return None
    return parsed


async def _find_post_process_signature_comment_addr(session, action, debug=False):
    try:
        result = await session.call_tool(
            name="find_bytes",
            arguments={"patterns": [action["pattern"]], "limit": 2},
        )
        payload = _parse_tool_json_content(result)
    except Exception as exc:
        if debug:
            print(f"  Post-process: find_bytes failed for {action['source_path']}: {exc}")
        return None

    if not isinstance(payload, list) or not payload:
        return None
    entry = payload[0]
    if not isinstance(entry, dict):
        return None

    matches = entry.get("matches", [])
    if not isinstance(matches, list):
        matches = []
    match_count = entry.get("n", len(matches))
    if match_count != 1 or not matches:
        if debug:
            print(
                "  Post-process: skipped "
                f"{action['kind']} comment in {action['source_path']} "
                f"because signature matched {match_count}"
            )
        return None

    match_addr = _parse_post_process_match_addr(matches[0])
    if match_addr is None:
        if debug:
            print(f"  Post-process: unparsable signature match in {action['source_path']}")
        return None
    return match_addr + action["disp"]


async def _post_process_set_comments(session, comment_items, debug=False):
    if not comment_items:
        return

    try:
        result = await session.call_tool(
            name="set_comments",
            arguments={"items": comment_items},
        )
        payload = _parse_tool_json_content(result)
        if isinstance(payload, dict):
            for item in payload.get("items", []):
                if isinstance(item, dict) and item.get("error") and debug:
                    print(f"  Post-process: set_comments item failed at {item.get('addr')}: {item.get('error')}")
        return
    except Exception as exc:
        if debug:
            print(f"  Post-process: set_comments unavailable, using py_eval fallback: {exc}")

    for item in comment_items:
        addr_int = _parse_post_process_int(item["addr"])
        if addr_int is None:
            continue
        code = f"import idc\nidc.set_cmt({addr_int}, {json.dumps(item['comment'])}, 0)\n"
        try:
            await session.call_tool(name="py_eval", arguments={"code": code})
        except Exception as exc:
            if debug:
                print(f"  Post-process: py_eval comment fallback failed at {item['addr']}: {exc}")


async def _post_process_func_renames(session, func_renames, debug=False):
    if not func_renames:
        return

    batch_size = POST_PROCESS_FUNC_RENAME_BATCH_SIZE
    total = len(func_renames)
    batch_count = (total + batch_size - 1) // batch_size
    if debug:
        print(f"  Post-process: function rename total={total} batch_size={batch_size}")

    for batch_index, start in enumerate(range(0, total, batch_size), start=1):
        batch = func_renames[start : start + batch_size]
        end = start + len(batch)
        if debug:
            print(
                "  Post-process: function rename batch "
                f"{batch_index}/{batch_count} items={len(batch)} "
                f"range={start + 1}-{end} "
                f"first={batch[0]['addr']} -> {batch[0]['name']} "
                f"last={batch[-1]['addr']} -> {batch[-1]['name']}"
            )
        try:
            result = await session.call_tool(
                name="rename",
                arguments={"batch": {"func": batch}},
            )
            payload = _parse_tool_json_content(result)
            if isinstance(payload, dict) and debug:
                for item in payload.get("func", []):
                    if isinstance(item, dict) and item.get("error"):
                        print(f"  Post-process: function rename item failed {item.get('addr')}: {item.get('error')}")
        except Exception as exc:
            if debug:
                print(
                    "  Post-process: function rename batch "
                    f"{batch_index}/{batch_count} failed "
                    f"(items={len(batch)}, range={start + 1}-{end}): {exc}"
                )
                for offset, item in enumerate(batch, start=start + 1):
                    print(f"    Post-process: function rename item {offset}: {item['addr']} -> {item['name']}")
            continue


async def _post_process_data_renames(session, data_renames, debug=False):
    for item in data_renames:
        addr_int = _parse_post_process_int(item["addr"])
        if addr_int is None:
            continue
        code = f"import idc\nidc.set_name({addr_int}, {json.dumps(item['name'])}, idc.SN_NOWARN)\n"
        try:
            await session.call_tool(name="py_eval", arguments={"code": code})
        except Exception as exc:
            if debug:
                print(f"  Post-process: data rename failed {item['addr']} -> {item['name']}: {exc}")


async def post_process_expected_outputs_via_session(
    session,
    yaml_items,
    debug=False,
):
    actions = _empty_post_process_actions()
    for source_path, payload in yaml_items:
        _extend_post_process_actions(
            actions,
            _build_post_process_actions_from_yaml(payload, source_path, debug=debug),
        )

    comment_items = []
    for action in actions["sig_comments"]:
        comment_addr = await _find_post_process_signature_comment_addr(
            session,
            action,
            debug=debug,
        )
        if comment_addr is None:
            continue
        comment_items.append(
            {
                "addr": f"0x{comment_addr:x}",
                "comment": action["comment"],
            }
        )

    await _post_process_set_comments(session, comment_items, debug=debug)
    await _post_process_func_renames(session, actions["func_renames"], debug=debug)
    await _post_process_data_renames(session, actions["data_renames"], debug=debug)
    return True


def should_skip_skill_for_existing_artifacts(binary_dir, skill, platform):
    """Return resolved skip paths when all configured skip_if_exists artifacts exist."""
    skip_if_exists = list(skill.get("skip_if_exists", []) or [])
    if not skip_if_exists:
        return False, []

    resolved_paths = expand_expected_paths(binary_dir, skip_if_exists, platform)
    return all_expected_outputs_exist(resolved_paths), resolved_paths


def get_binary_path(bin_dir, gamever, module_name, module_path):
    """
    Build binary file path.

    Args:
        bin_dir: Base binary directory
        gamever: Game version subdirectory
        module_name: Module name (e.g., "engine")
        module_path: Module path from config (e.g., "game/bin/win64/engine2.dll")

    Returns:
        Full path to binary file: {bin_dir}/{gamever}/{module_name}/{filename}
    """
    filename = Path(module_path).name
    return os.path.join(bin_dir, gamever, module_name, filename)


def wait_for_port(host, port, timeout=60):
    """
    Wait for a port to become available.

    Args:
        host: Host address
        port: Port number
        timeout: Maximum time to wait in seconds

    Returns:
        True if port is available, False if timeout
    """
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except socket.error:
            pass
        time.sleep(2)
    return False


def is_port_in_use(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def wait_for_port_release(host, port, timeout=MCP_SHUTDOWN_TIMEOUT, retry_interval=0.1):
    """Wait for a stopped local supervisor to release its listening port."""
    deadline = time.monotonic() + max(0.0, timeout)
    while is_port_in_use(host, port):
        if time.monotonic() >= deadline:
            return False
        time.sleep(max(0.0, retry_interval))
    return True


def start_idalib_mcp(
    binary_path,
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    ida_args="",
    debug=False,
    stdout=None,
    stderr=None,
):
    """
    Start idalib-mcp as a background process.

    Args:
        binary_path: Path to binary file to analyze
        host: MCP server host
        port: MCP server port
        ida_args: Additional arguments for idalib-mcp
        debug: Enable debug output

    Returns:
        subprocess.Popen object if successful, None if failed
    """
    if is_port_in_use(host, port):
        print(f"  Error: MCP port {host}:{port} is already in use")
        return None

    cmd = ["idalib-mcp", "--unsafe", "--host", host, "--port", str(port)]

    if ida_args:
        cmd.extend(ida_args.split())

    cmd.append(binary_path)

    print(f"  Starting idalib-mcp: {' '.join(cmd)}")

    try:
        if debug or stdout is not None or stderr is not None:
            process = subprocess.Popen(cmd, stdout=stdout, stderr=stderr)
        else:
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Wait for MCP server to be ready
        print(f"  Waiting for MCP server on {host}:{port}...")
        if not wait_for_port(host, port, timeout=MCP_STARTUP_TIMEOUT):
            print(f"  Error: MCP server failed to start within {MCP_STARTUP_TIMEOUT} seconds")
            process.kill()
            return None

        print("  MCP server port is ready")
        return process

    except Exception as e:
        print(f"  Error starting idalib-mcp: {e}")
        return None


def _report_skill_status(reporting, job_id, skill_name, status, phase, **details):
    if reporting is None or job_id is None:
        return
    reporting.emit_task_status(build_task_id(job_id, skill_name), status, phase, **details)


def _report_vcall_status(reporting, job_id, object_name, status, phase, **details):
    if reporting is None or job_id is None:
        return
    reporting.emit_task_status(build_vcall_task_id(job_id, object_name), status, phase, **details)


def _report_post_process_status(reporting, job_id, status, phase, **details):
    if reporting is None or job_id is None:
        return
    reporting.emit_task_status(build_post_process_task_id(job_id), status, phase, **details)


def _abort_binary_reporting(reporting, job_id, reason, message):
    if reporting is not None and job_id is not None:
        reporting.abort_job_tasks(job_id, reason, message)


def _abort_vcall_reporting(reporting, job_id, object_names, reason, message):
    if reporting is None or job_id is None:
        return
    task_ids = [build_vcall_task_id(job_id, object_name) for object_name in object_names]
    reporting.finish_tasks(task_ids, TaskStatus.ABORTED, reason, message)


def _build_agent_progress_callback(reporting, job_id, skill_name):
    if reporting is None or job_id is None:
        return None
    task_id = build_task_id(job_id, skill_name)

    def report_progress(**progress):
        reporting.emit_agent_progress(task_id, **progress)

    return report_progress


def process_binary(
    binary_path,
    skills,
    agent,
    host,
    port,
    ida_args,
    platform,
    debug=False,
    max_retries=3,
    old_binary_dir=None,
    gamever=None,
    module_name=None,
    vcall_targets=None,
    vcall_output_dir="vcall_finder",
    llm_model=DEFAULT_LLM_MODEL,
    llm_apikey=None,
    llm_baseurl=None,
    llm_temperature=None,
    llm_effort="medium",
    llm_fake_as=None,
    rename=False,
    agent_model=DEFAULT_AGENT_MODEL,
    skip_error=False,
    skip_pp=False,
    reporting=None,
    job_id=None,
    config_path=None,
    category_map=None,
    symbol_aliases=None,
    found_vcall_objects=None,
):
    """
    Process a single binary file.

    Args:
        binary_path: Path to binary file
        skills: List of skill dicts with 'name', 'expected_output', 'expected_input',
            optional legacy 'prerequisite', and optional 'max_retries' keys
        agent: Agent type ("claude" or "codex")
        host: MCP server host
        port: MCP server port
        ida_args: Additional arguments for idalib-mcp
        platform: Platform name (e.g., "windows", "linux")
        debug: Enable debug output
        max_retries: Default maximum number of retry attempts for skill execution
        old_binary_dir: Directory containing old version YAML files for signature reuse
        rename: Run module/platform post_process over valid expected output YAML mappings
        skip_error: Continue processing later skills after skill or preprocessor failures
        skip_pp: Skip preprocessing scripts and run Agent Skills directly
        found_vcall_objects: Optional run-scoped set updated when an object exists in this binary

    Returns:
        Tuple of (success_count, fail_count, skip_count)
    """
    success_count = 0
    fail_count = 0
    skip_count = 0

    # Get the directory containing the binary for yaml output check
    binary_dir = os.path.dirname(binary_path)

    # Build skill_map for lookup
    skill_map = {skill["name"]: skill for skill in skills}

    # Topological sort skills based on inferred dependency tree
    sorted_skill_names = topological_sort_skills(skills, platform=platform)

    # Filter skills that need processing (skip if configured outputs already exist)
    skills_to_process = []
    for skill_name in sorted_skill_names:
        skill = skill_map[skill_name]
        # Skip skills restricted to a different platform
        skill_platform = skill.get("platform")
        if skill_platform and skill_platform != platform:
            print(f"  Skipping skill: {skill_name} (platform '{skill_platform}' != '{platform}')")
            skip_count += 1
            _report_skill_status(
                reporting,
                job_id,
                skill_name,
                TaskStatus.SKIPPED,
                ProcessPhase.FINISHED,
                reason=ProcessReason.PLATFORM_MISMATCH,
            )
            continue
        try:
            required_outputs, optional_outputs, preprocess_outputs = expand_skill_output_paths(
                binary_dir,
                skill,
                platform,
            )
        except ValueError as e:
            fail_count += 1
            print(f"  Failed: {skill_name} ({e})")
            _report_skill_status(reporting, job_id, skill_name, TaskStatus.RUNNING, ProcessPhase.PREFLIGHT)
            _report_skill_status(
                reporting,
                job_id,
                skill_name,
                TaskStatus.FAILED,
                ProcessPhase.FINISHED,
                reason=ProcessReason.INVALID_INPUT,
                error=str(e),
            )
            continue
        # Check if configured output files already make the skill unnecessary.
        if should_skip_skill_for_existing_outputs(required_outputs, optional_outputs):
            print(f"  Skipping skill: {skill_name} (all outputs exist)")
            skip_count += 1
            _report_skill_status(
                reporting,
                job_id,
                skill_name,
                TaskStatus.SKIPPED,
                ProcessPhase.FINISHED,
                reason=ProcessReason.EXISTING_OUTPUTS,
            )
        else:
            try:
                skip_for_existing_artifacts, _skip_paths = should_skip_skill_for_existing_artifacts(
                    binary_dir,
                    skill,
                    platform,
                )
            except ValueError as e:
                fail_count += 1
                print(f"  Failed: {skill_name} ({e})")
                _report_skill_status(reporting, job_id, skill_name, TaskStatus.RUNNING, ProcessPhase.PREFLIGHT)
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.FAILED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.INVALID_INPUT,
                    error=str(e),
                )
                continue
            if skip_for_existing_artifacts:
                print(f"  Skipping skill: {skill_name} (all skip_if_exists artifacts exist)")
                skip_count += 1
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.SKIPPED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.SKIP_IF_EXISTS,
                )
            else:
                # Use skill-specific max_retries if provided, otherwise use default
                skill_max_retries = skill.get("max_retries") or max_retries
                skills_to_process.append(
                    (
                        skill_name,
                        required_outputs,
                        optional_outputs,
                        preprocess_outputs,
                        skill_max_retries,
                    )
                )

    vcall_targets = list(vcall_targets or [])
    startup_post_process_yaml_items = []
    startup_post_process_failed = False
    if rename:
        _report_post_process_status(reporting, job_id, TaskStatus.RUNNING, ProcessPhase.PREFLIGHT)
        try:
            startup_post_process_yaml_items = _collect_post_process_yaml_mappings(
                binary_dir,
                sorted_skill_names,
                skill_map,
                platform,
                debug=debug,
            )
        except Exception as exc:
            startup_post_process_failed = True
            fail_count += 1
            _report_post_process_status(
                reporting,
                job_id,
                TaskStatus.FAILED,
                ProcessPhase.FINISHED,
                reason=ProcessReason.UNKNOWN_ERROR,
                error=str(exc),
            )
            if debug:
                print(f"  Post-process preflight collection failed: {exc}")

    if not should_start_binary_processing(
        skills_to_process,
        vcall_targets,
        startup_post_process_yaml_items,
    ):
        if startup_post_process_failed:
            print("  Post-process preflight failed before IDA startup")
        else:
            if rename:
                _report_post_process_status(
                    reporting,
                    job_id,
                    TaskStatus.SKIPPED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.OPTIONAL_OUTPUT_ABSENT,
                )
            print(
                "  All skills already have yaml files and no vcall_finder/post_process targets remain, skipping IDA startup"
            )
        return success_count, fail_count, skip_count

    # Refuse to start IDA if an `.id0` lock file exists next to the binary —
    # that means another IDA instance currently has this IDB open, and starting
    # idalib-mcp on top of it would corrupt the database.
    lock_file = f"{binary_path}.id0"
    if os.path.exists(lock_file):
        print(
            f"  Failed: IDB lock file detected ({lock_file}); another IDA instance "
            f"has this database open. Close it and retry."
        )
        post_process_failure = 1 if startup_post_process_yaml_items else 0
        _abort_binary_reporting(
            reporting,
            job_id,
            ProcessReason.MCP_UNAVAILABLE,
            "IDB lock file prevented IDA startup",
        )
        return (
            success_count,
            fail_count + len(skills_to_process) + len(vcall_targets) + post_process_failure,
            skip_count,
        )

    # Start idalib-mcp
    process = start_idalib_mcp(binary_path, host, port, ida_args, debug)
    if process is None:
        post_process_failure = 1 if startup_post_process_yaml_items else 0
        _abort_binary_reporting(
            reporting,
            job_id,
            ProcessReason.MCP_UNAVAILABLE,
            "Unable to start the IDA MCP process",
        )
        return (
            success_count,
            fail_count + len(skills_to_process) + len(vcall_targets) + post_process_failure,
            skip_count,
        )

    if reporting is not None and job_id is not None:
        reporting.emit_task_status(job_id, TaskStatus.RUNNING, ProcessPhase.VALIDATING_BINARY)
    force_local_process_stop = False
    recovery_budget = McpRecoveryBudget()
    try:
        process, verified = verify_owned_mcp_with_single_recovery(
            process,
            binary_path,
            platform,
            host,
            port,
            ida_args,
            debug,
            recovery_budget=recovery_budget,
        )
        if not verified:
            if _has_ida_database(binary_path):
                print(
                    "  Existing IDA database failed binary identity verification; rebuilding from the original binary"
                )
                stop_idalib_mcp_process(process, debug=debug)
                released = wait_for_port_release(host, port)
                if debug and not released:
                    print(f"  MCP port {host}:{port} remained in use before IDB rebuild")
                removed = _invalidate_ida_database(binary_path, debug=debug)
                if removed:
                    print(f"  Removed stale IDA database files: {', '.join(removed)}")
                process = start_idalib_mcp(binary_path, host, port, ida_args, debug)
                if process is not None:
                    process, verified = verify_owned_mcp_with_single_recovery(
                        process,
                        binary_path,
                        platform,
                        host,
                        port,
                        ida_args,
                        debug,
                        recovery_budget=recovery_budget,
                    )

        if not verified:
            pending_count = _pending_binary_work_count(
                skills_to_process=skills_to_process,
                vcall_targets=vcall_targets,
                post_process_yaml_items=startup_post_process_yaml_items,
            )
            fail_count += pending_count
            force_local_process_stop = True
            print(
                f"  Aborting current binary after opened binary verification failure ({pending_count} pending work item(s))"
            )
            _abort_binary_reporting(
                reporting,
                job_id,
                ProcessReason.BINARY_VERIFICATION_FAILED,
                "Opened binary verification failed",
            )
            return success_count, fail_count, skip_count

        # Process each skill: try preprocess first, then run_skill if needed
        abort_binary_processing = False
        for skill_index, (
            skill_name,
            required_outputs,
            optional_outputs,
            preprocess_outputs,
            skill_max_retries,
        ) in enumerate(skills_to_process):
            if should_skip_skill_for_existing_outputs(required_outputs, optional_outputs):
                print(f"  Skipping skill: {skill_name} (all outputs exist)")
                skip_count += 1
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.SKIPPED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.EXISTING_OUTPUTS,
                )
                continue

            skill = skill_map[skill_name]
            try:
                skip_for_existing_artifacts, _skip_paths = should_skip_skill_for_existing_artifacts(
                    binary_dir,
                    skill,
                    platform,
                )
            except ValueError as e:
                fail_count += 1
                print(f"  Failed: {skill_name} ({e})")
                _report_skill_status(reporting, job_id, skill_name, TaskStatus.RUNNING, ProcessPhase.PREFLIGHT)
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.FAILED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.INVALID_INPUT,
                    error=str(e),
                )
                continue
            if skip_for_existing_artifacts:
                print(f"  Skipping skill: {skill_name} (all skip_if_exists artifacts exist)")
                skip_count += 1
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.SKIPPED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.SKIP_IF_EXISTS,
                )
                continue

            print(f"  Start skill: {skill_name}")
            _report_skill_status(reporting, job_id, skill_name, TaskStatus.RUNNING, ProcessPhase.WAITING_FOR_MCP)

            # Ensure MCP connection is alive before running the skill
            process, mcp_ok = ensure_mcp_available(
                process,
                binary_path,
                host,
                port,
                ida_args,
                debug,
                recovery_budget=recovery_budget,
            )
            if not mcp_ok:
                remaining = _pending_binary_work_count(
                    skills_to_process=skills_to_process,
                    skill_index=skill_index,
                    vcall_targets=vcall_targets,
                    post_process_yaml_items=startup_post_process_yaml_items,
                )
                fail_count += remaining
                print(f"  Failed to restore MCP connection, aborting remaining {remaining} work item(s)")
                _abort_binary_reporting(
                    reporting,
                    job_id,
                    ProcessReason.MCP_UNAVAILABLE,
                    "MCP connection could not be restored",
                )
                abort_binary_processing = True
                break
            process, verified = verify_owned_mcp_with_single_recovery(
                process,
                binary_path,
                platform,
                host,
                port,
                ida_args,
                debug,
                recovery_budget=recovery_budget,
            )
            if not verified:
                remaining = _pending_binary_work_count(
                    skills_to_process=skills_to_process,
                    skill_index=skill_index,
                    vcall_targets=vcall_targets,
                    post_process_yaml_items=startup_post_process_yaml_items,
                )
                fail_count += remaining
                force_local_process_stop = True
                print(
                    "  Aborting current binary after opened binary verification failure "
                    f"({remaining} pending work item(s))"
                )
                _abort_binary_reporting(
                    reporting,
                    job_id,
                    ProcessReason.BINARY_VERIFICATION_FAILED,
                    "Opened binary verification failed",
                )
                abort_binary_processing = True
                break

            # Resolve required and optional input declarations before running the skill.
            _report_skill_status(reporting, job_id, skill_name, TaskStatus.RUNNING, ProcessPhase.VALIDATING_INPUTS)
            platform_input_key = f"expected_input_{platform}"
            combined_input = list(skill.get("expected_input", []) or [])
            combined_input += list(skill.get(platform_input_key, []) or [])
            platform_optional_input_key = f"optional_input_{platform}"
            combined_optional_input = list(skill.get("optional_input", []) or [])
            combined_optional_input += list(skill.get(platform_optional_input_key, []) or [])
            try:
                expected_inputs = expand_expected_paths(binary_dir, combined_input, platform)
                optional_inputs = expand_expected_paths(binary_dir, combined_optional_input, platform)
            except ValueError as e:
                fail_count += 1
                print(f"  Failed: {skill_name} ({e})")
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.FAILED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.INVALID_INPUT,
                    error=str(e),
                )
                continue
            overlapping_inputs = sorted(
                set(map(os.path.normcase, expected_inputs)) & set(map(os.path.normcase, optional_inputs))
            )
            if overlapping_inputs:
                fail_count += 1
                print(f"  Failed: {skill_name} (input declared as both expected and optional)")
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.FAILED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.INVALID_INPUT,
                    payload={"overlapping_inputs": overlapping_inputs},
                )
                continue
            missing_inputs = [p for p in expected_inputs if not os.path.exists(p)]
            if missing_inputs:
                fail_count += 1
                missing_names = [os.path.basename(p) for p in missing_inputs]
                print(f"  Failed: {skill_name} (missing expected_input: {', '.join(missing_names)})")
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.FAILED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.MISSING_INPUT,
                    payload={"missing_inputs": missing_inputs},
                )
                continue
            missing_optional_inputs = [p for p in optional_inputs if not os.path.exists(p)]
            if missing_optional_inputs:
                missing_optional_names = [os.path.basename(p) for p in missing_optional_inputs]
                print(f"    Optional input missing: {', '.join(missing_optional_names)}")
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.RUNNING,
                    ProcessPhase.VALIDATING_INPUTS,
                    payload={"missing_optional_inputs": missing_optional_inputs},
                )
            invalid_expected_inputs = _run_validate_expected_input_artifacts_via_mcp(
                host=host,
                port=port,
                expected_inputs=expected_inputs,
                platform=platform,
                binary_dir=binary_dir,
                expected_binary=binary_path,
                debug=debug,
                config_path=config_path,
                category_map=category_map,
            )
            if invalid_expected_inputs:
                fail_count += 1
                invalid_label = "artifact" if len(invalid_expected_inputs) == 1 else "artifacts"
                print(
                    f"  Failed: {skill_name} (invalid expected_input {invalid_label}: "
                    f"{' | '.join(invalid_expected_inputs)})"
                )
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.FAILED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.INVALID_INPUT,
                    payload={"invalid_inputs": invalid_expected_inputs},
                )
                continue
            existing_optional_inputs = [path for path in optional_inputs if os.path.exists(path)]
            invalid_optional_inputs = []
            if existing_optional_inputs:
                invalid_optional_inputs = _run_validate_expected_input_artifacts_via_mcp(
                    host=host,
                    port=port,
                    expected_inputs=existing_optional_inputs,
                    platform=platform,
                    binary_dir=binary_dir,
                    expected_binary=binary_path,
                    debug=debug,
                    config_path=config_path,
                    category_map=category_map,
                )
            if invalid_optional_inputs:
                fail_count += 1
                invalid_label = "artifact" if len(invalid_optional_inputs) == 1 else "artifacts"
                print(
                    f"  Failed: {skill_name} (invalid optional_input {invalid_label}: "
                    f"{' | '.join(invalid_optional_inputs)})"
                )
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.FAILED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.INVALID_INPUT,
                    payload={"invalid_optional_inputs": invalid_optional_inputs},
                )
                continue
            process, verified = verify_owned_mcp_with_single_recovery(
                process,
                binary_path,
                platform,
                host,
                port,
                ida_args,
                debug,
                recovery_budget=recovery_budget,
            )
            if not verified:
                remaining = _pending_binary_work_count(
                    skills_to_process=skills_to_process,
                    skill_index=skill_index,
                    vcall_targets=vcall_targets,
                    post_process_yaml_items=startup_post_process_yaml_items,
                )
                fail_count += remaining
                force_local_process_stop = True
                print(
                    "  Aborting current binary after opened binary verification failure "
                    f"({remaining} pending work item(s))"
                )
                _abort_binary_reporting(
                    reporting,
                    job_id,
                    ProcessReason.BINARY_VERIFICATION_FAILED,
                    "Opened binary verification failed",
                )
                abort_binary_processing = True
                break

            preprocess_status = PREPROCESS_STATUS_NO_SCRIPT
            _report_skill_status(reporting, job_id, skill_name, TaskStatus.RUNNING, ProcessPhase.PREPROCESSING)
            if skip_pp:
                print(f"    Skipping preprocess: {skill_name} (-skip_pp)")
            else:
                # Try preprocessing first. Some preprocessors can run without old YAMLs.
                old_yaml_map = None
                if old_binary_dir:
                    old_yaml_map = {}
                    for new_path in preprocess_outputs:
                        filename = os.path.basename(new_path)
                        old_path = os.path.join(old_binary_dir, filename)
                        old_yaml_map[new_path] = old_path

                try:
                    preprocess_status = _run_preprocess_single_skill_via_mcp(
                        host=host,
                        port=port,
                        skill_name=skill_name,
                        expected_outputs=preprocess_outputs,
                        expected_inputs=expected_inputs,
                        optional_inputs=optional_inputs,
                        old_yaml_map=old_yaml_map,
                        new_binary_dir=binary_dir,
                        platform=platform,
                        expected_binary=binary_path,
                        debug=debug,
                        llm_model=llm_model,
                        llm_apikey=llm_apikey,
                        llm_baseurl=llm_baseurl,
                        llm_temperature=llm_temperature,
                        llm_effort=llm_effort,
                        llm_fake_as=llm_fake_as,
                        llm_max_retries=skill_max_retries,
                        symbol_aliases=symbol_aliases,
                    )
                except Exception as e:
                    report_preprocess_exception(skill_name, "runner dispatch", e, debug=debug)
                    preprocess_status = PREPROCESS_STATUS_FAILED

            if preprocess_status is True or preprocess_status == PREPROCESS_STATUS_SUCCESS:
                preprocess_status = PREPROCESS_STATUS_SUCCESS
            elif preprocess_status == PREPROCESS_STATUS_ABSENT_OK:
                preprocess_status = PREPROCESS_STATUS_ABSENT_OK
            elif preprocess_status == PREPROCESS_STATUS_NO_SCRIPT:
                preprocess_status = PREPROCESS_STATUS_NO_SCRIPT
            else:
                preprocess_status = PREPROCESS_STATUS_FAILED

            if preprocess_status == PREPROCESS_STATUS_SUCCESS:
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.RUNNING,
                    ProcessPhase.VALIDATING_OUTPUTS,
                )
                missing_required_outputs = [p for p in required_outputs if not os.path.exists(p)]
                optional_output_generated = any(os.path.exists(p) for p in optional_outputs)
                if missing_required_outputs:
                    fail_count += 1
                    missing_names = [os.path.basename(p) for p in missing_required_outputs]
                    print(f"  Pre-processed but missing expected_output: {skill_name} ({', '.join(missing_names)})")
                    _report_skill_status(
                        reporting,
                        job_id,
                        skill_name,
                        TaskStatus.FAILED,
                        ProcessPhase.FINISHED,
                        reason=ProcessReason.PREPROCESS_FAILED,
                        payload={"missing_outputs": missing_required_outputs},
                    )
                    if skip_error:
                        print("  Continuing after preprocess output validation failure (-skip_error)")
                        continue
                    print("  Aborting remaining skills after preprocess output validation failure")
                    abort_binary_processing = True
                    break
                elif not required_outputs and optional_outputs and not optional_output_generated:
                    skip_count += 1
                    print(f"  Skipping skill: {skill_name} (optional outputs not generated)")
                    _report_skill_status(
                        reporting,
                        job_id,
                        skill_name,
                        TaskStatus.SKIPPED,
                        ProcessPhase.FINISHED,
                        reason=ProcessReason.OPTIONAL_OUTPUT_ABSENT,
                    )
                else:
                    success_count += 1
                    print(f"  Pre-processed: {skill_name} OK")
                    _report_skill_status(
                        reporting,
                        job_id,
                        skill_name,
                        TaskStatus.SUCCEEDED,
                        ProcessPhase.FINISHED,
                    )
                continue
            if preprocess_status == PREPROCESS_STATUS_ABSENT_OK:
                skip_count += 1
                print(f"  Skipping skill: {skill_name} (preprocess reported absent_ok)")
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.SKIPPED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.PREPROCESS_ABSENT,
                )
                continue
            if preprocess_status == PREPROCESS_STATUS_FAILED:
                print(f"    Preprocess failed: {skill_name}; falling back to AGENT SKILL")

            if should_skip_skill_for_existing_outputs(required_outputs, optional_outputs):
                print(f"  Skipping skill: {skill_name} (all outputs exist)")
                skip_count += 1
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.SKIPPED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.EXISTING_OUTPUTS,
                )
                continue

            if not required_outputs and optional_outputs and not skip_pp:
                skip_count += 1
                print(f"  Skipping skill: {skill_name} (optional outputs not generated)")
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.SKIPPED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.OPTIONAL_OUTPUT_ABSENT,
                )
                continue

            process, verified = verify_owned_mcp_with_single_recovery(
                process,
                binary_path,
                platform,
                host,
                port,
                ida_args,
                debug,
                recovery_budget=recovery_budget,
            )
            if not verified:
                remaining = _pending_binary_work_count(
                    skills_to_process=skills_to_process,
                    skill_index=skill_index,
                    vcall_targets=vcall_targets,
                    post_process_yaml_items=startup_post_process_yaml_items,
                )
                fail_count += remaining
                force_local_process_stop = True
                print(
                    "  Aborting current binary after opened binary verification failure "
                    f"({remaining} pending work item(s))"
                )
                _abort_binary_reporting(
                    reporting,
                    job_id,
                    ProcessReason.BINARY_VERIFICATION_FAILED,
                    "Opened binary verification failed",
                )
                abort_binary_processing = True
                break

            print(f"    Starting agent skill: {skill_name}")
            _report_skill_status(reporting, job_id, skill_name, TaskStatus.RUNNING, ProcessPhase.AGENT_FALLBACK)
            progress_callback = _build_agent_progress_callback(reporting, job_id, skill_name)

            if run_skill(
                skill_name,
                agent,
                debug,
                expected_yaml_paths=required_outputs,
                max_retries=skill_max_retries,
                agent_model=agent_model,
                progress_callback=progress_callback,
            ):
                optional_output_generated = any(os.path.exists(path) for path in optional_outputs)
                if not required_outputs and optional_outputs and not optional_output_generated:
                    skip_count += 1
                    print("    Skipped: optional outputs not generated")
                    _report_skill_status(
                        reporting,
                        job_id,
                        skill_name,
                        TaskStatus.SKIPPED,
                        ProcessPhase.FINISHED,
                        reason=ProcessReason.OPTIONAL_OUTPUT_ABSENT,
                    )
                else:
                    success_count += 1
                    print("    Success")
                    _report_skill_status(
                        reporting,
                        job_id,
                        skill_name,
                        TaskStatus.SUCCEEDED,
                        ProcessPhase.FINISHED,
                    )
            else:
                fail_count += 1
                print("    Failed")
                _report_skill_status(
                    reporting,
                    job_id,
                    skill_name,
                    TaskStatus.FAILED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.AGENT_FAILED,
                )
                if skip_error:
                    print("  Continuing after fallback skill failure (-skip_error)")
                    continue
                print("  Aborting remaining skills after fallback skill failure")
                abort_binary_processing = True
                break

        if abort_binary_processing:
            _abort_binary_reporting(
                reporting,
                job_id,
                ProcessReason.UPSTREAM_ABORTED,
                "Remaining binary tasks were aborted after a skill failure",
            )
            return success_count, fail_count, skip_count

        for object_index, object_name in enumerate(vcall_targets):
            _report_vcall_status(
                reporting,
                job_id,
                object_name,
                TaskStatus.RUNNING,
                ProcessPhase.WAITING_FOR_MCP,
            )
            process, mcp_ok = ensure_mcp_available(
                process,
                binary_path,
                host,
                port,
                ida_args,
                debug,
                recovery_budget=recovery_budget,
            )
            if not mcp_ok:
                remaining = len(vcall_targets) - object_index
                fail_count += remaining
                print(f"  Failed to restore MCP connection, aborting remaining {remaining} vcall_finder target(s)")
                _abort_vcall_reporting(
                    reporting,
                    job_id,
                    vcall_targets[object_index:],
                    ProcessReason.MCP_UNAVAILABLE,
                    "MCP connection could not be restored",
                )
                break
            process, verified = verify_owned_mcp_with_single_recovery(
                process,
                binary_path,
                platform,
                host,
                port,
                ida_args,
                debug,
                recovery_budget=recovery_budget,
            )
            if not verified:
                remaining = _pending_binary_work_count(
                    vcall_targets=vcall_targets,
                    vcall_index=object_index,
                    post_process_yaml_items=startup_post_process_yaml_items,
                )
                fail_count += remaining
                force_local_process_stop = True
                print(
                    "  Aborting current binary after opened binary verification failure "
                    f"({remaining} pending work item(s))"
                )
                _abort_binary_reporting(
                    reporting,
                    job_id,
                    ProcessReason.BINARY_VERIFICATION_FAILED,
                    "Opened binary verification failed",
                )
                abort_binary_processing = True
                break

            print(f"  Processing vcall_finder: {object_name}")
            _report_vcall_status(
                reporting,
                job_id,
                object_name,
                TaskStatus.RUNNING,
                ProcessPhase.VCALL_EXPORT,
            )
            try:
                export_stats = asyncio.run(
                    preprocess_single_vcall_object_via_mcp(
                        host=host,
                        port=port,
                        output_root=vcall_output_dir,
                        gamever=gamever,
                        module_name=module_name,
                        platform=platform,
                        object_name=object_name,
                        expected_binary=binary_path,
                        debug=debug,
                    )
                )
            except Exception as exc:
                fail_count += 1
                print(f"    Failed to export vcall_finder for {object_name}: {exc}")
                _report_vcall_status(
                    reporting,
                    job_id,
                    object_name,
                    TaskStatus.FAILED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.UNKNOWN_ERROR,
                    error=str(exc),
                )
                continue

            object_status = export_stats["status"]
            if export_stats.get("object_found") is True and found_vcall_objects is not None:
                found_vcall_objects.add(object_name)
            if object_status == "success":
                success_count += 1
                _report_vcall_status(
                    reporting,
                    job_id,
                    object_name,
                    TaskStatus.SUCCEEDED,
                    ProcessPhase.FINISHED,
                )
            elif object_status == "failed":
                fail_count += 1
                _report_vcall_status(
                    reporting,
                    job_id,
                    object_name,
                    TaskStatus.FAILED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.UNKNOWN_ERROR,
                    payload=export_stats,
                )
            else:
                skip_count += 1
                _report_vcall_status(
                    reporting,
                    job_id,
                    object_name,
                    TaskStatus.SKIPPED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.OPTIONAL_OUTPUT_ABSENT,
                    payload=export_stats,
                )

            exported_functions = export_stats["exported_functions"]
            failed_functions = export_stats["failed_functions"]
            skipped_functions = export_stats["skipped_functions"]
            if debug or failed_functions:
                print(
                    "    vcall_finder summary: "
                    f"status={object_status}, "
                    f"exported_functions={exported_functions}, "
                    f"failed_functions={failed_functions}, "
                    f"skipped_functions={skipped_functions}"
                )

        if abort_binary_processing:
            _abort_binary_reporting(
                reporting,
                job_id,
                ProcessReason.UPSTREAM_ABORTED,
                "Remaining binary tasks were aborted after binary verification failure",
            )
            return success_count, fail_count, skip_count

        post_process_yaml_items = []
        post_process_collection_failed = False
        if rename and not startup_post_process_failed:
            try:
                post_process_yaml_items = _collect_post_process_yaml_mappings(
                    binary_dir,
                    sorted_skill_names,
                    skill_map,
                    platform,
                    debug=debug,
                )
            except Exception as exc:
                post_process_collection_failed = True
                fail_count += 1
                _report_post_process_status(
                    reporting,
                    job_id,
                    TaskStatus.FAILED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.UNKNOWN_ERROR,
                    error=str(exc),
                )
                if debug:
                    print(f"  Post-process final collection failed: {exc}")

        if rename and post_process_collection_failed:
            print("  Post-process failed during YAML recollection")
        elif rename and post_process_yaml_items:
            _report_post_process_status(
                reporting,
                job_id,
                TaskStatus.RUNNING,
                ProcessPhase.POSTPROCESSING,
            )
            process, mcp_ok = ensure_mcp_available(
                process,
                binary_path,
                host,
                port,
                ida_args,
                debug,
                recovery_budget=recovery_budget,
            )
            if not mcp_ok:
                fail_count += 1
                print("  Failed to restore MCP connection, skipping post_process")
                _report_post_process_status(
                    reporting,
                    job_id,
                    TaskStatus.ABORTED,
                    ProcessPhase.FINISHED,
                    reason=ProcessReason.MCP_UNAVAILABLE,
                )
            else:
                process, verified = verify_owned_mcp_with_single_recovery(
                    process,
                    binary_path,
                    platform,
                    host,
                    port,
                    ida_args,
                    debug,
                    recovery_budget=recovery_budget,
                )
                if not verified:
                    fail_count += 1
                    force_local_process_stop = True
                    print("  Aborting current binary after opened binary verification failure (1 pending work item(s))")
                    _report_post_process_status(
                        reporting,
                        job_id,
                        TaskStatus.ABORTED,
                        ProcessPhase.FINISHED,
                        reason=ProcessReason.BINARY_VERIFICATION_FAILED,
                    )
                    return success_count, fail_count, skip_count
                try:
                    post_process_ok = _run_post_process_expected_outputs_via_mcp(
                        host=host,
                        port=port,
                        yaml_items=post_process_yaml_items,
                        expected_binary=binary_path,
                        debug=debug,
                    )
                except Exception as exc:
                    post_process_ok = False
                    if debug:
                        print(f"  Post-process error: {exc}")
                if not post_process_ok:
                    fail_count += 1
                    print("  Post-process failed")
                    _report_post_process_status(
                        reporting,
                        job_id,
                        TaskStatus.FAILED,
                        ProcessPhase.FINISHED,
                        reason=ProcessReason.UNKNOWN_ERROR,
                    )
                else:
                    _report_post_process_status(
                        reporting,
                        job_id,
                        TaskStatus.SUCCEEDED,
                        ProcessPhase.FINISHED,
                    )
        elif rename and not startup_post_process_failed:
            _report_post_process_status(
                reporting,
                job_id,
                TaskStatus.SKIPPED,
                ProcessPhase.FINISHED,
                reason=ProcessReason.OPTIONAL_OUTPUT_ABSENT,
            )

    finally:
        # Avoid sending qexit to an unverified MCP endpoint; stop only our process.
        if force_local_process_stop:
            print("  Stopping current idalib-mcp after opened binary verification failure")
            stop_idalib_mcp_process(process, debug=debug)
            released = wait_for_port_release(host, port)
            if debug and not released:
                print(f"  MCP port {host}:{port} remained in use after shutdown")
        else:
            quit_ida_gracefully(process, host, port, expected_binary=binary_path, debug=debug)

    return success_count, fail_count, skip_count


def _print_main_configuration(args):
    print(f"Config file: {args.configyaml}")
    print(f"Binary directory: {args.bindir}")
    print(f"Game version: {args.gamever}")
    print(f"Old game version: {args.oldgamever or '(disabled)'}")
    print(f"Platforms: {', '.join(args.platforms)}")
    print(f"Modules filter: {args.modules}")
    if getattr(args, "skill", None):
        print(f"Skill filter: {args.skill}")
    print(f"Agent: {args.agent}")
    if args.ida_args:
        print(f"IDA args: {args.ida_args}")
    if args.debug:
        print("Debug mode: enabled")
    if getattr(args, "skip_error", False):
        print("Skip error mode: enabled")
    if getattr(args, "skip_pp", False):
        print("Agent Skill only mode: enabled (-skip_pp)")


def _select_execution_modules(modules, args):
    if args.module_filter is not None:
        available_module_names = {module["name"] for module in modules}
        missing_module_names = [name for name in args.module_filter if name not in available_module_names]
        if missing_module_names:
            raise ValueError(f"Module(s) not found: {', '.join(missing_module_names)}")
    selected = _select_modules_by_skill(modules, getattr(args, "skill", None), args.module_filter)
    if args.module_filter is not None:
        selected = [module for module in selected if module["name"] in args.module_filter]
    selected = [
        module
        for module in selected
        if module["skills"] or resolve_module_vcall_targets(module, args.vcall_finder_filter)
    ]
    for fallback_index, module in enumerate(selected):
        module.setdefault("stage_index", fallback_index)
    return selected


def _resolve_old_binary_dir(args, module_name, module_path):
    if not args.oldgamever:
        return None
    old_binary_path = get_binary_path(args.bindir, args.oldgamever, module_name, module_path)
    candidate_dir = os.path.dirname(old_binary_path)
    if os.path.isdir(candidate_dir):
        return candidate_dir
    if args.debug:
        print(f"  Old version directory not found: {candidate_dir}")
    return None


def _invoke_process_binary(
    args,
    module,
    platform,
    binary_path,
    old_binary_dir,
    vcall_targets,
    reporting,
    job_id,
    found_vcall_objects,
):
    return process_binary(
        binary_path,
        module["skills"],
        args.agent,
        DEFAULT_HOST,
        DEFAULT_PORT,
        args.ida_args,
        platform,
        args.debug,
        max_retries=args.maxretry,
        old_binary_dir=old_binary_dir,
        gamever=args.gamever,
        module_name=module["name"],
        vcall_targets=vcall_targets,
        llm_model=args.llm_model,
        llm_apikey=args.llm_apikey,
        llm_baseurl=args.llm_baseurl,
        llm_temperature=args.llm_temperature,
        llm_effort=args.llm_effort,
        llm_fake_as=args.llm_fake_as,
        rename=args.rename,
        agent_model=getattr(args, "agent_model", DEFAULT_AGENT_MODEL),
        skip_error=getattr(args, "skip_error", False),
        skip_pp=getattr(args, "skip_pp", False),
        reporting=reporting,
        job_id=job_id,
        config_path=args.configyaml,
        category_map=args.artifact_category_map,
        symbol_aliases=args.symbol_aliases,
        found_vcall_objects=found_vcall_objects,
    )


def _skip_platform_job(reporting, job_id, status, reason, message, task_status=TaskStatus.SKIPPED):
    reporting.emit_task_status(job_id, status, ProcessPhase.FINISHED, reason=reason, message=message)
    reporting.finish_job_tasks(job_id, task_status, reason, message)


def _process_platform(args, module, platform, vcall_targets, reporting, found_vcall_objects):
    job_id = build_job_id(build_stage_id(module.get("stage_index", 0), module["name"]), platform)
    module_path = module.get(f"path_{platform}")
    work_count = len(module["skills"]) + len(vcall_targets)
    if not module_path:
        print(f"\n  Platform {platform}: No path defined, skipping")
        _skip_platform_job(reporting, job_id, TaskStatus.SKIPPED, ProcessReason.PLATFORM_MISMATCH, "No binary path")
        return 0, 0, work_count

    binary_path = get_binary_path(args.bindir, args.gamever, module["name"], module_path)
    print(f"\n  Platform: {platform}")
    print(f"  Binary: {binary_path}")
    if not os.path.exists(binary_path):
        print(f"  Error: Binary file not found: {binary_path}")
        print("  Hint: Run download_bin.py first to download binaries")
        _skip_platform_job(
            reporting,
            job_id,
            TaskStatus.SKIPPED,
            ProcessReason.MISSING_BINARY,
            "Binary not found",
            task_status=TaskStatus.ABORTED,
        )
        return 0, 0, work_count

    reporting.emit_task_status(job_id, TaskStatus.RUNNING, ProcessPhase.WAITING_FOR_MCP)
    old_binary_dir = _resolve_old_binary_dir(args, module["name"], module_path)
    counts = _invoke_process_binary(
        args,
        module,
        platform,
        binary_path,
        old_binary_dir,
        vcall_targets,
        reporting,
        job_id,
        found_vcall_objects,
    )
    job_status = TaskStatus.FAILED if counts[1] else TaskStatus.SUCCEEDED
    reporting.emit_task_status(job_id, job_status, ProcessPhase.FINISHED)
    return counts


def _print_module_header(module, vcall_targets):
    print(f"\n{'=' * 60}")
    print(f"Module: {module['name']}")
    print(f"Skills: {len(module['skills'])}")
    if vcall_targets:
        print(f"VCall targets: {len(vcall_targets)}")
    print(f"{'=' * 60}")


def _aggregate_vcall_object(args, object_name):
    aggregate_kwargs = {
        "base_dir": "vcall_finder",
        "gamever": args.gamever,
        "object_name": object_name,
        "model": args.llm_model,
        "api_key": args.llm_apikey,
        "base_url": args.llm_baseurl,
        "temperature": args.llm_temperature,
        "debug": args.debug,
    }
    aggregate_signature = inspect.signature(aggregate_vcall_results_for_object)
    if "effort" in aggregate_signature.parameters:
        aggregate_kwargs["effort"] = args.llm_effort
    if "fake_as" in aggregate_signature.parameters:
        aggregate_kwargs["fake_as"] = args.llm_fake_as
    return aggregate_vcall_results_for_object(**aggregate_kwargs)


def _run_vcall_aggregation(args, object_names, found_object_names=None):
    counts = [0, 0, 0]
    if not args.vcall_finder_filter or not object_names:
        return counts
    print("\nRunning vcall_finder LLM aggregation")
    found_object_names = set(object_names) if found_object_names is None else found_object_names
    for object_name in object_names:
        if object_name not in found_object_names:
            counts[1] += 1
            print(f"  Failed to find vcall_finder object in selected modules/platforms: {object_name}")
            continue
        print(f"  Aggregating vcall_finder: {object_name}")
        try:
            stats = _aggregate_vcall_object(args, object_name)
            status_index = {"success": 0, "failed": 1}.get(stats["status"], 2)
            counts[status_index] += 1
            if args.debug or stats["failed"]:
                print(
                    "    vcall_finder aggregation summary: "
                    f"status={stats['status']}, processed={stats['processed']}, failed={stats['failed']}"
                )
        except Exception as exc:
            counts[1] += 1
            print(f"  Failed to aggregate {object_name}: {exc}")
    return counts


def _execute_analysis(args, modules, reporting):
    totals = [0, 0, 0]
    all_vcall_objects = list((args.vcall_finder_filter or {}).get("names", []))
    found_vcall_objects = set()
    abort_processing = False
    for module in modules:
        vcall_targets = resolve_module_vcall_targets(module, args.vcall_finder_filter)
        _print_module_header(module, vcall_targets)
        for platform in args.platforms:
            counts = _process_platform(args, module, platform, vcall_targets, reporting, found_vcall_objects)
            totals = [total + count for total, count in zip(totals, counts)]
            if counts[1] and not getattr(args, "skip_error", False):
                abort_processing = True
                print("  Aborting remaining modules after binary processing failure")
                break
            if counts[1]:
                print("  Continuing after binary processing failure (-skip_error)")
        if abort_processing:
            break
    if not abort_processing:
        aggregate_counts = _run_vcall_aggregation(args, all_vcall_objects, found_vcall_objects)
        totals = [total + count for total, count in zip(totals, aggregate_counts)]
    return totals, abort_processing


def _print_summary(totals):
    print(f"\n{'=' * 60}")
    print("Summary")
    print(f"{'=' * 60}")
    print(f"  Successful: {totals[0]}")
    print(f"  Failed: {totals[1]}")
    print(f"  Skipped: {totals[2]}")


def main():
    """Main entry point."""
    args = parse_args()
    try:
        args.configyaml = str(resolve_analysis_config(args.gamever, args.configyaml))
    except AnalysisConfigError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    config_document = _load_config_document(args.configyaml)
    args.artifact_category_map = _artifact_symbol_category_map_from_document(config_document)
    args.symbol_aliases = _symbol_alias_map_from_document(config_document)
    _print_main_configuration(args)

    print("\nParsing config...")
    modules = parse_config(args.configyaml, config_document=config_document)
    validate_module_skill_dependencies(modules)
    print(f"Found {len(modules)} modules")
    if not modules:
        print("No modules found in config.")
        sys.exit(0)
    try:
        modules = _select_execution_modules(modules, args)
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    try:
        plan = build_execution_plan(
            modules,
            platforms=args.platforms,
            bin_dir=args.bindir,
            gamever=args.gamever,
            vcall_finder_selector=args.vcall_finder_filter,
            include_post_process=args.rename,
        )
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    try:
        reporter = BestEffortProcessReporter(create_process_reporter(args))
    except ProcessReporterConfigurationError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    run_id = reporter.initialize_run(plan.to_dict(), run_id=getattr(args, "run_id", None))
    reporting = AnalysisReporting(reporter, run_id, plan)

    try:
        reporting.emit_run_status(RunStatus.RUNNING)
        reporter.heartbeat(run_id)
        totals, aborted = _execute_analysis(args, modules, reporting)
        abort_message = "Run aborted after an upstream failure" if aborted else "Task was not executed before run end"
        reporting.abort_pending(ProcessReason.UPSTREAM_ABORTED, abort_message)
        final_status = RunStatus.FAILED if totals[1] else RunStatus.SUCCEEDED
        reporting.emit_run_status(final_status)
        reporter.finalize_run(run_id, final_status, reporting.summary())
    except BaseException:
        reporting.abort_pending(ProcessReason.UNKNOWN_ERROR, "Run terminated by an unexpected exception")
        reporting.emit_run_status(RunStatus.FAILED)
        reporter.finalize_run(run_id, RunStatus.FAILED, reporting.summary())
        raise
    finally:
        reporter.flush()
        reporter.close()

    _print_summary(totals)
    if totals[1] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
