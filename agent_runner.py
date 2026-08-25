"""Agent CLI execution, MCP preflight, retries, and output validation."""

import json
import os
import re
import shlex
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path


SKILL_TIMEOUT = 1200
MCP_LIST_TIMEOUT = 30
SKILL_ERROR_RE = re.compile(r"<skill_error>\s*(.*?)\s*</skill_error>", re.IGNORECASE | re.DOTALL)
CYBERSECURITY_BLOCK_MARKERS = (
    "This chat was flagged for possible cybersecurity risk",
    "flagged this message for a cybersecurity topic",
)
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_MCP_PREFLIGHT_DONE: set[tuple[str, str | None]] = set()
_MCP_PREFLIGHT_FAILED: set[tuple[str, str | None]] = set()
CLAUDE_SKILL_RUNNER_SETTINGS = ".claude/skill_runner.settings.json"
SKILL_RUNNER_SYSTEM_PROMPT = ".claude/SKILL_RUNNER.md"
OPENCODE_SKILL_RUNNER_CONFIG = ".opencode/skill_runner.config.json"
DEFAULT_AGENT_MODEL = ""


@dataclass(frozen=True)
class AgentCommand:
    args: list[str]
    input_text: str | None
    retry_target_desc: str


def _detect_agent_kind(agent: str) -> str | None:
    agent_lower = agent.lower()
    if "claude" in agent_lower:
        return "claude"
    if "codex" in agent_lower:
        return "codex"
    if "opencode" in agent_lower:
        return "opencode"
    return None


def _extract_opencode_session_id(output: str) -> str | None:
    for line in (output or "").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        session_id = event.get("sessionID")
        if isinstance(session_id, str) and session_id:
            return session_id
    return None


def _extract_skill_error(*texts: str) -> str | None:
    merged_output = "\n".join(text for text in texts if text)
    match = SKILL_ERROR_RE.search(merged_output)
    if match is None:
        return None
    return match.group(1).strip()


def _extract_cybersecurity_block(*texts: str) -> str | None:
    merged_output = "\n".join(text for text in texts if text).casefold()
    for marker in CYBERSECURITY_BLOCK_MARKERS:
        if marker.casefold() in merged_output:
            return marker
    return None


def _mcp_list_contains_server(output, server_name="ida-pro-mcp"):
    if not output:
        return False
    normalized_output = ANSI_ESCAPE_RE.sub("", output)
    prefix = r"(?:[-*•●|│T—]\s*)*(?:[✓✗]\s*)?"
    pattern = re.compile(rf"(?m)^\s*{prefix}{re.escape(server_name)}(?:\s|:|$)")
    return bool(pattern.search(normalized_output))


def _format_mcp_list_output(output, limit=1200):
    text = (output or "").strip()
    if not text:
        return "<empty>"
    if len(text) > limit:
        text = text[:limit] + "... <truncated>"
    return "\n".join(f"      {line}" for line in text.splitlines())


def _agent_mcp_override_args(agent_kind: str, mcp_url: str | None) -> list[str]:
    if not mcp_url:
        return []
    if agent_kind == "claude":
        config = {
            "mcpServers": {
                "ida-pro-mcp": {
                    "type": "http",
                    "url": mcp_url,
                }
            }
        }
        return ["--mcp-config", json.dumps(config, separators=(",", ":")), "--strict-mcp-config"]
    if agent_kind == "codex":
        return [
            "-c",
            f"mcp_servers.ida-pro-mcp.url={json.dumps(mcp_url)}",
            "-c",
            "mcp_servers.ida-pro-mcp.required=true",
        ]
    return []


def _agent_process_env(agent_kind: str, mcp_url: str | None = None) -> dict[str, str] | None:
    if agent_kind != "opencode":
        return None
    env = os.environ.copy()
    env.update(
        {
            "OPENCODE_DISABLE_CLAUDE_CODE_PROMPT": "1",
            "OPENCODE_CONFIG": OPENCODE_SKILL_RUNNER_CONFIG,
        }
    )
    if mcp_url:
        env["OPENCODE_CONFIG_CONTENT"] = json.dumps(
            {
                "mcp": {
                    "ida-pro-mcp": {
                        "type": "remote",
                        "url": mcp_url,
                        "enabled": True,
                    }
                }
            },
            separators=(",", ":"),
        )
    return env


def _ensure_agent_mcp_preflight(agent, debug=False, server_name="ida-pro-mcp", mcp_url=None):
    preflight_key = (agent, mcp_url)
    if preflight_key in _MCP_PREFLIGHT_DONE:
        return True
    if preflight_key in _MCP_PREFLIGHT_FAILED:
        print("    Error: MCP preflight previously failed; refusing to start agent.")
        return False

    agent_kind = _detect_agent_kind(agent) or ""
    cmd = [agent, *_agent_mcp_override_args(agent_kind, mcp_url), "mcp", "list"]
    print(f"    Checking MCP server list: {' '.join(cmd)}")
    try:
        result = _run_process_with_stream_capture(
            cmd,
            debug=debug,
            timeout=MCP_LIST_TIMEOUT,
            env=_agent_process_env(agent_kind, mcp_url),
        )
    except subprocess.TimeoutExpired:
        _MCP_PREFLIGHT_FAILED.add(preflight_key)
        print(f"    Error: MCP list preflight timeout ({MCP_LIST_TIMEOUT} seconds): {' '.join(cmd)}")
        return False
    except FileNotFoundError:
        _MCP_PREFLIGHT_FAILED.add(preflight_key)
        print(f"    Error: Agent '{agent}' not found while running MCP list preflight.")
        return False
    except Exception as error:
        _MCP_PREFLIGHT_FAILED.add(preflight_key)
        print(f"    Error executing MCP list preflight: {error}")
        return False

    output = "\n".join(text for text in (result.stdout, result.stderr) if text)
    if _mcp_list_contains_server(output, server_name):
        _MCP_PREFLIGHT_DONE.add(preflight_key)
        return True

    _MCP_PREFLIGHT_FAILED.add(preflight_key)
    print(f"    Error: Required MCP server '{server_name}' is not listed by '{agent} mcp list'.")
    if result.returncode != 0:
        print(f"    mcp list return code: {result.returncode}")
    print(f"    mcp list output:\n{_format_mcp_list_output(output)}")
    return False


def _drain_text_stream(stream, chunks, forward_stream=None):
    try:
        for chunk in iter(stream.readline, ""):
            chunks.append(chunk)
            if forward_stream is not None:
                forward_stream.write(chunk)
                forward_stream.flush()
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _run_process_with_stream_capture(cmd, *, agent_input=None, debug=False, timeout=SKILL_TIMEOUT, env=None):
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if agent_input is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    if agent_input is not None and process.stdin is not None:
        process.stdin.write(agent_input)
        process.stdin.flush()
        process.stdin.close()

    stdout_chunks, stderr_chunks = [], []
    stdout_thread = threading.Thread(
        target=_drain_text_stream, args=(process.stdout, stdout_chunks, sys.stdout if debug else None)
    )
    stderr_thread = threading.Thread(
        target=_drain_text_stream, args=(process.stderr, stderr_chunks, sys.stderr if debug else None)
    )
    stdout_thread.start()
    stderr_thread.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=1)
        except Exception:
            pass
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)
        raise

    stdout_thread.join()
    stderr_thread.join()
    return subprocess.CompletedProcess(cmd, process.returncode, "".join(stdout_chunks), "".join(stderr_chunks))


def _strip_optional_frontmatter(prompt: str) -> str:
    stripped = prompt.strip()
    if not stripped.startswith("---"):
        return stripped
    lines = stripped.splitlines()
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            return "\n".join(lines[index + 1 :]).strip()
    return stripped


def _load_codex_developer_instructions(
    system_prompt_path: Path = Path(".claude/agents/sig-finder.md"),
) -> str | None:
    try:
        raw_prompt = system_prompt_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"    Error: Codex system prompt file not found: {system_prompt_path}")
        return None
    except OSError as error:
        print(f"    Error: Failed to read Codex system prompt from {system_prompt_path}: {error}")
        return None

    prompt = _strip_optional_frontmatter(raw_prompt)
    if not prompt:
        print(f"    Error: Codex system prompt is empty in {system_prompt_path}")
        return None
    return f"developer_instructions={json.dumps(prompt)}"


def _split_cli_args(raw_args: str) -> list[str]:
    text = str(raw_args or "").strip()
    if not text:
        return []
    try:
        return shlex.split(text, posix=False)
    except ValueError:
        return text.split()


def _agent_permission_args(agent_kind: str, *, claude_permission_mode: str = "") -> list[str]:
    if agent_kind == "opencode":
        return ["--auto"]
    if agent_kind == "codex":
        return []
    permission_mode = str(claude_permission_mode or "").strip() or "auto"
    return ["--permission-mode", permission_mode]


def _agent_model_args(agent_kind: str, agent_model: str = DEFAULT_AGENT_MODEL) -> list[str]:
    model = str(agent_model or "").strip()
    if not model:
        return []
    if agent_kind == "opencode" and "/" not in model:
        raise ValueError("OpenCode model must use provider/model format")
    return ["--model" if agent_kind == "claude" else "-m", model]


def _build_claude_base_args(
    *,
    agent: str,
    prompt_arg: str,
    agent_profile: str,
    session_id: str,
    is_retry: bool,
    permission_mode: str = "",
    extra_args: str = "",
    agent_model: str = DEFAULT_AGENT_MODEL,
    mcp_url: str | None = None,
) -> list[str]:
    args = [agent, "-p", prompt_arg, "--agent", agent_profile]
    args.extend(_agent_mcp_override_args("claude", mcp_url))
    args.extend(_agent_model_args("claude", agent_model))
    args.extend(["--settings", CLAUDE_SKILL_RUNNER_SETTINGS])
    args.extend(["--append-system-prompt-file", SKILL_RUNNER_SYSTEM_PROMPT])
    args.extend(_agent_permission_args("claude", claude_permission_mode=permission_mode))
    args.extend(_split_cli_args(extra_args))
    args.extend(["--resume" if is_retry else "--session-id", session_id])
    return args


def _build_codex_base_args(
    agent: str,
    developer_instructions: str,
    is_retry: bool,
    agent_model: str = DEFAULT_AGENT_MODEL,
    mcp_url: str | None = None,
) -> list[str]:
    args = [
        agent,
        "--profile",
        "skill_runner",
        "-c",
        developer_instructions,
    ]
    args.extend(_agent_mcp_override_args("codex", mcp_url))
    args.extend(_agent_model_args("codex", agent_model))
    args.extend(_agent_permission_args("codex"))
    args.append("exec")
    if is_retry:
        args.extend(["resume", "--last"])
    return args


def _build_opencode_base_args(
    agent: str,
    agent_profile: str,
    is_retry: bool,
    session_id: str | None,
    agent_model: str = DEFAULT_AGENT_MODEL,
) -> list[str]:
    args = [agent, "run", "--format", "json"]
    args.extend(_agent_model_args("opencode", agent_model))
    args.extend(_agent_permission_args("opencode"))
    if is_retry and session_id:
        args.extend(["--session", session_id])
    elif is_retry:
        args.append("--continue")
    args.extend(["--agent", agent_profile])
    return args


def _build_claude_command(
    agent: str,
    skill_name: str,
    session_id: str,
    is_retry: bool,
    agent_model: str = DEFAULT_AGENT_MODEL,
    mcp_url: str | None = None,
) -> AgentCommand:
    args = _build_claude_base_args(
        agent=agent,
        prompt_arg=f"/{skill_name}",
        agent_profile="sig-finder",
        session_id=session_id,
        is_retry=is_retry,
        agent_model=agent_model,
        mcp_url=mcp_url,
    )
    return AgentCommand(args, None, f"session {session_id}")


def _build_codex_command(
    agent: str,
    skill_name: str,
    developer_instructions: str,
    is_retry: bool,
    agent_model: str = DEFAULT_AGENT_MODEL,
    mcp_url: str | None = None,
) -> AgentCommand:
    args = _build_codex_base_args(agent, developer_instructions, is_retry, agent_model, mcp_url)
    args.append("-")
    return AgentCommand(args, f"Run SKILL: .claude/skills/{skill_name}/SKILL.md", "the latest codex session (--last)")


def _build_opencode_command(
    agent: str,
    skill_name: str,
    is_retry: bool,
    session_id: str | None,
    agent_model: str = DEFAULT_AGENT_MODEL,
) -> AgentCommand:
    args = _build_opencode_base_args(agent, "sig-finder", is_retry, session_id, agent_model)
    args.append(f"Run SKILL: .claude/skills/{skill_name}/SKILL.md")
    retry_target = f"OpenCode session {session_id}" if session_id else "the latest OpenCode session (--continue)"
    return AgentCommand(args, None, retry_target)


def _display_command(args: list[str]) -> list[str]:
    display_args = args
    for index, arg in enumerate(args[:-1]):
        if arg == "-c" and args[index + 1].startswith("developer_instructions="):
            if display_args is args:
                display_args = args.copy()
            display_args[index + 1] = "developer_instructions=<sig-finder-system-prompt>"
    return display_args


def _missing_expected_outputs(expected_yaml_paths) -> list[str]:
    if expected_yaml_paths is None:
        return []
    return [path for path in expected_yaml_paths if not os.path.exists(path)]


def _build_agent_command(
    *,
    agent: str,
    agent_kind: str,
    skill_name: str,
    session_id: str,
    opencode_session_id: str | None,
    developer_instructions: str | None,
    is_retry: bool,
    agent_model: str = DEFAULT_AGENT_MODEL,
    mcp_url: str | None = None,
) -> AgentCommand:
    if agent_kind == "claude":
        return _build_claude_command(agent, skill_name, session_id, is_retry, agent_model, mcp_url)
    if agent_kind == "opencode":
        return _build_opencode_command(agent, skill_name, is_retry, opencode_session_id, agent_model)
    if developer_instructions is None:
        raise ValueError("Codex developer instructions are required")
    return _build_codex_command(agent, skill_name, developer_instructions, is_retry, agent_model, mcp_url)


def _print_command(command: AgentCommand, attempt: int, max_retries: int) -> None:
    attempt_str = f"(attempt {attempt + 1}/{max_retries})" if max_retries > 1 else ""
    retry_str = "[RETRY] " if attempt else ""
    prompt_transport = " <prompt via stdin>" if command.input_text is not None else ""
    print(f"    {retry_str}Running {attempt_str}: {' '.join(_display_command(command.args))}{prompt_transport}")


def _retry_if_available(attempt: int, max_retries: int, retry_target_desc: str) -> None:
    if attempt < max_retries - 1:
        print(f"    Retrying with {retry_target_desc}...")


def _notify_progress(progress_callback, event: str, **payload) -> None:
    if progress_callback is None:
        return
    try:
        progress_callback(event=event, **payload)
    except Exception as error:
        print(f"    Warning: Skill progress callback failed: {error}")


def _failure_progress_payload(reason, result) -> dict:
    if reason == "returncode":
        return {"reason": "returncode", "returncode": result.returncode}
    if isinstance(reason, tuple):
        return {"reason": reason[0], "error": reason[1]}
    return {"reason": "missing_expected_output", "missing_outputs": list(reason)}


def _result_failure_reason(result, expected_yaml_paths):
    if result.returncode != 0:
        return "returncode"
    cybersecurity_block = _extract_cybersecurity_block(result.stdout, result.stderr)
    if cybersecurity_block is not None:
        return ("cybersecurity_block", cybersecurity_block)
    skill_error = _extract_skill_error(result.stdout, result.stderr)
    if skill_error is not None:
        return ("skill_error", skill_error)
    missing_files = _missing_expected_outputs(expected_yaml_paths)
    if missing_files:
        return missing_files
    return None


def _report_result_failure(reason, result, debug: bool) -> None:
    if reason == "returncode":
        print(f"    Skill failed with return code: {result.returncode}")
        if not debug and result.stderr:
            print(f"    stderr: {result.stderr[:500]}")
    elif isinstance(reason, tuple) and reason[0] == "skill_error":
        print(f"    Error: Skill reported: {reason[1]}")
    elif isinstance(reason, tuple) and reason[0] == "cybersecurity_block":
        print(f"    Error: Skill blocked by cybersecurity filter: {reason[1]}")
    elif reason:
        print(f"    Error: Expected yaml files not generated: {reason}")


def _run_skill_attempts(
    *,
    skill_name: str,
    agent: str,
    agent_kind: str,
    session_id: str,
    developer_instructions: str | None,
    debug: bool,
    expected_yaml_paths,
    max_retries: int,
    agent_model: str,
    mcp_url: str | None,
    progress_callback=None,
) -> bool:
    opencode_session_id = None
    process_env = _agent_process_env(agent_kind, mcp_url)
    for attempt in range(max_retries):
        attempt_number = attempt + 1
        _notify_progress(
            progress_callback,
            "attempt_started",
            attempt=attempt_number,
            max_attempts=max_retries,
        )
        command = _build_agent_command(
            agent=agent,
            agent_kind=agent_kind,
            skill_name=skill_name,
            session_id=session_id,
            opencode_session_id=opencode_session_id,
            developer_instructions=developer_instructions,
            is_retry=attempt > 0,
            agent_model=agent_model,
            mcp_url=mcp_url,
        )
        _print_command(command, attempt, max_retries)
        try:
            result = _run_process_with_stream_capture(
                command.args,
                agent_input=command.input_text,
                debug=debug,
                timeout=SKILL_TIMEOUT,
                env=process_env,
            )
            if agent_kind == "opencode" and opencode_session_id is None:
                opencode_session_id = _extract_opencode_session_id(result.stdout)
            reason = _result_failure_reason(result, expected_yaml_paths)
            if reason is None:
                _notify_progress(
                    progress_callback,
                    "succeeded",
                    attempt=attempt_number,
                    max_attempts=max_retries,
                )
                return True
            _report_result_failure(reason, result, debug)
            failure_payload = _failure_progress_payload(reason, result)
            if isinstance(reason, tuple) and reason[0] == "cybersecurity_block":
                _notify_progress(
                    progress_callback,
                    "failed",
                    attempt=attempt_number,
                    max_attempts=max_retries,
                    **failure_payload,
                )
                return False
            _notify_progress(
                progress_callback,
                "attempt_failed",
                attempt=attempt_number,
                max_attempts=max_retries,
                will_retry=attempt < max_retries - 1,
                **failure_payload,
            )
            _retry_if_available(attempt, max_retries, command.retry_target_desc)
        except subprocess.TimeoutExpired:
            print(f"    Error: Skill execution timeout ({SKILL_TIMEOUT} seconds)")
            _notify_progress(
                progress_callback,
                "attempt_failed",
                attempt=attempt_number,
                max_attempts=max_retries,
                reason="timeout",
                timeout_seconds=SKILL_TIMEOUT,
                will_retry=attempt < max_retries - 1,
            )
            _retry_if_available(attempt, max_retries, command.retry_target_desc)
        except FileNotFoundError:
            print(f"    Error: Agent '{agent}' not found. Please ensure it is installed and in PATH.")
            _notify_progress(
                progress_callback,
                "failed",
                attempt=attempt_number,
                max_attempts=max_retries,
                reason="agent_not_found",
            )
            return False
        except Exception as error:
            print(f"    Error executing skill: {error}")
            _notify_progress(
                progress_callback,
                "attempt_failed",
                attempt=attempt_number,
                max_attempts=max_retries,
                reason="execution_error",
                error=str(error),
                will_retry=attempt < max_retries - 1,
            )
            _retry_if_available(attempt, max_retries, command.retry_target_desc)

    print(f"    Failed after {max_retries} attempts")
    _notify_progress(
        progress_callback,
        "failed",
        attempt=max_retries,
        max_attempts=max_retries,
        reason="retries_exhausted",
    )
    return False


def run_skill(
    skill_name,
    agent="claude",
    debug=False,
    expected_yaml_paths=None,
    max_retries=3,
    agent_model=DEFAULT_AGENT_MODEL,
    progress_callback=None,
    mcp_url=None,
) -> bool:
    """Execute a skill with its configured agent and retry support."""
    agent_kind = _detect_agent_kind(agent)
    if agent_kind is None:
        print(f"    Error: Unknown agent type '{agent}'. Agent name must contain 'claude', 'codex', or 'opencode'.")
        _notify_progress(progress_callback, "failed", reason="unknown_agent")
        return False
    try:
        _agent_model_args(agent_kind, agent_model)
    except ValueError as error:
        print(f"    Error: {error}")
        _notify_progress(progress_callback, "failed", reason="invalid_agent_model", error=str(error))
        return False

    skill_md_path = os.path.join(".claude", "skills", skill_name, "SKILL.md")
    print(f"    Falling back to: {skill_md_path}")
    if not os.path.exists(skill_md_path):
        print(f"    Error: Skill file not found: {skill_md_path}")
        _notify_progress(progress_callback, "failed", reason="skill_file_missing", path=skill_md_path)
        return False
    if not _ensure_agent_mcp_preflight(agent, debug=debug, mcp_url=mcp_url):
        _notify_progress(progress_callback, "failed", reason="mcp_unavailable")
        return False

    developer_instructions = _load_codex_developer_instructions() if agent_kind == "codex" else None
    if agent_kind == "codex" and developer_instructions is None:
        _notify_progress(progress_callback, "failed", reason="developer_instructions_unavailable")
        return False
    return _run_skill_attempts(
        skill_name=skill_name,
        agent=agent,
        agent_kind=agent_kind,
        session_id=str(uuid.uuid4()) if agent_kind == "claude" else "",
        developer_instructions=developer_instructions,
        debug=debug,
        expected_yaml_paths=expected_yaml_paths,
        max_retries=max_retries,
        agent_model=agent_model,
        mcp_url=mcp_url,
        progress_callback=progress_callback,
    )
