import io
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import agent_runner


class TestSkillRunnerProjectPromptConfiguration(unittest.TestCase):
    def test_claude_command_loads_skill_runner_settings_and_system_prompt(self) -> None:
        command = agent_runner._build_claude_command(
            "claude",
            "find-test",
            "session-id",
            False,
        )

        self.assertIn(
            ["--settings", ".claude/skill_runner.settings.json"],
            [command.args[index : index + 2] for index in range(len(command.args) - 1)],
        )
        self.assertIn(
            ["--append-system-prompt-file", ".claude/SKILL_RUNNER.md"],
            [command.args[index : index + 2] for index in range(len(command.args) - 1)],
        )
        self.assertNotIn("--allowedTools", command.args)
        self.assertNotIn("--disallowedTools", command.args)

    def test_codex_command_uses_skill_runner_profile_for_runtime_settings(self) -> None:
        command = agent_runner._build_codex_command(
            "codex",
            "find-test",
            'developer_instructions="sig finder prompt"',
            False,
        )

        self.assertEqual(["codex", "--profile", "skill_runner"], command.args[:3])
        self.assertNotIn("model_reasoning_effort=high", command.args)
        self.assertNotIn("model_reasoning_summary=none", command.args)
        self.assertNotIn("model_verbosity=low", command.args)
        self.assertNotIn("--approval-mode", command.args)
        self.assertNotIn("full-auto", command.args)

    def test_claude_dynamic_mcp_override_is_reused_for_retry(self) -> None:
        mcp_url = "http://127.0.0.1:54321/mcp"
        first = agent_runner._build_claude_command(
            "claude",
            "find-test",
            "session-id",
            False,
            mcp_url=mcp_url,
        )
        retry = agent_runner._build_claude_command(
            "claude",
            "find-test",
            "session-id",
            True,
            mcp_url=mcp_url,
        )

        for command in (first, retry):
            config_index = command.args.index("--mcp-config")
            self.assertEqual(
                {
                    "mcpServers": {
                        "ida-pro-mcp": {
                            "type": "http",
                            "url": mcp_url,
                        }
                    }
                },
                json.loads(command.args[config_index + 1]),
            )
            self.assertIn("--strict-mcp-config", command.args)

    def test_codex_dynamic_mcp_override_is_reused_for_retry(self) -> None:
        mcp_url = "http://127.0.0.1:54321/mcp"
        expected_override = [
            "-c",
            f'mcp_servers.ida-pro-mcp.url="{mcp_url}"',
            "-c",
            "mcp_servers.ida-pro-mcp.required=true",
        ]
        first = agent_runner._build_codex_command(
            "codex",
            "find-test",
            'developer_instructions="sig finder prompt"',
            False,
            mcp_url=mcp_url,
        )
        retry = agent_runner._build_codex_command(
            "codex",
            "find-test",
            'developer_instructions="sig finder prompt"',
            True,
            mcp_url=mcp_url,
        )

        for command in (first, retry):
            override_index = command.args.index(expected_override[1]) - 1
            self.assertEqual(expected_override, command.args[override_index : override_index + 4])


class TestAgentPermissionArgs(unittest.TestCase):
    def test_returns_permission_args_for_each_agent_kind(self) -> None:
        expected_args = {
            "claude": ["--permission-mode", "auto"],
            "codex": [],
            "opencode": ["--auto"],
        }

        for agent_kind, permission_args in expected_args.items():
            with self.subTest(agent_kind=agent_kind):
                self.assertEqual(permission_args, agent_runner._agent_permission_args(agent_kind))

    def test_explicit_claude_permission_mode_overrides_auto_default(self) -> None:
        self.assertEqual(
            ["--permission-mode", "acceptEdits"],
            agent_runner._agent_permission_args("claude", claude_permission_mode="acceptEdits"),
        )

    def test_skill_commands_use_cli_permission_args_when_required(self) -> None:
        expected_args = {
            "claude": ["--permission-mode", "auto"],
            "opencode": ["--auto"],
        }

        for agent_kind, permission_args in expected_args.items():
            with self.subTest(agent_kind=agent_kind):
                command = agent_runner._build_agent_command(
                    agent=agent_kind,
                    agent_kind=agent_kind,
                    skill_name="find-test",
                    session_id="session-id",
                    opencode_session_id=None,
                    developer_instructions='developer_instructions="test"',
                    is_retry=False,
                )
                permission_index = command.args.index(permission_args[0])
                self.assertEqual(
                    permission_args,
                    command.args[permission_index : permission_index + len(permission_args)],
                )

        codex_command = agent_runner._build_agent_command(
            agent="codex",
            agent_kind="codex",
            skill_name="find-test",
            session_id="session-id",
            opencode_session_id=None,
            developer_instructions='developer_instructions="test"',
            is_retry=False,
        )
        self.assertNotIn("--approval-mode", codex_command.args)
        self.assertNotIn("full-auto", codex_command.args)


class TestAgentModelArgs(unittest.TestCase):
    def test_empty_model_keeps_existing_agent_defaults(self) -> None:
        for agent_kind in ("claude", "codex", "opencode"):
            with self.subTest(agent_kind=agent_kind):
                self.assertEqual([], agent_runner._agent_model_args(agent_kind, ""))

    def test_returns_cli_specific_model_args(self) -> None:
        expected_args = {
            "claude": ["--model", "sonnet"],
            "codex": ["-m", "gpt-5.4"],
            "opencode": ["-m", "openai/gpt-5.4"],
        }

        for agent_kind, model_args in expected_args.items():
            with self.subTest(agent_kind=agent_kind):
                self.assertEqual(model_args, agent_runner._agent_model_args(agent_kind, model_args[1]))

    def test_opencode_model_requires_provider_prefix(self) -> None:
        with self.assertRaisesRegex(ValueError, "provider/model"):
            agent_runner._agent_model_args("opencode", "gpt-5.4")

    def test_skill_commands_include_custom_model(self) -> None:
        models = {
            "claude": "sonnet",
            "codex": "gpt-5.4",
            "opencode": "openai/gpt-5.4",
        }

        for agent_kind, agent_model in models.items():
            with self.subTest(agent_kind=agent_kind):
                command = agent_runner._build_agent_command(
                    agent=agent_kind,
                    agent_kind=agent_kind,
                    agent_model=agent_model,
                    skill_name="find-test",
                    session_id="session-id",
                    opencode_session_id=None,
                    developer_instructions='developer_instructions="test"',
                    is_retry=False,
                )
                expected_args = agent_runner._agent_model_args(agent_kind, agent_model)
                model_index = command.args.index(expected_args[0])
                self.assertEqual(expected_args, command.args[model_index : model_index + 2])

    @patch("agent_runner._ensure_agent_mcp_preflight")
    def test_run_skill_rejects_invalid_opencode_model_before_preflight(self, mock_preflight) -> None:
        output = io.StringIO()

        with patch("sys.stdout", output):
            result = agent_runner.run_skill(
                "find-test",
                agent="opencode",
                agent_model="gpt-5.4",
            )

        self.assertFalse(result)
        self.assertIn("provider/model", output.getvalue())
        mock_preflight.assert_not_called()


class _FakePipe:
    def __init__(self, chunks: list[str]) -> None:
        self._chunks = list(chunks)
        self.closed = False

    def readline(self) -> str:
        return self._chunks.pop(0) if self._chunks else ""

    def close(self) -> None:
        self.closed = True


class _FakeStdin:
    def __init__(self) -> None:
        self.writes: list[str] = []
        self.closed = False

    def write(self, data: str) -> int:
        self.writes.append(data)
        return len(data)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FakePopen:
    def __init__(
        self,
        *,
        stdout_chunks: list[str] | None = None,
        stderr_chunks: list[str] | None = None,
        returncode: int = 0,
    ) -> None:
        self.stdout = _FakePipe(stdout_chunks or [])
        self.stderr = _FakePipe(stderr_chunks or [])
        self.stdin = _FakeStdin()
        self.returncode = returncode
        self.killed = False

    def wait(self, timeout: int | None = None) -> int:
        return self.returncode

    def kill(self) -> None:
        self.killed = True


class TestOpenCodeCommandConstruction(unittest.TestCase):
    def setUp(self) -> None:
        agent_runner._MCP_PREFLIGHT_DONE.clear()

    def test_detect_agent_kind_accepts_opencode_executable_names(self) -> None:
        self.assertEqual("opencode", agent_runner._detect_agent_kind("opencode"))
        self.assertEqual("opencode", agent_runner._detect_agent_kind("opencode.cmd"))
        self.assertEqual("opencode", agent_runner._detect_agent_kind(r"C:\tools\opencode.cmd"))
        self.assertEqual("claude", agent_runner._detect_agent_kind("claude.cmd"))
        self.assertEqual("codex", agent_runner._detect_agent_kind("codex.cmd"))
        self.assertIsNone(agent_runner._detect_agent_kind("unknown-agent"))

    def test_extract_opencode_session_id_uses_first_valid_event(self) -> None:
        output = "\n".join(
            [
                "not json",
                '{"type":"step_start","sessionID":"ses_first"}',
                '{"type":"text","sessionID":"ses_second"}',
            ]
        )

        self.assertEqual("ses_first", agent_runner._extract_opencode_session_id(output))

    def test_extract_opencode_session_id_ignores_invalid_values(self) -> None:
        output = "\n".join(
            [
                "[]",
                '{"type":"text","sessionID":""}',
                '{"type":"error","sessionID":42}',
            ]
        )

        self.assertIsNone(agent_runner._extract_opencode_session_id(output))

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner._run_process_with_stream_capture")
    def test_run_skill_retries_opencode_with_reported_session_id(
        self,
        mock_run_process,
        _mock_exists,
    ) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(["opencode", "mcp", "list"], 0, "ida-pro-mcp failed\n", ""),
            subprocess.CompletedProcess(
                ["opencode", "run"],
                1,
                '{"type":"step_start","sessionID":"ses_exact"}\n',
                "first failure",
            ),
            subprocess.CompletedProcess(
                ["opencode", "run"],
                0,
                '{"type":"text","sessionID":"ses_exact"}\n',
                "",
            ),
        ]

        result = agent_runner.run_skill(
            "find-IGameSystem_vtable",
            agent="opencode",
            max_retries=2,
        )

        self.assertTrue(result)
        prompt = "Run SKILL: .claude/skills/find-IGameSystem_vtable/SKILL.md"
        self.assertEqual(
            ["opencode", "run", "--format", "json", "--auto", "--agent", "sig-finder", prompt],
            mock_run_process.call_args_list[1].args[0],
        )
        self.assertEqual(
            [
                "opencode",
                "run",
                "--format",
                "json",
                "--auto",
                "--session",
                "ses_exact",
                "--agent",
                "sig-finder",
                prompt,
            ],
            mock_run_process.call_args_list[2].args[0],
        )
        self.assertIsNone(mock_run_process.call_args_list[1].kwargs["agent_input"])
        self.assertIsNone(mock_run_process.call_args_list[2].kwargs["agent_input"])

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner._run_process_with_stream_capture")
    def test_run_skill_falls_back_to_continue_without_session_id(
        self,
        mock_run_process,
        _mock_exists,
    ) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(["opencode.cmd", "mcp", "list"], 0, "ida-pro-mcp failed\n", ""),
            subprocess.CompletedProcess(["opencode.cmd", "run"], 1, "", "failed before first event"),
            subprocess.CompletedProcess(
                ["opencode.cmd", "run"],
                0,
                '{"type":"text","sessionID":"ses_late"}\n',
                "",
            ),
        ]

        result = agent_runner.run_skill(
            "find-IGameSystem_vtable",
            agent="opencode.cmd",
            max_retries=2,
        )

        self.assertTrue(result)
        retry_args = mock_run_process.call_args_list[2].args[0]
        self.assertIn("--continue", retry_args)
        self.assertNotIn("--session", retry_args)

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner._run_process_with_stream_capture")
    def test_run_skill_sets_opencode_only_process_environment(
        self,
        mock_run_process,
        _mock_exists,
    ) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(
                ["opencode", "mcp", "list"],
                0,
                "ida-pro-mcp failed\n",
                "",
            ),
            subprocess.CompletedProcess(["opencode", "run"], 0, "", ""),
        ]

        self.assertTrue(
            agent_runner.run_skill(
                "find-IGameSystem_vtable",
                agent="opencode",
                max_retries=1,
            )
        )

        for process_call in mock_run_process.call_args_list:
            process_env = process_call.kwargs.get("env")
            self.assertIsNotNone(process_env)
            self.assertEqual("1", process_env["OPENCODE_DISABLE_CLAUDE_CODE_PROMPT"])
            self.assertEqual(".opencode/skill_runner.config.json", process_env["OPENCODE_CONFIG"])

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner._run_process_with_stream_capture")
    def test_run_skill_injects_opencode_mcp_override_for_preflight_and_retries(
        self,
        mock_run_process,
        _mock_exists,
    ) -> None:
        mcp_url = "http://127.0.0.1:54321/mcp"
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(["opencode", "mcp", "list"], 0, "ida-pro-mcp connected\n", ""),
            subprocess.CompletedProcess(["opencode", "run"], 1, "", "first failure"),
            subprocess.CompletedProcess(["opencode", "run"], 0, "", ""),
        ]

        self.assertTrue(
            agent_runner.run_skill(
                "find-IGameSystem_vtable",
                agent="opencode",
                max_retries=2,
                mcp_url=mcp_url,
            )
        )

        expected_content = {
            "mcp": {
                "ida-pro-mcp": {
                    "type": "remote",
                    "url": mcp_url,
                    "enabled": True,
                }
            }
        }
        for process_call in mock_run_process.call_args_list:
            process_env = process_call.kwargs["env"]
            self.assertEqual(expected_content, json.loads(process_env["OPENCODE_CONFIG_CONTENT"]))


class TestRunSkillOutputDetection(unittest.TestCase):
    def setUp(self) -> None:
        agent_runner._MCP_PREFLIGHT_DONE.clear()

    def test_extract_skill_error_returns_tag_contents(self) -> None:
        self.assertEqual(
            "lookup failed",
            agent_runner._extract_skill_error("prefix <skill_error>lookup failed</skill_error> suffix"),
        )
        self.assertEqual(
            "multi-line\nreason",
            agent_runner._extract_skill_error("<skill_error>\nmulti-line\nreason\n</skill_error>"),
        )

    def test_extract_skill_error_ignores_legacy_error_markers(self) -> None:
        self.assertIsNone(agent_runner._extract_skill_error("Error"))
        self.assertIsNone(agent_runner._extract_skill_error("prefix [ERROR] suffix"))
        self.assertIsNone(agent_runner._extract_skill_error("all good"))


class TestRunSkillCodexPromptTransport(unittest.TestCase):
    def setUp(self) -> None:
        agent_runner._MCP_PREFLIGHT_DONE.clear()

    @patch.object(Path, "read_text", return_value="sig finder prompt")
    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner._run_process_with_stream_capture")
    def test_run_skill_passes_codex_prompt_via_stdin_on_retry(
        self,
        mock_run_process,
        _mock_exists,
        _mock_read_text,
    ) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(
                args=["codex", "mcp", "list"],
                returncode=1,
                stdout="Name\nida-pro-mcp  http://127.0.0.1:13337/mcp  enabled\n",
                stderr="",
            ),
            subprocess.CompletedProcess(
                args=["codex"],
                returncode=1,
                stdout="",
                stderr="first failure",
            ),
            subprocess.CompletedProcess(
                args=["codex"],
                returncode=0,
                stdout="",
                stderr="",
            ),
        ]

        result = agent_runner.run_skill(
            skill_name="find-IGameSystem_vtable",
            agent="codex",
            debug=False,
            max_retries=2,
        )

        self.assertTrue(result)
        self.assertEqual(3, mock_run_process.call_count)

        preflight_call = mock_run_process.call_args_list[0]
        first_call = mock_run_process.call_args_list[1]
        second_call = mock_run_process.call_args_list[2]

        self.assertEqual(["codex", "mcp", "list"], preflight_call.args[0])
        self.assertEqual(["exec", "-"], first_call.args[0][-2:])
        self.assertEqual(["exec", "resume", "--last", "-"], second_call.args[0][-4:])
        expected_prompt = "Run SKILL: .claude/skills/find-IGameSystem_vtable/SKILL.md"
        self.assertEqual(expected_prompt, first_call.kwargs["agent_input"])
        self.assertEqual(expected_prompt, second_call.kwargs["agent_input"])
        self.assertFalse(first_call.kwargs["debug"])
        self.assertFalse(second_call.kwargs["debug"])
        self.assertEqual(agent_runner.SKILL_TIMEOUT, first_call.kwargs["timeout"])
        self.assertEqual(agent_runner.SKILL_TIMEOUT, second_call.kwargs["timeout"])

    @patch.object(Path, "read_text", return_value="sig finder prompt")
    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner._run_process_with_stream_capture")
    def test_run_skill_reports_attempt_retry_and_success_progress(
        self,
        mock_run_process,
        _mock_exists,
        _mock_read_text,
    ) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(
                args=["codex", "mcp", "list"],
                returncode=0,
                stdout="ida-pro-mcp  http://127.0.0.1:13337/mcp  enabled\n",
                stderr="",
            ),
            subprocess.CompletedProcess(args=["codex"], returncode=1, stdout="", stderr="failed"),
            subprocess.CompletedProcess(args=["codex"], returncode=0, stdout="", stderr=""),
        ]
        progress = []

        result = agent_runner.run_skill(
            skill_name="find-IGameSystem_vtable",
            agent="codex",
            max_retries=2,
            progress_callback=lambda **event: progress.append(event),
        )

        self.assertTrue(result)
        self.assertEqual(
            ["attempt_started", "attempt_failed", "attempt_started", "succeeded"],
            [event["event"] for event in progress],
        )
        self.assertEqual(1, progress[1]["attempt"])
        self.assertTrue(progress[1]["will_retry"])
        self.assertEqual(2, progress[-1]["attempt"])

    @patch.object(Path, "read_text", return_value="sig finder prompt")
    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner._run_process_with_stream_capture")
    def test_run_skill_reports_timeout_without_changing_retry_result(
        self,
        mock_run_process,
        _mock_exists,
        _mock_read_text,
    ) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(
                args=["codex", "mcp", "list"],
                returncode=0,
                stdout="ida-pro-mcp  http://127.0.0.1:13337/mcp  enabled\n",
                stderr="",
            ),
            subprocess.TimeoutExpired(cmd="codex", timeout=agent_runner.SKILL_TIMEOUT),
        ]
        progress = []

        result = agent_runner.run_skill(
            skill_name="find-IGameSystem_vtable",
            agent="codex",
            max_retries=1,
            progress_callback=lambda **event: progress.append(event),
        )

        self.assertFalse(result)
        timeout_event = next(event for event in progress if event.get("reason") == "timeout")
        self.assertEqual("attempt_failed", timeout_event["event"])
        self.assertEqual(agent_runner.SKILL_TIMEOUT, timeout_event["timeout_seconds"])

    @patch.object(Path, "read_text", return_value="sig finder prompt")
    @patch("agent_runner.os.path.exists", side_effect=lambda path: not str(path).endswith("missing.yaml"))
    @patch("agent_runner._run_process_with_stream_capture")
    def test_run_skill_reports_missing_expected_output(
        self,
        mock_run_process,
        _mock_exists,
        _mock_read_text,
    ) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(
                args=["codex", "mcp", "list"],
                returncode=0,
                stdout="ida-pro-mcp  http://127.0.0.1:13337/mcp  enabled\n",
                stderr="",
            ),
            subprocess.CompletedProcess(args=["codex"], returncode=0, stdout="", stderr=""),
        ]
        progress = []

        result = agent_runner.run_skill(
            skill_name="find-IGameSystem_vtable",
            agent="codex",
            expected_yaml_paths=["missing.yaml"],
            max_retries=1,
            progress_callback=lambda **event: progress.append(event),
        )

        self.assertFalse(result)
        failure = next(event for event in progress if event.get("reason") == "missing_expected_output")
        self.assertEqual(["missing.yaml"], failure["missing_outputs"])

    @patch.object(Path, "read_text", return_value="sig finder prompt")
    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner._run_process_with_stream_capture")
    def test_progress_callback_failure_does_not_change_skill_success(
        self,
        mock_run_process,
        _mock_exists,
        _mock_read_text,
    ) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(
                args=["codex", "mcp", "list"],
                returncode=0,
                stdout="ida-pro-mcp  http://127.0.0.1:13337/mcp  enabled\n",
                stderr="",
            ),
            subprocess.CompletedProcess(args=["codex"], returncode=0, stdout="", stderr=""),
        ]

        def failing_callback(**_event):
            raise RuntimeError("reporter offline")

        result = agent_runner.run_skill(
            skill_name="find-IGameSystem_vtable",
            agent="codex",
            max_retries=1,
            progress_callback=failing_callback,
        )

        self.assertTrue(result)

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner.subprocess.Popen")
    def test_run_skill_debug_true_forwards_stdout_and_stderr(
        self,
        mock_popen,
        _mock_exists,
    ) -> None:
        preflight_process = _FakePopen(
            stdout_chunks=["ida-pro-mcp: http://127.0.0.1:13337/mcp (HTTP) - Failed\n"],
            stderr_chunks=[],
            returncode=0,
        )
        agent_process = _FakePopen(
            stdout_chunks=["agent stdout line\n"],
            stderr_chunks=["agent stderr line\n"],
            returncode=0,
        )
        mock_popen.side_effect = [preflight_process, agent_process]

        with (
            patch("sys.stdout", new_callable=io.StringIO) as fake_stdout,
            patch("sys.stderr", new_callable=io.StringIO) as fake_stderr,
        ):
            result = agent_runner.run_skill(
                skill_name="find-IGameSystem_vtable",
                agent="claude",
                debug=True,
                max_retries=1,
            )

        self.assertTrue(result)
        self.assertEqual(["claude", "mcp", "list"], mock_popen.call_args_list[0].args[0])
        self.assertIn("agent stdout line\n", fake_stdout.getvalue())
        self.assertIn("agent stderr line\n", fake_stderr.getvalue())

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner.subprocess.Popen")
    def test_run_skill_loads_claude_tool_permissions_from_settings(
        self,
        mock_popen,
        _mock_exists,
    ) -> None:
        preflight_process = _FakePopen(
            stdout_chunks=["ida-pro-mcp: http://127.0.0.1:13337/mcp (HTTP) - Failed\n"],
            stderr_chunks=[],
            returncode=0,
        )
        agent_process = _FakePopen(stdout_chunks=["done\n"], stderr_chunks=[], returncode=0)
        mock_popen.side_effect = [preflight_process, agent_process]

        result = agent_runner.run_skill(
            skill_name="find-IGameSystem_vtable",
            agent="claude",
            debug=False,
            max_retries=1,
        )

        self.assertTrue(result)
        agent_cmd = mock_popen.call_args_list[1].args[0]
        settings_index = agent_cmd.index("--settings")
        self.assertEqual(".claude/skill_runner.settings.json", agent_cmd[settings_index + 1])
        self.assertNotIn("--allowedTools", agent_cmd)
        self.assertNotIn("--disallowedTools", agent_cmd)

    @patch.object(Path, "read_text", return_value="sig finder prompt")
    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner.subprocess.Popen")
    def test_run_skill_retries_when_output_contains_skill_error(
        self,
        mock_popen,
        _mock_exists,
        _mock_read_text,
    ) -> None:
        preflight_process = _FakePopen(
            stdout_chunks=["ida-pro-mcp  http://127.0.0.1:13337/mcp  enabled\n"],
            stderr_chunks=[],
            returncode=0,
        )
        first_process = _FakePopen(
            stdout_chunks=["starting\n", "<skill_error>lookup failed</skill_error>\n"],
            stderr_chunks=[],
            returncode=0,
        )
        second_process = _FakePopen(
            stdout_chunks=["done\n"],
            stderr_chunks=[],
            returncode=0,
        )
        mock_popen.side_effect = [preflight_process, first_process, second_process]

        with (
            patch("sys.stdout", new_callable=io.StringIO) as fake_stdout,
            patch("sys.stderr", new_callable=io.StringIO) as fake_stderr,
        ):
            result = agent_runner.run_skill(
                skill_name="find-IGameSystem_vtable",
                agent="codex",
                debug=False,
                max_retries=2,
            )

        self.assertTrue(result)
        self.assertEqual(3, mock_popen.call_count)
        self.assertEqual(["codex", "mcp", "list"], mock_popen.call_args_list[0].args[0])
        self.assertIn("Skill reported: lookup failed", fake_stdout.getvalue())
        self.assertNotIn("<skill_error>", fake_stdout.getvalue())
        self.assertEqual("", fake_stderr.getvalue())
        expected_prompt = "Run SKILL: .claude/skills/find-IGameSystem_vtable/SKILL.md"
        self.assertEqual(expected_prompt, "".join(first_process.stdin.writes))
        self.assertEqual(expected_prompt, "".join(second_process.stdin.writes))

    @patch.object(Path, "read_text", return_value="sig finder prompt")
    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner.subprocess.Popen")
    def test_run_skill_does_not_retry_cybersecurity_blocks(
        self,
        mock_popen,
        _mock_exists,
        _mock_read_text,
    ) -> None:
        block_messages = [
            "This chat was flagged for possible cybersecurity risk",
            "flagged this message for a cybersecurity topic",
        ]

        for block_message in block_messages:
            with self.subTest(block_message=block_message):
                agent_runner._MCP_PREFLIGHT_DONE.clear()
                preflight_process = _FakePopen(
                    stdout_chunks=["ida-pro-mcp  http://127.0.0.1:13337/mcp  enabled\n"],
                    stderr_chunks=[],
                    returncode=0,
                )
                blocked_process = _FakePopen(
                    stdout_chunks=[f"{block_message}\n"],
                    stderr_chunks=[],
                    returncode=0,
                )
                mock_popen.reset_mock(side_effect=True)
                mock_popen.side_effect = [preflight_process, blocked_process]

                result = agent_runner.run_skill(
                    skill_name="find-IGameSystem_vtable",
                    agent="codex",
                    debug=False,
                    max_retries=3,
                )

                self.assertFalse(result)
                self.assertEqual(2, mock_popen.call_count)


class TestRunSkillMcpListPreflight(unittest.TestCase):
    def setUp(self) -> None:
        agent_runner._MCP_PREFLIGHT_DONE.clear()

    @patch("agent_runner._run_process_with_stream_capture")
    def test_claude_dynamic_endpoint_reuses_prior_health_check_without_mcp_list(
        self,
        mock_run_process,
    ) -> None:
        mcp_url = "http://127.0.0.1:54321/mcp"
        mock_run_process.return_value = subprocess.CompletedProcess(
            ["claude", "mcp", "list"],
            0,
            "ida-pro-mcp connected\n",
            "",
        )

        self.assertTrue(agent_runner._ensure_agent_mcp_preflight("claude", mcp_url=mcp_url))

        mock_run_process.assert_not_called()

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner.subprocess.Popen")
    def test_claude_mcp_list_accepts_failed_connection_when_server_is_listed(
        self,
        mock_popen,
        _mock_exists,
    ) -> None:
        preflight_process = _FakePopen(
            stdout_chunks=["ida-pro-mcp: http://127.0.0.1:13337/mcp (HTTP) - Failed to connect\n"],
            stderr_chunks=[],
            returncode=0,
        )
        agent_process = _FakePopen(stdout_chunks=["done\n"], stderr_chunks=[], returncode=0)
        mock_popen.side_effect = [preflight_process, agent_process]

        result = agent_runner.run_skill(
            skill_name="find-IGameSystem_vtable",
            agent="claude",
            debug=False,
            max_retries=1,
        )

        self.assertTrue(result)
        self.assertEqual(["claude", "mcp", "list"], mock_popen.call_args_list[0].args[0])
        self.assertEqual(2, mock_popen.call_count)

    @patch.object(Path, "read_text", return_value="sig finder prompt")
    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner._run_process_with_stream_capture")
    def test_codex_mcp_list_accepts_table_row_when_server_is_listed(
        self,
        mock_run_process,
        _mock_exists,
        _mock_read_text,
    ) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(
                args=["codex", "mcp", "list"],
                returncode=0,
                stdout=(
                    "Name         Url                         Status\n"
                    "ida-pro-mcp  http://127.0.0.1:13337/mcp  enabled\n"
                ),
                stderr="",
            ),
            subprocess.CompletedProcess(
                args=["codex"],
                returncode=0,
                stdout="",
                stderr="",
            ),
        ]

        result = agent_runner.run_skill(
            skill_name="find-IGameSystem_vtable",
            agent="codex",
            debug=False,
            max_retries=1,
        )

        self.assertTrue(result)
        self.assertEqual(["codex", "mcp", "list"], mock_run_process.call_args_list[0].args[0])
        self.assertEqual(2, mock_run_process.call_count)

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner.subprocess.Popen")
    def test_missing_ida_pro_mcp_blocks_agent_start(
        self,
        mock_popen,
        _mock_exists,
    ) -> None:
        preflight_process = _FakePopen(
            stdout_chunks=["basic-memory: http://127.0.0.1:9131/mcp (HTTP) - Connected\n"],
            stderr_chunks=[],
            returncode=0,
        )
        mock_popen.return_value = preflight_process

        with patch("sys.stdout", new_callable=io.StringIO) as fake_stdout:
            result = agent_runner.run_skill(
                skill_name="find-IGameSystem_vtable",
                agent="claude",
                debug=False,
                max_retries=1,
            )

        self.assertFalse(result)
        self.assertEqual(1, mock_popen.call_count)
        self.assertEqual(["claude", "mcp", "list"], mock_popen.call_args.args[0])
        self.assertIn("Required MCP server 'ida-pro-mcp' is not listed", fake_stdout.getvalue())

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner.subprocess.Popen")
    def test_mcp_list_timeout_blocks_agent_start(
        self,
        mock_popen,
        _mock_exists,
    ) -> None:
        timeout_process = _FakePopen(stdout_chunks=[], stderr_chunks=[], returncode=0)
        timeout_process.wait = MagicMock(
            side_effect=subprocess.TimeoutExpired(
                ["claude", "mcp", "list"],
                30,
            )
        )
        mock_popen.return_value = timeout_process

        with patch("sys.stdout", new_callable=io.StringIO) as fake_stdout:
            result = agent_runner.run_skill(
                skill_name="find-IGameSystem_vtable",
                agent="claude",
                debug=False,
                max_retries=1,
            )

        self.assertFalse(result)
        self.assertEqual(1, mock_popen.call_count)
        self.assertIn("MCP list preflight timeout", fake_stdout.getvalue())
        self.assertTrue(timeout_process.killed)

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner.subprocess.Popen", side_effect=FileNotFoundError)
    def test_mcp_list_missing_agent_blocks_agent_start(
        self,
        mock_popen,
        _mock_exists,
    ) -> None:
        with patch("sys.stdout", new_callable=io.StringIO) as fake_stdout:
            result = agent_runner.run_skill(
                skill_name="find-IGameSystem_vtable",
                agent="claude",
                debug=False,
                max_retries=1,
            )

        self.assertFalse(result)
        self.assertEqual(1, mock_popen.call_count)
        self.assertIn(
            "Agent 'claude' not found while running MCP list preflight",
            fake_stdout.getvalue(),
        )

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner.subprocess.Popen")
    def test_empty_mcp_list_output_blocks_agent_start(
        self,
        mock_popen,
        _mock_exists,
    ) -> None:
        mock_popen.return_value = _FakePopen(stdout_chunks=[], stderr_chunks=[], returncode=0)

        with patch("sys.stdout", new_callable=io.StringIO) as fake_stdout:
            result = agent_runner.run_skill(
                skill_name="find-IGameSystem_vtable",
                agent="claude",
                debug=False,
                max_retries=1,
            )

        self.assertFalse(result)
        self.assertEqual(1, mock_popen.call_count)
        self.assertIn("Required MCP server 'ida-pro-mcp' is not listed", fake_stdout.getvalue())

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner.subprocess.Popen")
    def test_preflight_runs_only_once_for_multiple_skills(
        self,
        mock_popen,
        _mock_exists,
    ) -> None:
        preflight_process = _FakePopen(
            stdout_chunks=["ida-pro-mcp: http://127.0.0.1:13337/mcp (HTTP) - Failed\n"],
            stderr_chunks=[],
            returncode=0,
        )
        first_agent = _FakePopen(stdout_chunks=["first\n"], stderr_chunks=[], returncode=0)
        second_agent = _FakePopen(stdout_chunks=["second\n"], stderr_chunks=[], returncode=0)
        mock_popen.side_effect = [preflight_process, first_agent, second_agent]

        first_result = agent_runner.run_skill(
            skill_name="find-IGameSystem_vtable",
            agent="claude",
            debug=False,
            max_retries=1,
        )
        second_result = agent_runner.run_skill(
            skill_name="find-CBaseEntity_vtable",
            agent="claude",
            debug=False,
            max_retries=1,
        )

        self.assertTrue(first_result)
        self.assertTrue(second_result)
        commands = [call_args.args[0] for call_args in mock_popen.call_args_list]
        self.assertEqual(1, commands.count(["claude", "mcp", "list"]))
        self.assertEqual(3, mock_popen.call_count)

    @patch("agent_runner.os.path.exists", return_value=True)
    @patch("agent_runner.subprocess.Popen")
    def test_failed_preflight_is_retried_for_later_skills(
        self,
        mock_popen,
        _mock_exists,
    ) -> None:
        first_preflight = _FakePopen(
            stdout_chunks=["basic-memory: http://127.0.0.1:9131/mcp (HTTP) - Connected\n"],
            stderr_chunks=[],
            returncode=0,
        )
        second_preflight = _FakePopen(
            stdout_chunks=["ida-pro-mcp: http://127.0.0.1:13337/mcp (HTTP) - Connected\n"],
            stderr_chunks=[],
            returncode=0,
        )
        agent_process = _FakePopen(stdout_chunks=["done\n"], stderr_chunks=[], returncode=0)
        mock_popen.side_effect = [first_preflight, second_preflight, agent_process]

        with patch("sys.stdout", new_callable=io.StringIO) as fake_stdout:
            first_result = agent_runner.run_skill(
                skill_name="find-IGameSystem_vtable",
                agent="claude",
                debug=False,
                max_retries=1,
            )
            second_result = agent_runner.run_skill(
                skill_name="find-CBaseEntity_vtable",
                agent="claude",
                debug=False,
                max_retries=1,
            )

        self.assertFalse(first_result)
        self.assertTrue(second_result)
        self.assertEqual(3, mock_popen.call_count)
        self.assertNotIn("MCP preflight previously failed", fake_stdout.getvalue())

    @patch("agent_runner._run_process_with_stream_capture")
    def test_preflight_cache_is_partitioned_by_dynamic_endpoint(self, mock_run_process) -> None:
        first_url = "http://127.0.0.1:54321/mcp"
        second_url = "http://127.0.0.1:54322/mcp"
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(["codex"], 0, "ida-pro-mcp enabled\n", ""),
            subprocess.CompletedProcess(["codex"], 0, "ida-pro-mcp enabled\n", ""),
        ]

        self.assertTrue(agent_runner._ensure_agent_mcp_preflight("codex", mcp_url=first_url))
        self.assertTrue(agent_runner._ensure_agent_mcp_preflight("codex", mcp_url=first_url))
        self.assertTrue(agent_runner._ensure_agent_mcp_preflight("codex", mcp_url=second_url))

        self.assertEqual(2, mock_run_process.call_count)
        for process_call, mcp_url in zip(mock_run_process.call_args_list, (first_url, second_url), strict=True):
            command = process_call.args[0]
            self.assertEqual(
                [
                    "codex",
                    "-c",
                    f'mcp_servers.ida-pro-mcp.url="{mcp_url}"',
                    "-c",
                    "mcp_servers.ida-pro-mcp.required=true",
                    "mcp",
                    "list",
                ],
                command,
            )

    def test_mcp_list_server_matching_requires_list_item_name(self) -> None:
        self.assertTrue(
            agent_runner._mcp_list_contains_server("ida-pro-mcp: http://127.0.0.1:13337/mcp (HTTP) - Failed\n")
        )
        self.assertTrue(agent_runner._mcp_list_contains_server("ida-pro-mcp  http://127.0.0.1:13337/mcp  enabled\n"))
        self.assertFalse(
            agent_runner._mcp_list_contains_server("not-ida-pro-mcp: http://127.0.0.1:13337/mcp (HTTP) - Failed\n")
        )
        self.assertTrue(
            agent_runner._mcp_list_contains_server("\x1b[34m•\x1b[39m  ✗ ida-pro-mcp \x1b[90mfailed\x1b[39m\n")
        )
        self.assertTrue(
            agent_runner._mcp_list_contains_server("\x1b[34m●\x1b[39m  ✓ ida-pro-mcp \x1b[90mconnected\x1b[39m\n")
        )
        self.assertFalse(
            agent_runner._mcp_list_contains_server("\x1b[34m•\x1b[39m  ✗ not-ida-pro-mcp \x1b[90mfailed\x1b[39m\n")
        )
