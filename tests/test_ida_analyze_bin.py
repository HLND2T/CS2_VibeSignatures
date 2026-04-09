import io
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, call, patch

import ida_analyze_bin


class TestResolveArtifactPath(unittest.TestCase):
    def test_resolve_artifact_path_keeps_current_module_artifacts_local(self) -> None:
        binary_dir = str(Path('/tmp/bin/14141/networksystem'))

        resolved = ida_analyze_bin.resolve_artifact_path(
            binary_dir,
            'CNetChan_vtable.{platform}.yaml',
            'linux',
        )

        self.assertEqual(
            str(Path('/tmp/bin/14141/networksystem/CNetChan_vtable.linux.yaml').resolve()),
            resolved,
        )

    def test_resolve_artifact_path_supports_sibling_module_reference(self) -> None:
        binary_dir = str(Path('/tmp/bin/14141/networksystem'))

        resolved = ida_analyze_bin.resolve_artifact_path(
            binary_dir,
            '../server/CFlattenedSerializers_CreateFieldChangedEventQueue.{platform}.yaml',
            'windows',
        )

        self.assertEqual(
            str(
                Path(
                    '/tmp/bin/14141/server/'
                    'CFlattenedSerializers_CreateFieldChangedEventQueue.windows.yaml'
                ).resolve()
            ),
            resolved,
        )

    def test_resolve_artifact_path_rejects_escape_outside_gamever_root(self) -> None:
        binary_dir = str(Path('/tmp/bin/14141/networksystem'))

        with self.assertRaises(ValueError):
            ida_analyze_bin.resolve_artifact_path(
                binary_dir,
                '../../outside/secret.{platform}.yaml',
                'windows',
            )


class TestResolveArtifactPathIntegration(unittest.TestCase):
    def test_expand_expected_paths_delegates_to_resolver(self) -> None:
        binary_dir = str(Path('/tmp/bin/14141/networksystem'))
        expected_paths = [
            'CNetChan_vtable.{platform}.yaml',
            '../server/CFlattenedSerializers_CreateFieldChangedEventQueue.{platform}.yaml',
        ]

        with patch.object(
            ida_analyze_bin,
            'resolve_artifact_path',
            side_effect=['/tmp/resolved-a.yaml', '/tmp/resolved-b.yaml'],
        ) as mock_resolver:
            resolved = ida_analyze_bin.expand_expected_paths(binary_dir, expected_paths, 'linux')

        self.assertEqual(['/tmp/resolved-a.yaml', '/tmp/resolved-b.yaml'], resolved)
        mock_resolver.assert_has_calls(
            [
                call(binary_dir, expected_paths[0], 'linux'),
                call(binary_dir, expected_paths[1], 'linux'),
            ]
        )

    def test_process_binary_rejects_illegal_expected_input_without_crash(self) -> None:
        binary_path = str(Path('/tmp/bin/14141/networksystem/networksystem.dll'))
        skills = [
            {
                'name': 'skill_illegal_expected_input',
                'expected_output': ['CNetChan_vtable.{platform}.yaml'],
                'expected_input': ['../../outside/secret.{platform}.yaml'],
            }
        ]
        fake_process = object()

        with (
            patch.object(ida_analyze_bin, 'start_idalib_mcp', return_value=fake_process),
            patch.object(ida_analyze_bin, 'ensure_mcp_available', return_value=(fake_process, True)),
            patch.object(ida_analyze_bin, 'quit_ida_gracefully') as mock_quit_ida,
            patch.object(ida_analyze_bin, 'run_skill') as mock_run_skill,
        ):
            success, fail, skip = ida_analyze_bin.process_binary(
                binary_path=binary_path,
                skills=skills,
                agent='codex',
                host='127.0.0.1',
                port=13337,
                ida_args='',
                platform='windows',
                debug=False,
                max_retries=1,
            )

        self.assertEqual((0, 1, 0), (success, fail, skip))
        mock_run_skill.assert_not_called()
        mock_quit_ida.assert_called_once_with(fake_process, '127.0.0.1', 13337, debug=False)

    def test_process_binary_preserves_prefilter_failures_when_mcp_startup_fails(self) -> None:
        binary_path = str(Path('/tmp/bin/14141/networksystem/networksystem.dll'))
        skills = [
            {
                'name': 'a_illegal_output',
                'expected_output': ['../../outside/secret.{platform}.yaml'],
                'expected_input': [],
            },
            {
                'name': 'b_valid_output',
                'expected_output': ['CNetChan_vtable.{platform}.yaml'],
                'expected_input': [],
            },
        ]

        with patch.object(ida_analyze_bin, 'start_idalib_mcp', return_value=None):
            success, fail, skip = ida_analyze_bin.process_binary(
                binary_path=binary_path,
                skills=skills,
                agent='codex',
                host='127.0.0.1',
                port=13337,
                ida_args='',
                platform='windows',
                debug=False,
                max_retries=1,
            )

        self.assertEqual((0, 2, 0), (success, fail, skip))


class _FakePipe:
    def __init__(self, chunks: list[str]) -> None:
        self._chunks = list(chunks)

    def readline(self) -> str:
        return self._chunks.pop(0) if self._chunks else ""

    def close(self) -> None:
        return None


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


class TestRunSkillOutputDetection(unittest.TestCase):
    def test_output_contains_error_marker_only_matches_standalone_tokens(self) -> None:
        self.assertTrue(ida_analyze_bin._output_contains_error_marker("Error"))
        self.assertTrue(ida_analyze_bin._output_contains_error_marker("prefix [ERROR] suffix"))
        self.assertTrue(ida_analyze_bin._output_contains_error_marker("before **ERROR** after"))
        self.assertTrue(ida_analyze_bin._output_contains_error_marker("line one\nerror\nline three"))

        self.assertFalse(ida_analyze_bin._output_contains_error_marker("myErrorCode"))
        self.assertFalse(ida_analyze_bin._output_contains_error_marker("error123"))
        self.assertFalse(ida_analyze_bin._output_contains_error_marker("XerrorY"))
        self.assertFalse(ida_analyze_bin._output_contains_error_marker("all good"))


class TestRunSkillCodexPromptTransport(unittest.TestCase):
    @patch.object(Path, 'read_text', return_value='sig finder prompt')
    @patch('ida_analyze_bin.os.path.exists', return_value=True)
    @patch('ida_analyze_bin._run_process_with_stream_capture')
    def test_run_skill_passes_codex_prompt_via_stdin_on_retry(
        self,
        mock_run_process,
        _mock_exists,
        _mock_read_text,
    ) -> None:
        mock_run_process.side_effect = [
            ida_analyze_bin.subprocess.CompletedProcess(
                args=['codex'],
                returncode=1,
                stdout='',
                stderr='first failure',
            ),
            ida_analyze_bin.subprocess.CompletedProcess(
                args=['codex'],
                returncode=0,
                stdout='',
                stderr='',
            ),
        ]

        result = ida_analyze_bin.run_skill(
            skill_name='find-IGameSystem_vtable',
            agent='codex',
            debug=False,
            max_retries=2,
        )

        self.assertTrue(result)
        self.assertEqual(2, mock_run_process.call_count)

        first_call = mock_run_process.call_args_list[0]
        second_call = mock_run_process.call_args_list[1]

        self.assertEqual(['exec', '-'], first_call.args[0][-2:])
        self.assertEqual(['exec', 'resume', '--last', '-'], second_call.args[0][-4:])
        expected_prompt = 'Run SKILL: .claude/skills/find-IGameSystem_vtable/SKILL.md'
        self.assertEqual(expected_prompt, first_call.kwargs['agent_input'])
        self.assertEqual(expected_prompt, second_call.kwargs['agent_input'])
        self.assertFalse(first_call.kwargs['debug'])
        self.assertFalse(second_call.kwargs['debug'])
        self.assertEqual(ida_analyze_bin.SKILL_TIMEOUT, first_call.kwargs['timeout'])
        self.assertEqual(ida_analyze_bin.SKILL_TIMEOUT, second_call.kwargs['timeout'])

    @patch('ida_analyze_bin.os.path.exists', return_value=True)
    @patch('ida_analyze_bin.subprocess.Popen')
    def test_run_skill_debug_true_forwards_stdout_and_stderr(
        self,
        mock_popen,
        _mock_exists,
    ) -> None:
        mock_popen.return_value = _FakePopen(
            stdout_chunks=['agent stdout line\n'],
            stderr_chunks=['agent stderr line\n'],
            returncode=0,
        )

        with patch('sys.stdout', new_callable=io.StringIO) as fake_stdout, patch(
            'sys.stderr', new_callable=io.StringIO
        ) as fake_stderr:
            result = ida_analyze_bin.run_skill(
                skill_name='find-IGameSystem_vtable',
                agent='claude',
                debug=True,
                max_retries=1,
            )

        self.assertTrue(result)
        self.assertIn('agent stdout line\n', fake_stdout.getvalue())
        self.assertIn('agent stderr line\n', fake_stderr.getvalue())

    @patch.object(Path, 'read_text', return_value='sig finder prompt')
    @patch('ida_analyze_bin.os.path.exists', return_value=True)
    @patch('ida_analyze_bin.subprocess.Popen')
    def test_run_skill_retries_when_output_contains_error_marker(
        self,
        mock_popen,
        _mock_exists,
        _mock_read_text,
    ) -> None:
        first_process = _FakePopen(
            stdout_chunks=['starting\n', '[ERROR] lookup failed\n'],
            stderr_chunks=[],
            returncode=0,
        )
        second_process = _FakePopen(
            stdout_chunks=['done\n'],
            stderr_chunks=[],
            returncode=0,
        )
        mock_popen.side_effect = [first_process, second_process]

        with patch('sys.stdout', new_callable=io.StringIO) as fake_stdout, patch(
            'sys.stderr', new_callable=io.StringIO
        ) as fake_stderr:
            result = ida_analyze_bin.run_skill(
                skill_name='find-IGameSystem_vtable',
                agent='codex',
                debug=False,
                max_retries=2,
            )

        self.assertTrue(result)
        self.assertEqual(2, mock_popen.call_count)
        self.assertNotIn('[ERROR] lookup failed\n', fake_stdout.getvalue())
        self.assertEqual('', fake_stderr.getvalue())
        expected_prompt = 'Run SKILL: .claude/skills/find-IGameSystem_vtable/SKILL.md'
        self.assertEqual(expected_prompt, ''.join(first_process.stdin.writes))
        self.assertEqual(expected_prompt, ''.join(second_process.stdin.writes))


class TestParseArgsLlmOptions(unittest.TestCase):
    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_accepts_llm_options(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14141",
                "-llm_model",
                "gpt-4.1-mini",
                "-llm_apikey",
                "test-api-key",
                "-llm_baseurl",
                "https://example.invalid/v1",
            ],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual("gpt-4.1-mini", args.llm_model)
        self.assertEqual("test-api-key", args.llm_apikey)
        self.assertEqual("https://example.invalid/v1", args.llm_baseurl)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_rejects_legacy_vcall_finder_model(
        self,
        _mock_resolve_oldgamever,
    ) -> None:
        with patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14141",
                "-vcall_finder_model",
                "gpt-4o",
            ],
        ), patch("sys.stderr", new_callable=io.StringIO) as fake_stderr:
            with self.assertRaises(SystemExit) as exc:
                ida_analyze_bin.parse_args()

        self.assertEqual(2, exc.exception.code)
        self.assertIn("-vcall_finder_model", fake_stderr.getvalue())


class TestProcessBinaryLlmWiring(unittest.TestCase):
    @patch("ida_analyze_bin.os.path.exists", return_value=False)
    @patch.object(ida_analyze_bin, "run_skill", return_value=False)
    @patch.object(
        ida_analyze_bin,
        "preprocess_single_skill_via_mcp",
        new_callable=AsyncMock,
        return_value=False,
    )
    @patch.object(ida_analyze_bin, "ensure_mcp_available")
    @patch.object(ida_analyze_bin, "start_idalib_mcp")
    @patch.object(ida_analyze_bin, "quit_ida_gracefully")
    def test_process_binary_passes_unified_llm_options_to_preprocess(
        self,
        _mock_quit_ida,
        mock_start_idalib_mcp,
        mock_ensure_mcp_available,
        mock_preprocess,
        _mock_run_skill,
        _mock_exists,
    ) -> None:
        fake_process = object()
        mock_start_idalib_mcp.return_value = fake_process
        mock_ensure_mcp_available.return_value = (fake_process, True)

        ida_analyze_bin.process_binary(
            binary_path="/tmp/bin/14141/networksystem/networksystem.dll",
            skills=[
                {
                    "name": "find-IGameSystem_vtable",
                    "expected_output": ["IGameSystem_vtable.{platform}.yaml"],
                    "expected_input": [],
                }
            ],
            agent="codex",
            host="127.0.0.1",
            port=13337,
            ida_args="",
            platform="windows",
            debug=False,
            max_retries=1,
            llm_model="gpt-4.1-mini",
            llm_apikey="test-api-key",
            llm_baseurl="https://example.invalid/v1",
        )

        self.assertEqual("gpt-4.1-mini", mock_preprocess.await_args.kwargs["llm_model"])
        self.assertEqual("test-api-key", mock_preprocess.await_args.kwargs["llm_apikey"])
        self.assertEqual(
            "https://example.invalid/v1",
            mock_preprocess.await_args.kwargs["llm_baseurl"],
        )


class TestMainLlmWiring(unittest.TestCase):
    @patch.object(ida_analyze_bin, "aggregate_vcall_results_for_object")
    @patch.object(ida_analyze_bin, "process_binary", return_value=(0, 0, 0))
    @patch.object(ida_analyze_bin, "parse_config")
    @patch("ida_analyze_bin.os.path.exists", return_value=True)
    @patch.object(ida_analyze_bin, "parse_args")
    def test_main_passes_unified_llm_options_to_vcall_aggregation(
        self,
        mock_parse_args,
        _mock_exists,
        mock_parse_config,
        _mock_process_binary,
        mock_aggregate,
    ) -> None:
        mock_parse_args.return_value = SimpleNamespace(
            configyaml="config.yaml",
            bindir="bin",
            gamever="14141",
            oldgamever=None,
            platforms=["windows"],
            module_filter=None,
            modules="*",
            agent="codex",
            ida_args="",
            debug=False,
            maxretry=3,
            vcall_finder_filter={"all": True},
            llm_model="gpt-4.1-mini",
            llm_apikey="test-api-key",
            llm_baseurl="https://example.invalid/v1",
        )
        mock_parse_config.return_value = [
            {
                "name": "networksystem",
                "skills": [],
                "vcall_finder_objects": ["g_pNetworkMessages"],
                "path_windows": "game/bin/win64/networksystem.dll",
            }
        ]
        mock_aggregate.return_value = {"status": "success", "processed": 1, "failed": 0}

        ida_analyze_bin.main()

        mock_aggregate.assert_called_once_with(
            base_dir="vcall_finder",
            gamever="14141",
            object_name="g_pNetworkMessages",
            model="gpt-4.1-mini",
            api_key="test-api-key",
            base_url="https://example.invalid/v1",
            debug=False,
        )


if __name__ == '__main__':
    unittest.main()
