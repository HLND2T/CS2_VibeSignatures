import unittest
from subprocess import CompletedProcess
from unittest.mock import patch

import run_cpp_tests


class TestRunFixHeaderAgent(unittest.TestCase):
    @patch.object(
        run_cpp_tests,
        "_load_codex_developer_instructions",
        return_value='developer_instructions="test prompt"',
    )
    @patch("run_cpp_tests.subprocess.run")
    def test_run_fix_header_agent_passes_codex_prompt_via_stdin_on_retry(
        self,
        mock_run,
        _mock_load_prompt,
    ) -> None:
        mock_run.side_effect = [
            CompletedProcess(args=["codex"], returncode=1, stdout="", stderr="first failure"),
            CompletedProcess(args=["codex"], returncode=0, stdout="", stderr=""),
        ]

        result = run_cpp_tests.run_fix_header_agent(
            fix_prompt="fix the vtable diff",
            agent="codex",
            debug=False,
            max_retries=2,
        )

        self.assertTrue(result)
        self.assertEqual(2, mock_run.call_count)

        first_call = mock_run.call_args_list[0]
        second_call = mock_run.call_args_list[1]

        self.assertEqual(["exec", "-"], first_call.args[0][-2:])
        self.assertEqual(
            ["exec", "resume", "--last", "-"],
            second_call.args[0][-4:],
        )
        self.assertEqual("fix the vtable diff", first_call.kwargs["input"])
        self.assertEqual("fix the vtable diff", second_call.kwargs["input"])
        self.assertTrue(first_call.kwargs["text"])
        self.assertTrue(second_call.kwargs["text"])


    @patch("run_cpp_tests.subprocess.run")
    def test_run_fix_header_agent_passes_claude_prompt_via_stdin(
        self,
        mock_run,
    ) -> None:
        mock_run.return_value = CompletedProcess(
            args=["claude"], returncode=0, stdout="", stderr=""
        )

        result = run_cpp_tests.run_fix_header_agent(
            fix_prompt="fix the vtable diff",
            agent="claude",
            debug=False,
            max_retries=1,
        )

        self.assertTrue(result)
        self.assertEqual(1, mock_run.call_count)

        call = mock_run.call_args_list[0]
        cmd = call.args[0]

        p_index = cmd.index("-p")
        self.assertEqual("-", cmd[p_index + 1])
        self.assertNotIn("fix the vtable diff", cmd)
        self.assertEqual("fix the vtable diff", call.kwargs["input"])
        self.assertTrue(call.kwargs["text"])
        self.assertIn("--session-id", cmd)
        self.assertNotIn("--resume", cmd)

    @patch("run_cpp_tests.subprocess.run")
    def test_run_fix_header_agent_passes_claude_prompt_via_stdin_on_retry(
        self,
        mock_run,
    ) -> None:
        mock_run.side_effect = [
            CompletedProcess(args=["claude"], returncode=1, stdout="", stderr="fail"),
            CompletedProcess(args=["claude"], returncode=0, stdout="", stderr=""),
        ]

        result = run_cpp_tests.run_fix_header_agent(
            fix_prompt="fix the vtable diff",
            agent="claude",
            debug=False,
            max_retries=2,
        )

        self.assertTrue(result)
        self.assertEqual(2, mock_run.call_count)

        first_call = mock_run.call_args_list[0]
        second_call = mock_run.call_args_list[1]
        first_cmd = first_call.args[0]
        second_cmd = second_call.args[0]

        for cmd in (first_cmd, second_cmd):
            p_index = cmd.index("-p")
            self.assertEqual("-", cmd[p_index + 1])
            self.assertNotIn("fix the vtable diff", cmd)

        self.assertEqual("fix the vtable diff", first_call.kwargs["input"])
        self.assertEqual("fix the vtable diff", second_call.kwargs["input"])

        self.assertIn("--session-id", first_cmd)
        self.assertNotIn("--resume", first_cmd)
        self.assertIn("--resume", second_cmd)
        self.assertNotIn("--session-id", second_cmd)

        sid_index = first_cmd.index("--session-id") + 1
        resume_index = second_cmd.index("--resume") + 1
        self.assertEqual(first_cmd[sid_index], second_cmd[resume_index])


if __name__ == "__main__":
    unittest.main()
