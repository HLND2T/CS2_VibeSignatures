import importlib
import subprocess
import unittest
from pathlib import Path
from unittest.mock import call, patch


class TestFormatRepoFiles(unittest.TestCase):
    def _load_module(self):
        try:
            return importlib.import_module("format_repo_files")
        except ModuleNotFoundError as exc:
            self.fail(f"format_repo_files module is missing: {exc}")

    def test_list_tracked_format_files_uses_git_python_and_yaml_patterns(self) -> None:
        module = self._load_module()
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="script.py\nconfig.yaml\n",
            stderr="",
        )

        with patch("format_repo_files.subprocess.run", return_value=completed) as run_mock:
            self.assertEqual(["script.py", "config.yaml"], module.list_tracked_format_files())

        run_mock.assert_called_once_with(
            ["git", "ls-files", "--cached", "--", "*.py", "*.yaml"],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_check_mode_passes_check_flag_to_ruff_and_yamlfix(self) -> None:
        module = self._load_module()

        with (
            patch(
                "format_repo_files.list_tracked_format_files",
                return_value=["format_repo_files.py", "configs/14168.yaml"],
            ),
            patch("format_repo_files.list_unchecked_preprocessor_scripts", return_value=[]),
            patch("format_repo_files.run_command_chunks", return_value=0) as run_chunks,
        ):
            self.assertEqual(0, module.main(["--check"]))

        run_chunks.assert_has_calls(
            [
                call(["ruff", "format", "--check"], ["format_repo_files.py"]),
                call(["yamlfix", "--check"], ["configs/14168.yaml"]),
            ]
        )

    def test_yamlfix_skips_generated_reference_yaml(self) -> None:
        module = self._load_module()
        tracked_files = [
            "configs/14168.yaml",
            "ida_preprocessor_scripts/references/server/generated.yaml",
            "ida_preprocessor_scripts\\references\\client\\generated.yaml",
            "gamesymbols/14168.yaml",
            "gamesymbols\\14168b.yaml",
            "bin_artifacts/14168/server/A.windows.yaml",
            "bin_artifacts\\14168\\server\\A.linux.yaml",
        ]

        with (
            patch("format_repo_files.list_tracked_format_files", return_value=tracked_files),
            patch("format_repo_files.list_unchecked_preprocessor_scripts", return_value=[]),
            patch("format_repo_files.run_command_chunks", return_value=0) as run_chunks,
        ):
            self.assertEqual(0, module.main(["--check"]))

        run_chunks.assert_has_calls(
            [
                call(["ruff", "format", "--check"], []),
                call(["yamlfix", "--check"], ["configs/14168.yaml"]),
            ]
        )

    def test_list_unchecked_preprocessor_scripts_includes_untracked_py_files(self) -> None:
        module = self._load_module()
        tracked = ["ida_preprocessor_scripts/find-Tracker.py", "other.py"]
        with (
            patch(
                "format_repo_files.Path.glob",
                return_value=[
                    Path("ida_preprocessor_scripts/find-Tracker.py"),
                    Path("ida_preprocessor_scripts/find-Untracked.py"),
                ],
            ),
            patch("format_repo_files.Path.is_file", return_value=True),
        ):
            extra = module.list_unchecked_preprocessor_scripts(tracked)
        self.assertEqual(["ida_preprocessor_scripts/find-Untracked.py"], extra)

    def test_paths_are_split_into_windows_safe_command_chunks(self) -> None:
        module = self._load_module()
        prefix = ["tool"]
        paths = ["aaa.yaml", "bbb.yaml", "ccc.yaml"]
        limit = len(subprocess.list2cmdline(prefix + paths[:2]))

        self.assertEqual(
            [["aaa.yaml", "bbb.yaml"], ["ccc.yaml"]],
            list(module.chunk_paths(prefix, paths, max_command_chars=limit)),
        )

    def test_main_returns_nonzero_when_any_formatter_fails(self) -> None:
        module = self._load_module()

        with (
            patch("format_repo_files.list_tracked_format_files", return_value=["a.py", "config.yaml"]),
            patch("format_repo_files.run_command_chunks", side_effect=[0, 1]),
        ):
            self.assertEqual(1, module.main([]))


if __name__ == "__main__":
    unittest.main()
