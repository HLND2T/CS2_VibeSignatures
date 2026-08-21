import importlib.util
import io
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(".claude/skills/create-pr/scripts/classify_delivery.py")
SPEC = importlib.util.spec_from_file_location("project_classify_delivery", SCRIPT)
classify_delivery = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(classify_delivery)


PLAIN_PR_PATHS = (
    ".claude/skills/create-pr/SKILL.md",
    "docs/en/conributing-via-pr.md",
    "memory/post_change_candidate_lifecycle.md",
    "pages/src/app.ts",
    ".github/workflows/pr-self-runner.yml",
    "tests/test_create_pr_classify_delivery.py",
    "README.md",
    "download.yaml",
    "config.toml",
    ".mcp.json",
    "release_workflow.py",
    "release_workflow_lib/promote.py",
    "process_api.py",
    "process_reporter.py",
    "vcall_finder/14172/notes.txt",
    "pyproject.toml",
)

SYMBOLS_PATHS = (
    "configs/14175.yaml",
    "gamesymbols/14175.yaml",
    "gamedata/14175/CS2Fixes.yaml",
    "gamedata-generators/CS2Fixes/generate.py",
    "ida_preprocessor_scripts/find-Example.py",
    "cpp_tests/iloopmode.cpp",
    "hl2sdk_cs2",
    "hl2sdk_cs2/public/iloopmode.h",
    "release-manifests/14175.json",
    "gamesymbol_snapshot_lib/candidate.py",
    "bin/14175/server/Example.windows.yaml",
    "agent_runner.py",
    "analysis_config.py",
    "analysis_output_contract.py",
    "binary_hashing.py",
    "cpp_tests_util.py",
    "format_repo_files.py",
    "gamedata_candidate.py",
    "generate_reference_yaml.py",
    "gamesymbol_candidate.py",
    "ida_analyze_bin.py",
    "init_gamebin.py",
    "push_binsync_symbols.py",
    "run_cpp_tests.py",
    "trusted_yaml.py",
    "update_gamedata.py",
)


class TestCreatePrClassifyDelivery(unittest.TestCase):
    def test_plain_pr_paths_do_not_trigger_lifecycle(self) -> None:
        for path in PLAIN_PR_PATHS:
            with self.subTest(path=path):
                self.assertFalse(classify_delivery.is_symbols_related_path(path))
        lifecycle, matched = classify_delivery.classify_paths(PLAIN_PR_PATHS)
        self.assertEqual(0, lifecycle)
        self.assertEqual([], matched)

    def test_symbols_paths_trigger_lifecycle(self) -> None:
        for path in SYMBOLS_PATHS:
            with self.subTest(path=path):
                self.assertTrue(classify_delivery.is_symbols_related_path(path))
        lifecycle, matched = classify_delivery.classify_paths(SYMBOLS_PATHS)
        self.assertEqual(1, lifecycle)
        self.assertEqual(list(SYMBOLS_PATHS), matched)

    def test_mixed_change_set_is_lifecycle(self) -> None:
        lifecycle, matched = classify_delivery.classify_paths(
            (".claude/skills/create-pr/SKILL.md", "ida_preprocessor_scripts/find-Example.py")
        )
        self.assertEqual(1, lifecycle)
        self.assertEqual(["ida_preprocessor_scripts/find-Example.py"], matched)

    def test_windows_separators_and_dot_slash_normalize(self) -> None:
        self.assertTrue(classify_delivery.is_symbols_related_path(r"configs\14175.yaml"))
        self.assertTrue(classify_delivery.is_symbols_related_path("./gamesymbol_candidate.py"))
        self.assertFalse(classify_delivery.is_symbols_related_path(r"docs\en\conributing-via-pr.md"))

    def test_nested_lookalike_root_modules_are_not_symbols(self) -> None:
        self.assertFalse(classify_delivery.is_symbols_related_path("pages/ida_analyze_bin.py"))
        self.assertFalse(classify_delivery.is_symbols_related_path("tests/gamedata_candidate.py"))

    def test_name_status_includes_both_rename_paths(self) -> None:
        output = "\n".join(
            (
                "M\tdocs/en/conributing-via-pr.md",
                "R100\tida_preprocessor_scripts/find-Old.py\tida_preprocessor_scripts/find-New.py",
            )
        )
        self.assertEqual(
            [
                "docs/en/conributing-via-pr.md",
                "ida_preprocessor_scripts/find-Old.py",
                "ida_preprocessor_scripts/find-New.py",
            ],
            classify_delivery.parse_name_status(output),
        )

    def test_main_prints_plain_pr_contract_for_explicit_paths(self) -> None:
        output = io.StringIO()
        with patch("sys.stdout", output):
            self.assertEqual(0, classify_delivery.main(["docs/en/conributing-via-pr.md", "memory/core.md"]))
        self.assertEqual("LIFECYCLE=0\nmode=plain-pr\nmatched=0\n", output.getvalue())

    def test_main_prints_lifecycle_contract_for_explicit_paths(self) -> None:
        output = io.StringIO()
        with patch("sys.stdout", output):
            self.assertEqual(0, classify_delivery.main(["configs/14175.yaml"]))
        self.assertEqual("LIFECYCLE=1\nmode=lifecycle\nmatched=1\nconfigs/14175.yaml\n", output.getvalue())

    def test_cached_and_committed_flags_read_git_name_status(self) -> None:
        cached = subprocess.CompletedProcess([], 0, stdout="M\tconfigs/14175.yaml\n", stderr="")
        committed = subprocess.CompletedProcess([], 0, stdout="M\tdocs/en/conributing-via-pr.md\n", stderr="")
        with patch.object(classify_delivery.subprocess, "run", return_value=cached) as run:
            output = io.StringIO()
            with patch("sys.stdout", output):
                self.assertEqual(0, classify_delivery.main(["--cached"]))
            run.assert_called_once_with(
                ["git", "diff", "--name-status", "--cached"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual("LIFECYCLE=1\nmode=lifecycle\nmatched=1\nconfigs/14175.yaml\n", output.getvalue())

        with patch.object(classify_delivery.subprocess, "run", return_value=committed) as run:
            output = io.StringIO()
            with patch("sys.stdout", output):
                self.assertEqual(0, classify_delivery.main(["--committed"]))
            run.assert_called_once_with(
                ["git", "diff", "--name-status", "origin/main...HEAD"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual("LIFECYCLE=0\nmode=plain-pr\nmatched=0\n", output.getvalue())

    def test_cached_flag_rejects_explicit_paths(self) -> None:
        output = io.StringIO()
        with patch("sys.stderr", output):
            self.assertEqual(1, classify_delivery.main(["--cached", "docs/en/foo.md"]))
        self.assertIn("do not pass explicit paths with --cached", output.getvalue())


if __name__ == "__main__":
    unittest.main()
