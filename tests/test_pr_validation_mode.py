"""Tests for the PR validation-mode classifier."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pr_validation_mode as pvm
from gamesymbol_snapshot_lib.model import ChangedPath

SAMPLE_RULES_YAML = """\
schema_version: 1
rules:
  - paths:
      - configs/*.yaml
      - ida_analyze_bin.py
    reason: analysis config and analyzer
  - regexes:
      - ^\\.claude/skills/find-.*
    reason: find-* skills
"""


def _load_sample_rules() -> tuple[pvm.ImpactRule, ...]:
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "pr_validation_mode.yaml"
        config.write_text(SAMPLE_RULES_YAML, encoding="utf-8")
        return pvm.load_rules_from_file(config)


class TestParseRules(unittest.TestCase):
    def test_valid_rules_parse(self) -> None:
        rules = _load_sample_rules()
        self.assertEqual(2, len(rules))
        self.assertIn("configs/*.yaml", rules[0].glob_patterns)
        self.assertEqual(1, len(rules[1].regex_patterns))

    def test_unknown_top_level_key_rejected(self) -> None:
        with self.assertRaises(pvm.PrValidationModeError):
            pvm.parse_rules({"schema_version": 1, "rules": [], "extra": []})

    def test_bad_schema_version_rejected(self) -> None:
        with self.assertRaises(pvm.PrValidationModeError):
            pvm.parse_rules({"schema_version": 2, "rules": [{"paths": ["a.py"]}]})

    def test_empty_rules_rejected(self) -> None:
        with self.assertRaises(pvm.PrValidationModeError):
            pvm.parse_rules({"schema_version": 1, "rules": []})

    def test_rule_without_paths_or_regexes_rejected(self) -> None:
        with self.assertRaises(pvm.PrValidationModeError):
            pvm.parse_rules({"schema_version": 1, "rules": [{"reason": "why"}]})

    def test_unknown_rule_key_rejected(self) -> None:
        with self.assertRaises(pvm.PrValidationModeError):
            pvm.parse_rules({"schema_version": 1, "rules": [{"paths": ["a.py"], "scope": "all"}]})

    def test_invalid_glob_rejected(self) -> None:
        for pattern in ("a\\b.py", "/abs.py", "../up.py", "a[1].py", "a{b}.py", "a//b.py", ""):
            with self.subTest(pattern=pattern), self.assertRaises(pvm.PrValidationModeError):
                pvm.parse_rules({"schema_version": 1, "rules": [{"paths": [pattern]}]})

    def test_invalid_regex_rejected(self) -> None:
        with self.assertRaises(pvm.PrValidationModeError):
            pvm.parse_rules({"schema_version": 1, "rules": [{"regexes": ["("]}]})

    def test_non_string_path_entry_rejected(self) -> None:
        with self.assertRaises(pvm.PrValidationModeError):
            pvm.parse_rules({"schema_version": 1, "rules": [{"paths": ["a.py", 42]}]})


class TestClassifyPaths(unittest.TestCase):
    def setUp(self) -> None:
        self.rules = _load_sample_rules()

    def test_glob_hit_routes_full(self) -> None:
        result = pvm.classify_paths(["configs/14176.yaml"], self.rules)
        self.assertEqual("full", result.mode)
        self.assertIn("analysis config and analyzer", result.matched_rules)

    def test_glob_star_crosses_slash(self) -> None:
        result = pvm.classify_paths(["configs/14176/extra.yaml"], self.rules)
        self.assertEqual("full", result.mode)

    def test_regex_hit_routes_full(self) -> None:
        result = pvm.classify_paths([".claude/skills/find-Foo/SKILL.md"], self.rules)
        self.assertEqual("full", result.mode)

    def test_no_match_routes_light(self) -> None:
        result = pvm.classify_paths(["docs/architecture.md"], self.rules)
        self.assertEqual("light", result.mode)
        self.assertEqual((), result.matched_rules)

    def test_backslash_path_normalized(self) -> None:
        result = pvm.classify_paths(["configs\\14176.yaml"], self.rules)
        self.assertEqual("full", result.mode)

    def test_leading_dot_slash_stripped(self) -> None:
        result = pvm.classify_paths(["./ida_analyze_bin.py"], self.rules)
        self.assertEqual("full", result.mode)

    def test_force_light_overrides_match(self) -> None:
        result = pvm.classify_paths(["ida_analyze_bin.py"], self.rules, force_light=True)
        self.assertEqual("light", result.mode)
        self.assertTrue(result.force_light)


class TestParseChangedPaths(unittest.TestCase):
    def test_rename_keeps_both_sides(self) -> None:
        raw = b"R100\x00configs/old.yaml\x00configs/new.yaml\x00"
        (change,) = pvm.parse_changed_paths(raw)
        self.assertEqual("R", change.status)
        self.assertEqual("configs/old.yaml", change.old_path)
        self.assertEqual("configs/new.yaml", change.new_path)

    def test_add_and_delete(self) -> None:
        added, deleted = pvm.parse_changed_paths(b"A\x00gamesymbols/new.yaml\x00D\x00docs/old.md\x00")
        self.assertEqual(ChangedPath("A", None, "gamesymbols/new.yaml"), added)
        self.assertEqual(ChangedPath("D", "docs/old.md", None), deleted)

    def test_malformed_status_rejected(self) -> None:
        with self.assertRaises(pvm.PrValidationModeError):
            pvm.parse_changed_paths(b"X\x00path\x00")

    def test_rename_sides_both_route_full(self) -> None:
        rules = pvm.parse_rules({"schema_version": 1, "rules": [{"paths": ["gamesymbols/**"]}]})
        change = pvm.parse_changed_paths(b"R100\x00gamesymbols/old.yaml\x00gamesymbols/new.yaml\x00")[0]
        paths = [path for path in (change.old_path, change.new_path) if path]
        self.assertEqual("full", pvm.classify_paths(paths, rules).mode)


class TestCli(unittest.TestCase):
    FAKE_SHA = "a" * 40

    def _run(self, *args, rules_yaml=SAMPLE_RULES_YAML):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "pr_validation_mode.yaml"
            config.write_text(rules_yaml, encoding="utf-8")
            output = Path(tmp) / "github-output.txt"
            changes = [ChangedPath("M", "ida_analyze_bin.py", "ida_analyze_bin.py")]
            with (
                mock.patch("pr_validation_mode.changed_paths", return_value=changes),
                mock.patch("pr_validation_mode.latest_gamever", return_value="14176"),
            ):
                exit_code = pvm.main(
                    [
                        "--repo-root",
                        ".",
                        "--base-ref",
                        self.FAKE_SHA,
                        "--config",
                        str(config),
                        "--github-output",
                        str(output),
                        *args,
                    ]
                )
            return exit_code, output.read_text(encoding="utf-8") if output.exists() else ""

    def test_main_writes_full_output(self) -> None:
        exit_code, text = self._run()
        self.assertEqual(0, exit_code)
        self.assertIn("validation-mode=full", text)
        self.assertIn("latest-gamever=14176", text)

    def test_main_writes_light_output_for_unmatched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "pr_validation_mode.yaml"
            config.write_text("schema_version: 1\nrules:\n  - paths: [configs/*.yaml]\n", encoding="utf-8")
            output = Path(tmp) / "github-output.txt"
            with mock.patch(
                "pr_validation_mode.changed_paths", return_value=[ChangedPath("M", "docs/x.md", "docs/x.md")]
            ):
                exit_code = pvm.main(
                    [
                        "--repo-root",
                        ".",
                        "--base-ref",
                        self.FAKE_SHA,
                        "--config",
                        str(config),
                        "--github-output",
                        str(output),
                    ]
                )
            self.assertEqual(0, exit_code)
            self.assertIn("validation-mode=light", output.read_text(encoding="utf-8"))

    def test_main_force_light_overrides(self) -> None:
        exit_code, text = self._run("--force-light")
        self.assertEqual(0, exit_code)
        self.assertIn("validation-mode=light", text)

    def test_main_fails_closed_to_full_when_trusted_config_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "github-output.txt"
            with (
                mock.patch(
                    "pr_validation_mode.load_rules_from_ref",
                    side_effect=pvm.TrustedConfigMissingError("missing trusted config"),
                ),
                mock.patch(
                    "pr_validation_mode.changed_paths",
                    return_value=[ChangedPath("M", "docs/x.md", "docs/x.md")],
                ),
                mock.patch("pr_validation_mode.latest_gamever", return_value="14176"),
            ):
                exit_code = pvm.main(
                    [
                        "--repo-root",
                        ".",
                        "--base-ref",
                        self.FAKE_SHA,
                        "--force-light",
                        "--github-output",
                        str(output),
                    ]
                )
            self.assertEqual(0, exit_code)
            text = output.read_text(encoding="utf-8")
            self.assertIn("validation-mode=full", text)

    def test_main_fails_closed_on_bad_base_ref(self) -> None:
        exit_code, _ = self._run_with_bad_base()
        self.assertEqual(1, exit_code)

    def _run_with_bad_base(self) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "pr_validation_mode.yaml"
            config.write_text(SAMPLE_RULES_YAML, encoding="utf-8")
            output = Path(tmp) / "github-output.txt"
            exit_code = pvm.main(
                ["--repo-root", ".", "--base-ref", "not-a-sha", "--config", str(config), "--github-output", str(output)]
            )
            return exit_code, output.read_text(encoding="utf-8") if output.exists() else ""


class PrValidationModeRepositoryContractTests(unittest.TestCase):
    def setUp(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        self.rules = pvm.load_rules_from_file(repo_root / "pr_validation_mode.yaml")

    def test_config_schema_is_current(self) -> None:
        document = pvm.load_yaml((Path(__file__).resolve().parents[1] / "pr_validation_mode.yaml").read_bytes())
        self.assertEqual(1, document["schema_version"])
        self.assertTrue(document["rules"])

    def test_analysis_paths_route_full(self) -> None:
        full_paths = [
            "download.yaml",
            "configs/14176.yaml",
            "gamesymbols/14176.yaml",
            "pr_validation_version.py",
            "ida_analyze_bin.py",
            "ida_analyze_util.py",
            "ida_skill_preprocessor.py",
            "ida_preprocessor_scripts/find-Foo.py",
            ".claude/skills/find-Foo/SKILL.md",
            ".claude/skills/create-preprocessor-scripts/SKILL.md",
            "gamesymbol_snapshot.py",
            "gamesymbol_snapshot_lib/pr_validation.py",
            "gamesymbol_candidate.py",
            "gamesymbol_pr_validation.py",
            "warmup_idb_worker.py",
            "idb_cache.py",
            "gamedata_candidate.py",
            "gamedata-generators/CS2Fixes/gamedata.py",
            "update_gamedata.py",
            "run_cpp_tests.py",
            "cpp_tests/foo.cpp",
            "hl2sdk_cs2",
            "process_scheduler_redis.py",
            "release_workflow.py",
            "release_workflow_lib/cli.py",
            "agent_runner.py",
            ".github/workflows/pr-self-runner.yml",
            "pyproject.toml",
            "pr_validation_mode.py",
            "pr_validation_mode.yaml",
        ]
        for path in full_paths:
            with self.subTest(path=path):
                result = pvm.classify_paths([path], self.rules)
                self.assertEqual("full", result.mode, f"expected full for {path}")

    def test_innocuous_paths_stay_light(self) -> None:
        for path in (
            "README.md",
            "docs/architecture.md",
            "memory/notes.md",
            ".claude/skills/cleanup-workspace/SKILL.md",
        ):
            with self.subTest(path=path):
                result = pvm.classify_paths([path], self.rules)
                self.assertEqual("light", result.mode, f"expected light for {path}")


if __name__ == "__main__":
    unittest.main()
