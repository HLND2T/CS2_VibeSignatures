import unittest
from pathlib import Path
from unittest.mock import patch

import pr_validation_version
from pr_validation_version import PrValidationVersionError, select_validation_gamever


class TestPrValidationVersion(unittest.TestCase):
    def test_snapshot_pattern_excludes_metadata_companion(self) -> None:
        self.assertIsNotNone(pr_validation_version.SNAPSHOT_PATTERN.fullmatch("gamesymbols/14176.yaml"))
        self.assertIsNone(pr_validation_version.SNAPSHOT_PATTERN.fullmatch("gamesymbols/14176.metadata.yaml"))

    def test_bootstrap_uses_pr_gamever(self) -> None:
        self.assertEqual("14180", select_validation_gamever("14180", [], []))

    def test_same_version_snapshot_wins(self) -> None:
        self.assertEqual(
            "14180",
            select_validation_gamever(
                "14180",
                ["gamesymbols/14179.yaml", "gamesymbols/14180.yaml"],
                ["gamesymbols/14179.yaml"],
            ),
        )

    def test_single_older_snapshot_is_validation_version(self) -> None:
        self.assertEqual(
            "14179",
            select_validation_gamever("14180", ["gamesymbols/14179.yaml"], []),
        )

    def test_multiple_snapshots_require_one_latest_change(self) -> None:
        with self.assertRaisesRegex(PrValidationVersionError, "ambiguous"):
            select_validation_gamever(
                "14180",
                ["gamesymbols/14178.yaml", "gamesymbols/14179.yaml"],
                ["gamesymbols/14178.yaml", "gamesymbols/14179.yaml"],
            )

    def test_multiple_snapshots_require_a_publication_file_list(self) -> None:
        with self.assertRaisesRegex(PrValidationVersionError, "failed to locate"):
            select_validation_gamever(
                "14180",
                ["gamesymbols/14178.yaml", "gamesymbols/14179.yaml"],
                [],
            )

    def test_resolver_returns_snapshot_path_and_publication_commit(self) -> None:
        with (
            patch.object(
                pr_validation_version,
                "load_yaml_file",
                return_value={"downloads": [{"tag": "14180"}]},
            ),
            patch.object(
                pr_validation_version,
                "_git_lines",
                side_effect=[
                    [],
                    ["gamesymbols/14178.yaml", "gamesymbols/14179.yaml"],
                    ["1" * 40, "gamesymbols/14179.yaml"],
                    ["2" * 40],
                ],
            ) as git_lines,
        ):
            selection = pr_validation_version.resolve_validation_selection(Path("."), "3" * 40)

        self.assertEqual("14180", selection.pr_gamever)
        self.assertEqual("14179", selection.gamever)
        self.assertEqual("gamesymbols/14179.yaml", selection.base_snapshot_path)
        self.assertEqual("2" * 40, selection.base_snapshot_commit)
        self.assertEqual(
            [
                "diff",
                "--name-only",
                "3" * 40,
                "HEAD",
                "--",
                "configs",
            ],
            git_lines.call_args_list[0].args[1],
        )
        self.assertEqual(
            [
                "log",
                "-1",
                "--format=%H",
                "--name-only",
                "--first-parent",
                "3" * 40,
                "--",
                "gamesymbols/14178.yaml",
                "gamesymbols/14179.yaml",
            ],
            git_lines.call_args_list[2].args[1],
        )
        self.assertEqual(
            ["log", "-1", "--format=%H", "3" * 40, "--", "gamesymbols/14179.yaml"],
            git_lines.call_args_list[3].args[1],
        )

    def test_resolver_prefers_single_changed_historical_config(self) -> None:
        with (
            patch.object(
                pr_validation_version,
                "load_yaml_file",
                return_value={"downloads": [{"tag": "14180"}]},
            ),
            patch.object(
                pr_validation_version,
                "changed_head_config_gamevers",
                return_value=["14176"],
            ),
            patch.object(
                pr_validation_version,
                "_git_lines",
                side_effect=[
                    ["gamesymbols/14176.yaml", "gamesymbols/14180.yaml"],
                    ["2" * 40],
                ],
            ),
        ):
            selection = pr_validation_version.resolve_validation_selection(Path("."), "3" * 40)

        self.assertEqual("14180", selection.pr_gamever)
        self.assertEqual("14176", selection.gamever)
        self.assertEqual("gamesymbols/14176.yaml", selection.base_snapshot_path)

    def test_resolver_rejects_multiple_changed_versioned_configs(self) -> None:
        with (
            patch.object(
                pr_validation_version,
                "load_yaml_file",
                return_value={"downloads": [{"tag": "14180"}]},
            ),
            patch.object(
                pr_validation_version,
                "changed_head_config_gamevers",
                return_value=["14176", "14177"],
            ),
            self.assertRaisesRegex(PrValidationVersionError, "multiple versioned configs"),
        ):
            pr_validation_version.resolve_validation_selection(Path("."), "3" * 40)


if __name__ == "__main__":
    unittest.main()
