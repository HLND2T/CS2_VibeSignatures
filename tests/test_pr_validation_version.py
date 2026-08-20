import unittest
from pathlib import Path
from unittest.mock import patch

import pr_validation_version
from pr_validation_version import PrValidationVersionError, select_validation_gamever


class TestPrValidationVersion(unittest.TestCase):
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
                    ["gamesymbols/14178.yaml", "gamesymbols/14179.yaml"],
                    ["1" * 40, "gamesymbols/14179.yaml"],
                    ["2" * 40],
                ],
            ),
        ):
            selection = pr_validation_version.resolve_validation_selection(Path("."), "3" * 40)

        self.assertEqual("14180", selection.pr_gamever)
        self.assertEqual("14179", selection.gamever)
        self.assertEqual("gamesymbols/14179.yaml", selection.base_snapshot_path)
        self.assertEqual("2" * 40, selection.base_snapshot_commit)


if __name__ == "__main__":
    unittest.main()
