import unittest

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


if __name__ == "__main__":
    unittest.main()
