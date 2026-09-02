from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bin_artifact_contract import ArtifactContractError
from release_source_preflight import ReleaseSourcePreflightError, validate_release_source


class ReleaseSourcePreflightTests(unittest.TestCase):
    source_sha = "a" * 40

    def _source_tree(self, root: Path, *, mode: str = "source-owned") -> None:
        (root / "source_artifact_policy.yaml").write_text(
            f"schema_version: 1\nmode: {mode}\nartifact_root: bin_artifacts\nartifact_contract_schema_version: 1\n",
            encoding="utf-8",
        )
        (root / "download.yaml").write_text("downloads:\n  - tag: '14180'\n", encoding="utf-8")
        (root / "configs").mkdir()
        (root / "configs" / "14180.yaml").write_text("modules: []\n", encoding="utf-8")

    def test_validates_reachable_source_owned_artifact_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._source_tree(root)
            inventory = SimpleNamespace(file_count=42, inventory_sha256="sha256:" + "b" * 64)
            binary_lock = SimpleNamespace(sha256="sha256:" + "d" * 64)
            with (
                patch(
                    "release_source_preflight._git",
                    side_effect=[self.source_sha, "c" * 40, "2026-09-01T12:34:56+08:00"],
                ),
                patch(
                    "release_source_preflight.subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, b"", b""),
                ),
                patch("release_source_preflight.build_game_artifact_inventory", return_value=inventory) as build,
                patch("release_source_preflight.load_source_binary_lock", return_value=binary_lock),
            ):
                result = validate_release_source(
                    repo_root=root,
                    repository="HLND2T/CS2_VibeSignatures",
                    game_version="14180",
                    source_sha=self.source_sha,
                    default_ref="origin/main",
                )

            self.assertEqual(42, result["artifact_file_count"])
            self.assertEqual(inventory.inventory_sha256, result["artifact_inventory_sha256"])
            self.assertEqual(binary_lock.sha256, result["binary_lock_sha256"])
            self.assertEqual("2026-09-01T04:34:56Z", result["source_publish_time"])
            self.assertTrue(build.call_args.kwargs["require_tracked"])

    def test_rejects_legacy_policy_before_artifact_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._source_tree(root, mode="legacy")
            with (
                patch("release_source_preflight._git", return_value=self.source_sha),
                patch(
                    "release_source_preflight.subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, b"", b""),
                ),
                patch("release_source_preflight.build_game_artifact_inventory") as build,
            ):
                with self.assertRaisesRegex(ReleaseSourcePreflightError, "must be source-owned"):
                    validate_release_source(
                        repo_root=root,
                        repository="HLND2T/CS2_VibeSignatures",
                        game_version="14180",
                        source_sha=self.source_sha,
                        default_ref="origin/main",
                    )
            build.assert_not_called()

    def test_reports_missing_artifacts_as_bootstrap_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._source_tree(root)
            with (
                patch("release_source_preflight._git", return_value=self.source_sha),
                patch(
                    "release_source_preflight.subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0, b"", b""),
                ),
                patch(
                    "release_source_preflight.build_game_artifact_inventory",
                    side_effect=ArtifactContractError("missing required artifacts"),
                ),
            ):
                with self.assertRaisesRegex(ReleaseSourcePreflightError, "bootstrap required"):
                    validate_release_source(
                        repo_root=root,
                        repository="HLND2T/CS2_VibeSignatures",
                        game_version="14180",
                        source_sha=self.source_sha,
                        default_ref="origin/main",
                    )


if __name__ == "__main__":
    unittest.main()
