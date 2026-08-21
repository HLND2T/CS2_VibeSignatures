import importlib.util
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from gamesymbol_snapshot_lib.operations import pack_snapshot
from tests.gamesymbol_snapshot_test_support import module, skill, write_binary, write_config, write_yaml


SCRIPT = Path(".claude/skills/restore-from-snapshot/scripts/restore_from_snapshot.py")
SPEC = importlib.util.spec_from_file_location("project_restore_from_snapshot", SCRIPT)
restore_skill = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(restore_skill)


class TestRestoreFromSnapshotSkill(unittest.TestCase):
    def test_script_resolves_its_own_repository_root(self) -> None:
        expected = SCRIPT.resolve().parents[4]
        completed = subprocess.CompletedProcess([], 0, stdout=f"{expected}\n", stderr="")
        with patch.object(restore_skill.subprocess, "run", return_value=completed):
            self.assertEqual(expected, restore_skill.repository_root())

    def test_base_snapshot_uses_newest_earlier_tracked_version(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            snapshots = root / "gamesymbols"
            snapshots.mkdir()
            (snapshots / "14168.yaml").write_text("snapshot", encoding="utf-8")
            (snapshots / "14170.yaml").write_text("snapshot", encoding="utf-8")
            result = restore_skill.find_base_snapshot(root, "14171", ["14168", "14169", "14170", "14171"])
        self.assertEqual(snapshots / "14170.yaml", result)

    def test_trusted_restore_uses_internal_round_trip_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            snapshot = root / "gamesymbols" / "14168.yaml"
            snapshot.parent.mkdir()
            snapshot.write_text("snapshot", encoding="utf-8")
            config = root / "configs" / "14168.yaml"
            with (
                patch.object(restore_skill, "load_versions", return_value=["14168"]),
                patch.object(restore_skill, "resolve_analysis_config", return_value=config),
                patch.object(restore_skill, "restore_snapshot") as restore,
            ):
                result = restore_skill.restore(root, "14168")
        restore.assert_called_once_with("14168", root / "bin", config, snapshot, replace=False)
        self.assertEqual("trusted", result["mode"])

    def test_trusted_restore_runs_against_a_real_temporary_snapshot_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "download.yaml").write_text('downloads:\n  - tag: "14168"\n', encoding="utf-8")
            config = root / "configs" / "14168.yaml"
            write_config(config, [module("server", [skill("find-a", ["A.{platform}.yaml"])])])
            windows = root / "bin/14168/server/A.windows.yaml"
            linux = root / "bin/14168/server/A.linux.yaml"
            write_yaml(windows, {"func_name": "A", "func_size": 1})
            write_yaml(linux, {"func_name": "A", "func_size": 2})
            write_binary(root / "bin/14168/server/server.dll")
            write_binary(root / "bin/14168/server/server.so")
            snapshot = root / "gamesymbols" / "14168.yaml"
            pack_snapshot("14168", root / "bin", config, snapshot)
            (root / "bin/14168/server/server.dll").unlink()
            (root / "bin/14168/server/server.so").unlink()
            windows.unlink()
            linux.unlink()

            result = restore_skill.restore(root, "14168")

            self.assertEqual("trusted", result["mode"])
            self.assertTrue(windows.is_file())
            self.assertTrue(linux.is_file())

    def test_missing_snapshot_suggests_base_without_mutation(self) -> None:
        root = Path("repo")
        base_snapshot = root / "gamesymbols" / "14168.yaml"
        with (
            patch.object(restore_skill, "load_versions", return_value=["14168", "14169"]),
            patch.object(restore_skill, "find_snapshot", side_effect=[None, base_snapshot]),
            patch.object(restore_skill, "restore_snapshot") as restore,
            patch.object(restore_skill, "force_restore_base_snapshot") as force_restore,
        ):
            result = restore_skill.restore(root, "14169")
        self.assertEqual("unavailable", result["mode"])
        self.assertEqual("14168", result["suggested_base_gamever"])
        restore.assert_not_called()
        force_restore.assert_not_called()

    def test_force_restore_replaces_only_target_yaml_without_contract_checks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            snapshot = root / "gamesymbols" / "14168.yaml"
            snapshot.parent.mkdir()
            snapshot.write_text(
                yaml.safe_dump(
                    {
                        "schema_version": 2,
                        "config_digest_version": 2,
                        "game_version": "14168",
                        "config_sha256": f"sha256:{'0' * 64}",
                        "file_count": 1,
                        "files": {"server/example.windows.yaml": {"func_name": "Example"}},
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            game_root = root / "bin" / "14169" / "server"
            game_root.mkdir(parents=True)
            (game_root / "stale.yaml").write_text("stale: true\n", encoding="utf-8")
            (game_root / "server.dll").write_bytes(b"binary")

            restore_skill.force_restore_base_snapshot(root, "14169", "14168", snapshot)

            self.assertFalse((game_root / "stale.yaml").exists())
            self.assertEqual({"func_name": "Example"}, yaml.safe_load((game_root / "example.windows.yaml").read_text()))
            self.assertEqual(b"binary", (game_root / "server.dll").read_bytes())

    def test_explicit_force_option_routes_through_forced_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            snapshot = root / "gamesymbols" / "14168.yaml"
            snapshot.parent.mkdir()
            snapshot.write_text("snapshot", encoding="utf-8")
            with (
                patch.object(restore_skill, "load_versions", return_value=["14168", "14169"]),
                patch.object(restore_skill, "force_restore_base_snapshot") as force_restore,
            ):
                result = restore_skill.restore(root, "14169", "14168")
        self.assertEqual("forced-base", result["mode"])
        force_restore.assert_called_once_with(root, "14169", "14168", snapshot)

    def test_main_reports_unavailable_and_suggestion(self) -> None:
        result = {"mode": "unavailable", "gamever": "14169", "suggested_base_gamever": "14168"}
        output = io.StringIO()
        with (
            patch.object(restore_skill, "repository_root", return_value=Path("repo")),
            patch.object(restore_skill, "restore", return_value=result),
            patch("sys.stdout", output),
        ):
            self.assertEqual(0, restore_skill.main(["14169"]))
        self.assertIn("Symbol snapshot: unavailable; no YAML restored", output.getvalue())
        self.assertIn("Suggested base snapshot: gamesymbols/14168.yaml", output.getvalue())


if __name__ == "__main__":
    unittest.main()
