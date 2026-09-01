import importlib.util
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.gamesymbol_snapshot_test_support import module, skill, write_binary, write_config, write_yaml


SCRIPT = Path(".claude/skills/pack-snapshot/scripts/pack_snapshot.py")
SPEC = importlib.util.spec_from_file_location("project_pack_snapshot", SCRIPT)
pack_skill = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(pack_skill)


class TestPackSnapshotSkill(unittest.TestCase):
    def test_script_resolves_its_own_repository_root(self) -> None:
        expected = SCRIPT.resolve().parents[4]
        completed = subprocess.CompletedProcess([], 0, stdout=f"{expected}\n", stderr="")
        with patch.object(pack_skill.subprocess, "run", return_value=completed):
            self.assertEqual(expected, pack_skill.repository_root())

    def test_pack_writes_then_verifies_same_snapshot(self) -> None:
        root = Path("repo")
        config = root / "configs" / "14168.yaml"
        snapshot = root / "gamesymbols" / "14168.yaml"
        with (
            patch.object(pack_skill, "resolve_analysis_config", return_value=config),
            patch.object(pack_skill, "pack_snapshot", return_value=b"snapshot") as pack,
            patch.object(pack_skill, "verify_snapshot") as verify,
        ):
            result = pack_skill.pack(root, "14168")
        pack.assert_called_once_with(
            "14168",
            root / "bin",
            config,
            snapshot,
            artifactdir=root / "bin_artifacts",
        )
        verify.assert_called_once_with(
            "14168",
            root / "bin",
            config,
            snapshot,
            artifactdir=root / "bin_artifacts",
        )
        self.assertEqual(8, result["size"])

    def test_pack_runs_against_a_real_temporary_snapshot_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "configs" / "14168.yaml"
            write_config(config, [module("server", [skill("find-a", ["A.{platform}.yaml"])])])
            write_yaml(root / "bin_artifacts/14168/server/A.windows.yaml", {"func_name": "A", "func_size": 1})
            write_yaml(root / "bin_artifacts/14168/server/A.linux.yaml", {"func_name": "A", "func_size": 2})
            write_binary(root / "bin/14168/server/server.dll")
            write_binary(root / "bin/14168/server/server.so")

            result = pack_skill.pack(root, "14168")

            self.assertEqual(root / "gamesymbols" / "14168.yaml", result["snapshot"])
            self.assertGreater(result["size"], 0)
            self.assertTrue(result["snapshot"].is_file())

    def test_main_reports_snapshot_and_verification(self) -> None:
        root = SCRIPT.resolve().parents[4]
        result = {"gamever": "14168", "snapshot": root / "gamesymbols" / "14168.yaml", "size": 42}
        output = io.StringIO()
        with (
            patch.object(pack_skill, "repository_root", return_value=root),
            patch.object(pack_skill, "pack", return_value=result),
            patch("sys.stdout", output),
        ):
            self.assertEqual(0, pack_skill.main(["14168"]))
        self.assertIn("Packed snapshot: gamesymbols/14168.yaml (42 bytes)", output.getvalue())
        self.assertIn("Snapshot verification: passed", output.getvalue())


if __name__ == "__main__":
    unittest.main()
