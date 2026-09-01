from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import ida_analyze_bin
import release_artifact_rebuild as rar
from bin_artifact_contract import build_game_artifact_inventory
from ida_analyze_util import canonical_symbol_yaml_bytes
from tests.gamesymbol_snapshot_test_support import write_binary, write_config


class ReleaseArtifactRebuildTests(unittest.TestCase):
    def _git(self, root: Path, *arguments: str, input_text: str | None = None) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            self.fail(result.stderr or f"git {' '.join(arguments)} failed")
        return result.stdout.strip()

    def _repository(self, root: Path) -> str:
        self._git(root, "init", "-b", "main")
        self._git(root, "config", "user.email", "test@example.com")
        self._git(root, "config", "user.name", "Test")
        write_config(
            root / "configs" / "1.yaml",
            [
                {
                    "name": "server",
                    "path_windows": "game/bin/win64/server.dll",
                    "skills": [{"name": "find-a", "expected_output": ["A.{platform}.yaml"]}],
                    "symbols": [{"name": "A", "category": "func", "platform": "windows"}],
                }
            ],
        )
        artifact = root / "bin_artifacts" / "1" / "server" / "A.windows.yaml"
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(canonical_symbol_yaml_bytes({"func_name": "A", "func_rva": "0x10"}, category="func"))
        write_binary(root / "bin" / "1" / "server" / "server.dll")
        empty_tree = self._git(root, "mktree", input_text="")
        sdk_commit = self._git(root, "commit-tree", empty_tree, "-m", "sdk")
        self._git(root, "add", ".")
        self._git(root, "update-index", "--add", "--cacheinfo", f"160000,{sdk_commit},hl2sdk_cs2")
        self._git(root, "commit", "-m", "source")
        return self._git(root, "rev-parse", "HEAD")

    def _write_execution_report(self, preparation: dict) -> None:
        actual = build_game_artifact_inventory(
            repo_root=Path(preparation["actual_artifact_root"]).parent,
            config_path=Path(preparation["analysis_command"][6]),
            game_version=preparation["game_version"],
            artifact_root=preparation["actual_artifact_root"],
            require_tracked=False,
        )
        document = {
            "schema_version": 1,
            "game_version": preparation["game_version"],
            "artifact_root": preparation["actual_artifact_root"],
            "force_all": True,
            "rename": True,
            "required_warm_idb": True,
            "valid": True,
            "inventory": {"file_count": actual.file_count, "inventory_sha256": actual.inventory_sha256},
        }
        document["execution_sha256"] = ida_analyze_bin._force_all_digest(document)
        Path(preparation["execution_report"]).write_bytes(rar._canonical_json_bytes(document))

    def test_prepare_requires_fresh_external_root_and_verify_matches_git_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            source_sha = self._repository(root)
            preparation = rar.prepare_release_rebuild(
                repo_root=root,
                source_sha=source_sha,
                game_version="1",
                binary_root=root / "bin",
                staging_root=temporary_root / "release-rebuild",
            )
            self.assertIn("-force_all", preparation["analysis_command"])
            self.assertIn("-rename", preparation["analysis_command"])
            shutil.copytree(root / "bin_artifacts", preparation["actual_artifact_root"], dirs_exist_ok=True)
            self._write_execution_report(preparation)

            result = rar.verify_release_rebuild(repo_root=root, preparation=preparation)

            self.assertEqual(source_sha, result["source_sha"])
            self.assertEqual(1, result["file_count"])

    def test_verify_rejects_one_byte_drift_and_execution_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            source_sha = self._repository(root)
            preparation = rar.prepare_release_rebuild(
                repo_root=root,
                source_sha=source_sha,
                game_version="1",
                binary_root=root / "bin",
                staging_root=temporary_root / "release-rebuild",
            )
            shutil.copytree(root / "bin_artifacts", preparation["actual_artifact_root"], dirs_exist_ok=True)
            self._write_execution_report(preparation)
            target = Path(preparation["actual_artifact_root"]) / "1" / "server" / "A.windows.yaml"
            target.write_bytes(target.read_bytes() + b" ")
            with self.assertRaisesRegex(rar.ReleaseArtifactRebuildError, "contract failed|differ"):
                rar.verify_release_rebuild(repo_root=root, preparation=preparation)

            shutil.copy2(root / "bin_artifacts" / "1" / "server" / "A.windows.yaml", target)
            report_path = Path(preparation["execution_report"])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["rename"] = False
            report_path.write_bytes(rar._canonical_json_bytes(report))
            with self.assertRaisesRegex(rar.ReleaseArtifactRebuildError, "digest mismatch"):
                rar.verify_release_rebuild(repo_root=root, preparation=preparation)


if __name__ == "__main__":
    unittest.main()
