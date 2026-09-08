from __future__ import annotations

import json
import contextlib
import io
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ida_analyze_bin
import release_artifact_rebuild as rar
from bin_artifact_contract import build_game_artifact_inventory
from ida_analyze_util import canonical_symbol_yaml_bytes
from tests.gamesymbol_snapshot_test_support import write_binary, write_config, write_source_binary_lock


class ReleaseArtifactRebuildTests(unittest.TestCase):
    def test_verify_failure_preserves_comparison_evidence(self):
        for failure in ("drift", "missing", "extra", "invalid", "noncanonical", "report", "checkout"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                temp = Path(temporary)
                root = temp / "repo"
                root.mkdir()
                source_sha = self._repository(root)
                preparation = rar.prepare_release_rebuild(
                    repo_root=root,
                    source_sha=source_sha,
                    game_version="1",
                    binary_root=root / "bin",
                    staging_root=temp / "rebuild",
                )
                shutil.copytree(root / "bin_artifacts", preparation["actual_artifact_root"], dirs_exist_ok=True)
                self._write_execution_report(preparation)
                relative = Path("1/server/A.windows.yaml")
                expected = (root / "bin_artifacts" / relative).read_bytes()
                target = Path(preparation["actual_artifact_root"]) / relative
                if failure == "drift":
                    target.write_bytes(
                        canonical_symbol_yaml_bytes({"func_name": "A", "func_rva": "0x20"}, category="func")
                    )
                elif failure == "missing":
                    target.unlink()
                elif failure == "extra":
                    target.with_name("extra.yaml").write_bytes(b"extra: true\n")
                elif failure == "invalid":
                    target.write_bytes(b"broken: [\n")
                elif failure == "noncanonical":
                    target.write_bytes(target.read_bytes() + b" ")
                elif failure == "checkout":
                    (root / "bin_artifacts" / relative).write_bytes(b"changed checkout\n")
                else:
                    Path(preparation["execution_report"]).unlink()
                bundle = temp / "diagnostics"
                error = io.StringIO()
                with contextlib.redirect_stderr(error):
                    code = rar.main(
                        [
                            "verify",
                            "--repo-root",
                            str(root),
                            "--preparation",
                            str(temp / "rebuild/release-rebuild-preparation.json"),
                            "--diagnostics-dir",
                            str(bundle),
                            "--output",
                            str(temp / "verified.json"),
                        ]
                    )
                self.assertEqual(1, code)
                self.assertFalse((temp / "verified.json").exists())
                self.assertEqual(expected, (bundle / "expected/bin_artifacts" / relative).read_bytes())
                self.assertEqual(
                    b"changed checkout\n" if failure == "checkout" else expected,
                    (root / "bin_artifacts" / relative).read_bytes(),
                )
                if target.exists():
                    self.assertEqual(target.read_bytes(), (bundle / "actual/bin_artifacts" / relative).read_bytes())
                else:
                    self.assertFalse((bundle / "actual/bin_artifacts" / relative).exists())
                metadata = json.loads((bundle / "diagnostics.json").read_bytes())
                self.assertEqual(source_sha, metadata["source_sha"])
                self.assertIn("Error:", (bundle / "verification-error.txt").read_text())
                if failure == "drift":
                    self.assertIn("sha256=", error.getvalue())
                    self.assertIn("-func_rva: '0x10'", error.getvalue())
                    self.assertIn("+func_rva: '0x20'", error.getvalue())
                    with patch.object(rar, "MAX_LOG_CHARACTERS", 100):
                        with self.assertRaisesRegex(rar.ReleaseArtifactRebuildError, "diagnostics truncated") as raised:
                            rar.verify_release_rebuild(repo_root=root, preparation=preparation)
                    self.assertLess(len(str(raised.exception)), 200)
                if failure == "extra":
                    self.assertEqual(
                        b"extra: true\n", (bundle / "actual/bin_artifacts/1/server/extra.yaml").read_bytes()
                    )
                if failure == "report":
                    self.assertTrue(metadata["collection_errors"])

    def test_collection_skips_linked_tree_and_retains_other_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            root = temp / "repo"
            root.mkdir()
            source_sha = self._repository(root)
            preparation = rar.prepare_release_rebuild(
                repo_root=root,
                source_sha=source_sha,
                game_version="1",
                binary_root=root / "bin",
                staging_root=temp / "rebuild",
            )
            linked_tree = Path(preparation["actual_artifact_root"]) / "linked"
            linked_tree.mkdir()
            (linked_tree / "private.txt").write_text("must not copy")
            original_check = rar.is_reparse_point
            with patch.object(
                rar, "is_reparse_point", side_effect=lambda path: path == linked_tree or original_check(path)
            ):
                rar.collect_failure_diagnostics(
                    repo_root=root,
                    preparation_path=temp / "rebuild/release-rebuild-preparation.json",
                    destination=temp / "diagnostics",
                    error="original",
                )
            self.assertFalse((temp / "diagnostics/actual/bin_artifacts/linked/private.txt").exists())
            self.assertTrue((temp / "diagnostics/expected/bin_artifacts/1/server/A.windows.yaml").is_file())
            metadata = json.loads((temp / "diagnostics/diagnostics.json").read_bytes())
            self.assertTrue(any("skipped link" in error for error in metadata["collection_errors"]))

    def test_missing_preparation_still_preserves_original_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            rar.collect_failure_diagnostics(
                repo_root=temp / "repo",
                preparation_path=temp / "staging/missing.json",
                destination=temp / "diagnostics",
                error="original failure",
            )
            self.assertEqual("original failure\n", (temp / "diagnostics/verification-error.txt").read_text())
            metadata = json.loads((temp / "diagnostics/diagnostics.json").read_bytes())
            self.assertTrue(metadata["collection_errors"])

    def test_diagnostic_failure_does_not_replace_verification_error(self):
        error = io.StringIO()
        with (
            patch.object(rar, "verify_release_rebuild", side_effect=rar.ReleaseArtifactRebuildError("original")),
            patch.object(rar, "collect_failure_diagnostics", side_effect=OSError("disk full")),
            contextlib.redirect_stderr(error),
        ):
            code = rar.main(["verify", "--preparation", "missing", "--diagnostics-dir", "unused"])
        self.assertEqual(1, code)
        self.assertIn("Error: original", error.getvalue())
        self.assertIn("disk full", error.getvalue())

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
        (root / "download.yaml").write_text(
            "downloads:\n  - tag: '1'\n    manifests:\n      '100': '200'\n",
            encoding="utf-8",
        )
        artifact = root / "bin_artifacts" / "1" / "server" / "A.windows.yaml"
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(canonical_symbol_yaml_bytes({"func_name": "A", "func_rva": "0x10"}, category="func"))
        write_binary(root / "bin" / "1" / "server" / "server.dll")
        write_source_binary_lock(root, "1")
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
            "schema_version": 2,
            "game_version": preparation["game_version"],
            "prior_gamever": None,
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
            self.assertRegex(preparation["binary_lock_sha256"], r"^sha256:[0-9a-f]{64}$")
            shutil.copytree(root / "bin_artifacts", preparation["actual_artifact_root"], dirs_exist_ok=True)
            self._write_execution_report(preparation)

            result = rar.verify_release_rebuild(repo_root=root, preparation=preparation)
            verification_path = temporary_root / "release-rebuild-verification.json"
            verification_path.write_bytes(rar._canonical_json_bytes(result))

            self.assertEqual(source_sha, result["source_sha"])
            self.assertEqual(1, result["file_count"])
            self.assertEqual(result, rar.load_release_rebuild_verification(verification_path))
            with contextlib.redirect_stdout(io.StringIO()):
                code = rar.main(
                    [
                        "verify",
                        "--repo-root",
                        str(root),
                        "--preparation",
                        str(temporary_root / "release-rebuild/release-rebuild-preparation.json"),
                        "--diagnostics-dir",
                        str(temporary_root / "diagnostics"),
                    ]
                )
            self.assertEqual(0, code)
            self.assertFalse((temporary_root / "diagnostics").exists())

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

    def test_release_verify_rejects_selected_execution_evidence(self) -> None:
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

            report_path = Path(preparation["execution_report"])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            del report["force_all"]
            report["execution_strategy"] = "base-inherited-selected-v1"
            report["execution_sha256"] = ida_analyze_bin._selected_execution_digest(report)
            report_path.write_bytes(rar._canonical_json_bytes(report))

            with self.assertRaisesRegex(
                rar.ReleaseArtifactRebuildError, "digest mismatch|does not prove the required release run"
            ):
                rar.verify_release_rebuild(repo_root=root, preparation=preparation)

    def test_prepare_rejects_canonical_checkout_artifact_drift_from_source_sha(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            source_sha = self._repository(root)
            artifact = root / "bin_artifacts" / "1" / "server" / "A.windows.yaml"
            artifact.write_bytes(canonical_symbol_yaml_bytes({"func_name": "A", "func_rva": "0x20"}, category="func"))

            with self.assertRaisesRegex(rar.ReleaseArtifactRebuildError, "differs from Git revision blob"):
                rar.prepare_release_rebuild(
                    repo_root=root,
                    source_sha=source_sha,
                    game_version="1",
                    binary_root=root / "bin",
                    staging_root=temporary_root / "release-rebuild",
                )

    def test_prepare_rejects_binary_drift_from_source_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            source_sha = self._repository(root)
            (root / "bin" / "1" / "server" / "server.dll").write_bytes(b"forged-binary")

            with self.assertRaisesRegex(rar.ReleaseArtifactRebuildError, "binary identity mismatch"):
                rar.prepare_release_rebuild(
                    repo_root=root,
                    source_sha=source_sha,
                    game_version="1",
                    binary_root=root / "bin",
                    staging_root=temporary_root / "release-rebuild",
                )


if __name__ == "__main__":
    unittest.main()
