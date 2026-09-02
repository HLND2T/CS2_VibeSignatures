from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import trusted_artifact_pr as tap
import trusted_pr_context as tpc
from source_artifact_schema import canonical_symbol_yaml_bytes
from tests.gamesymbol_snapshot_test_support import write_binary, write_config, write_source_binary_lock


class TrustedArtifactPrTests(unittest.TestCase):
    def _git(self, root: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            self.fail(result.stderr or f"git {' '.join(arguments)} failed")
        return result.stdout.strip()

    def _write_artifact(self, root: Path, name: str, rva: str) -> None:
        path = root / "bin_artifacts" / "1" / "server" / f"{name}.windows.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_symbol_yaml_bytes({"func_name": name, "func_rva": rva}, category="func"))

    def _write_execution_report(self, root: Path, plan: dict, preparation: dict) -> None:
        version = plan["game_versions"][0]
        gamever = version["game_version"]
        inventory = tap.build_game_artifact_inventory(
            repo_root=root,
            config_path=Path(preparation["config_root"]) / f"{gamever}.yaml",
            game_version=gamever,
            artifact_root=preparation["actual_artifact_root"],
            require_tracked=False,
        )
        files = {
            item["path"].removeprefix(f"bin_artifacts/{gamever}/"): item for item in version["merge_artifacts"]["files"]
        }
        report = {
            "schema_version": 2,
            "game_version": gamever,
            "config_path": str(Path(preparation["config_root"]) / f"{gamever}.yaml"),
            "binary_root": preparation["binary_root"],
            "artifact_root": preparation["actual_artifact_root"],
            "old_artifact_root": str(root / "bin_artifacts"),
            "prior_gamever": version["prior_gamever"],
            "force_all": True,
            "rename": False,
            "required_warm_idb": True,
            "run_id": "test",
            "summary": {},
            "inventory": {
                "file_count": inventory.file_count,
                "inventory_sha256": inventory.inventory_sha256,
            },
            "nodes": [],
            "producer_groups": [
                {
                    **group,
                    "attempted_node_ids": [group["alternative_node_ids"][0]],
                    "winner_node_id": group["alternative_node_ids"][0],
                    "output_sha256": files[group["artifact_path"]]["sha256"],
                }
                for group in version["affected_producer_groups"]
            ],
            "issues": [],
            "valid": True,
        }
        raw = tap._canonical_json_bytes(report)
        report["execution_sha256"] = "sha256:" + hashlib.sha256(b"source2-force-all-execution:v2\n" + raw).hexdigest()
        Path(preparation["execution_reports"][gamever]).write_bytes(tap._canonical_json_bytes(report))

    def _repository(
        self,
        root: Path,
        *,
        change_artifact: bool = True,
        add_extra: bool = False,
        add_unconfigured: bool = False,
        changed_path: str | None = None,
        cutover_transition: bool = False,
    ):
        self._git(root, "init", "-b", "main")
        self._git(root, "config", "user.email", "test@example.com")
        self._git(root, "config", "user.name", "Test")
        required = {path: f"trusted base {path}\n".encode() for path in tpc.TRUSTED_FILE_PATHS}
        required.update(
            {
                tpc.POLICY_REPO_PATH: (
                    b"schema_version: 1\nmode: "
                    + (b"bridge" if cutover_transition else b"source-owned")
                    + b"\nartifact_root: bin_artifacts\n"
                    b"artifact_contract_schema_version: 1\n"
                ),
                ".gitignore": b"bin/\n",
                "download.yaml": b"downloads:\n  - tag: '1'\n    manifests: {'1': '1'}\n",
                "ida_analyze_util.py": b"SERIALIZER = 1\n",
            }
        )
        for relative, payload in required.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        write_config(
            root / "configs" / "1.yaml",
            [
                {
                    "name": "server",
                    "path_windows": "game/bin/win64/server.dll",
                    "skills": [
                        {"name": "find-a", "expected_output": ["A.{platform}.yaml"]},
                        {
                            "name": "find-b",
                            "expected_input": ["A.{platform}.yaml"],
                            "expected_output": ["B.{platform}.yaml"],
                        },
                    ],
                    "symbols": [
                        {"name": "A", "category": "func", "platform": "windows"},
                        {"name": "B", "category": "func", "platform": "windows"},
                    ],
                }
            ],
        )
        write_binary(root / "bin" / "1" / "server" / "server.dll")
        write_source_binary_lock(root, "1")
        self._write_artifact(root, "A", "0x10")
        self._write_artifact(root, "B", "0x20")
        if cutover_transition:
            legacy = root / "gamesymbols" / "1.yaml"
            legacy.parent.mkdir(parents=True, exist_ok=True)
            legacy.write_text("legacy: true\n", encoding="utf-8")
        self._git(root, "add", ".")
        self._git(root, "commit", "-m", "base")
        base_sha = self._git(root, "rev-parse", "HEAD")

        self._git(root, "switch", "-c", "feature")
        if cutover_transition:
            (root / tpc.POLICY_REPO_PATH).write_text(
                "schema_version: 1\nmode: source-owned\nartifact_root: bin_artifacts\n"
                "artifact_contract_schema_version: 1\n",
                encoding="utf-8",
            )
            (root / "gamesymbols" / "1.yaml").unlink()
        if change_artifact:
            self._write_artifact(root, "A", "0x30")
        elif changed_path is None:
            (root / "ida_analyze_util.py").write_text("SERIALIZER = 2\n", encoding="utf-8")
        if changed_path == "download.yaml":
            (root / "download.yaml").write_text(
                "downloads:\n  - tag: '1'\n    manifests: {'1': '2'}\n", encoding="utf-8"
            )
            write_source_binary_lock(root, "1")
        elif changed_path == "binary_locks/1.json":
            write_binary(root / "bin" / "1" / "server" / "server.dll", b"replacement binary")
            write_source_binary_lock(root, "1")
        elif changed_path == "delete-binary-lock":
            (root / "binary_locks" / "1.json").unlink()
        elif changed_path == "add-unconfigured-binary-lock":
            path = root / "binary_locks" / "2.json"
            path.write_text("{}\n", encoding="utf-8")
        elif changed_path == "source_artifact_policy.yaml":
            (root / changed_path).write_text(
                "schema_version: 1\nmode: bridge\nartifact_root: bin_artifacts\n"
                "artifact_contract_schema_version: 1\n",
                encoding="utf-8",
            )
        elif changed_path:
            (root / changed_path).write_text("prospective trust-root change\n", encoding="utf-8")
        if add_extra:
            self._write_artifact(root, "Extra", "0x40")
        if add_unconfigured:
            path = root / "bin_artifacts" / "2" / "server" / "Extra.windows.yaml"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(canonical_symbol_yaml_bytes({"func_name": "Extra"}, category="func"))
        self._git(root, "add", ".")
        self._git(root, "commit", "-m", "head")
        head_sha = self._git(root, "rev-parse", "HEAD")
        self._git(root, "switch", "main")
        self._git(root, "merge", "--no-ff", "feature", "-m", "prospective merge")
        merge_sha = self._git(root, "rev-parse", "HEAD")
        context = tpc.build_trusted_pr_context(
            repo_root=root,
            base_ref=base_sha,
            head_ref=head_sha,
            merge_ref=merge_sha,
        )
        return base_sha, head_sha, merge_sha, context

    def test_plan_binds_tree_and_expands_artifact_owner_downstream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, merge, context = self._repository(root)

            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

            self.assertEqual("full", plan["mode"])
            self.assertEqual(merge, plan["merge_sha"])
            self.assertEqual(["1"], plan["affected_game_versions"])
            version = plan["game_versions"][0]
            self.assertEqual(version["base_binary_lock_sha256"], version["merge_binary_lock_sha256"])
            self.assertRegex(version["merge_binary_lock_sha256"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(["server/A.windows.yaml", "server/B.windows.yaml"], version["invalidated_paths"])
            self.assertEqual(
                {"find-a", "find-b"},
                {node["skill"] for node in version["selected_alternative_nodes"]},
            )
            self.assertEqual(plan, tap.validate_trusted_artifact_plan(plan))

    def test_bridge_to_source_owned_transition_validates_only_merge_truth_and_forces_full(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root, cutover_transition=True)

            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

            self.assertTrue(context["cutover_transition"])
            self.assertTrue(plan["cutover_transition"])
            self.assertEqual("full", plan["mode"])
            self.assertEqual(["1"], plan["affected_game_versions"])
            version = plan["game_versions"][0]
            self.assertIsNone(version["base_artifacts"])
            self.assertEqual(2, len(version["affected_producer_groups"]))
            self.assertIn("atomic legacy-to-source-owned cutover", version["reasons"])

    def test_isolated_preparation_uses_empty_root_and_exact_force_all_verify_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root)
            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

            preparation = tap.prepare_isolated_rebuild(repo_root=root, plan=plan, staging_root=staging)

            actual = Path(preparation["actual_artifact_root"])
            expected = Path(preparation["expected_artifact_root"])
            self.assertEqual([], list(actual.iterdir()))
            shutil.copytree(expected, actual, dirs_exist_ok=True)
            self._write_execution_report(root, plan, preparation)
            result = tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)
            self.assertEqual("1", result["game_versions"][0]["game_version"])
            self.assertRegex(result["game_versions"][0]["execution_sha256"], r"^sha256:[0-9a-f]{64}$")

    def test_isolated_verify_rejects_one_byte_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root)
            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)
            preparation = tap.prepare_isolated_rebuild(repo_root=root, plan=plan, staging_root=staging)
            actual = Path(preparation["actual_artifact_root"])
            shutil.copytree(Path(preparation["expected_artifact_root"]), actual, dirs_exist_ok=True)
            self._write_execution_report(root, plan, preparation)
            target = actual / "1" / "server" / "A.windows.yaml"
            target.write_bytes(target.read_bytes() + b" ")

            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "contract failed|byte mismatch"):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_isolated_verify_rejects_missing_execution_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root)
            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)
            preparation = tap.prepare_isolated_rebuild(repo_root=root, plan=plan, staging_root=staging)
            shutil.copytree(
                Path(preparation["expected_artifact_root"]),
                Path(preparation["actual_artifact_root"]),
                dirs_exist_ok=True,
            )

            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "unable to load force-all execution report"):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_isolated_preparation_rejects_gamever_outside_affected_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root)
            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "not an affected full-plan target"):
                tap.prepare_isolated_rebuild(
                    repo_root=root,
                    plan=plan,
                    staging_root=Path(temporary) / "isolated",
                    game_version="2",
                )

    def test_shared_serializer_change_broadly_selects_all_groups(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root, change_artifact=False)

            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

            version = plan["game_versions"][0]
            self.assertEqual(2, len(version["affected_producer_groups"]))
            self.assertIn("shared analyzer/serializer contract changed", version["reasons"])

    def test_root_analysis_runtime_change_broadly_selects_all_groups(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(
                root,
                change_artifact=False,
                changed_path="agent_runner.py",
            )

            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

            self.assertEqual("full", plan["mode"])
            version = plan["game_versions"][0]
            self.assertEqual(2, len(version["affected_producer_groups"]))
            self.assertIn("shared analyzer/serializer contract changed", version["reasons"])
            self.assertNotEqual(
                plan["base_analysis_sources"]["sha256"],
                plan["merge_analysis_sources"]["sha256"],
            )

    def test_download_identity_change_broadly_selects_all_groups(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(
                root,
                change_artifact=False,
                changed_path="download.yaml",
            )

            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

            self.assertEqual("full", plan["mode"])
            version = plan["game_versions"][0]
            self.assertEqual(2, len(version["affected_producer_groups"]))
            self.assertIn("download/binary identity changed", version["reasons"])

    def test_binary_lock_change_broadly_selects_all_groups(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(
                root,
                change_artifact=False,
                changed_path="binary_locks/1.json",
            )

            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

            self.assertEqual("full", plan["mode"])
            version = plan["game_versions"][0]
            self.assertNotEqual(version["base_binary_lock_sha256"], version["merge_binary_lock_sha256"])
            self.assertEqual(2, len(version["affected_producer_groups"]))
            self.assertIn("download/binary identity changed", version["reasons"])

    def test_missing_or_unconfigured_binary_lock_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root, changed_path="delete-binary-lock")
            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "binary lock"):
                tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root, changed_path="add-unconfigured-binary-lock")
            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "unconfigured GAMEVER"):
                tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

    def test_trust_root_change_requires_independent_bridge_update(self) -> None:
        for changed_path in ("source_artifact_policy.yaml", "binary_lock.py"):
            with self.subTest(changed_path=changed_path), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "repo"
                root.mkdir()
                _base, _head, _merge, context = self._repository(
                    root,
                    change_artifact=False,
                    changed_path=changed_path,
                )

                with self.assertRaisesRegex(tap.TrustedArtifactPrError, "independently merged bridge update"):
                    tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

    def test_unknown_artifact_and_plan_tamper_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root, add_extra=True)
            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "extra/stale"):
                tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root, add_unconfigured=True)
            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "unconfigured GAMEVER"):
                tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root)
            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)
            plan["merge_tree_sha"] = "0" * 40
            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "digest mismatch"):
                tap.validate_trusted_artifact_plan(plan)


if __name__ == "__main__":
    unittest.main()
