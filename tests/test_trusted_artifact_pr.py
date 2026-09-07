from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import trusted_artifact_pr as tap
import trusted_pr_context as tpc
from ida_analyze_util import canonical_symbol_yaml_bytes
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
                for group in version["execute_groups"]
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
    ):
        self._git(root, "init", "-b", "main")
        self._git(root, "config", "user.email", "test@example.com")
        self._git(root, "config", "user.name", "Test")
        required = {path: f"trusted base {path}\n".encode() for path in tpc.TRUSTED_FILE_PATHS}
        required.update(
            {
                tpc.POLICY_REPO_PATH: (
                    b"schema_version: 1\nmode: source-owned\nartifact_root: bin_artifacts\n"
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
        self._git(root, "add", ".")
        self._git(root, "commit", "-m", "base")
        base_sha = self._git(root, "rev-parse", "HEAD")

        self._git(root, "switch", "-c", "feature")
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
                {node["skill"] for node in version["execute_nodes"]},
            )
            self.assertEqual(tap.FRESH_FULL_STRATEGY, plan["execution_strategy"])
            self.assertTrue(version["maintained"])
            self.assertEqual([], version["removed_paths"])
            self.assertEqual(plan, tap.validate_trusted_artifact_plan(plan))

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
            self.assertEqual(2, len(version["execute_groups"]))
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
            self.assertEqual(2, len(version["execute_groups"]))
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
            self.assertEqual(2, len(version["execute_groups"]))
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
            self.assertEqual(2, len(version["execute_groups"]))
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
        for changed_path in (
            "source_artifact_policy.yaml",
            "binary_lock.py",
            "analysis_output_contract.py",
            ".github/workflows/warmup-idb.yml",
            ".github/workflows/future-privileged.yml",
        ):
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


SELECTED_POLICY = (
    b"schema_version: 1\nmode: source-owned\nartifact_root: bin_artifacts\n"
    b"artifact_contract_schema_version: 1\nexecution_strategy: base-inherited-selected-v1\n"
)


class SelectedExecutionTests(unittest.TestCase):
    """Behavior tests for the base-inherited selected execution strategy."""

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

    def _artifact(self, name: str, rva: str):
        return canonical_symbol_yaml_bytes({"func_name": name, "func_rva": rva}, category="func")

    def _write_artifact(self, root: Path, name: str, rva: str) -> None:
        path = root / "bin_artifacts" / "1" / "server" / f"{name}.windows.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self._artifact(name, rva))

    def _skills(self, *, with_find_c: bool = True, alternatives: bool = False) -> list[dict]:
        skills = [
            {"name": "find-a", "expected_output": ["A.{platform}.yaml"]},
            {
                "name": "find-b",
                "expected_input": ["A.{platform}.yaml"],
                "expected_output": ["B.{platform}.yaml"],
            },
        ]
        if with_find_c:
            skills.append({"name": "find-c", "expected_output": ["C.{platform}.yaml"]})
        if alternatives:
            # Two alternatives competing for one shared optional output: the first may
            # legitimately concede (optional absent) and the second may materialize it.
            skills.extend(
                [
                    {"name": "find-p", "optional_output": ["Shared.{platform}.yaml"]},
                    {"name": "find-f", "optional_output": ["Shared.{platform}.yaml"]},
                ]
            )
        skills.extend(
            [
                {"name": "find-pre", "expected_output": ["Pre.{platform}.yaml"]},
                {
                    "name": "find-dep",
                    "prerequisite": ["find-pre", "find-session"],
                    "expected_input": ["Pre.{platform}.yaml"],
                    "expected_output": ["Dep.{platform}.yaml"],
                },
                # A pure session-side-effect prerequisite: no outputs, so it belongs to no
                # producer group and must still be proven executed when find-dep executes.
                {"name": "find-session"},
                {"name": "find-opt", "optional_output": ["Opt.{platform}.yaml"]},
            ]
        )
        return skills

    def _symbols(self, *, with_c: bool = True, alternatives: bool = False) -> list[dict]:
        symbols = [{"name": name, "category": "func", "platform": "windows"} for name in ("A", "B")]
        if with_c:
            symbols.append({"name": "C", "category": "func", "platform": "windows"})
        if alternatives:
            symbols.append({"name": "Shared", "category": "func", "platform": "windows"})
        symbols.extend({"name": name, "category": "func", "platform": "windows"} for name in ("Pre", "Dep", "Opt"))
        return symbols

    def _repository(
        self,
        root: Path,
        *,
        selected_policy: bool,
        change: str = "artifact-a",
    ):
        self._git(root, "init", "-b", "main")
        self._git(root, "config", "user.email", "test@example.com")
        self._git(root, "config", "user.name", "Test")
        required = {path: f"trusted base {path}\n".encode() for path in tpc.TRUSTED_FILE_PATHS}
        required.update(
            {
                tpc.POLICY_REPO_PATH: SELECTED_POLICY
                if selected_policy
                else (
                    b"schema_version: 1\nmode: source-owned\nartifact_root: bin_artifacts\n"
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
        alternatives = change == "alt-shared"
        write_config(
            root / "configs" / "1.yaml",
            [
                {
                    "name": "server",
                    "path_windows": "game/bin/win64/server.dll",
                    "skills": self._skills(alternatives=alternatives),
                    "symbols": self._symbols(alternatives=alternatives),
                }
            ],
        )
        write_binary(root / "bin" / "1" / "server" / "server.dll")
        write_source_binary_lock(root, "1")
        for name, rva in (("A", "0x10"), ("B", "0x20"), ("C", "0x30"), ("Pre", "0x40"), ("Dep", "0x50")):
            self._write_artifact(root, name, rva)
        if change == "drop-opt":
            self._write_artifact(root, "Opt", "0x70")
        self._git(root, "add", ".")
        self._git(root, "commit", "-m", "base")
        base_sha = self._git(root, "rev-parse", "HEAD")

        self._git(root, "switch", "-c", "feature")
        if change == "artifact-a":
            self._write_artifact(root, "A", "0x11")
        elif change == "artifact-dep":
            self._write_artifact(root, "Dep", "0x51")
        elif change == "shared-runtime":
            (root / "ida_analyze_util.py").write_text("SERIALIZER = 2\n", encoding="utf-8")
        elif change == "drop-opt":
            (root / "bin_artifacts" / "1" / "server" / "Opt.windows.yaml").unlink()
        elif change == "alt-shared":
            # A brand-new shared optional output: the planner executes both competing
            # alternatives, and the merge tree carries the fallback's materialized bytes.
            self._write_artifact(root, "Shared", "0x80")
        elif change == "remove-c":
            write_config(
                root / "configs" / "1.yaml",
                [
                    {
                        "name": "server",
                        "path_windows": "game/bin/win64/server.dll",
                        "skills": self._skills(with_find_c=False),
                        "symbols": self._symbols(with_c=False),
                    }
                ],
            )
            (root / "bin_artifacts" / "1" / "server" / "C.windows.yaml").unlink()
        else:
            raise AssertionError(f"unsupported change: {change}")
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

    def _plan_and_preparation(self, root: Path, staging: Path, *, change: str = "artifact-a"):
        _base, _head, _merge, context = self._repository(root, selected_policy=True, change=change)
        plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)
        preparation = tap.prepare_isolated_rebuild(repo_root=root, plan=plan, staging_root=staging)
        return plan, preparation

    def _simulate_selected_execution(self, root: Path, plan: dict, preparation: dict, *, skip_group: str | None = None):
        """Materialize the executed outputs exactly as the prospective merge tree carries them."""
        version = plan["game_versions"][0]
        gamever = version["game_version"]
        expected = Path(preparation["expected_artifact_root"]) / gamever
        actual = Path(preparation["actual_artifact_root"]) / gamever
        for group in version["execute_groups"]:
            if skip_group is not None and group["group_id"] == skip_group:
                continue
            source = expected / group["artifact_path"]
            if source.is_file():
                target = actual / group["artifact_path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)

    def _write_selected_report(
        self,
        root: Path,
        plan: dict,
        preparation: dict,
        *,
        extra_group: dict | None = None,
    ) -> None:
        version = plan["game_versions"][0]
        gamever = version["game_version"]
        manifest_path = Path(preparation["selected_execution_manifests"][gamever])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        try:
            inventory = tap.build_game_artifact_inventory(
                repo_root=root,
                config_path=Path(preparation["config_root"]) / f"{gamever}.yaml",
                game_version=gamever,
                artifact_root=preparation["actual_artifact_root"],
                require_tracked=False,
            )
            inventory_summary = {
                "file_count": inventory.file_count,
                "inventory_sha256": inventory.inventory_sha256,
            }
        except Exception:
            inventory_summary = None
        files = {
            item["path"].removeprefix(f"bin_artifacts/{gamever}/"): item for item in version["merge_artifacts"]["files"]
        }
        groups = []
        for group in version["execute_groups"]:
            produced = group["artifact_path"] in files
            groups.append(
                {
                    **group,
                    "attempted_node_ids": [group["alternative_node_ids"][0]],
                    "winner_node_id": group["alternative_node_ids"][0] if produced else None,
                    "output_sha256": files[group["artifact_path"]]["sha256"] if produced else None,
                }
            )
        if extra_group is not None:
            groups.append(extra_group)
        nodes = []
        for node in version["execute_nodes"]:
            produced = sorted(path for path in node["outputs"] if path in files)
            # The executor records every declared output that does not pre-exist as attempted;
            # a declared output that never materializes legally ends skipped (optional absent).
            attempted_paths = sorted(node["outputs"])
            if produced or not node["outputs"]:
                status, reason = "succeeded", None
            else:
                status, reason = "skipped", "optional_output_absent"
            nodes.append(
                {key: node[key] for key in ("node_id", "stage_index", "module", "platform", "skill", "fingerprint")}
                | {
                    "status": status,
                    "reason": reason,
                    "attempted": True,
                    "attempted_paths": attempted_paths,
                    "produced_paths": produced,
                }
            )
        report = {
            "schema_version": 1,
            "execution_strategy": tap.BASE_INHERITED_SELECTED_STRATEGY,
            "game_version": gamever,
            "config_path": str(Path(preparation["config_root"]) / f"{gamever}.yaml"),
            "binary_root": preparation["binary_root"],
            "artifact_root": preparation["actual_artifact_root"],
            "old_artifact_root": str(root / "bin_artifacts"),
            "prior_gamever": version["prior_gamever"],
            "plan_sha256": plan["plan_sha256"],
            "manifest_sha256": manifest["manifest_sha256"],
            "inherited_initial_inventory_sha256": preparation["initial_actual_inventory_sha256"][gamever],
            "required_warm_idb": True,
            "run_id": "test",
            "summary": {},
            "inventory": inventory_summary,
            "nodes": nodes,
            "producer_groups": groups,
            "issues": [],
            "valid": True,
        }
        raw = tap._canonical_json_bytes(report)
        report["execution_sha256"] = "sha256:" + hashlib.sha256(b"source2-selected-execution:v1\n" + raw).hexdigest()
        Path(preparation["execution_reports"][gamever]).write_bytes(tap._canonical_json_bytes(report))

    def _retamper_selected_report(self, preparation: dict, gamever: str, mutate) -> None:
        """Apply a mutation and honestly re-sign the digest, like a valid-signature forger."""
        path = Path(preparation["execution_reports"][gamever])
        report = json.loads(path.read_text(encoding="utf-8"))
        mutate(report)
        report.pop("execution_sha256", None)
        report["execution_sha256"] = (
            "sha256:"
            + hashlib.sha256(b"source2-selected-execution:v1\n" + tap._canonical_json_bytes(report)).hexdigest()
        )
        path.write_bytes(tap._canonical_json_bytes(report))

    def test_selected_plan_partitions_unchanged_outputs_for_inheritance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root, selected_policy=True)

            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

            version = plan["game_versions"][0]
            self.assertEqual(tap.BASE_INHERITED_SELECTED_STRATEGY, plan["execution_strategy"])
            self.assertEqual("full", plan["mode"])
            executed = {group["artifact_path"] for group in version["execute_groups"]}
            self.assertEqual({"server/A.windows.yaml", "server/B.windows.yaml"}, executed)
            self.assertEqual(
                {"find-a", "find-b"},
                {node["skill"] for node in version["execute_nodes"]},
            )
            inherited = {item["path"] for item in version["inherit_paths"]}
            self.assertEqual(
                {"server/C.windows.yaml", "server/Pre.windows.yaml", "server/Dep.windows.yaml"},
                inherited,
            )
            absent = {group["artifact_path"] for group in version["inherited_absent_groups"]}
            self.assertEqual({"server/Opt.windows.yaml"}, absent)
            self.assertEqual([], version["removed_paths"])
            self.assertEqual(plan, tap.validate_trusted_artifact_plan(plan))

    def test_selected_plan_executes_session_prerequisites_of_executed_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root, selected_policy=True, change="artifact-dep")

            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

            version = plan["game_versions"][0]
            executed = {group["artifact_path"] for group in version["execute_groups"]}
            self.assertIn("server/Dep.windows.yaml", executed)
            self.assertIn("server/Pre.windows.yaml", executed)
            self.assertEqual(
                {"find-pre", "find-dep", "find-session"},
                {node["skill"] for node in version["execute_nodes"]},
            )
            session_node = next(node for node in version["execute_nodes"] if node["skill"] == "find-session")
            self.assertEqual([], session_node["outputs"])
            inherited = {item["path"] for item in version["inherit_paths"]}
            self.assertEqual(
                {"server/A.windows.yaml", "server/B.windows.yaml", "server/C.windows.yaml"},
                inherited,
            )

    def test_selected_plan_full_fallback_keeps_inheritance_empty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root, selected_policy=True, change="shared-runtime")

            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

            version = plan["game_versions"][0]
            self.assertEqual(tap.BASE_INHERITED_SELECTED_STRATEGY, plan["execution_strategy"])
            self.assertEqual(6, len(version["execute_groups"]))
            self.assertEqual([], version["inherit_paths"])
            self.assertEqual([], version["inherited_absent_groups"])
            self.assertIn("shared analyzer/serializer contract changed", version["reasons"])

    def test_selected_plan_records_contract_removed_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root, selected_policy=True, change="remove-c")

            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

            version = plan["game_versions"][0]
            self.assertEqual(["server/C.windows.yaml"], version["removed_paths"])
            inherited = {item["path"] for item in version["inherit_paths"]}
            self.assertEqual(
                {
                    "server/A.windows.yaml",
                    "server/B.windows.yaml",
                    "server/Pre.windows.yaml",
                    "server/Dep.windows.yaml",
                },
                inherited,
            )

    def test_prepare_materializes_only_the_inherited_whitelist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging)

            self.assertEqual(tap.BASE_INHERITED_SELECTED_STRATEGY, preparation["execution_strategy"])
            actual = Path(preparation["actual_artifact_root"]) / "1"
            materialized = {path.relative_to(actual).as_posix() for path in actual.rglob("*") if path.is_file()}
            self.assertEqual(
                {"server/C.windows.yaml", "server/Pre.windows.yaml", "server/Dep.windows.yaml"},
                materialized,
            )
            for group in plan["game_versions"][0]["execute_groups"]:
                self.assertFalse((actual / group["artifact_path"]).exists())
            manifest_path = Path(preparation["selected_execution_manifests"]["1"])
            self.assertTrue(manifest_path.is_file())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(plan["plan_sha256"], manifest["plan_sha256"])
            self.assertIn("sha256:", manifest["initial_actual_inventory_sha256"])

    def test_selected_verify_roundtrip_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging)

            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)
            result = tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

            report = result["game_versions"][0]
            self.assertEqual("1", report["game_version"])
            self.assertEqual(2, report["executed_group_count"])
            self.assertEqual(3, report["inherited_count"])
            self.assertEqual(0, report["removed_count"])
            self.assertEqual(tap.BASE_INHERITED_SELECTED_STRATEGY, result["execution_strategy"])

    def test_selected_verify_rejects_inherited_byte_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging)
            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)
            inherited = Path(preparation["actual_artifact_root"]) / "1" / "server" / "C.windows.yaml"
            inherited.write_bytes(self._artifact("C", "0x99"))

            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "contract failed|byte mismatch"):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_selected_verify_rejects_missing_planned_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging)
            skip = "producer-group:server/B.windows.yaml"
            self._simulate_selected_execution(root, plan, preparation, skip_group=skip)
            self._write_selected_report(root, plan, preparation)

            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "inventory mismatch|contract failed"):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_selected_verify_rejects_report_group_set_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging)
            self._simulate_selected_execution(root, plan, preparation)
            extra_group = {
                "group_id": "producer-group:server/C.windows.yaml",
                "artifact_path": "server/C.windows.yaml",
                "required": True,
                "fingerprint": "0" * 64,
                "alternative_node_ids": ["0:2:server:windows:find-c"],
                "attempted_node_ids": ["0:2:server:windows:find-c"],
                "winner_node_id": "0:2:server:windows:find-c",
                "output_sha256": None,
            }
            self._write_selected_report(root, plan, preparation, extra_group=extra_group)

            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "does not match the planned execution set"):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_selected_verify_rejects_tampered_report_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging)
            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)
            report_path = Path(preparation["execution_reports"]["1"])
            document = json.loads(report_path.read_text(encoding="utf-8"))
            document["producer_groups"][0]["winner_node_id"] = "forged"
            report_path.write_bytes(tap._canonical_json_bytes(document))

            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "digest mismatch"):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_full_strategy_preparation_leaves_actual_root_empty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root, selected_policy=False)

            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)
            self.assertEqual(tap.FRESH_FULL_STRATEGY, plan["execution_strategy"])
            preparation = tap.prepare_isolated_rebuild(repo_root=root, plan=plan, staging_root=staging)

            actual = Path(preparation["actual_artifact_root"])
            self.assertEqual([], list(actual.rglob("*")))
            self.assertEqual({}, preparation["selected_execution_manifests"])
            self.assertEqual({}, preparation["initial_actual_inventory_sha256"])

    def test_prepare_rejects_reused_staging_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root, selected_policy=True)
            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)
            staging.mkdir()

            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "already exists"):
                tap.prepare_isolated_rebuild(repo_root=root, plan=plan, staging_root=staging)

    def test_selected_verify_independently_rejects_unexecuted_node_evidence(self) -> None:
        """A valid-signature report claiming aborted nodes and empty attempts must fail."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging)
            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)
            self._retamper_selected_report(
                preparation,
                "1",
                lambda report: (
                    [
                        record.update(
                            {"status": "aborted", "attempted": False, "attempted_paths": [], "produced_paths": []}
                        )
                        for record in report["nodes"]
                    ],
                    [group.update({"attempted_node_ids": []}) for group in report["producer_groups"]],
                ),
            )

            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "attempts drifted|terminal execution status"):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_selected_verify_rejects_duplicate_node_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging)
            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)
            self._retamper_selected_report(
                preparation,
                "1",
                lambda report: report["nodes"].append(dict(report["nodes"][0])),
            )

            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "duplicate node evidence"):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_selected_verify_rejects_winner_without_success_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging)
            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)
            self._retamper_selected_report(
                preparation,
                "1",
                lambda report: report["nodes"][0].update({"status": "failed", "produced_paths": []}),
            )

            with self.assertRaisesRegex(
                tap.TrustedArtifactPrError, "exactly one producing winner|contradicts the group attempts"
            ):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_selected_verify_reports_drift_content_diff(self) -> None:
        """A drifted selected output must surface the expected-vs-actual content diff."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging)
            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)

            version = plan["game_versions"][0]
            gamever = version["game_version"]
            group = next(
                record for record in version["execute_groups"] if record["artifact_path"] == "server/A.windows.yaml"
            )
            drifted = canonical_symbol_yaml_bytes({"func_name": "A", "func_rva": "0x99"}, category="func")
            actual_path = Path(preparation["actual_artifact_root"]) / gamever / group["artifact_path"]
            actual_path.write_bytes(drifted)

            def claim_drifted_output(report):
                for record in report["producer_groups"]:
                    if record["artifact_path"] == "server/A.windows.yaml":
                        record["output_sha256"] = "sha256:" + hashlib.sha256(drifted).hexdigest()

            self._retamper_selected_report(preparation, gamever, claim_drifted_output)

            with self.assertRaisesRegex(
                tap.TrustedArtifactPrError, r"(?s)drifted from the trusted plan.*content diff.*0x99"
            ):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_selected_verify_rejects_recorded_write_to_inherited_artifact(self) -> None:
        """Even a byte-identical rewrite of an inherited artifact must fail once recorded."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging)
            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)

            def record_rewrite(report):
                winner = report["nodes"][0]
                winner["attempted_paths"] = sorted(set(winner["attempted_paths"]) | {"server/C.windows.yaml"})
                winner["produced_paths"] = sorted(set(winner["produced_paths"]) | {"server/C.windows.yaml"})

            self._retamper_selected_report(preparation, "1", record_rewrite)

            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "beyond its authorized outputs"):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_selected_verify_supports_pure_deletion_without_execution(self) -> None:
        """A contract deletion plans zero producers and must compose the inherited inventory."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging, change="remove-c")

            version = plan["game_versions"][0]
            self.assertEqual("full", plan["mode"])
            self.assertEqual([], version["execute_groups"])
            self.assertEqual([], version["execute_nodes"])
            manifest = json.loads(Path(preparation["selected_execution_manifests"]["1"]).read_text(encoding="utf-8"))
            self.assertEqual([], manifest["execute_nodes"])

            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)
            result = tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

            report = result["game_versions"][0]
            self.assertEqual(0, report["executed_group_count"])
            self.assertEqual(4, report["inherited_count"])
            self.assertEqual(1, report["removed_count"])

    def test_selected_verify_rejects_unexecuted_outputless_prerequisite(self) -> None:
        """A no-output prerequisite belongs to no group and still needs its own proof."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging, change="artifact-dep")
            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)

            def abort_session_prerequisite(report):
                session = next(record for record in report["nodes"] if record["skill"] == "find-session")
                session.update({"status": "aborted", "attempted": False})

            self._retamper_selected_report(preparation, "1", abort_session_prerequisite)

            with self.assertRaisesRegex(
                tap.TrustedArtifactPrError, "prerequisite node lacks successful execution evidence"
            ):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_selected_verify_rejects_failed_outputless_prerequisite(self) -> None:
        """A failed prerequisite proves the session side effects were never established."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging, change="artifact-dep")
            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)

            def fail_session_prerequisite(report):
                session = next(record for record in report["nodes"] if record["skill"] == "find-session")
                session.update({"status": "failed", "attempted": True})

            self._retamper_selected_report(preparation, "1", fail_session_prerequisite)

            with self.assertRaisesRegex(
                tap.TrustedArtifactPrError, "prerequisite node lacks successful execution evidence"
            ):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_selected_verify_accepts_legal_alternative_fallback(self) -> None:
        """A skipped first alternative conceding to a later winning alternative is valid."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging, change="alt-shared")

            version = plan["game_versions"][0]
            shared_group = next(
                group for group in version["execute_groups"] if group["artifact_path"] == "server/Shared.windows.yaml"
            )
            self.assertEqual(2, len(shared_group["alternative_node_ids"]))

            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)
            primary, fallback = shared_group["alternative_node_ids"]

            def record_fallback(report):
                primary_record = next(record for record in report["nodes"] if record["node_id"] == primary)
                primary_record.update(
                    {
                        "status": "skipped",
                        "reason": "optional_output_absent",
                        "attempted_paths": ["server/Shared.windows.yaml"],
                        "produced_paths": [],
                    }
                )
                fallback_record = next(record for record in report["nodes"] if record["node_id"] == fallback)
                fallback_record.update(
                    {
                        "status": "succeeded",
                        "reason": None,
                        "attempted_paths": ["server/Shared.windows.yaml"],
                        "produced_paths": ["server/Shared.windows.yaml"],
                    }
                )
                group_record = next(
                    record for record in report["producer_groups"] if record["group_id"] == shared_group["group_id"]
                )
                group_record.update({"attempted_node_ids": [primary, fallback], "winner_node_id": fallback})

            self._retamper_selected_report(preparation, "1", record_fallback)
            result = tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

            self.assertEqual(1, result["game_versions"][0]["executed_group_count"])

    def test_selected_verify_rejects_fallback_claim_before_earlier_winner(self) -> None:
        """A node claimed absent cannot also be positioned after the group winner."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging, change="alt-shared")
            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)
            shared_group = next(
                group for group in plan["game_versions"][0]["execute_groups"] if "Shared" in group["artifact_path"]
            )
            primary, fallback = shared_group["alternative_node_ids"]

            def forge_post_winner_attempt(report):
                # Winner stays the first alternative, but the later one claims it also
                # attempted (and skipped on) the same materialized path.
                later_record = next(record for record in report["nodes"] if record["node_id"] == fallback)
                later_record.update(
                    {
                        "status": "skipped",
                        "reason": "optional_output_absent",
                        "attempted_paths": ["server/Shared.windows.yaml"],
                        "produced_paths": [],
                    }
                )
                group_record = next(
                    record for record in report["producer_groups"] if record["group_id"] == shared_group["group_id"]
                )
                group_record.update({"attempted_node_ids": [primary, fallback], "winner_node_id": primary})

            self._retamper_selected_report(preparation, "1", forge_post_winner_attempt)

            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "attempts drifted|terminal execution status"):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_selected_verify_accepts_legal_optional_absent_skip(self) -> None:
        """A planned optional producer that ran and legally produced nothing ends skipped."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging, change="drop-opt")

            version = plan["game_versions"][0]
            self.assertIn("server/Opt.windows.yaml", {group["artifact_path"] for group in version["execute_groups"]})

            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)
            result = tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

            report = result["game_versions"][0]
            self.assertEqual(1, report["executed_group_count"])

    def test_selected_verify_rejects_arbitrary_skip_reasons(self) -> None:
        """Only optional/preprocess-absent skips with a truly absent output may pass."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging, change="drop-opt")
            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)

            def relabel_skip(report):
                skipped = next(record for record in report["nodes"] if record["skill"] == "find-opt")
                skipped["reason"] = "existing_outputs"

            self._retamper_selected_report(preparation, "1", relabel_skip)

            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "terminal execution status"):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_selected_verify_rejects_absent_skip_on_materialized_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            plan, preparation = self._plan_and_preparation(root, staging)
            self._simulate_selected_execution(root, plan, preparation)
            self._write_selected_report(root, plan, preparation)

            def skip_winner(report):
                winner = report["nodes"][0]
                winner.update(
                    {
                        "status": "skipped",
                        "reason": "optional_output_absent",
                        "produced_paths": [],
                    }
                )

            self._retamper_selected_report(preparation, "1", skip_winner)

            with self.assertRaisesRegex(
                tap.TrustedArtifactPrError, "terminal execution status|exactly one producing winner"
            ):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)


if __name__ == "__main__":
    unittest.main()
