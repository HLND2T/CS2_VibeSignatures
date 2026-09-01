from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import trusted_artifact_pr as tap
import trusted_pr_context as tpc
from ida_analyze_util import canonical_symbol_yaml_bytes
from tests.gamesymbol_snapshot_test_support import write_config


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

    def _repository(
        self,
        root: Path,
        *,
        change_artifact: bool = True,
        add_extra: bool = False,
        add_unconfigured: bool = False,
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
                "download.yaml": b"downloads:\n  - tag: '1'\n",
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
        self._write_artifact(root, "A", "0x10")
        self._write_artifact(root, "B", "0x20")
        self._git(root, "add", ".")
        self._git(root, "commit", "-m", "base")
        base_sha = self._git(root, "rev-parse", "HEAD")

        self._git(root, "switch", "-c", "feature")
        if change_artifact:
            self._write_artifact(root, "A", "0x30")
        else:
            (root / "ida_analyze_util.py").write_text("SERIALIZER = 2\n", encoding="utf-8")
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
            self.assertEqual(["server/A.windows.yaml", "server/B.windows.yaml"], version["invalidated_paths"])
            self.assertEqual(
                {"find-a", "find-b"},
                {node["skill"] for node in version["selected_alternative_nodes"]},
            )
            self.assertEqual(plan, tap.validate_trusted_artifact_plan(plan))

    def test_isolated_preparation_omits_invalidated_paths_and_exact_verify_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            staging = Path(temporary) / "isolated"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root)
            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

            preparation = tap.prepare_isolated_rebuild(repo_root=root, plan=plan, staging_root=staging)

            actual = Path(preparation["actual_artifact_root"])
            expected = Path(preparation["expected_artifact_root"])
            self.assertFalse((actual / "1" / "server" / "A.windows.yaml").exists())
            self.assertFalse((actual / "1" / "server" / "B.windows.yaml").exists())
            shutil.copytree(expected, actual, dirs_exist_ok=True)
            result = tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)
            self.assertEqual("1", result["game_versions"][0]["game_version"])

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
            target = actual / "1" / "server" / "A.windows.yaml"
            target.write_bytes(target.read_bytes() + b" ")

            with self.assertRaisesRegex(tap.TrustedArtifactPrError, "contract failed|byte mismatch"):
                tap.validate_isolated_rebuild(repo_root=root, plan=plan, preparation=preparation)

    def test_shared_serializer_change_broadly_selects_all_groups(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _base, _head, _merge, context = self._repository(root, change_artifact=False)

            plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

            version = plan["game_versions"][0]
            self.assertEqual(2, len(version["affected_producer_groups"]))
            self.assertIn("shared analyzer/serializer contract changed", version["reasons"])

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
