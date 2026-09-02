from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import new_gamever_artifact as nga
import trusted_artifact_pr as tap
import trusted_pr_context as tpc
from bin_artifact_contract import build_game_artifact_inventory
from ida_analyze_util import canonical_symbol_yaml_bytes
from tests.gamesymbol_snapshot_test_support import write_config


class NewGameverArtifactTests(unittest.TestCase):
    gamever = "14179"

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

    def _repository(self, root: Path, *, include_prior: bool = False, major_update: bool = False):
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
                "download.yaml": b"downloads:\n  - tag: '14178'\n",
            }
        )
        for relative, payload in required.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        if include_prior:
            write_config(
                root / "configs" / "14178.yaml",
                [
                    {
                        "name": "server",
                        "path_windows": "game/bin/win64/server.dll",
                        "skills": [{"name": "find-a", "expected_output": ["A.{platform}.yaml"]}],
                        "symbols": [{"name": "A", "category": "func", "platform": "windows"}],
                    }
                ],
            )
            prior_artifact = root / "bin_artifacts" / "14178" / "server" / "A.windows.yaml"
            prior_artifact.parent.mkdir(parents=True)
            prior_artifact.write_bytes(
                canonical_symbol_yaml_bytes({"func_name": "A", "func_rva": "0x8"}, category="func")
            )
        self._git(root, "add", ".")
        self._git(root, "commit", "-m", "base")
        base_sha = self._git(root, "rev-parse", "HEAD")

        self._git(root, "switch", "-c", f"bump-download/{self.gamever}")
        major_update_line = "\n    major_update: true" if major_update else ""
        (root / "download.yaml").write_text(
            f"downloads:\n  - tag: '14178'\n  - tag: '{self.gamever}'{major_update_line}\n",
            encoding="utf-8",
        )
        write_config(
            root / "configs" / f"{self.gamever}.yaml",
            [
                {
                    "name": "server",
                    "path_windows": "game/bin/win64/server.dll",
                    "skills": [{"name": "find-a", "expected_output": ["A.{platform}.yaml"]}],
                    "symbols": [{"name": "A", "category": "func", "platform": "windows"}],
                }
            ],
        )
        self._git(root, "add", ".")
        self._git(root, "commit", "-m", "head")
        head_sha = self._git(root, "rev-parse", "HEAD")
        self._git(root, "switch", "main")
        self._git(root, "merge", "--no-ff", f"bump-download/{self.gamever}", "-m", "prospective merge")
        merge_sha = self._git(root, "rev-parse", "HEAD")
        context = tpc.build_trusted_pr_context(
            repo_root=root,
            base_ref=base_sha,
            head_ref=head_sha,
            merge_ref=merge_sha,
        )
        plan = tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)
        return head_sha, merge_sha, plan

    def _candidate(self, root: Path) -> Path:
        artifact_root = root / "candidate-bin-artifacts"
        artifact = artifact_root / self.gamever / "server" / "A.windows.yaml"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(canonical_symbol_yaml_bytes({"func_name": "A", "func_rva": "0x10"}, category="func"))
        return artifact_root

    def _execution_report(self, root: Path, plan: dict, artifact_root: Path) -> Path:
        version = next(version for version in plan["game_versions"] if version.get("bootstrap_required"))
        inventory = build_game_artifact_inventory(
            repo_root=root,
            config_path=root / "configs" / f"{self.gamever}.yaml",
            game_version=self.gamever,
            artifact_root=artifact_root,
            require_tracked=False,
        )
        files = {item.path.removeprefix(f"bin_artifacts/{self.gamever}/"): item for item in inventory.files}
        groups = []
        winning_node_ids = set()
        for planned in version["affected_producer_groups"]:
            item = files.get(planned["artifact_path"])
            winner = planned["alternative_node_ids"][0] if item is not None else None
            if winner is not None:
                winning_node_ids.add(winner)
            groups.append(
                {
                    **planned,
                    "attempted_node_ids": [winner] if winner is not None else list(planned["alternative_node_ids"]),
                    "winner_node_id": winner,
                    "output_sha256": item.sha256 if item is not None else None,
                }
            )
        nodes = [
            {
                "node_id": planned["node_id"],
                "module": planned["module"],
                "platform": planned["platform"],
                "skill": planned["skill"],
                "fingerprint": planned["fingerprint"],
                "attempted": planned["node_id"] in winning_node_ids,
                "status": "succeeded" if planned["node_id"] in winning_node_ids else "skipped",
                "produced_paths": [
                    group["artifact_path"] for group in groups if group["winner_node_id"] == planned["node_id"]
                ],
            }
            for planned in version["selected_alternative_nodes"]
        ]
        document = {
            "schema_version": 2,
            "game_version": self.gamever,
            "prior_gamever": version["prior_gamever"],
            "config_path": str((root / "configs" / f"{self.gamever}.yaml").resolve()),
            "binary_root": str((root / "bin").resolve()),
            "artifact_root": str(artifact_root.resolve()),
            "old_artifact_root": str((root / "bin_artifacts").resolve()),
            "force_all": True,
            "rename": True,
            "required_warm_idb": True,
            "run_id": "bootstrap-test",
            "summary": {},
            "inventory": {
                "file_count": inventory.file_count,
                "inventory_sha256": inventory.inventory_sha256,
            },
            "nodes": nodes,
            "producer_groups": groups,
            "issues": [],
            "valid": True,
        }
        digest_input = b"source2-force-all-execution:v2\n" + nga._canonical_json_bytes(document)
        document["execution_sha256"] = f"sha256:{hashlib.sha256(digest_input).hexdigest()}"
        path = root.parent / "force-all-execution.json"
        path.write_bytes(nga._canonical_json_bytes(document))
        return path

    def _build_and_verify(self, root: Path, plan: dict, head_sha: str, artifact_root: Path):
        manifest_path = root.parent / "candidate-manifest.json"
        execution_report = self._execution_report(root, plan, artifact_root)
        gates = {
            "schema_version": 2,
            "binsync_mode": "local-only",
            "remote_refs_before_sha256": "sha256:" + "1" * 64,
            "remote_refs_after_sha256": "sha256:" + "1" * 64,
            "snapshot_sha256": "sha256:" + "2" * 64,
            "gamedata_sha256": "sha256:" + "3" * 64,
            "cpp_validation_sha256": "sha256:" + "4" * 64,
        }
        manifest = nga.build_bootstrap_candidate(
            repo_root=root,
            plan=plan,
            artifact_root=artifact_root,
            output_manifest=manifest_path,
            repository=nga.ALLOWED_REPOSITORY,
            pr_number=17,
            workflow_run_id="123",
            workflow_run_attempt="1",
            gate_evidence=gates,
            execution_report=execution_report,
        )
        verification = nga.verify_bootstrap_candidate(
            repo_root=root,
            plan=plan,
            artifact_root=artifact_root,
            manifest=manifest_path,
            repository=nga.ALLOWED_REPOSITORY,
            default_branch="main",
            base_repository=nga.ALLOWED_REPOSITORY,
            base_ref="main",
            base_sha=plan["base_sha"],
            head_repository=nga.ALLOWED_REPOSITORY,
            head_ref=f"bump-download/{self.gamever}",
            head_sha=head_sha,
            current_remote_head=head_sha,
            pr_number=17,
            actions_artifact_name=manifest["actions_artifact_name"],
            actions_artifact_digest="sha256:" + "a" * 64,
            workflow_run_id="123",
            workflow_run_attempt="1",
            execution_report=execution_report,
        )
        return manifest_path, manifest, verification

    def test_bootstrap_candidate_binds_complete_inventory_and_publication_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            head_sha, _merge_sha, plan = self._repository(root)
            self.assertEqual("bootstrap_required", plan["mode"])
            artifact_root = self._candidate(root)

            _manifest_path, manifest, verification = self._build_and_verify(root, plan, head_sha, artifact_root)

            self.assertEqual(1, manifest["file_count"])
            self.assertIsNone(manifest["prior_gamever"])
            self.assertTrue(manifest["execution_sha256"].startswith("sha256:"))
            self.assertEqual(self.gamever, verification["game_version"])
            self.assertIsNone(verification["prior_gamever"])
            self.assertEqual(head_sha, verification["head_sha"])

    def test_hosted_verifier_rejects_remote_head_drift_and_manifest_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            head_sha, _merge_sha, plan = self._repository(root)
            artifact_root = self._candidate(root)
            manifest_path, manifest, _verification = self._build_and_verify(root, plan, head_sha, artifact_root)
            manifest["head_sha"] = "0" * 40
            manifest_path.write_bytes(nga._canonical_json_bytes(manifest))
            with self.assertRaisesRegex(nga.NewGameverArtifactError, "digest mismatch"):
                nga.load_bootstrap_candidate(manifest_path)

            drifted_gates = dict(manifest["gates"])
            drifted_gates["remote_refs_after_sha256"] = "sha256:" + "9" * 64
            with self.assertRaisesRegex(nga.NewGameverArtifactError, "changed remote BinSync refs"):
                nga._load_gate_evidence(drifted_gates)

            clean_manifest = root.parent / "clean-manifest.json"
            nga.build_bootstrap_candidate(
                repo_root=root,
                plan=plan,
                artifact_root=artifact_root,
                output_manifest=clean_manifest,
                repository=nga.ALLOWED_REPOSITORY,
                pr_number=17,
                workflow_run_id="123",
                workflow_run_attempt="1",
                gate_evidence=manifest["gates"],
                execution_report=self._execution_report(root, plan, artifact_root),
            )
            with self.assertRaisesRegex(nga.NewGameverArtifactError, "remote head drifted"):
                nga.verify_bootstrap_candidate(
                    repo_root=root,
                    plan=plan,
                    artifact_root=artifact_root,
                    manifest=clean_manifest,
                    repository=nga.ALLOWED_REPOSITORY,
                    default_branch="main",
                    base_repository=nga.ALLOWED_REPOSITORY,
                    base_ref="main",
                    base_sha=plan["base_sha"],
                    head_repository=nga.ALLOWED_REPOSITORY,
                    head_ref=f"bump-download/{self.gamever}",
                    head_sha=head_sha,
                    current_remote_head="f" * 40,
                    pr_number=17,
                    actions_artifact_name=manifest["actions_artifact_name"],
                    actions_artifact_digest="sha256:" + "a" * 64,
                    workflow_run_id="123",
                    workflow_run_attempt="1",
                    execution_report=root.parent / "force-all-execution.json",
                )

    def test_hosted_verifier_rejects_non_default_base(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            head_sha, _merge_sha, plan = self._repository(root)
            artifact_root = self._candidate(root)
            manifest_path, manifest, _verification = self._build_and_verify(root, plan, head_sha, artifact_root)

            with self.assertRaisesRegex(nga.NewGameverArtifactError, "bound default branch"):
                nga.verify_bootstrap_candidate(
                    repo_root=root,
                    plan=plan,
                    artifact_root=artifact_root,
                    manifest=manifest_path,
                    repository=nga.ALLOWED_REPOSITORY,
                    default_branch="main",
                    base_repository=nga.ALLOWED_REPOSITORY,
                    base_ref="staging",
                    base_sha=plan["base_sha"],
                    head_repository=nga.ALLOWED_REPOSITORY,
                    head_ref=f"bump-download/{self.gamever}",
                    head_sha=head_sha,
                    current_remote_head=head_sha,
                    pr_number=17,
                    actions_artifact_name=manifest["actions_artifact_name"],
                    actions_artifact_digest="sha256:" + "a" * 64,
                    workflow_run_id="123",
                    workflow_run_attempt="1",
                    execution_report=root.parent / "force-all-execution.json",
                )

    def test_candidate_rejects_forged_force_all_execution_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _head_sha, _merge_sha, plan = self._repository(root)
            artifact_root = self._candidate(root)
            execution_path = self._execution_report(root, plan, artifact_root)
            execution = json.loads(execution_path.read_text(encoding="utf-8"))
            execution["rename"] = False
            execution.pop("execution_sha256")
            digest_input = b"source2-force-all-execution:v2\n" + nga._canonical_json_bytes(execution)
            execution["execution_sha256"] = f"sha256:{hashlib.sha256(digest_input).hexdigest()}"
            execution_path.write_bytes(nga._canonical_json_bytes(execution))
            gates = {
                "schema_version": 2,
                "binsync_mode": "local-only",
                "remote_refs_before_sha256": "sha256:" + "1" * 64,
                "remote_refs_after_sha256": "sha256:" + "1" * 64,
                "snapshot_sha256": "sha256:" + "2" * 64,
                "gamedata_sha256": "sha256:" + "3" * 64,
                "cpp_validation_sha256": "sha256:" + "4" * 64,
            }

            with self.assertRaisesRegex(nga.NewGameverArtifactError, "force-all.*rename"):
                nga.build_bootstrap_candidate(
                    repo_root=root,
                    plan=plan,
                    artifact_root=artifact_root,
                    output_manifest=root.parent / "candidate-manifest.json",
                    repository=nga.ALLOWED_REPOSITORY,
                    pr_number=17,
                    workflow_run_id="123",
                    workflow_run_attempt="1",
                    gate_evidence=gates,
                    execution_report=execution_path,
                )

            execution_path = self._execution_report(root, plan, artifact_root)
            execution = json.loads(execution_path.read_text(encoding="utf-8"))
            execution["producer_groups"] = []
            execution.pop("execution_sha256")
            digest_input = b"source2-force-all-execution:v2\n" + nga._canonical_json_bytes(execution)
            execution["execution_sha256"] = f"sha256:{hashlib.sha256(digest_input).hexdigest()}"
            execution_path.write_bytes(nga._canonical_json_bytes(execution))
            with self.assertRaisesRegex(nga.NewGameverArtifactError, "cover every planned group"):
                nga.build_bootstrap_candidate(
                    repo_root=root,
                    plan=plan,
                    artifact_root=artifact_root,
                    output_manifest=root.parent / "candidate-manifest.json",
                    repository=nga.ALLOWED_REPOSITORY,
                    pr_number=17,
                    workflow_run_id="123",
                    workflow_run_attempt="1",
                    gate_evidence=gates,
                    execution_report=execution_path,
                )

            execution_path = self._execution_report(root, plan, artifact_root)
            execution = json.loads(execution_path.read_text(encoding="utf-8"))
            execution["prior_gamever"] = "14178"
            execution.pop("execution_sha256")
            digest_input = b"source2-force-all-execution:v2\n" + nga._canonical_json_bytes(execution)
            execution["execution_sha256"] = f"sha256:{hashlib.sha256(digest_input).hexdigest()}"
            execution_path.write_bytes(nga._canonical_json_bytes(execution))
            with self.assertRaisesRegex(nga.NewGameverArtifactError, "prior GAMEVER"):
                nga.build_bootstrap_candidate(
                    repo_root=root,
                    plan=plan,
                    artifact_root=artifact_root,
                    output_manifest=root.parent / "candidate-manifest.json",
                    repository=nga.ALLOWED_REPOSITORY,
                    pr_number=17,
                    workflow_run_id="123",
                    workflow_run_attempt="1",
                    gate_evidence=gates,
                    execution_report=execution_path,
                )

    def test_prior_gamever_is_bound_from_plan_through_hosted_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            head_sha, _merge_sha, plan = self._repository(root, include_prior=True)
            version = next(version for version in plan["game_versions"] if version.get("bootstrap_required"))
            self.assertEqual("14178", version["prior_gamever"])
            artifact_root = self._candidate(root)

            manifest_path, manifest, verification = self._build_and_verify(root, plan, head_sha, artifact_root)

            self.assertEqual("14178", manifest["prior_gamever"])
            self.assertEqual("14178", verification["prior_gamever"])
            tampered = dict(manifest)
            tampered["prior_gamever"] = None
            tampered.pop("candidate_sha256")
            tampered["candidate_sha256"] = nga._digest("candidate-manifest", tampered)
            manifest_path.write_bytes(nga._canonical_json_bytes(tampered))
            with self.assertRaisesRegex(nga.NewGameverArtifactError, "plan or GAMEVER binding"):
                nga.verify_bootstrap_candidate(
                    repo_root=root,
                    plan=plan,
                    artifact_root=artifact_root,
                    manifest=manifest_path,
                    repository=nga.ALLOWED_REPOSITORY,
                    default_branch="main",
                    base_repository=nga.ALLOWED_REPOSITORY,
                    base_ref="main",
                    base_sha=plan["base_sha"],
                    head_repository=nga.ALLOWED_REPOSITORY,
                    head_ref=f"bump-download/{self.gamever}",
                    head_sha=head_sha,
                    current_remote_head=head_sha,
                    pr_number=17,
                    actions_artifact_name=manifest["actions_artifact_name"],
                    actions_artifact_digest="sha256:" + "a" * 64,
                    workflow_run_id="123",
                    workflow_run_attempt="1",
                    execution_report=root.parent / "force-all-execution.json",
                )

    def test_major_update_explicitly_disables_available_prior_gamever(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            _head_sha, _merge_sha, plan = self._repository(root, include_prior=True, major_update=True)
            version = next(version for version in plan["game_versions"] if version.get("bootstrap_required"))

            self.assertIsNone(version["prior_gamever"])

    def test_prepare_commit_only_stages_new_gamever_artifacts_with_bound_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            head_sha, _merge_sha, plan = self._repository(root)
            artifact_root = self._candidate(root)
            _manifest_path, _manifest, verification = self._build_and_verify(root, plan, head_sha, artifact_root)
            publisher = temporary_root / "publisher"
            self._git(temporary_root, "clone", "-q", str(root), str(publisher))
            self._git(publisher, "config", "user.email", "automation@example.com")
            self._git(publisher, "config", "user.name", "Artifact Automation")
            self._git(publisher, "checkout", "--detach", head_sha)

            result = nga.prepare_bootstrap_commit(
                repo_root=publisher,
                artifact_root=artifact_root,
                verification=verification,
                workflow_run_url="https://github.example/run/123",
            )

            self.assertEqual(head_sha, result["parent_sha"])
            self.assertEqual(
                [f"bin_artifacts/{self.gamever}/server/A.windows.yaml"],
                result["changed_paths"],
            )
            self.assertEqual(result["commit_sha"], self._git(publisher, "rev-parse", "HEAD"))
            self.assertEqual(verification["execution_sha256"], result["execution_sha256"])


if __name__ == "__main__":
    unittest.main()
