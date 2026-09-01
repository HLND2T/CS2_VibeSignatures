from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import new_gamever_artifact as nga
import trusted_artifact_pr as tap
import trusted_pr_context as tpc
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

    def _repository(self, root: Path):
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
        self._git(root, "add", ".")
        self._git(root, "commit", "-m", "base")
        base_sha = self._git(root, "rev-parse", "HEAD")

        self._git(root, "switch", "-c", f"bump-download/{self.gamever}")
        (root / "download.yaml").write_text(
            f"downloads:\n  - tag: '14178'\n  - tag: '{self.gamever}'\n",
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

    def _build_and_verify(self, root: Path, plan: dict, head_sha: str, artifact_root: Path):
        manifest_path = root.parent / "candidate-manifest.json"
        gates = {
            "schema_version": 1,
            "force_all": True,
            "rename": True,
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
        )
        verification = nga.verify_bootstrap_candidate(
            repo_root=root,
            plan=plan,
            artifact_root=artifact_root,
            manifest=manifest_path,
            repository=nga.ALLOWED_REPOSITORY,
            default_branch="main",
            head_repository=nga.ALLOWED_REPOSITORY,
            head_ref=f"bump-download/{self.gamever}",
            head_sha=head_sha,
            current_remote_head=head_sha,
            pr_number=17,
            actions_artifact_name=manifest["actions_artifact_name"],
            actions_artifact_digest="sha256:" + "a" * 64,
            workflow_run_id="123",
            workflow_run_attempt="1",
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
            self.assertEqual(self.gamever, verification["game_version"])
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
            )
            with self.assertRaisesRegex(nga.NewGameverArtifactError, "remote head drifted"):
                nga.verify_bootstrap_candidate(
                    repo_root=root,
                    plan=plan,
                    artifact_root=artifact_root,
                    manifest=clean_manifest,
                    repository=nga.ALLOWED_REPOSITORY,
                    default_branch="main",
                    head_repository=nga.ALLOWED_REPOSITORY,
                    head_ref=f"bump-download/{self.gamever}",
                    head_sha=head_sha,
                    current_remote_head="f" * 40,
                    pr_number=17,
                    actions_artifact_name=manifest["actions_artifact_name"],
                    actions_artifact_digest="sha256:" + "a" * 64,
                    workflow_run_id="123",
                    workflow_run_attempt="1",
                )

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


if __name__ == "__main__":
    unittest.main()
