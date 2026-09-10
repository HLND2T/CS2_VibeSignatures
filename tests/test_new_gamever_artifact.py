from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
import copy
import shutil
from pathlib import Path
from unittest.mock import patch

import new_gamever_artifact as nga
import trusted_artifact_pr as tap
import trusted_pr_context as tpc
from bin_artifact_contract import build_game_artifact_inventory
from ida_analyze_util import canonical_symbol_yaml_bytes
from tests.gamesymbol_snapshot_test_support import write_binary, write_config, write_source_binary_lock


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
                ".gitignore": b"bin/\n",
                "download.yaml": b"downloads:\n  - tag: '14178'\n    manifests: {'1': '1'}\n",
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
            write_binary(root / "bin" / "14178" / "server" / "server.dll")
            write_source_binary_lock(root, "14178")
        self._git(root, "add", ".")
        self._git(root, "commit", "-m", "base")
        base_sha = self._git(root, "rev-parse", "HEAD")

        self._git(root, "switch", "-c", f"bump-download/{self.gamever}")
        major_update_line = "\n    major_update: true" if major_update else ""
        (root / "download.yaml").write_text(
            "downloads:\n"
            "  - tag: '14178'\n"
            "    manifests: {'1': '1'}\n"
            f"  - tag: '{self.gamever}'\n"
            "    manifests: {'1': '2'}"
            f"{major_update_line}\n",
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
        write_binary(root / "bin" / self.gamever / "server" / "server.dll", b"new GAMEVER binary")
        write_source_binary_lock(root, self.gamever)
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
        for planned in version["execute_groups"]:
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
            for planned in version["execute_nodes"]
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
            version = next(version for version in plan["game_versions"] if version.get("bootstrap_required"))
            self.assertRegex(version["merge_binary_lock_sha256"], r"^sha256:[0-9a-f]{64}$")
            artifact_root = self._candidate(root)

            _manifest_path, manifest, verification = self._build_and_verify(root, plan, head_sha, artifact_root)

            self.assertEqual(1, manifest["file_count"])
            self.assertIsNone(manifest["prior_gamever"])
            self.assertTrue(manifest["execution_sha256"].startswith("sha256:"))
            self.assertEqual(self.gamever, verification["game_version"])
            self.assertIsNone(verification["prior_gamever"])
            self.assertEqual(head_sha, verification["head_sha"])

    def _reuse_fixture(self, root: Path):
        head, _, old_plan = self._repository(root, include_prior=True)
        artifacts = self._candidate(root)
        _, manifest, _ = self._build_and_verify(root, old_plan, head, artifacts)
        execution = json.loads((root.parent / "force-all-execution.json").read_bytes())
        self._git(root, "checkout", "--detach", head)
        shutil.copytree(artifacts / self.gamever, root / "bin_artifacts" / self.gamever)
        self._git(root, "add", "bin_artifacts")
        self._git(root, "commit", "-m", "bootstrap outputs")
        publication = self._git(root, "rev-parse", "HEAD")
        evidence = {
            "bootstrap_plan": old_plan,
            "manifest": manifest,
            "execution": execution,
            "publication_sha": publication,
        }
        return evidence

    def _reuse_plan(self, root: Path, evidence: dict) -> dict:
        sha = self._git(root, "rev-parse", "HEAD")
        base = evidence["bootstrap_plan"]["base_sha"]
        merge = self._git(root, "commit-tree", "HEAD^{tree}", "-p", base, "-p", sha, "-m", "prospective")
        self._git(root, "checkout", "--detach", merge)
        context = tpc.build_trusted_pr_context(repo_root=root, base_ref=base, head_ref=sha, merge_ref=merge)
        return tap.build_trusted_artifact_plan(repo_root=root, trusted_context=context)

    def test_reuse_accepts_publication_and_unrelated_followup(self):
        import bootstrap_reuse as reuse

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            evidence = self._reuse_fixture(root)
            for followup in (False, True):
                if followup:
                    (root / "release_publish.py").write_text("# publication only\n")
                    self._git(root, "add", "release_publish.py")
                    self._git(root, "commit", "-m", "release fix")
                plan = self._reuse_plan(root, evidence)
                receipt = reuse.verify_reuse(repo_root=root, plan=plan, gamever=self.gamever, evidence=evidence)
                self.assertEqual(plan["merge_tree_sha"], receipt["merge_tree_sha"])
                self.assertEqual(plan["plan_sha256"], receipt["plan_sha256"])

    def test_reuse_rejects_changed_artifact_generator_and_baseline(self):
        import bootstrap_reuse as reuse

        for path, payload in (
            (f"bin_artifacts/{self.gamever}/server/A.windows.yaml", b"func_name: A\nfunc_rva: '0x20'\n"),
            ("ida_analyze_bin.py", b"# changed executor\n"),
            ("bin_artifacts/14178/server/A.windows.yaml", b"func_name: A\nfunc_rva: '0x20'\n"),
        ):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "repo"
                root.mkdir()
                evidence = self._reuse_fixture(root)
                plan = self._reuse_plan(root, evidence)
                (root / path).write_bytes(payload)
                self._git(root, "add", path)
                self._git(root, "commit", "-m", "input drift")
                # A newly bound plan is needed, but historical-version policy rejects baseline edits earlier.
                plan["head_sha"] = plan["merge_sha"] = self._git(root, "rev-parse", "HEAD")
                plan["merge_tree_sha"] = self._git(root, "rev-parse", "HEAD^{tree}")
                plan.pop("plan_sha256")
                plan["plan_sha256"] = tap._digest("trusted-pr-plan", plan)
                with self.assertRaises(reuse.BootstrapReuseError):
                    reuse.verify_reuse(repo_root=root, plan=plan, gamever=self.gamever, evidence=evidence)

    def test_reuse_rejects_forged_execution_and_plan_binding(self):
        import bootstrap_reuse as reuse

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            evidence = self._reuse_fixture(root)
            plan = self._reuse_plan(root, evidence)
            for key in ("execution", "manifest"):
                forged = copy.deepcopy(evidence)
                forged[key]["game_version"] = "99999"
                with self.subTest(key=key), self.assertRaises(reuse.BootstrapReuseError):
                    reuse.verify_reuse(repo_root=root, plan=plan, gamever=self.gamever, evidence=forged)

    def test_reuse_authenticates_successful_evidence_even_when_push_failed(self):
        import bootstrap_reuse as reuse

        run = {
            "id": 123,
            "run_attempt": 1,
            "repository": {"full_name": nga.ALLOWED_REPOSITORY},
            "head_repository": {"full_name": nga.ALLOWED_REPOSITORY},
            "event": "pull_request_target",
            "path": reuse.WORKFLOW_PATH,
            "head_sha": "a" * 40,
            "head_branch": f"bump-download/{self.gamever}",
        }
        jobs = [
            {"name": "bind-source-artifact-plan", "conclusion": "success"},
            {"name": "bootstrap-new-gamever / build-bootstrap-candidate", "conclusion": "success"},
            {
                "name": "bootstrap-new-gamever / publish-new-gamever-artifacts",
                "conclusion": "failure",
                "steps": [
                    {"name": "Revalidate PR, remote head, candidate, and allowed branch", "conclusion": "success"},
                    {"name": "Create direct-child artifact-only commit", "conclusion": "success"},
                    {
                        "name": "Fast-forward push only the bound bump branch with protected PAT",
                        "conclusion": "failure",
                    },
                ],
            },
        ]
        kwargs = {"head": "a" * 40, "gamever": self.gamever, "run_id": "123", "attempt": "1"}
        reuse.authenticate_run(run, jobs, **kwargs)
        for key, value in (
            ("event", "workflow_dispatch"),
            ("head_sha", "b" * 40),
            ("run_attempt", 2),
            ("repository", {"full_name": "someone/fork"}),
            ("path", ".github/workflows/other.yml"),
        ):
            with self.subTest(key=key), self.assertRaises(reuse.BootstrapReuseError):
                reuse.authenticate_run({**run, key: value}, jobs, **kwargs)
        jobs[-1]["steps"][0]["conclusion"] = "failure"
        with self.assertRaises(reuse.BootstrapReuseError):
            reuse.authenticate_run(run, jobs, **kwargs)

    def test_reuse_probe_falls_back_when_evidence_is_unavailable(self):
        import bootstrap_reuse as reuse

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, evidence = root / "outputs", root / "evidence.json"
            argv = [
                "bootstrap_reuse.py",
                "probe",
                "--repo-root",
                str(root),
                "--plan",
                "unused",
                "--plan-sha256",
                "digest",
                "--gamever",
                self.gamever,
                "--evidence",
                str(evidence),
                "--github-output",
                str(output),
            ]
            with (
                patch("sys.argv", argv),
                patch.object(reuse, "load_trusted_artifact_plan", return_value={"plan_sha256": "digest"}),
                patch.object(reuse, "discover_reuse", side_effect=reuse.BootstrapReuseError("expired artifact")),
            ):
                self.assertEqual(0, reuse.main())
            self.assertEqual("reused=false\n", output.read_text())
            self.assertFalse(evidence.exists())

    def test_reuse_rejects_archive_digest_tampering(self):
        import bootstrap_reuse as reuse

        metadata = {"id": 1, "name": "candidate", "expired": False, "size_in_bytes": 10, "digest": "sha256:" + "0" * 64}
        with (
            patch.object(reuse, "_api", return_value=b"tampered archive"),
            self.assertRaisesRegex(reuse.BootstrapReuseError, "digest mismatch"),
        ):
            reuse._archive(metadata, "candidate")

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
