import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import ci_runner as runner
import ci_cpp_validation as cpp_evidence
from release_workflow_lib.errors import ReleaseWorkflowError
from tests import test_ci_cpp_validation as evidence_support
import trusted_artifact_pr as trusted_plan


class TestTrustedPlanDownload(unittest.TestCase):
    def plan(self):
        document = {
            "schema_version": trusted_plan.PLAN_SCHEMA_VERSION,
            "base_sha": "a" * 40,
            "head_sha": "b" * 40,
            "merge_sha": "c" * 40,
            "merge_tree_sha": "d" * 40,
            "mode": "light",
            "execution_strategy": sorted(trusted_plan.EXECUTION_STRATEGIES)[0],
            "game_versions": [],
            "padding": "完整计划" * 300000,
        }
        document["plan_sha256"] = trusted_plan._digest("trusted-pr-plan", document)
        return document

    def test_download_retries_incomplete_failed_and_unbound_plans_before_atomic_publication(self):
        for failure in ("truncated", "missing", "command", "digest", "binding", "source", "schema", None):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                plan = self.plan()
                destination = root / "trusted-pr-plan/trusted-source-artifact-plan.json"
                destination.parent.mkdir()
                destination.write_bytes(b"previous verified plan")
                values = {
                    "RUNNER_TEMP": str(root),
                    "GITHUB_RUN_ID": "100",
                    "GITHUB_REPOSITORY": "owner/repo",
                    "CI_PLAN_ARTIFACT_NAME": "trusted-source-artifact-plan-100-1",
                    "PLAN_SHA256": plan["plan_sha256"],
                    "SOURCE_SHA": plan["merge_sha"],
                }
                attempts = []

                def download(args):
                    self.assertEqual(b"previous verified plan", destination.read_bytes())
                    attempts.append(args)
                    payload = dict(plan)
                    target = Path(args[args.index("--dir") + 1]) / destination.name
                    if len(attempts) == 1 and failure:
                        if failure == "missing":
                            return
                        if failure == "command":
                            raise subprocess.CalledProcessError(1, args)
                        if failure == "truncated":
                            target.write_bytes(b'{"padding":"incomplete')
                            return
                        if failure in ("digest", "binding"):
                            payload["padding"] = "tampered"
                        elif failure == "source":
                            payload["merge_sha"] = "e" * 40
                        elif failure == "schema":
                            payload["schema_version"] = 0
                        if failure != "digest":
                            payload.pop("plan_sha256")
                            payload["plan_sha256"] = trusted_plan._digest("trusted-pr-plan", payload)
                    target.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

                with patch.dict(os.environ, values), patch.object(runner, "command", side_effect=download):
                    self.assertEqual(0, runner.main(["download-plan"]))
                self.assertEqual(2 if failure else 1, len(attempts))
                self.assertEqual(plan, trusted_plan.load_trusted_artifact_plan(destination))
                self.assertEqual([destination], list(destination.parent.iterdir()))
                for args in attempts:
                    self.assertEqual(["gh", "run", "download", "100", "--repo", "owner/repo"], args[:6])
                    self.assertEqual(values["CI_PLAN_ARTIFACT_NAME"], args[args.index("--name") + 1])

    def test_download_fails_closed_after_three_attempts_without_publishing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = self.plan()
            values = {
                "RUNNER_TEMP": str(root),
                "GITHUB_RUN_ID": "100",
                "GITHUB_REPOSITORY": "owner/repo",
                "CI_PLAN_ARTIFACT_NAME": "trusted-source-artifact-plan-100-1",
                "PLAN_SHA256": plan["plan_sha256"],
                "SOURCE_SHA": plan["merge_sha"],
            }
            with patch.dict(os.environ, values), patch.object(runner, "command") as download:
                with self.assertRaisesRegex(ValueError, "after 3 attempts"):
                    runner.download_plan()
            self.assertEqual(3, download.call_count)
            self.assertEqual([], list((root / "trusted-pr-plan").iterdir()))

    def test_both_pr_consumers_use_verified_plan_downloads(self):
        import yaml

        workflow = yaml.safe_load((Path(runner.__file__).parent / ".github/workflows/pr-self-runner.yml").read_text())
        for job in ("bootstrap-reuse", "validate"):
            steps = workflow["jobs"][job]["steps"]
            downloads = [step for step in steps if step.get("with", {}).get("command") == "download-plan"]
            self.assertEqual(1, len(downloads))
            self.assertEqual("${{ github.token }}", downloads[0]["env"]["GH_TOKEN"])
            self.assertEqual("${{ inputs.plan_artifact_name }}", downloads[0]["env"]["CI_PLAN_ARTIFACT_NAME"])
            self.assertFalse(
                any(step.get("with", {}).get("path") == "${{ runner.temp }}/trusted-pr-plan" for step in steps)
            )

    def test_invalid_workflow_binding_is_rejected_before_downloading(self):
        for field in ("PLAN_SHA256", "SOURCE_SHA"):
            values = {"PLAN_SHA256": "sha256:" + "a" * 64, "SOURCE_SHA": "b" * 40, field: "invalid"}
            with (
                self.subTest(field=field),
                patch.dict(os.environ, values),
                patch.object(runner, "command") as download,
                self.assertRaisesRegex(ValueError, "workflow binding is invalid"),
            ):
                runner.download_plan()
            download.assert_not_called()


class TestConsumerIdaPreflight(unittest.TestCase):
    def test_consumer_resolves_ida_mcp_and_agent_before_exporting_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            python = str(root / "ida" / "python")
            with (
                patch.dict(os.environ, {}, clear=True),
                patch.object(runner, "host_tool", side_effect=lambda name: str(root / "ida" / name)) as host,
                patch.object(runner, "command", return_value="9.3") as command,
                patch.object(runner, "emit") as emit,
            ):
                self.assertEqual(0, runner.main(["resolve-consumer-ida"]))
                command.assert_called_once_with([python, "warmup_idb_worker.py", "--print-ida-version"], capture=True)
                self.assertEqual(["python", "idalib-mcp", "claude"], [call.args[0] for call in host.call_args_list])
                emit.assert_any_call({"IDA_PYTHON": python, "IDA_VERSION": "9.3"}, environment=True)
                self.assertEqual(python, os.environ["IDA_PYTHON"])

    def test_missing_ida_version_does_not_export_environment(self):
        with (
            patch.object(runner, "host_tool", return_value="python"),
            patch.object(runner, "command", return_value=""),
            patch.object(runner, "emit") as emit,
            self.assertRaisesRegex(ValueError, "runtime version"),
        ):
            runner.resolve_ida(consumer=True)
        emit.assert_not_called()

    def test_consumer_rejects_mismatched_mcp_installation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mcp = root / "other" / "idalib-mcp"
            mcp.parent.mkdir()
            mcp.write_text("#!/unrelated/python\n")
            with (
                patch.object(runner, "host_tool", side_effect=[str(root / "ida" / "python"), str(mcp)]),
                patch.object(runner, "command", return_value="9.3"),
                patch.object(runner, "emit") as emit,
                self.assertRaisesRegex(ValueError, "different installations"),
            ):
                runner.resolve_ida(consumer=True)
            emit.assert_not_called()

    def test_warmup_resolution_only_requires_python(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(runner, "host_tool", return_value="python") as host,
            patch.object(runner, "command", return_value="9.3"),
            patch.object(runner, "emit"),
        ):
            runner.resolve_ida()
            host.assert_called_once_with("python")


class TestCiRunner(unittest.TestCase):
    def variables(self, root):
        return {
            "GITHUB_WORKSPACE": str(root / "workspace"),
            "RUNNER_TEMP": str(root / "temp"),
            "GITHUB_RUN_ID": "100",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": "owner/repo",
            "GAMEVER": "14190",
            "CI_CACHE_ROOT": str(root / "store"),
            "IDA_VERSION": "9.2",
            "GITHUB_ENV": str(root / "environment"),
            "GITHUB_OUTPUT": str(root / "outputs"),
        }

    def test_idb_hit_exports_exact_selection_and_miss_does_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            hit = {
                "cache_hit": True,
                "generation": "a" * 64 + "-99-1",
                "cache_key": "a" * 64,
                "lease_id": "b" * 32,
                "lease_sha256": "c" * 64,
            }
            with patch.dict(os.environ, self.variables(root)), patch.object(runner, "document", return_value=hit):
                runner.idb("probe")
                environment = (root / "environment").read_text()
                for field in ("generation", "cache_key", "lease_id", "lease_sha256"):
                    self.assertIn(hit[field], environment)
            (root / "environment").unlink()
            with (
                patch.dict(os.environ, self.variables(root)),
                patch.object(
                    runner, "document", return_value={"cache_hit": False, "generation": None, "cache_key": "a" * 64}
                ),
            ):
                runner.idb("probe")
                self.assertFalse((root / "environment").exists())

    def test_consumer_restores_producer_selection_without_discovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = self.variables(root) | {
                "IDB_CACHE_GENERATION": "a" * 64 + "-99-1",
                "IDB_CACHE_KEY": "a" * 64,
                "IDB_CACHE_LEASE_ID": "b" * 32,
                "IDB_CACHE_LEASE_SHA256": "c" * 64,
            }
            with patch.dict(os.environ, values), patch.object(runner, "document", return_value={}) as command:
                runner.idb("restore")
                command.assert_called_once()
                argv = command.call_args.args
                self.assertEqual("restore", argv[1])
                for flag, key in (
                    ("--generation", "IDB_CACHE_GENERATION"),
                    ("--cache-key", "IDB_CACHE_KEY"),
                    ("--lease-id", "IDB_CACHE_LEASE_ID"),
                    ("--lease-sha256", "IDB_CACHE_LEASE_SHA256"),
                ):
                    self.assertEqual(values[key], argv[argv.index(flag) + 1])

    def test_bootstrap_reuse_still_binds_and_verifies_source_binaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = self.variables(root)
            Path(values["GITHUB_WORKSPACE"]).mkdir()
            plan = root / "plan.json"
            lock = "sha256:" + "d" * 64
            plan.write_text(
                json.dumps({"game_versions": [{"game_version": "14190", "merge_binary_lock_sha256": lock}]})
            )
            values.update(
                CI_KIND="pr",
                SOURCE_SHA="a" * 40,
                PLAN_SHA256="sha256:" + "e" * 64,
                CI_PLAN=str(plan),
                BOOTSTRAP_REUSED="true",
                BINARY_LOCK_SHA256="",
            )
            with (
                patch.dict(os.environ, values),
                patch.object(runner, "command", return_value="a" * 40),
                patch.object(runner, "document", return_value={"binary_lock_sha256": lock}) as document,
                patch.object(runner, "init_binaries") as initialize,
            ):
                runner.accepted_restore()
                initialize.assert_called_once()
                self.assertEqual(2, document.call_count)
                self.assertNotIn("--required", document.call_args_list[0].args)
                self.assertEqual("verify", document.call_args_list[1].args[1])
                self.assertIn(lock, (root / "environment").read_text())

    def test_release_requires_warmup_lock_only_for_rebuilt_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = self.variables(root)
            Path(values["GITHUB_WORKSPACE"]).mkdir()
            lock = "sha256:" + "d" * 64
            values.update(
                CI_KIND="release",
                SOURCE_ARTIFACT_MODE="tracked",
                SOURCE_BINARY_LOCK_SHA256=lock,
                WARMUP_BINARY_LOCK_SHA256="",
                BINARY_LOCK_SHA256="",
            )
            with (
                patch.dict(os.environ, values),
                patch.object(runner, "document", return_value={"binary_lock_sha256": lock}) as document,
            ):
                runner.accepted_restore()
                self.assertNotIn("--required", document.call_args.args)
                os.environ["SOURCE_ARTIFACT_MODE"] = "rebuild"
                with self.assertRaises(ValueError):
                    runner.accepted_restore()

    def test_cleanup_cannot_remove_paths_outside_runner_temp(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "unrelated"
            outside.mkdir()
            values = self.variables(root)
            Path(values["RUNNER_TEMP"]).mkdir()
            values.update(CANDIDATE_ROOT=str(outside), RELEASE_BUNDLE_ROOT="")
            with patch.dict(os.environ, values), self.assertRaises((ValueError, ReleaseWorkflowError)):
                runner.cleanup()
            self.assertTrue(outside.exists())

    def test_bootstrap_finalization_requires_portable_content_and_both_abis(self):
        for mutation in (None, "gamedata", "snapshot", "failed-abi", "missing-abi"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repo, inputs_root, inputs, results = evidence_support.TestCppEvidence().fixture(root)
                values = self.variables(root) | {
                    "GITHUB_WORKSPACE": str(repo),
                    "SOURCE_SHA": inputs["source_sha"],
                    "PR_NUMBER": "10",
                    "CI_SNAPSHOT_DIGEST": inputs["snapshot_sha256"],
                    "CI_GAMEDATA_DIGEST": "sha256:" + "d" * 64,
                }
                temp = Path(values["RUNNER_TEMP"])
                gates = temp / "new-gamever-gates" / "100-1"
                gates.mkdir(parents=True)
                shutil.copytree(inputs_root, gates / "cpp-inputs")
                (gates / "gamedata").mkdir()
                (gates / "gamedata" / "test.txt").write_text("validated gamedata")
                (gates / "gamedata.session.json").write_text("runner-local paths and inodes")
                actual = root / "actual"
                (actual / "14190").mkdir(parents=True)
                (actual / "14190" / "artifact.yaml").write_text("symbol truth")
                report = root / "report.json"
                report.write_text("{}")
                values.update(ACTUAL_ARTIFACT_ROOT=str(actual), EXECUTION_REPORT=str(report))
                with patch.dict(os.environ, values):
                    runner.bootstrap_package()
                prepared = temp / "new-gamever-prepared" / "100-1"
                self.assertFalse((prepared / "gamedata.session.json").exists())
                merged = temp / "cpp-evidence"
                cpp_evidence.aggregate(root=inputs_root, results=results, output=merged)
                if mutation == "gamedata":
                    (prepared / "gamedata" / "test.txt").write_text("tampered")
                elif mutation == "snapshot":
                    gates_file = prepared / "prepared-gates.json"
                    document = json.loads(gates_file.read_text())
                    document["snapshot_sha256"] = "sha256:" + "f" * 64
                    gates_file.write_text(json.dumps(document))
                elif mutation in ("failed-abi", "missing-abi"):
                    evidence_file = merged / "evidence.json"
                    document = json.loads(evidence_file.read_text())
                    if mutation == "failed-abi":
                        document["results"][1]["status"] = "failed"
                    else:
                        document["results"].pop()
                    evidence_file.write_text(json.dumps(document))
                values["CI_PREPARED_ROOT"] = str(prepared)
                with (
                    patch.dict(os.environ, values),
                    patch.object(
                        cpp_evidence,
                        "source_identity",
                        return_value={"source_sha": inputs["source_sha"], "sdk_sha": inputs["sdk_sha"]},
                    ),
                    patch.object(runner, "tool") as build,
                ):
                    if mutation:
                        with self.assertRaises(ValueError):
                            runner.bootstrap_finalize()
                        build.assert_not_called()
                        self.assertFalse((temp / "new-gamever-package").exists())
                    else:
                        runner.bootstrap_finalize()
                        build.assert_called_once()
                        canonical = temp / "new-gamever-package" / "100-1"
                        gate = json.loads((canonical / "gate-evidence.json").read_text())
                        self.assertNotIn("gamedata_files", gate)
                        self.assertEqual(
                            "sha256:" + cpp_evidence.sha256_file(merged / "validation.log"),
                            gate["cpp_validation_sha256"],
                        )
