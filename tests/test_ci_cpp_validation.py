import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ci_cpp_validation as evidence
from gamesymbol_snapshot_lib.operations import pack_snapshot
from release_workflow_lib.hashing import sha256_file, write_canonical_json
from release_workflow_lib.errors import ReleaseWorkflowError
from tests.gamesymbol_snapshot_test_support import module, skill, write_binary, write_config, write_yaml


class TestCppEvidence(unittest.TestCase):
    def fixture(self, root):
        repo = root / "source"
        config = repo / "config.yaml"
        write_config(config, [module("server", [skill("find", ["ITest_vtable.{platform}.yaml"])])])
        for platform, filename in (("windows", "server.dll"), ("linux", "server.so")):
            write_binary(repo / "bin" / "14190" / "server" / filename)
            write_yaml(
                repo / "bin_artifacts" / "14190" / "server" / f"ITest_vtable.{platform}.yaml",
                {"vtable_class": "ITest", "vtable_size": "0x8", "vtable_numvfunc": 1},
            )
        snapshot = root / "snapshot.yaml"
        pack_snapshot("14190", repo / "bin", config, snapshot, artifactdir=repo / "bin_artifacts")
        inputs_root = root / "inputs"
        identity = {"source_sha": "a" * 40, "sdk_sha": "b" * 40}
        with patch.object(evidence, "source_identity", return_value=identity):
            inputs = evidence.export_inputs(
                repo_root=repo,
                source_sha=identity["source_sha"],
                gamever="14190",
                snapshot=snapshot,
                config=config,
                output=inputs_root,
            )
        results = root / "results"
        for platform in evidence.PLATFORMS:
            leg = results / platform
            leg.mkdir(parents=True)
            (leg / evidence.LOG_NAME).write_text(platform + " has no configured tests\n", encoding="utf-8")
            receipt = {
                **inputs,
                "platform": platform,
                "configured": 0,
                "executed": 0,
                "status": "no-tests",
                "log_sha256": sha256_file(leg / evidence.LOG_NAME),
            }
            write_canonical_json(leg / evidence.RESULT_NAME, receipt)
        return repo, inputs_root, inputs, results

    def test_inputs_survive_moving_to_a_different_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _repo, inputs_root, inputs, _results = self.fixture(root)
            relocated = root / "different-drive-root"
            inputs_root.rename(relocated)
            self.assertEqual(inputs, evidence.validate_inputs(relocated))
            with self.assertRaisesRegex(ValueError, "different source"):
                evidence.validate_inputs(relocated, source_sha="f" * 40)
            with self.assertRaisesRegex(ValueError, "different GAMEVER"):
                evidence.validate_inputs(relocated, gamever="14189")

    def test_aggregate_is_ordered_and_content_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _repo, inputs_root, inputs, results = self.fixture(root)
            merged = root / "merged"
            actual = evidence.aggregate(root=inputs_root, results=results, output=merged)
            self.assertEqual(actual, evidence.validate_evidence(merged, inputs, inputs_root / "analysis-config.yaml"))
            log = (merged / evidence.LOG_NAME).read_text()
            self.assertLess(log.index("=== windows"), log.index("=== linux"))
            (merged / evidence.LOG_NAME).write_text("tampered")
            with self.assertRaisesRegex(ValueError, "log digest"):
                evidence.validate_evidence(merged, inputs, inputs_root / "analysis-config.yaml")

    def test_missing_failed_mismatched_and_incomplete_results_fail(self):
        mutations = (
            lambda r: r.update(status="failed"),
            lambda r: r.update(sdk_sha="f" * 40),
            lambda r: r.update(configured=1, executed=0, status="passed"),
            lambda r: r.update(platform="linux"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _repo, inputs_root, _inputs, results = self.fixture(root)
            result_file = results / "windows" / evidence.RESULT_NAME
            original = json.loads(result_file.read_text())
            for index, mutate in enumerate(mutations):
                with self.subTest(index=index):
                    changed = copy.deepcopy(original)
                    mutate(changed)
                    write_canonical_json(result_file, changed)
                    with self.assertRaises(ValueError):
                        evidence.aggregate(root=inputs_root, results=results, output=root / f"merged-{index}")
            write_canonical_json(result_file, original)
            (results / "linux" / evidence.RESULT_NAME).unlink()
            with self.assertRaises(ReleaseWorkflowError):
                evidence.aggregate(root=inputs_root, results=results, output=root / "merged-missing")

    def test_snapshot_and_configuration_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _repo, inputs_root, _inputs, _results = self.fixture(root)
            (inputs_root / "analysis-config.yaml").write_text("different config")
            with self.assertRaisesRegex(ValueError, "configuration bytes"):
                evidence.validate_inputs(inputs_root)

    def test_source_and_sdk_checkout_drift_is_rejected(self):
        source, sdk = "a" * 40, "b" * 40
        with patch.object(evidence, "git", side_effect=[source, sdk, sdk, ""]):
            self.assertEqual({"source_sha": source, "sdk_sha": sdk}, evidence.source_identity(Path("."), source))
        for responses, error in (
            (["c" * 40], "source checkout"),
            ([source, sdk, "c" * 40], "gitlink"),
            ([source, sdk, sdk, " M header.h"], "modified tracked"),
        ):
            with self.subTest(error=error), patch.object(evidence, "git", side_effect=responses):
                with self.assertRaisesRegex(ValueError, error):
                    evidence.source_identity(Path("."), source)

    def test_real_empty_abi_subprocess_emits_content_bound_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, inputs_root, inputs, _results = self.fixture(root)
            identity = {field: inputs[field] for field in ("source_sha", "sdk_sha")}
            with patch.object(evidence, "source_identity", return_value=identity):
                code = evidence.run_validation(
                    root=inputs_root,
                    repo_root=repo,
                    platform="linux",
                    output=root / "subprocess",
                    source_sha=inputs["source_sha"],
                    gamever="14190",
                )
            self.assertEqual(0, code)
            receipt = json.loads((root / "subprocess" / evidence.RESULT_NAME).read_text())
            evidence.validate_result(receipt, inputs, "linux", 0)
            self.assertEqual(evidence.sha256_file(root / "subprocess" / evidence.LOG_NAME), receipt["log_sha256"])

    def test_artifact_binding_rejects_wrong_run_and_digest(self):
        artifact = {"expired": False, "workflow_run": {"id": 123}, "digest": "sha256:" + "c" * 64}
        with patch.dict("os.environ", {"GITHUB_REPOSITORY": "owner/repo", "GITHUB_RUN_ID": "123"}):
            with patch.object(evidence.subprocess, "check_output", return_value=json.dumps(artifact)):
                self.assertEqual(artifact, evidence.bind_artifact("456", "c" * 64))
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    evidence.bind_artifact("456", "d" * 64)
                artifact["workflow_run"]["id"] = 124
            with patch.object(evidence.subprocess, "check_output", return_value=json.dumps(artifact)):
                with self.assertRaisesRegex(ValueError, "another run"):
                    evidence.bind_artifact("456", "c" * 64)
