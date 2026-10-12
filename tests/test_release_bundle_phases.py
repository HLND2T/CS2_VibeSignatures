import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ci_cpp_validation as cpp
import gamesymbol_store
import release_bundle as bundle
from release_workflow_lib.hashing import sha256_file, write_canonical_json
from tests import test_release_bundle as bundle_tests


class TestReleaseBundlePhases(unittest.TestCase):
    def test_prepared_bundle_is_not_publishable_and_requires_both_abi_results(self):
        fixture = bundle_tests.ReleaseBundleTests()
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            repo, preparation, _binsync, inputs = fixture._fixture(temp)
            prepared_root = temp / "prepared"
            identity = {"source_sha": preparation["source_sha"], "sdk_sha": preparation["sdk_gitlink_sha"]}
            with (
                patch.object(cpp, "source_identity", return_value=identity),
                # The existing Release fixture uses GAMEVER '1'; retain all
                # snapshot checks while bypassing only its legacy name shape.
                patch.object(
                    gamesymbol_store, "resolve_analysis_config", side_effect=lambda _gamever, path: Path(path)
                ),
                patch.object(bundle, "guard_candidate", return_value=inputs["gamedata_evidence"]),
                patch.object(bundle, "_sdk_inventory", return_value=inputs["sdk_inventory"]),
                patch.object(bundle, "_copy_sdk", side_effect=fixture._copy_sdk_fixture),
                patch.object(bundle, "_producer_contract", return_value={"files": [], "digest": "sha256:" + "c" * 64}),
                patch.object(bundle, "discover_generator_modules", return_value=[object()]),
                patch.object(bundle, "generator_contract_sha256", return_value="a" * 64),
                patch.object(bundle, "validate_output_tree", return_value=inputs["gamedata_evidence"]["files"]),
                patch.object(bundle, "gamedata_manifest_sha256", return_value="b" * 64),
                patch.object(bundle, "_verify_gamedata_reproducibility"),
            ):
                prepared = bundle.prepare_release_bundle(
                    repo_root=repo,
                    bundle_root=prepared_root,
                    repository="HLND2T/CS2_VibeSignatures",
                    release_version="1",
                    build_id=preparation["source_sha"],
                    preparation=Path(preparation["actual_artifact_root"]).parent / "release-rebuild-preparation.json",
                    rebuild_verification=inputs["verification_path"],
                    snapshot=inputs["snapshot"],
                    metadata=inputs["metadata"],
                    gamedata_candidate_root=inputs["gamedata_candidate"],
                    gamedata_session=temp / "unused-session.json",
                    binsync_candidate_root=inputs["binsync_root"],
                    ida_runtime_identity="IDA 9.2",
                    warm_idb_generation="generation-1",
                    warm_idb_cache_key="cache-key-1",
                    actions_artifact_name=f"release-bundle-{preparation['source_sha']}-1",
                    cpp_sdk_ref=bundle.CPP_SDK_REF,
                    cpp_sdk_sha=preparation["sdk_gitlink_sha"],
                )
                self.assertNotIn("cpp_validation_sha256", prepared["manifest"])
                self.assertFalse(list(prepared_root.glob("release-manifest-*.json")))
                with self.assertRaises(bundle.ReleaseBundleError):
                    bundle.verify_release_bundle(bundle_root=prepared_root, repo_root=repo)
                input_root = prepared_root / "cpp-inputs"
                cpp_inputs = cpp.validate_inputs(input_root)
                results = temp / "results"
                for platform in cpp.PLATFORMS:
                    leg = results / platform
                    leg.mkdir(parents=True)
                    (leg / cpp.LOG_NAME).write_text("no configured tests\n", encoding="utf-8")
                    write_canonical_json(
                        leg / cpp.RESULT_NAME,
                        {
                            **cpp_inputs,
                            "platform": platform,
                            "configured": 0,
                            "executed": 0,
                            "status": "no-tests",
                            "log_sha256": sha256_file(leg / cpp.LOG_NAME),
                        },
                    )
                evidence_root = temp / "evidence"
                evidence = cpp.aggregate(root=input_root, results=results, output=evidence_root)
                for index, mutate in enumerate(
                    (
                        lambda e: e["results"].pop(),
                        lambda e: e["results"][0].update(status="failed"),
                        lambda e: e["inputs"].update(sdk_sha="f" * 40),
                        lambda e: e["results"][1].update(configured=1, executed=1, status="passed"),
                    )
                ):
                    changed = copy.deepcopy(evidence)
                    mutate(changed)
                    write_canonical_json(evidence_root / "evidence.json", changed)
                    with self.subTest(index=index), self.assertRaises(ValueError):
                        bundle.finalize_release_bundle(
                            repo_root=repo,
                            prepared_root=prepared_root,
                            bundle_root=temp / f"invalid-{index}",
                            cpp_evidence_root=evidence_root,
                        )
                    self.assertFalse((temp / f"invalid-{index}").exists())
                write_canonical_json(evidence_root / "evidence.json", evidence)
                moved = temp / "relocated-prepared"
                prepared_root.rename(moved)
                manifest = bundle.finalize_release_bundle(
                    repo_root=repo, prepared_root=moved, bundle_root=temp / "final", cpp_evidence_root=evidence_root
                )
                self.assertEqual(evidence["log_sha256"], manifest["cpp_validation_sha256"])
                verified = bundle.verify_release_bundle(bundle_root=temp / "final", repo_root=repo)
                self.assertEqual(preparation["source_sha"], verified["source_sha"])
                self.assertFalse((temp / "final" / "prepared-release.json").exists())
                self.assertFalse((temp / "final" / "cpp-inputs").exists())

    def test_finalize_rejects_corrupt_preparation_before_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            prepared = temp / "prepared"
            prepared.mkdir()
            write_canonical_json(prepared / "prepared-release.json", {"schema_version": 1, "manifest": {}, "files": []})
            (prepared / "unexpected").write_text("tampered")
            with self.assertRaisesRegex(bundle.ReleaseBundleError, "inventory changed"):
                bundle.finalize_release_bundle(
                    repo_root=temp, prepared_root=prepared, bundle_root=temp / "final", cpp_evidence_root=temp
                )
            self.assertFalse((temp / "final").exists())
