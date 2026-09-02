from __future__ import annotations

import copy
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import binsync_candidate
import release_artifact_rebuild as rebuild
import release_bundle
from gamesymbol_metadata import generate_metadata
from gamesymbol_snapshot_lib.codec import canonical_snapshot_bytes
from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.operations import build_actual_document
from release_workflow_lib.hashing import sha256_file
from tests import test_binsync_candidate as candidate_tests
from tests import test_release_artifact_rebuild as rebuild_tests


class ReleaseBundleTests(unittest.TestCase):
    @staticmethod
    def _copy_sdk_fixture(_sdk_root: Path, _sdk_sha: str, destination: Path, inventory: list[dict]) -> None:
        for item in inventory:
            target = destination / item["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("sdk\n", encoding="utf-8")

    def _fixture(self, temporary_root: Path) -> tuple[Path, dict, Path, dict]:
        candidate_fixture = candidate_tests.BinSyncCandidateTests()
        root = temporary_root / "repo"
        root.mkdir()
        source_sha, preparation, _binsync_repo = candidate_fixture._repository(root)
        shutil.copytree(root / "bin_artifacts", preparation["actual_artifact_root"], dirs_exist_ok=True)
        rebuild_fixture = rebuild_tests.ReleaseArtifactRebuildTests()
        rebuild_fixture._write_execution_report(preparation)
        verification = rebuild.verify_release_rebuild(repo_root=root, preparation=preparation)
        verification_path = temporary_root / "release-rebuild-verification.json"
        verification_path.write_bytes(rebuild._canonical_json_bytes(verification))

        snapshot = temporary_root / "1.yaml"
        contract = load_contract(
            root / "configs" / "1.yaml",
            "1",
            root / "bin",
            artifactdir=Path(preparation["actual_artifact_root"]),
        )
        snapshot.write_bytes(
            canonical_snapshot_bytes(build_actual_document(contract, last_publish_time="2026-01-01T00:00:00Z"))
        )
        metadata = temporary_root / "1.metadata.yaml"
        generate_metadata("1", root / "configs" / "1.yaml", metadata)
        gamedata_candidate = temporary_root / "gamedata-candidate"
        gamedata_file = gamedata_candidate / "gamedata" / "1" / "sample.txt"
        gamedata_file.parent.mkdir(parents=True)
        gamedata_file.write_text("generated\n", encoding="utf-8")
        gamedata_files = [
            {
                "path": "gamedata/1/sample.txt",
                "size": gamedata_file.stat().st_size,
                "sha256": sha256_file(gamedata_file),
            }
        ]
        gamedata_evidence = {
            "candidate_root": str(gamedata_candidate.resolve()),
            "files": gamedata_files,
            "generator_contract_sha256": "a" * 64,
            "gamedata_manifest_sha256": "b" * 64,
        }
        cpp_log = temporary_root / "cpp.log"
        cpp_log.write_text("C++ validation passed\n", encoding="utf-8")

        sdk_root = root / "hl2sdk_cs2"
        sdk_root.mkdir()
        sdk_file = sdk_root / "sdk.txt"
        sdk_file.write_text("sdk\n", encoding="utf-8")
        sdk_inventory = [{"path": "sdk.txt", "size": sdk_file.stat().st_size, "sha256": sha256_file(sdk_file)}]

        binsync_root = temporary_root / "binsync-candidate"
        with patch.object(binsync_candidate, "_remote_heads", return_value={}):
            binsync_manifest = binsync_candidate.build_candidate(
                repo_root=root,
                preparation=preparation,
                candidate_root=binsync_root,
                release_version="1",
                build_id=source_sha,
                ida_runtime_identity="IDA 9.2",
                actions_artifact_name=f"binsync-candidate-{source_sha}-1",
            )
        inputs = {
            "verification_path": verification_path,
            "snapshot": snapshot,
            "metadata": metadata,
            "gamedata_candidate": gamedata_candidate,
            "gamedata_evidence": gamedata_evidence,
            "cpp_log": cpp_log,
            "binsync_root": binsync_root,
            "sdk_inventory": sdk_inventory,
        }
        return root, preparation, binsync_root, {"binsync_manifest": binsync_manifest, **inputs}

    def test_builds_and_hosted_verifies_exact_release_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root, preparation, _binsync_root, inputs = self._fixture(temporary_root)
            bundle_root = temporary_root / "release-bundle"
            producer_contract = {"files": [], "digest": "sha256:" + "c" * 64}

            with (
                patch.object(release_bundle, "guard_candidate", return_value=inputs["gamedata_evidence"]),
                patch.object(release_bundle, "_sdk_inventory", return_value=inputs["sdk_inventory"]),
                patch.object(release_bundle, "_copy_sdk", side_effect=self._copy_sdk_fixture),
                patch.object(release_bundle, "_producer_contract", return_value=producer_contract),
                patch.object(release_bundle, "discover_generator_modules", return_value=[object()]),
                patch.object(release_bundle, "generator_contract_sha256", return_value="a" * 64),
                patch.object(
                    release_bundle,
                    "validate_output_tree",
                    return_value=inputs["gamedata_evidence"]["files"],
                ),
                patch.object(release_bundle, "gamedata_manifest_sha256", return_value="b" * 64),
            ):
                manifest = release_bundle.build_release_bundle(
                    repo_root=root,
                    bundle_root=bundle_root,
                    repository="HLND2T/CS2_VibeSignatures",
                    release_version="1",
                    build_id=preparation["source_sha"],
                    preparation=Path(preparation["actual_artifact_root"]).parent / "release-rebuild-preparation.json",
                    rebuild_verification=inputs["verification_path"],
                    snapshot=inputs["snapshot"],
                    metadata=inputs["metadata"],
                    gamedata_candidate_root=inputs["gamedata_candidate"],
                    gamedata_session=temporary_root / "gamedata.session.json",
                    cpp_validation_log=inputs["cpp_log"],
                    binsync_candidate_root=inputs["binsync_root"],
                    ida_runtime_identity="IDA 9.2",
                    warm_idb_generation="generation-1",
                    warm_idb_cache_key="cache-key-1",
                    actions_artifact_name=f"release-bundle-{preparation['source_sha']}-1",
                    cpp_sdk_ref=release_bundle.CPP_SDK_REF,
                    cpp_sdk_sha=preparation["sdk_gitlink_sha"],
                )
                verified = release_bundle.verify_release_bundle(
                    bundle_root=bundle_root,
                    repo_root=root,
                    expected_source_sha=preparation["source_sha"],
                    expected_game_version="1",
                    expected_release_version="1",
                    expected_build_id=preparation["source_sha"],
                    expected_actions_artifact_name=f"release-bundle-{preparation['source_sha']}-1",
                    expected_binsync_candidate_digest=inputs["binsync_manifest"]["publication_digest"],
                    expected_binsync_target_state_digest=binsync_candidate.publication_target_state(
                        inputs["binsync_manifest"]
                    )["target_state_digest"],
                )
                tampered = copy.deepcopy(manifest)
                gamedata_archive = tampered["archives"]["archives/gamedata-1.7z"]
                gamedata_archive["files"].append({"path": "unbound-secret.txt", "size": 6, "sha256": "0" * 64})
                gamedata_archive["files"].sort(key=lambda item: item["path"])
                with self.assertRaisesRegex(release_bundle.ReleaseBundleError, "exact source-derived inventory"):
                    release_bundle._verify_source(root, tampered)

            self.assertEqual(manifest["source_sha"], verified["source_sha"])
            self.assertEqual(manifest["source_sha"], manifest["build_id"])
            self.assertEqual(manifest["binsync"]["target_state_digest"], verified["binsync_target_state_digest"])
            self.assertEqual(4, len(manifest["public_assets"]))
            mutable_sdk = copy.deepcopy(manifest)
            mutable_sdk["cpp_sdk"] = {"ref": "cs2-1", "sha": manifest["cpp_sdk"]["sha"]}
            with self.assertRaisesRegex(release_bundle.ReleaseBundleError, "immutable source gitlink"):
                release_bundle.validate_release_manifest(mutable_sdk)

    def test_verify_rejects_public_asset_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root, preparation, _binsync_root, inputs = self._fixture(temporary_root)
            bundle_root = temporary_root / "release-bundle"
            patches = (
                patch.object(release_bundle, "guard_candidate", return_value=inputs["gamedata_evidence"]),
                patch.object(release_bundle, "_sdk_inventory", return_value=inputs["sdk_inventory"]),
                patch.object(release_bundle, "_copy_sdk", side_effect=self._copy_sdk_fixture),
                patch.object(
                    release_bundle,
                    "_producer_contract",
                    return_value={"files": [], "digest": "sha256:" + "c" * 64},
                ),
                patch.object(release_bundle, "discover_generator_modules", return_value=[object()]),
                patch.object(release_bundle, "generator_contract_sha256", return_value="a" * 64),
                patch.object(
                    release_bundle,
                    "validate_output_tree",
                    return_value=inputs["gamedata_evidence"]["files"],
                ),
                patch.object(release_bundle, "gamedata_manifest_sha256", return_value="b" * 64),
            )
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                patches[5],
                patches[6],
                patches[7],
            ):
                release_bundle.build_release_bundle(
                    repo_root=root,
                    bundle_root=bundle_root,
                    repository="HLND2T/CS2_VibeSignatures",
                    release_version="1",
                    build_id=preparation["source_sha"],
                    preparation=Path(preparation["actual_artifact_root"]).parent / "release-rebuild-preparation.json",
                    rebuild_verification=inputs["verification_path"],
                    snapshot=inputs["snapshot"],
                    metadata=inputs["metadata"],
                    gamedata_candidate_root=inputs["gamedata_candidate"],
                    gamedata_session=temporary_root / "gamedata.session.json",
                    cpp_validation_log=inputs["cpp_log"],
                    binsync_candidate_root=inputs["binsync_root"],
                    ida_runtime_identity="IDA 9.2",
                    warm_idb_generation="generation-1",
                    warm_idb_cache_key="cache-key-1",
                    actions_artifact_name=f"release-bundle-{preparation['source_sha']}-1",
                    cpp_sdk_ref=release_bundle.CPP_SDK_REF,
                    cpp_sdk_sha=preparation["sdk_gitlink_sha"],
                )
                (bundle_root / "gamesymbols" / "1.yaml").write_bytes(
                    (bundle_root / "gamesymbols" / "1.yaml").read_bytes() + b"tamper"
                )
                with self.assertRaisesRegex(release_bundle.ReleaseBundleError, "public asset mismatch"):
                    release_bundle.verify_release_bundle(bundle_root=bundle_root, repo_root=root)

    def test_archive_preflight_rejects_traversal_links_and_duplicates(self) -> None:
        with self.assertRaisesRegex(release_bundle.ReleaseBundleError, "unsafe entry"):
            release_bundle._listed_archive_files("Path = ../secret\nSize = 1\n")
        with self.assertRaisesRegex(release_bundle.ReleaseBundleError, "unsafe entry"):
            release_bundle._listed_archive_files("Path = C:\\secret\nSize = 1\n")
        with self.assertRaisesRegex(release_bundle.ReleaseBundleError, "link or unsupported"):
            release_bundle._listed_archive_files("Path = safe\nSize = 1\nSymbolic Link = target\n")
        with self.assertRaisesRegex(release_bundle.ReleaseBundleError, "duplicate paths"):
            release_bundle._listed_archive_files("Path = safe\nSize = 1\n\nPath = safe\nSize = 1\n")
        with self.assertRaisesRegex(release_bundle.ReleaseBundleError, "link or unsupported"):
            release_bundle._listed_archive_files(
                "Path = linked\nSize = 0\nFolder = +\nSymbolic Link = ../outside\n\n"
                "Path = linked/payload\nSize = 1\nFolder = -\n"
            )
        with self.assertRaisesRegex(release_bundle.ReleaseBundleError, "unsafe entry"):
            release_bundle._listed_archive_files("Path = unsupported\nFolder = -\n")
        with self.assertRaisesRegex(release_bundle.ReleaseBundleError, "unexpected empty"):
            release_bundle._listed_archive_files(
                "Path = empty\nSize = 0\nFolder = +\n\nPath = safe/file\nSize = 1\nFolder = -\n"
            )
        with self.assertRaisesRegex(release_bundle.ReleaseBundleError, "duplicate paths"):
            release_bundle._listed_archive_files(
                "Path = Safe\nSize = 0\nFolder = +\n\nPath = safe\nSize = 1\nFolder = -\n"
            )


if __name__ == "__main__":
    unittest.main()
