from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import release_publish
from release_workflow_lib.hashing import write_canonical_json


class ReleasePublishTests(unittest.TestCase):
    def _bundle(self, root: Path) -> tuple[Path, dict, dict]:
        bundle = root / "release-bundle"
        payload = bundle / "archives" / "payload.7z"
        payload.parent.mkdir(parents=True)
        payload.write_bytes(b"payload")
        manifest = {
            "repository": "HLND2T/CS2_VibeSignatures",
            "release_version": "14174",
            "game_version": "14174",
            "build_id": "123-1",
            "source_sha": "a" * 40,
            "artifact_inventory_sha256": "sha256:" + "b" * 64,
            "binsync": {
                "target_state_digest": "sha256:" + "c" * 64,
                "repositories": [
                    {
                        "repository_id": "HLND2T__repo",
                        "owner": "HLND2T",
                        "name": "repo",
                        "refs": [{"ref": "refs/heads/binsync/release", "commit": "d" * 40}],
                    }
                ],
            },
            "public_assets": [
                {
                    "path": "archives/payload.7z",
                    "name": "payload.7z",
                    "size": payload.stat().st_size,
                    "sha256": release_publish.sha256_file(payload),
                }
            ],
        }
        manifest_path = bundle / "release-manifest-14174.json"
        write_canonical_json(manifest_path, manifest)
        (bundle / "SHA256SUMS-14174.txt").write_text("checksums\n", encoding="utf-8")
        verified = {
            "schema_version": 1,
            "source_sha": manifest["source_sha"],
            "game_version": manifest["game_version"],
            "release_version": manifest["release_version"],
            "build_id": manifest["build_id"],
            "manifest_sha256": release_publish.sha256_file(manifest_path),
            "bundle_inventory_sha256": "sha256:" + "e" * 64,
            "binsync_target_state_digest": manifest["binsync"]["target_state_digest"],
        }
        return bundle, manifest, verified

    def test_draft_publish_and_exact_rerun_are_immutable_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, manifest, verified = self._bundle(root)
            tag = {"value": None}
            release = {"value": None}
            remote_bytes: dict[str, bytes] = {}

            def create_tag(_repository: str, _tag: str, source_sha: str) -> None:
                tag["value"] = source_sha

            def create_release(_repository: str, release_tag: str, source_sha: str, title: str, notes: str) -> dict:
                release["value"] = {
                    "id": 7,
                    "tag_name": release_tag,
                    "target_commitish": source_sha,
                    "name": title,
                    "body": notes,
                    "draft": True,
                    "prerelease": False,
                    "assets": [],
                }
                return copy.deepcopy(release["value"])

            def upload(_repository: str, _tag: str, path: Path) -> None:
                data = path.read_bytes()
                remote_bytes[path.name] = data
                release["value"]["assets"].append({"name": path.name, "size": len(data)})

            def download(_repository: str, _tag: str, name: str, destination: Path) -> Path:
                path = destination / name
                path.write_bytes(remote_bytes[name])
                return path

            def publish(_repository: str, release_id: int) -> None:
                self.assertEqual(7, release_id)
                release["value"]["draft"] = False

            with (
                patch.dict("os.environ", {"GH_TOKEN": "token"}),
                patch.object(release_publish, "verify_release_bundle", return_value=verified),
                patch.object(release_publish, "_remote_heads", return_value={"refs/heads/binsync/release": "d" * 40}),
                patch.object(release_publish, "_tag_target", side_effect=lambda _repository, _tag: tag["value"]),
                patch.object(release_publish, "_create_tag", side_effect=create_tag) as create_tag_mock,
                patch.object(
                    release_publish,
                    "_release_state",
                    side_effect=lambda _repository, _tag: copy.deepcopy(release["value"]),
                ),
                patch.object(
                    release_publish, "_create_draft_release", side_effect=create_release
                ) as create_release_mock,
                patch.object(release_publish, "_upload_asset", side_effect=upload) as upload_mock,
                patch.object(release_publish, "_download_asset", side_effect=download),
                patch.object(release_publish, "_publish_release", side_effect=publish) as publish_mock,
            ):
                binding = {
                    "expected_manifest_digest": verified["manifest_sha256"],
                    "expected_bundle_digest": verified["bundle_inventory_sha256"],
                    "expected_verified_binsync_target_state_digest": verified["binsync_target_state_digest"],
                }
                first = release_publish.publish_release(bundle_root=bundle, repo_root=root, **binding)
                second = release_publish.publish_release(bundle_root=bundle, repo_root=root, **binding)

            self.assertEqual("published", first["status"])
            self.assertEqual("already-published", second["status"])
            create_tag_mock.assert_called_once()
            create_release_mock.assert_called_once()
            self.assertEqual(3, upload_mock.call_count)
            publish_mock.assert_called_once()
            self.assertEqual(manifest["source_sha"], tag["value"])

    def test_published_release_asset_drift_fails_without_clobber(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, manifest, verified = self._bundle(root)
            title = "gamedata-14174"
            notes = release_publish._notes(manifest)
            release = {
                "id": 7,
                "tag_name": "14174",
                "target_commitish": manifest["source_sha"],
                "name": title,
                "body": notes,
                "draft": False,
                "prerelease": False,
                "assets": [
                    {"name": "payload.7z", "size": 7},
                    {
                        "name": "release-manifest-14174.json",
                        "size": (bundle / "release-manifest-14174.json").stat().st_size,
                    },
                    {"name": "SHA256SUMS-14174.txt", "size": (bundle / "SHA256SUMS-14174.txt").stat().st_size},
                ],
            }

            def download(_repository: str, _tag: str, name: str, destination: Path) -> Path:
                source = bundle / ("archives/payload.7z" if name == "payload.7z" else name)
                target = destination / name
                shutil.copyfile(source, target)
                if name == "payload.7z":
                    target.write_bytes(b"drifted")
                return target

            with (
                patch.dict("os.environ", {"GH_TOKEN": "token"}),
                patch.object(release_publish, "verify_release_bundle", return_value=verified),
                patch.object(release_publish, "_remote_heads", return_value={"refs/heads/binsync/release": "d" * 40}),
                patch.object(release_publish, "_tag_target", return_value=manifest["source_sha"]),
                patch.object(release_publish, "_release_state", return_value=release),
                patch.object(release_publish, "_download_asset", side_effect=download),
                patch.object(release_publish, "_upload_asset") as upload,
                self.assertRaisesRegex(release_publish.ReleasePublishError, "asset digest mismatch"),
            ):
                release_publish.publish_release(bundle_root=bundle, repo_root=root)
            upload.assert_not_called()

    def test_asset_upload_never_requests_clobber(self) -> None:
        with patch.object(release_publish, "_gh") as gh:
            release_publish._upload_asset("HLND2T/CS2_VibeSignatures", "14174", Path("asset.7z"))
        command = gh.call_args.args[0]
        self.assertNotIn("--clobber", command)
        self.assertEqual("upload", command[1])

    def test_hosted_digest_mismatch_fails_before_any_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, _manifest, verified = self._bundle(root)
            with (
                patch.dict("os.environ", {"GH_TOKEN": "token"}),
                patch.object(release_publish, "verify_release_bundle", return_value=verified),
                patch.object(release_publish, "_create_tag") as create_tag,
                self.assertRaisesRegex(release_publish.ReleasePublishError, "manifest digest differs"),
            ):
                release_publish.publish_release(
                    bundle_root=bundle,
                    repo_root=root,
                    expected_manifest_digest="sha256:" + "0" * 64,
                )

            create_tag.assert_not_called()

    def test_create_draft_release_returns_the_created_release(self) -> None:
        created = {"id": 7, "tag_name": "14174", "draft": True}
        result = subprocess.CompletedProcess([], 0, stdout=json.dumps(created))
        with patch.object(release_publish, "_gh", return_value=result) as gh:
            self.assertEqual(
                created,
                release_publish._create_draft_release("HLND2T/CS2_VibeSignatures", "14174", "a" * 40, "t", "b"),
            )

        self.assertEqual("POST", gh.call_args.args[0][2])

    def test_create_draft_release_rejects_an_invalid_response(self) -> None:
        result = subprocess.CompletedProcess([], 0, stdout=json.dumps({"tag_name": "14174"}))
        with (
            patch.object(release_publish, "_gh", return_value=result),
            self.assertRaisesRegex(release_publish.ReleasePublishError, "invalid response"),
        ):
            release_publish._create_draft_release("HLND2T/CS2_VibeSignatures", "14174", "a" * 40, "t", "b")

    def test_release_state_falls_back_to_the_list_for_drafts(self) -> None:
        draft = {"id": 7, "tag_name": "14174", "draft": True}
        listing = subprocess.CompletedProcess([], 0, stdout=json.dumps([draft]))
        with (
            patch.object(release_publish, "_gh_json", return_value=None),
            patch.object(release_publish, "_gh", return_value=listing) as gh,
        ):
            self.assertEqual(draft, release_publish._release_state("HLND2T/CS2_VibeSignatures", "14174"))

        self.assertEqual(["api", "repos/HLND2T/CS2_VibeSignatures/releases?per_page=100"], gh.call_args.args[0])

    def test_release_state_prefers_the_by_tag_lookup(self) -> None:
        published = {"id": 8, "tag_name": "14174", "draft": False}
        with (
            patch.object(release_publish, "_gh_json", return_value=published) as by_tag,
            patch.object(release_publish, "_gh") as listing,
        ):
            self.assertEqual(published, release_publish._release_state("HLND2T/CS2_VibeSignatures", "14174"))

        by_tag.assert_called_once()
        listing.assert_not_called()

    def test_release_state_returns_none_when_no_release_declares_the_tag(self) -> None:
        listing = subprocess.CompletedProcess([], 0, stdout=json.dumps([{"tag_name": "14178", "draft": False}]))
        with (
            patch.object(release_publish, "_gh_json", return_value=None),
            patch.object(release_publish, "_gh", return_value=listing),
        ):
            self.assertIsNone(release_publish._release_state("HLND2T/CS2_VibeSignatures", "14174"))


if __name__ == "__main__":
    unittest.main()
