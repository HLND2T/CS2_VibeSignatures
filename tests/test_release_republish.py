import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import release_publish as publisher
from tests import test_release_publish


class RepublishTests(unittest.TestCase):
    def test_target_preflight_rejects_missing_immutable_and_publish_conflict(self):
        for mode, release, message in (
            ("republish", None, "use publish"),
            ("republish", {"immutable": True}, "immutable"),
            ("publish", {}, "does not point"),
        ):
            with (
                self.subTest(mode=mode, release=release),
                patch.object(publisher, "_tag_target", return_value="b" * 40),
                patch.object(publisher, "_release_state", return_value=release),
            ):
                with self.assertRaisesRegex(publisher.ReleasePublishError, message):
                    publisher.check_publication_target("owner/repo", "14174", "a" * 40, mode)

    def test_republish_recovers_interrupted_upload_and_is_idempotent(self):
        self._exercise_failure("assets")

    def test_draft_failure_leaves_existing_content_untouched(self):
        self._exercise_failure("draft")

    def test_tag_conflict_stops_before_asset_changes(self):
        self._exercise_failure("tag")

    def test_binsync_verification_failure_leaves_draft(self):
        self._exercise_failure("verification")

    def test_publish_response_failure_restores_draft(self):
        self._exercise_failure("publish")

    def _exercise_failure(self, failure_stage):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, manifest, verified = test_release_publish.ReleasePublishTests()._bundle(root)
            state = dict(
                id=7,
                tag_name="14174",
                target_commitish="b" * 40,
                name="old",
                body="old",
                draft=False,
                prerelease=False,
                immutable=False,
            )
            remote = {
                "obsolete.zip": b"old",
                "payload.7z": b"changed",
                "SHA256SUMS-14174.txt": (bundle / "SHA256SUMS-14174.txt").read_bytes(),
            }
            initial_remote = dict(remote)
            uploads = []
            tag = ["b" * 40]
            fail = [True]
            asset_ids = {}

            def interrupt(stage):
                if fail[0] and failure_stage == stage:
                    fail[0] = False
                    raise publisher.ReleasePublishError(f"{stage} interrupted")

            def read(*args, **kwargs):
                for name in remote:
                    asset_ids.setdefault(name, len(asset_ids) + 1)
                return {
                    **copy.deepcopy(state),
                    "assets": [dict(id=asset_ids[name], name=name, size=len(data)) for name, data in remote.items()],
                }

            def update(repository, release_id, **fields):
                self.assertEqual(7, release_id)
                interrupt("draft")
                state.update(fields)

            def move(repository, release_tag, new_sha, old_sha, repo_root):
                self.assertEqual(tag[0], old_sha)
                # Force-updating a draft's tag makes GitHub rewrite tag_name to
                # an untagged-* placeholder until the draft is rebound.
                state["tag_name"] = "untagged-" + new_sha[:20]
                interrupt("tag")
                tag[0] = new_sha

            def verify_binsync(manifest):
                if state["draft"] and "obsolete.zip" not in remote:
                    interrupt("verification")

            def publish(*args):
                state["draft"] = False
                interrupt("publish")

            def download(repository, release_tag, name, destination):
                path = destination / name
                path.write_bytes(remote[name])
                return path

            def delete(repository, asset_id):
                del remote[next(name for name in remote if asset_ids[name] == asset_id)]

            def upload(repository, release_tag, path):
                interrupt("assets")
                uploads.append(path.name)
                remote[path.name] = path.read_bytes()

            with (
                patch.dict("os.environ", {"GH_TOKEN": "token"}),
                patch.object(publisher, "verify_release_bundle", return_value=verified),
                patch.object(publisher, "_verify_binsync_targets", side_effect=verify_binsync),
                patch.object(publisher, "_tag_target", side_effect=lambda *a: tag[0]),
                patch.object(publisher, "_release_state", side_effect=read),
                patch.object(publisher, "_release_by_id", side_effect=read),
                patch.object(publisher, "_update_release", side_effect=update) as updates,
                patch.object(publisher, "_move_tag", side_effect=move),
                patch.object(publisher, "_download_asset", side_effect=download),
                patch.object(publisher, "_delete_asset", side_effect=delete),
                patch.object(publisher, "_upload_asset", side_effect=upload),
                patch.object(publisher, "_publish_release", side_effect=publish) as publication,
            ):
                with self.assertRaisesRegex(publisher.ReleasePublishError, f"{failure_stage} interrupted"):
                    publisher.publish_release(bundle_root=bundle, repo_root=root, publication_mode="republish")
                self.assertEqual(failure_stage != "draft", state["draft"])
                if failure_stage != "publish":
                    publication.assert_not_called()
                if failure_stage in ("draft", "tag"):
                    self.assertEqual(initial_remote, remote)
                result = publisher.publish_release(bundle_root=bundle, repo_root=root, publication_mode="republish")
                self.assertEqual("republished", result["status"])
                self.assertEqual(7, result["release_id"])
                self.assertEqual(manifest["source_sha"], tag[0])
                self.assertEqual("14174", state["tag_name"])
                self.assertNotIn("obsolete.zip", remote)
                self.assertEqual(b"payload", remote["payload.7z"])
                self.assertNotIn("SHA256SUMS-14174.txt", uploads)
                updates.reset_mock()
                result = publisher.publish_release(bundle_root=bundle, repo_root=root, publication_mode="republish")
                self.assertEqual("already-published", result["status"])
                updates.assert_not_called()

    def test_hosted_digest_failure_does_not_enter_republish(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, _, verified = test_release_publish.ReleasePublishTests()._bundle(root)
            with (
                patch.dict("os.environ", {"GH_TOKEN": "token"}),
                patch.object(publisher, "verify_release_bundle", return_value=verified),
                patch.object(publisher, "_republish") as republish,
            ):
                with self.assertRaisesRegex(publisher.ReleasePublishError, "manifest digest differs"):
                    publisher.publish_release(
                        bundle_root=bundle,
                        repo_root=root,
                        publication_mode="republish",
                        expected_manifest_digest="wrong",
                    )
                republish.assert_not_called()

    def test_missing_and_annotated_tags_are_rejected(self):
        with (
            patch.object(publisher, "_tag_target", return_value=None),
            patch.object(publisher, "_release_state", return_value={"immutable": False}),
            self.assertRaisesRegex(publisher.ReleasePublishError, "tag is missing"),
        ):
            publisher.check_publication_target("owner/repo", "14174", "a" * 40, "republish")
        with (
            patch.object(publisher, "_gh_json", return_value={"object": {"type": "tag", "sha": "b" * 40}}),
            self.assertRaisesRegex(publisher.ReleasePublishError, "direct commit"),
        ):
            publisher._tag_target("owner/repo", "14174")

    def test_tag_update_uses_explicit_lease_and_reports_failure(self):
        with (
            patch.dict("os.environ", {"GH_TOKEN": "secret"}),
            patch.object(publisher.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as run,
            self.assertRaisesRegex(publisher.ReleasePublishError, "lease update failed"),
        ):
            publisher._move_tag("owner/repo", "14174", "a" * 40, "b" * 40, Path("."))
        command = run.call_args.args[0]
        self.assertIn("--force-with-lease=refs/tags/14174:" + "b" * 40, command)
        self.assertIn("a" * 40 + ":refs/tags/14174", command)
        self.assertNotIn("secret", " ".join(command))

    def test_draft_lookup_by_id_collects_all_asset_pages(self):
        pages = [[{"id": 1, "name": "one"}], [{"id": 2, "name": "two"}]]
        with (
            patch.object(publisher, "_gh_json", return_value={"id": 7, "draft": True}),
            patch.object(
                publisher, "_gh", return_value=subprocess.CompletedProcess([], 0, stdout=json.dumps(pages))
            ) as gh,
        ):
            result = publisher._release_by_id("owner/repo", 7)
        self.assertEqual(pages[0] + pages[1], result["assets"])
        self.assertIn("repos/owner/repo/releases/7/assets?per_page=100", gh.call_args.args[0])
        self.assertIn("--paginate", gh.call_args.args[0])

    def test_orphaned_draft_is_only_a_republish_target(self):
        orphan = {
            "id": 7,
            "tag_name": "untagged-0123456789abcdef0123",
            "name": "gamedata-14174",
            "draft": True,
            "immutable": False,
        }
        published = {"id": 8, "tag_name": "14174", "name": "gamedata-14174", "draft": False}
        published_untagged = {**orphan, "id": 9, "draft": False}
        with patch.object(publisher, "_gh_json", return_value=None):
            with patch.object(
                publisher,
                "_gh",
                return_value=subprocess.CompletedProcess([], 0, stdout=json.dumps([orphan, published_untagged])),
            ):
                self.assertIsNone(publisher._release_state("owner/repo", "14174"))
                self.assertEqual(orphan, publisher._release_state("owner/repo", "14174", allow_orphan=True))
            with patch.object(
                publisher,
                "_gh",
                return_value=subprocess.CompletedProcess([], 0, stdout=json.dumps([orphan, published])),
            ):
                self.assertEqual(published, publisher._release_state("owner/repo", "14174", allow_orphan=True))

    def test_republish_rebinds_orphaned_draft_before_touching_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle, manifest, verified = test_release_publish.ReleasePublishTests()._bundle(root)
            notes = publisher._notes(manifest)
            state = {
                "id": 7,
                "tag_name": "untagged-0123456789abcdef0123",
                "target_commitish": manifest["source_sha"],
                "name": "gamedata-14174",
                "body": notes,
                "draft": True,
                "prerelease": False,
                "immutable": False,
            }
            remote = {
                "payload.7z": (bundle / "archives" / "payload.7z").read_bytes(),
                "release-manifest-14174.json": (bundle / "release-manifest-14174.json").read_bytes(),
                "SHA256SUMS-14174.txt": (bundle / "SHA256SUMS-14174.txt").read_bytes(),
            }
            asset_ids = {name: index + 1 for index, name in enumerate(remote)}
            updates = []

            def read(*args, **kwargs):
                return {
                    **copy.deepcopy(state),
                    "assets": [dict(id=asset_ids[name], name=name, size=len(data)) for name, data in remote.items()],
                }

            def update(repository, release_id, **fields):
                updates.append(fields)
                state.update(fields)

            def download(repository, release_tag, name, destination):
                self.assertEqual("14174", state["tag_name"])
                path = destination / name
                path.write_bytes(remote[name])
                return path

            with (
                patch.dict("os.environ", {"GH_TOKEN": "token"}),
                patch.object(publisher, "verify_release_bundle", return_value=verified),
                patch.object(publisher, "_verify_binsync_targets"),
                patch.object(publisher, "_tag_target", return_value=manifest["source_sha"]),
                patch.object(publisher, "_release_state", side_effect=read),
                patch.object(publisher, "_release_by_id", side_effect=read),
                patch.object(publisher, "_update_release", side_effect=update),
                patch.object(publisher, "_move_tag") as move,
                patch.object(publisher, "_download_asset", side_effect=download),
                patch.object(publisher, "_delete_asset") as delete,
                patch.object(publisher, "_upload_asset") as upload,
                patch.object(publisher, "_publish_release", side_effect=lambda *a: state.update(draft=False)),
            ):
                result = publisher.publish_release(bundle_root=bundle, repo_root=root, publication_mode="republish")

            self.assertEqual("republished", result["status"])
            self.assertEqual("14174", state["tag_name"])
            self.assertIs(False, state["draft"])
            self.assertIn("tag_name", updates[-1])
            move.assert_not_called()
            delete.assert_not_called()
            upload.assert_not_called()

    def test_target_only_cli_never_calls_publisher(self):
        with (
            patch.object(publisher, "check_publication_target") as check,
            patch.object(publisher, "publish_release") as publish,
        ):
            self.assertEqual(
                0,
                publisher.main(
                    [
                        "--check-target-only",
                        "--repository",
                        "owner/repo",
                        "--release-version",
                        "14174",
                        "--source-sha",
                        "a" * 40,
                        "--publication-mode",
                        "republish",
                    ]
                ),
            )
        check.assert_called_once_with("owner/repo", "14174", "a" * 40, "republish")
        publish.assert_not_called()
