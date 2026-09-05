from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import binsync_candidate
import binsync_publish
from tests import test_binsync_candidate as candidate_tests


class BinSyncPublishTests(unittest.TestCase):
    def _candidate(self, temporary_root: Path) -> tuple[Path, Path, dict]:
        fixture = candidate_tests.BinSyncCandidateTests()
        root = temporary_root / "repo"
        root.mkdir()
        _source_sha, preparation, _binsync_repo = fixture._repository(root)
        destination = temporary_root / "candidate"
        with patch.object(binsync_candidate, "_remote_heads", return_value={}):
            manifest = binsync_candidate.build_candidate(
                repo_root=root,
                preparation=preparation,
                candidate_root=destination,
                release_version="1",
                build_id="123-1",
                ida_runtime_identity="IDA 9.2",
                actions_artifact_name=f"binsync-candidate-123-1-{preparation['source_sha']}-1",
            )
        return root, destination, manifest

    def test_publish_fast_forwards_then_exact_rerun_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root, candidate_root, manifest = self._candidate(temporary_root)
            repository = manifest["repositories"][0]
            remote_state: dict[str, dict[str, str]] = {repository["remote_url"]: {}}

            def remote_heads(remote_url: str) -> dict[str, str]:
                return dict(remote_state[remote_url])

            def push_refs(repository_record: dict, _bundle: Path, refs: list[dict], _environment: dict) -> None:
                for item in refs:
                    remote_state[repository_record["remote_url"]][item["ref"]] = item["candidate_commit"]

            receipt = temporary_root / "receipt.json"
            with (
                patch.object(binsync_publish, "_remote_heads", side_effect=remote_heads),
                patch.object(binsync_publish, "_push_refs", side_effect=push_refs) as push,
            ):
                first = binsync_publish.publish_candidate(
                    candidate_root=candidate_root,
                    repo_root=root,
                    token="test-token",
                    receipt_path=receipt,
                )
                second = binsync_publish.publish_candidate(
                    candidate_root=candidate_root,
                    repo_root=root,
                    token="test-token",
                    receipt_path=temporary_root / "receipt-rerun.json",
                )

            self.assertEqual(1, push.call_count)
            self.assertEqual("published", first["repositories"][0]["status"])
            self.assertEqual("already-published", second["repositories"][0]["status"])
            self.assertNotIn("test-token", receipt.read_text(encoding="utf-8"))
            self.assertEqual(first, json.loads(receipt.read_text(encoding="utf-8")))

    def test_publish_preflights_every_ref_and_refuses_divergence_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root, candidate_root, manifest = self._candidate(temporary_root)
            repository = manifest["repositories"][0]
            divergent = {item["ref"]: item["expected_remote_head"] for item in repository["refs"]}
            divergent[repository["refs"][-1]["ref"]] = "e" * 40

            with (
                patch.object(binsync_publish, "_remote_heads", return_value=divergent),
                patch.object(binsync_publish, "_push_refs") as push,
                self.assertRaisesRegex(binsync_publish.BinSyncPublishError, "remote divergence"),
            ):
                binsync_publish.publish_candidate(
                    candidate_root=candidate_root,
                    repo_root=root,
                    token="test-token",
                    receipt_path=temporary_root / "receipt.json",
                )

            push.assert_not_called()

    def test_publish_resumes_partial_candidate_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root, candidate_root, manifest = self._candidate(temporary_root)
            repository = manifest["repositories"][0]
            first_ref, second_ref = repository["refs"]
            remote_state = {
                first_ref["ref"]: first_ref["candidate_commit"],
                second_ref["ref"]: second_ref["expected_remote_head"],
            }

            def push_refs(_repository: dict, _bundle: Path, refs: list[dict], _environment: dict) -> None:
                self.assertEqual([second_ref["ref"]], [item["ref"] for item in refs])
                remote_state[second_ref["ref"]] = second_ref["candidate_commit"]

            with (
                patch.object(binsync_publish, "_remote_heads", side_effect=lambda _url: dict(remote_state)),
                patch.object(binsync_publish, "_push_refs", side_effect=push_refs) as push,
            ):
                result = binsync_publish.publish_candidate(
                    candidate_root=candidate_root,
                    repo_root=root,
                    token="test-token",
                    receipt_path=temporary_root / "receipt.json",
                )

            push.assert_called_once()
            self.assertEqual("published", result["repositories"][0]["status"])

    def test_push_uses_exact_expected_head_leases(self) -> None:
        refs = [
            {
                "ref": "refs/heads/binsync/__root__",
                "expected_remote_head": None,
                "candidate_commit": "a" * 40,
            },
            {
                "ref": "refs/heads/binsync/release",
                "expected_remote_head": "b" * 40,
                "candidate_commit": "c" * 40,
            },
        ]
        with patch.object(binsync_publish, "_run_git", return_value="") as run_git:
            binsync_publish._push_refs(
                {"remote_url": "https://github.com/HLND2T/example"},
                Path("candidate.bundle"),
                refs,
                {},
            )

        push_arguments = run_git.call_args_list[-1].args[1]
        self.assertIn("--force-with-lease=refs/heads/binsync/__root__:", push_arguments)
        self.assertIn(f"--force-with-lease=refs/heads/binsync/release:{'b' * 40}", push_arguments)


if __name__ == "__main__":
    unittest.main()
