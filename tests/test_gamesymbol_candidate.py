import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from gamesymbol_snapshot_lib.codec import build_snapshot_document, canonical_snapshot_bytes, parse_snapshot_bytes
from gamesymbol_snapshot_lib.candidate import (
    CandidateContractError,
    CandidatePublicationError,
    build_candidate_snapshot,
    compare_snapshots,
    complete_candidate_step,
    guard_candidate,
    publish_candidate,
)
from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.errors import SnapshotMismatchError
from gamesymbol_snapshot_lib.operations import pack_snapshot
from gamesymbol_store import CandidateChangedError
from tests.gamesymbol_snapshot_test_support import module, skill, write_binary, write_config, write_yaml


class CandidateWorkspace:
    def __init__(self, root: Path):
        self.root = root
        self.gamever = "14199"
        self.config = root / "config.yaml"
        self.bindir = root / "bin"
        self.stage = root / "stage"
        self.candidate = self.stage / f"{self.gamever}.yaml"
        self.session = self.stage / f"{self.gamever}.session.json"
        write_config(self.config, [module("server", [skill("find", ["Foo.{platform}.yaml"])], linux=False)])
        write_yaml(self.bindir / self.gamever / "server" / "Foo.windows.yaml", {"func_name": "Foo"})
        write_binary(self.bindir / self.gamever / "server" / "server.dll")

    def build(self):
        return build_candidate_snapshot(
            game_version=self.gamever,
            bin_root=self.bindir,
            config_path=self.config,
            output_path=self.candidate,
            session_path=self.session,
        )


class TestCandidateLifecycle(unittest.TestCase):
    def test_build_compare_validate_and_publish_preserve_bytes(self) -> None:
        with TemporaryDirectory() as temp_dir:
            previous = Path.cwd()
            os.chdir(temp_dir)
            try:
                workspace = CandidateWorkspace(Path(temp_dir))
                info = workspace.build()
                expected = Path(temp_dir) / "expected.yaml"
                expected.write_bytes(workspace.candidate.read_bytes())

                diff = compare_snapshots(
                    actual_path=workspace.candidate,
                    expected_path=expected,
                    config_path=workspace.config,
                    expected_game_version=workspace.gamever,
                    session_path=workspace.session,
                )
                self.assertTrue(diff.equal)
                complete_candidate_step(
                    candidate_path=workspace.candidate,
                    session_path=workspace.session,
                    step="gamedata",
                )
                complete_candidate_step(
                    candidate_path=workspace.candidate,
                    session_path=workspace.session,
                    step="cpp_tests",
                )
                destination = Path(temp_dir) / "gamesymbols" / f"{workspace.gamever}.yaml"
                published = publish_candidate(
                    candidate_path=workspace.candidate,
                    session_path=workspace.session,
                    destination=destination,
                )

                self.assertEqual(workspace.candidate.read_bytes(), destination.read_bytes())
                self.assertEqual(info.candidate_sha256, published.candidate_sha256)
                manifest = json.loads(workspace.session.read_text())
                self.assertEqual(2, manifest["schema_version"])
                self.assertEqual(5, manifest["snapshot_schema_version"])
                self.assertEqual(2, manifest["config_digest_version"])
                self.assertEqual("published", manifest["state"])
            finally:
                os.chdir(previous)

    def test_build_reuses_binary_metadata_from_tracked_snapshot(self) -> None:
        with TemporaryDirectory() as temp_dir:
            previous = Path.cwd()
            os.chdir(temp_dir)
            try:
                workspace = CandidateWorkspace(Path(temp_dir))
                tracked_snapshot = Path(temp_dir) / "gamesymbols" / f"{workspace.gamever}.yaml"
                with patch(
                    "gamesymbol_snapshot_lib.operations._utc_publish_time",
                    return_value="2026-01-02T03:04:05Z",
                ):
                    pack_snapshot(workspace.gamever, workspace.bindir, workspace.config, tracked_snapshot)
                    with patch("gamesymbol_snapshot_lib.operations.hash_file") as hash_file:
                        workspace.build()

                hash_file.assert_not_called()
                self.assertEqual(tracked_snapshot.read_bytes(), workspace.candidate.read_bytes())
            finally:
                os.chdir(previous)

    def test_guard_rejects_content_and_identity_changes(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = CandidateWorkspace(Path(temp_dir))
            workspace.build()
            raw = workspace.candidate.read_bytes()
            workspace.candidate.write_bytes(raw + b"# changed\n")
            with self.assertRaises(CandidateChangedError):
                guard_candidate(candidate_path=workspace.candidate, session_path=workspace.session)

        with TemporaryDirectory() as temp_dir:
            workspace = CandidateWorkspace(Path(temp_dir))
            workspace.build()
            replacement = workspace.stage / "replacement.yaml"
            replacement.write_bytes(workspace.candidate.read_bytes())
            os.replace(replacement, workspace.candidate)
            with self.assertRaises(CandidateChangedError):
                guard_candidate(candidate_path=workspace.candidate, session_path=workspace.session)

    def test_compare_reports_semantic_mismatch(self) -> None:
        with TemporaryDirectory() as temp_dir:
            first = CandidateWorkspace(Path(temp_dir) / "first")
            second = CandidateWorkspace(Path(temp_dir) / "second")
            first.build()
            write_yaml(second.bindir / second.gamever / "server" / "Foo.windows.yaml", {"func_name": "Changed"})
            second.build()
            with self.assertRaisesRegex(SnapshotMismatchError, "Modified"):
                compare_snapshots(
                    actual_path=first.candidate,
                    expected_path=second.candidate,
                    config_path=first.config,
                    expected_game_version=first.gamever,
                )

    def test_compare_rejects_equal_payload_with_different_schema_metadata(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = CandidateWorkspace(Path(temp_dir))
            workspace.build()
            actual = parse_snapshot_bytes(workspace.candidate.read_bytes())
            legacy_contract = load_contract(workspace.config, workspace.gamever, workspace.bindir, 1)
            expected = workspace.root / "expected-v1.yaml"
            expected.write_bytes(
                canonical_snapshot_bytes(
                    build_snapshot_document(
                        workspace.gamever,
                        legacy_contract.config_sha256,
                        actual["files"],
                        schema_version=1,
                        config_digest_version=1,
                    )
                )
            )

            with self.assertRaisesRegex(SnapshotMismatchError, "metadata mismatch"):
                compare_snapshots(
                    actual_path=workspace.candidate,
                    expected_path=expected,
                    config_path=workspace.config,
                    expected_game_version=workspace.gamever,
                )

    def test_compare_accepts_only_last_publish_time_difference(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = CandidateWorkspace(Path(temp_dir))
            workspace.build()
            actual = parse_snapshot_bytes(workspace.candidate.read_bytes())
            expected = workspace.root / "expected-time.yaml"
            expected_document = dict(actual)
            expected_document["last_publish_time"] = "2026-01-02T03:04:05Z"
            expected.write_bytes(canonical_snapshot_bytes(expected_document))

            diff = compare_snapshots(
                actual_path=workspace.candidate,
                expected_path=expected,
                config_path=workspace.config,
                expected_game_version=workspace.gamever,
            )

        self.assertTrue(diff.equal)
        self.assertNotEqual(diff.actual_sha256, diff.expected_sha256)

    def test_compare_rejects_binary_metadata_difference(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = CandidateWorkspace(Path(temp_dir))
            workspace.build()
            expected_document = parse_snapshot_bytes(workspace.candidate.read_bytes())
            expected_document["binaries"]["server"]["windows"]["md5"] = "0" * 32
            expected = workspace.root / "expected-binary.yaml"
            expected.write_bytes(canonical_snapshot_bytes(expected_document))

            with self.assertRaisesRegex(SnapshotMismatchError, "binaries"):
                compare_snapshots(
                    actual_path=workspace.candidate,
                    expected_path=expected,
                    config_path=workspace.config,
                    expected_game_version=workspace.gamever,
                )

    def test_publish_failure_leaves_existing_snapshot_unchanged(self) -> None:
        with TemporaryDirectory() as temp_dir:
            previous = Path.cwd()
            os.chdir(temp_dir)
            try:
                workspace = CandidateWorkspace(Path(temp_dir))
                workspace.build()
                complete_candidate_step(
                    candidate_path=workspace.candidate, session_path=workspace.session, step="gamedata"
                )
                complete_candidate_step(
                    candidate_path=workspace.candidate, session_path=workspace.session, step="cpp_tests"
                )
                destination = Path(temp_dir) / "gamesymbols" / f"{workspace.gamever}.yaml"
                destination.parent.mkdir()
                destination.write_bytes(b"original\n")
                real_replace = os.replace

                def fail_destination(source, target):
                    if Path(target) == destination:
                        raise OSError("injected publication failure")
                    return real_replace(source, target)

                with patch("gamesymbol_snapshot_lib.candidate.os.replace", side_effect=fail_destination):
                    with self.assertRaises(CandidatePublicationError):
                        publish_candidate(
                            candidate_path=workspace.candidate,
                            session_path=workspace.session,
                            destination=destination,
                        )
                self.assertEqual(b"original\n", destination.read_bytes())
            finally:
                os.chdir(previous)

    def test_build_rejects_tracked_destination_and_incomplete_formal_set(self) -> None:
        with TemporaryDirectory() as temp_dir:
            previous = Path.cwd()
            os.chdir(temp_dir)
            try:
                workspace = CandidateWorkspace(Path(temp_dir))
                with self.assertRaises(CandidateContractError):
                    build_candidate_snapshot(
                        game_version=workspace.gamever,
                        bin_root=workspace.bindir,
                        config_path=workspace.config,
                        output_path=Path(temp_dir) / "gamesymbols" / f"{workspace.gamever}.yaml",
                        session_path=Path(temp_dir) / "gamesymbols" / "session.json",
                    )
                (workspace.bindir / workspace.gamever / "server" / "Foo.windows.yaml").unlink()
                with self.assertRaises(Exception):
                    workspace.build()
                self.assertFalse(workspace.candidate.exists())
                self.assertFalse(workspace.session.exists())
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
