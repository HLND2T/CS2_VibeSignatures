from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import binsync_candidate as candidate
import init_gamebin
import release_artifact_rebuild as rebuild
from ida_analyze_util import canonical_symbol_yaml_bytes
from tests.gamesymbol_snapshot_test_support import write_binary, write_config


class BinSyncCandidateTests(unittest.TestCase):
    def _git(self, root: Path, *arguments: str, input_text: str | None = None) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            input=input_text,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            self.fail(result.stderr or f"git {' '.join(arguments)} failed")
        return result.stdout.strip()

    def _repository(self, root: Path) -> tuple[str, dict, Path]:
        self._git(root, "init", "-b", "main")
        self._git(root, "config", "user.email", "test@example.com")
        self._git(root, "config", "user.name", "Test")
        write_config(
            root / "configs" / "1.yaml",
            [
                {
                    "name": "server",
                    "path_windows": "game/bin/win64/server.dll",
                    "skills": [{"name": "find-a", "expected_output": ["A.{platform}.yaml"]}],
                    "symbols": [{"name": "A", "category": "func", "platform": "windows"}],
                }
            ],
        )
        (root / "download.yaml").write_text("downloads:\n  - gamever: '1'\n", encoding="utf-8")
        artifact = root / "bin_artifacts" / "1" / "server" / "A.windows.yaml"
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(canonical_symbol_yaml_bytes({"func_name": "A", "func_rva": "0x10"}, category="func"))
        binary = root / "bin" / "1" / "server" / "server.dll"
        write_binary(binary)
        empty_tree = self._git(root, "mktree", input_text="")
        sdk_commit = self._git(root, "commit-tree", empty_tree, "-m", "sdk")
        self._git(root, "add", ".")
        self._git(root, "update-index", "--add", "--cacheinfo", f"160000,{sdk_commit},hl2sdk_cs2")
        self._git(root, "commit", "-m", "source")
        source_sha = self._git(root, "rev-parse", "HEAD")
        preparation = rebuild.prepare_release_rebuild(
            repo_root=root,
            source_sha=source_sha,
            game_version="1",
            binary_root=root / "bin",
            staging_root=root.parent / "release-rebuild",
        )

        repo_name = "CS2_VibeSignatures_binsync_1_server.dll"
        binsync_repo = binary.parent / "server.dll.bsproj"
        binsync_repo.mkdir()
        binary_md5 = preparation["binary_inventory"]["server"]["windows"]["md5"]
        init_gamebin.initialize_minimal_binsync_repo(binsync_repo, binary_md5, repo_name, "TestUser")
        self._git(binsync_repo, "remote", "add", "origin", f"https://github.com/HLND2T/{repo_name}")
        self._git(binsync_repo, "switch", "binsync/TestUser")
        (binsync_repo / "symbols.toml").write_text("symbols = []\n", encoding="utf-8")
        self._git(binsync_repo, "add", "symbols.toml")
        self._git(
            binsync_repo,
            "-c",
            "user.name=TestUser",
            "-c",
            "user.email=TestUser@binsync.local",
            "commit",
            "-m",
            "Update symbols",
        )
        return source_sha, preparation, binsync_repo

    def _build(
        self, root: Path, preparation: dict, destination: Path, remote_heads: dict[str, str] | None = None
    ) -> dict:
        with patch.object(candidate, "_remote_heads", return_value=remote_heads or {}):
            return candidate.build_candidate(
                repo_root=root,
                preparation=preparation,
                candidate_root=destination,
                release_version="1",
                build_id="123-1",
                ida_runtime_identity="IDA 9.2",
                actions_artifact_name=f"binsync-candidate-123-1-{preparation['source_sha']}-1",
            )

    def test_builds_canonical_self_contained_candidate_and_hosted_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            source_sha, preparation, _binsync_repo = self._repository(root)
            destination = temporary_root / "candidate"

            manifest = self._build(root, preparation, destination)
            verified = candidate.verify_candidate(
                candidate_root=destination,
                repo_root=root,
                expected_source_sha=source_sha,
                expected_game_version="1",
                expected_release_version="1",
                expected_build_id="123-1",
                expected_ida_runtime_identity="IDA 9.2",
                expected_actions_artifact_name=f"binsync-candidate-123-1-{source_sha}-1",
            )

            self.assertEqual(candidate.CANDIDATE_SCHEMA_VERSION, manifest["schema_version"])
            self.assertEqual(manifest["publication_digest"], verified["publication_digest"])
            self.assertEqual(
                candidate.publication_target_state(manifest)["target_state_digest"],
                verified["target_state_digest"],
            )
            self.assertEqual(1, verified["repository_count"])
            self.assertEqual(
                manifest,
                json.loads((destination / "manifest.json").read_text(encoding="utf-8")),
            )
            self.assertEqual(
                {"manifest.json", "SHA256SUMS.txt", manifest["repositories"][0]["bundle"]["path"]},
                {path.relative_to(destination).as_posix() for path in destination.rglob("*") if path.is_file()},
            )
            self.assertEqual(
                ["refs/heads/binsync/TestUser", "refs/heads/binsync/__root__"],
                sorted(item["ref"] for item in manifest["repositories"][0]["refs"]),
            )
            self.assertTrue(all(item["relationship"] == "create" for item in manifest["repositories"][0]["refs"]))

    def test_build_rejects_non_fast_forward_remote_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            _source_sha, preparation, binsync_repo = self._repository(root)
            unrelated = self._git(
                binsync_repo, "commit-tree", self._git(binsync_repo, "mktree", input_text=""), "-m", "x"
            )

            with self.assertRaisesRegex(candidate.BinSyncCandidateError, "not a fast-forward"):
                self._build(
                    root,
                    preparation,
                    temporary_root / "candidate",
                    {"refs/heads/binsync/TestUser": unrelated},
                )

    def test_build_rejects_unallowlisted_file_in_publication_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            _source_sha, preparation, binsync_repo = self._repository(root)
            (binsync_repo / "arbitrary-payload.txt").write_text("secret\n", encoding="utf-8")
            self._git(binsync_repo, "add", "arbitrary-payload.txt")
            self._git(
                binsync_repo,
                "-c",
                "user.name=TestUser",
                "-c",
                "user.email=TestUser@binsync.local",
                "commit",
                "-m",
                "Add arbitrary payload",
            )

            with self.assertRaisesRegex(candidate.BinSyncCandidateError, "publication allowlist"):
                self._build(root, preparation, temporary_root / "candidate")

    def test_verify_rejects_bundle_tamper_and_unexpected_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            _source_sha, preparation, _binsync_repo = self._repository(root)
            destination = temporary_root / "candidate"
            manifest = self._build(root, preparation, destination)
            bundle = destination / manifest["repositories"][0]["bundle"]["path"]
            bundle.write_bytes(bundle.read_bytes() + b"tamper")

            with self.assertRaisesRegex(candidate.BinSyncCandidateError, "bundle (size|checksum) mismatch"):
                candidate.verify_candidate(candidate_root=destination, repo_root=root)

            self._build(root, preparation, temporary_root / "candidate-clean")
            (temporary_root / "candidate-clean" / "secret.txt").write_text("not allowed", encoding="utf-8")
            with self.assertRaisesRegex(candidate.BinSyncCandidateError, "unexpected candidate files"):
                candidate.verify_candidate(candidate_root=temporary_root / "candidate-clean", repo_root=root)

    def test_verify_rejects_manifest_identity_and_remote_head_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            source_sha, preparation, _binsync_repo = self._repository(root)
            destination = temporary_root / "candidate"
            manifest = self._build(root, preparation, destination)

            with self.assertRaisesRegex(candidate.BinSyncCandidateError, "source SHA mismatch"):
                candidate.verify_candidate(
                    candidate_root=destination,
                    repo_root=root,
                    expected_source_sha="f" * 40,
                )

            remote = {
                item["ref"]: ("e" * 40 if item["expected_remote_head"] is None else item["expected_remote_head"])
                for item in manifest["repositories"][0]["refs"]
            }
            with patch.object(candidate, "_remote_heads", return_value=remote):
                with self.assertRaisesRegex(candidate.BinSyncCandidateError, "remote head drift"):
                    candidate.verify_candidate(
                        candidate_root=destination,
                        repo_root=root,
                        check_remotes=True,
                    )


if __name__ == "__main__":
    unittest.main()
