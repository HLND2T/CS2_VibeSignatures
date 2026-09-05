from __future__ import annotations

import copy
import json
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import binsync_candidate as candidate
import init_gamebin
import release_artifact_rebuild as rebuild
from ida_analyze_util import canonical_symbol_yaml_bytes
from tests.gamesymbol_snapshot_test_support import write_binary, write_config, write_source_binary_lock


def _build_min_pe(first_section_rva: int = 0x1000) -> bytes:
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    optional_size = 0xF0
    pe = bytearray(4 + 20 + optional_size)
    pe[0:4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", pe, 4, 0x8664, 1, 0, 0, 0, optional_size, 0x2022)
    struct.pack_into("<H", pe, 24, 0x20B)
    section = bytearray(40)
    section[0:8] = b".text\0\0\0"
    struct.pack_into("<I", section, 12, first_section_rva)
    return bytes(dos) + bytes(pe) + bytes(section)


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
                    "skills": [{"name": "find-a", "expected_output": ["A.{platform}.yaml", "B.{platform}.yaml"]}],
                    "symbols": [
                        {"name": "A", "category": "func", "platform": "windows"},
                        {"name": "B", "category": "gv", "platform": "windows"},
                    ],
                }
            ],
        )
        (root / "download.yaml").write_text(
            "downloads:\n  - tag: '1'\n    manifests:\n      '100': '200'\n",
            encoding="utf-8",
        )
        artifact = root / "bin_artifacts" / "1" / "server" / "A.windows.yaml"
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(canonical_symbol_yaml_bytes({"func_name": "A", "func_rva": "0x1010"}, category="func"))
        (artifact.parent / "B.windows.yaml").write_bytes(
            canonical_symbol_yaml_bytes({"gv_name": "B", "gv_rva": "0x1020"}, category="gv")
        )
        binary = root / "bin" / "1" / "server" / "server.dll"
        write_binary(binary, _build_min_pe())
        write_source_binary_lock(root, "1")
        empty_tree = self._git(root, "mktree", input_text="")
        sdk_commit = self._git(
            root,
            "-c",
            "user.name=TestUser",
            "-c",
            "user.email=TestUser@binsync.local",
            "commit-tree",
            empty_tree,
            "-m",
            "sdk",
        )
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
        (binsync_repo / "metadata.toml").write_text('user = "TestUser"\nversion = "5.15.3"\n', encoding="utf-8")
        for name in (
            "comments.toml",
            "enums.toml",
            "patches.toml",
            "segments.toml",
            "typedefs.toml",
        ):
            (binsync_repo / name).write_text("", encoding="utf-8")
        (binsync_repo / "global_vars.toml").write_text(
            '["0x20"]\naddr = 0x20\nname = "B"\ntype = "int"\nsize = 0x8\n',
            encoding="utf-8",
        )
        function = binsync_repo / "functions" / "00000010.toml"
        function.parent.mkdir()
        function.write_text(
            'addr = 0x10\nsize = 0x1\nname = "A"\n\n[header]\nname = "A"\naddr = 0x10\n\n[header.args]\n',
            encoding="utf-8",
        )
        self._git(binsync_repo, "add", ".")
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
            user_ref = next(item for item in manifest["repositories"][0]["refs"] if item["ref"] != candidate.ROOT_REF)
            self.assertEqual(1, len(user_ref["new_commits"]))
            projection = manifest["source_projection"]
            self.assertEqual(1, projection["schema_version"])
            self.assertEqual(
                [
                    {
                        "artifact_path": "bin_artifacts/1/server/A.windows.yaml",
                        "artifact_sha256": "sha256:"
                        + candidate.sha256_file(root / "bin_artifacts" / "1" / "server" / "A.windows.yaml"),
                        "category": "func",
                        "module": "server",
                        "platform": "windows",
                        "repository_id": "HLND2T__CS2_VibeSignatures_binsync_1_server.dll",
                        "source_rva": 0x1010,
                        "symbol": "A",
                    },
                    {
                        "artifact_path": "bin_artifacts/1/server/B.windows.yaml",
                        "artifact_sha256": "sha256:"
                        + candidate.sha256_file(root / "bin_artifacts" / "1" / "server" / "B.windows.yaml"),
                        "category": "gv",
                        "module": "server",
                        "platform": "windows",
                        "repository_id": "HLND2T__CS2_VibeSignatures_binsync_1_server.dll",
                        "source_rva": 0x1020,
                        "symbol": "B",
                    },
                ],
                projection["entries"],
            )
            lowering = manifest["repositories"][0]["lowering_evidence"]
            self.assertEqual(0x1000, lowering["lift_bias"])
            self.assertEqual(
                [
                    {
                        "artifact_path": "bin_artifacts/1/server/A.windows.yaml",
                        "artifact_sha256": projection["entries"][0]["artifact_sha256"],
                        "category": "func",
                        "lifted_address": 0x10,
                        "source_rva": 0x1010,
                        "symbol": "A",
                        "tree_path": "functions/00000010.toml",
                    },
                    {
                        "artifact_path": "bin_artifacts/1/server/B.windows.yaml",
                        "artifact_sha256": projection["entries"][1]["artifact_sha256"],
                        "category": "gv",
                        "lifted_address": 0x20,
                        "source_rva": 0x1020,
                        "symbol": "B",
                        "tree_path": "global_vars.toml",
                    },
                ],
                lowering["entries"],
            )

    def test_hosted_verifier_recomputes_source_projection_from_git_blobs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            _source_sha, preparation, _binsync_repo = self._repository(root)
            destination = temporary_root / "candidate"
            manifest = self._build(root, preparation, destination)
            forged = copy.deepcopy(manifest)
            forged_digest = "sha256:" + "f" * 64
            forged["source_projection"]["entries"][0]["artifact_sha256"] = forged_digest
            forged["repositories"][0]["lowering_evidence"]["entries"][0]["artifact_sha256"] = forged_digest
            projection_unsigned = {
                "schema_version": forged["source_projection"]["schema_version"],
                "entries": forged["source_projection"]["entries"],
            }
            forged["source_projection"]["digest"] = candidate._digest(
                "binsync-source-projection:v1",
                projection_unsigned,
            )
            lowering = forged["repositories"][0]["lowering_evidence"]
            lowering_unsigned = {
                "schema_version": lowering["schema_version"],
                "lift_bias": lowering["lift_bias"],
                "entries": lowering["entries"],
            }
            lowering["digest"] = candidate._digest("binsync-lowering-evidence:v1", lowering_unsigned)
            manifest_unsigned = dict(forged)
            manifest_unsigned.pop("publication_digest")
            forged["publication_digest"] = candidate._digest(
                "binsync-publication-candidate:v4",
                manifest_unsigned,
            )
            candidate.write_canonical_json(destination / "manifest.json", forged)

            with self.assertRaisesRegex(candidate.BinSyncCandidateError, "source projection mismatch"):
                candidate.verify_candidate(candidate_root=destination, repo_root=root)

    def test_hosted_verifier_rejects_self_consistent_binary_inventory_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            _source_sha, preparation, _binsync_repo = self._repository(root)
            destination = temporary_root / "candidate"
            forged = copy.deepcopy(self._build(root, preparation, destination))
            forged["repositories"][0]["binary"]["sha256"] = "f" * 64
            forged["binary_inventory_sha256"] = candidate._release_rebuild_digest(
                "binary-inventory",
                candidate._nested_binary_inventory(forged["repositories"]),
            )
            manifest_unsigned = dict(forged)
            manifest_unsigned.pop("publication_digest")
            forged["publication_digest"] = candidate._digest(
                "binsync-publication-candidate:v4",
                manifest_unsigned,
            )
            candidate.write_canonical_json(destination / "manifest.json", forged)

            with self.assertRaisesRegex(candidate.BinSyncCandidateError, "source binary lock mismatch"):
                candidate.verify_candidate(candidate_root=destination, repo_root=root)

    def test_build_rejects_projected_address_missing_from_candidate_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            _source_sha, preparation, binsync_repo = self._repository(root)
            original = binsync_repo / "functions" / "00000010.toml"
            original.unlink()
            replacement = binsync_repo / "functions" / "00000011.toml"
            replacement.write_text('addr = 0x11\nsize = 0x1\nname = "A"\n', encoding="utf-8")
            self._git(binsync_repo, "add", "-A")
            self._git(
                binsync_repo,
                "-c",
                "user.name=TestUser",
                "-c",
                "user.email=TestUser@binsync.local",
                "commit",
                "-m",
                "Move projected address",
            )

            with self.assertRaisesRegex(candidate.BinSyncCandidateError, "projected function address is missing"):
                self._build(root, preparation, temporary_root / "candidate")

    def test_hosted_verifier_rejects_forged_lowering_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            _source_sha, preparation, _binsync_repo = self._repository(root)
            destination = temporary_root / "candidate"
            forged = copy.deepcopy(self._build(root, preparation, destination))
            lowering = forged["repositories"][0]["lowering_evidence"]
            lowering["lift_bias"] -= 1
            for entry in lowering["entries"]:
                entry["lifted_address"] += 1
                if entry["category"] != "gv":
                    entry["tree_path"] = f"functions/{entry['lifted_address']:08x}.toml"
            lowering_unsigned = {
                "schema_version": lowering["schema_version"],
                "lift_bias": lowering["lift_bias"],
                "entries": lowering["entries"],
            }
            lowering["digest"] = candidate._digest("binsync-lowering-evidence:v1", lowering_unsigned)
            manifest_unsigned = dict(forged)
            manifest_unsigned.pop("publication_digest")
            forged["publication_digest"] = candidate._digest(
                "binsync-publication-candidate:v4",
                manifest_unsigned,
            )
            candidate.write_canonical_json(destination / "manifest.json", forged)

            with self.assertRaisesRegex(candidate.BinSyncCandidateError, "lowering evidence .* tree mismatch"):
                candidate.verify_candidate(candidate_root=destination, repo_root=root)

    def test_build_rejects_non_fast_forward_remote_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            _source_sha, preparation, binsync_repo = self._repository(root)
            unrelated = self._git(
                binsync_repo,
                "-c",
                "user.name=TestUser",
                "-c",
                "user.email=TestUser@binsync.local",
                "commit-tree",
                self._git(binsync_repo, "mktree", input_text=""),
                "-m",
                "x",
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

    def test_build_rejects_payload_hidden_in_intermediate_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            _source_sha, preparation, binsync_repo = self._repository(root)
            payload = binsync_repo / "arbitrary-payload.txt"
            payload.write_text("secret\n", encoding="utf-8")
            self._git(binsync_repo, "add", "arbitrary-payload.txt")
            self._git(
                binsync_repo,
                "-c",
                "user.name=TestUser",
                "-c",
                "user.email=TestUser@binsync.local",
                "commit",
                "-m",
                "Add hidden payload",
            )
            payload.unlink()
            self._git(binsync_repo, "add", "-u")
            self._git(
                binsync_repo,
                "-c",
                "user.name=TestUser",
                "-c",
                "user.email=TestUser@binsync.local",
                "commit",
                "-m",
                "Remove hidden payload",
            )

            with self.assertRaisesRegex(candidate.BinSyncCandidateError, "publication allowlist"):
                self._build(root, preparation, temporary_root / "candidate")

    def test_build_rejects_invalid_binsync_toml_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            root = temporary_root / "repo"
            root.mkdir()
            _source_sha, preparation, binsync_repo = self._repository(root)
            (binsync_repo / "metadata.toml").write_text(
                'user = "WrongUser"\nversion = "5.15.3"\nsecret = "payload"\n',
                encoding="utf-8",
            )
            self._git(binsync_repo, "add", "metadata.toml")
            self._git(
                binsync_repo,
                "-c",
                "user.name=TestUser",
                "-c",
                "user.email=TestUser@binsync.local",
                "commit",
                "-m",
                "Forge metadata",
            )

            with self.assertRaisesRegex(candidate.BinSyncCandidateError, "metadata TOML"):
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
