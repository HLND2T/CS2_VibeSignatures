import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from binary_hashing import hash_file
from gamedata_candidate import build_candidate, publish_candidate
from gamesymbol_snapshot_lib.codec import build_snapshot_document, canonical_snapshot_bytes, parse_snapshot_bytes
from gamesymbol_snapshot_lib.config import load_contract
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    contained_path,
    file_inventory,
    inventory_sha256,
    reject_reparse_points,
    validate_output_paths,
)
from release_workflow_lib.manifests import (
    build_tracked_manifest,
    format_output_branch,
    load_tracked_manifest,
    manifest_config_digest_version,
    parse_output_branch,
    write_release_metadata,
)
from release_workflow_lib.promotion import finalize_promotion, promote_bin
from release_workflow_lib.staging import (
    finalize_stage,
    load_indexed_pending,
    stage_build,
    write_pr_index,
)
from release_workflow_lib.validation import prepare_oldgamever_baseline
from tests.release_branch_protocol import (
    ACCEPTED_OUTPUT_BRANCHES,
    REJECTED_OUTPUT_BRANCHES,
)


class ReleaseFixture:
    gamever = "14170"
    build_id = "123456789-1"
    source_sha = "1" * 40
    head_sha = "2" * 40

    def __init__(self, root: Path) -> None:
        self.root = root
        self.repo = root / "repo"
        self.staging = root / "persisted" / "release-staging"
        self.bin_source = self.repo / "bin" / self.gamever
        self.candidate = root / "candidate.yaml"
        self.analysis_config = self.repo / "configs" / f"{self.gamever}.yaml"
        self.gamedata_candidate_root = root / "gamedata-candidate"
        self.gamedata_session = self.gamedata_candidate_root / "session.json"
        (self.repo / "gamesymbols").mkdir(parents=True)
        self.analysis_config.parent.mkdir(parents=True)
        generator = self.repo / "gamedata-generators" / "fixture"
        generator.mkdir(parents=True)
        self.bin_source.mkdir(parents=True)
        client_binary = self.bin_source / "client" / "client.dll"
        client_binary.parent.mkdir()
        client_binary.write_bytes(b"dll")
        client_hashes = hash_file(client_binary)
        (self.bin_source / "client" / "client.yaml").write_text("value: 1\n", encoding="utf-8")
        self.analysis_config.write_text(
            "modules:\n  - name: client\n    path_windows: game/bin/win64/client.dll\n    skills: []\n",
            encoding="utf-8",
        )
        contract = load_contract(self.analysis_config, self.gamever, self.repo / "bin")
        snapshot = canonical_snapshot_bytes(
            build_snapshot_document(
                self.gamever,
                contract.config_sha256,
                {},
                last_publish_time="2026-01-02T03:04:05Z",
                binaries={
                    "client": {
                        "windows": {
                            "path": "game/bin/win64/client.dll",
                            **client_hashes,
                        }
                    }
                },
            )
        )
        (self.repo / "gamesymbols" / f"{self.gamever}.yaml").write_bytes(snapshot)
        self.candidate.write_bytes(snapshot)
        (generator / "gamedata.py").write_text(
            "from pathlib import Path\n"
            "MODULE_NAME = 'Fixture'\n"
            "OUTPUT_PATHS = ('nested/gamedata.txt',)\n"
            "DOWNLOAD_SOURCES = ()\n"
            "def update(yaml_data, func_lib_map, platforms, output_dir, alias_to_name_map, debug=False):\n"
            "    path = Path(output_dir) / OUTPUT_PATHS[0]\n"
            "    path.parent.mkdir(parents=True, exist_ok=True)\n"
            "    path.write_text('gamedata\\n', encoding='utf-8')\n"
            "    return 1, 0, [], []\n",
            encoding="utf-8",
        )
        build_candidate(
            gamever=self.gamever,
            build_id=self.build_id,
            snapshot=self.candidate,
            analysis_config=self.analysis_config,
            modules_dir=self.repo / "gamedata-generators",
            candidate_root=self.gamedata_candidate_root,
            session_path=self.gamedata_session,
        )
        publish_candidate(
            session_path=self.gamedata_session,
            output_dir=self.repo / "gamedata" / self.gamever,
        )
        (self.repo / ".gitignore").write_text("__pycache__/\n*.pyc\n", encoding="utf-8")
        (self.repo / ".gitattributes").write_text("gamedata/** -text\n", encoding="utf-8")
        self.git("init", "--quiet")
        self.git("add", "--", "gamesymbols", "gamedata", "gamedata-generators")

    def git(self, *arguments: str) -> None:
        subprocess.run(["git", *arguments], cwd=self.repo, check=True, capture_output=True)

    def stage(self, *, output_branch: str | None = None) -> dict:
        return stage_build(
            repo_root=self.repo,
            staging_root=self.staging,
            bin_source=self.bin_source,
            candidate=self.candidate,
            repository="HLND2T/CS2_VibeSignatures",
            output_branch=output_branch or format_output_branch(self.gamever, self.build_id),
            gamever=self.gamever,
            mode="new",
            build_id=self.build_id,
            source_sha=self.source_sha,
            workflow_run_url="https://github.com/HLND2T/CS2_VibeSignatures/actions/runs/123456789",
            analysis_config=self.analysis_config,
            gamedata_session=self.gamedata_session,
        )

    def finalize_and_index(self, pr_number: int = 42) -> Path:
        finalize_stage(
            repo_root=self.repo,
            staging_root=self.staging,
            gamever=self.gamever,
            build_id=self.build_id,
            pr_head_sha=self.head_sha,
        )
        write_pr_index(
            staging_root=self.staging,
            pr_number=pr_number,
            gamever=self.gamever,
            build_id=self.build_id,
            pr_head_sha=self.head_sha,
        )
        return self.staging / self.gamever / self.build_id


class TestReleaseWorkflow(unittest.TestCase):
    def test_output_branch_parser_and_formatter_use_the_canonical_protocol(self) -> None:
        for branch in ACCEPTED_OUTPUT_BRANCHES:
            with self.subTest(branch=branch):
                gamever, build_id = parse_output_branch(branch)
                self.assertEqual(branch, format_output_branch(gamever, build_id))

        for branch in REJECTED_OUTPUT_BRANCHES:
            with self.subTest(branch=branch), self.assertRaises(ReleaseWorkflowError):
                parse_output_branch(branch)

        self.assertEqual(
            ACCEPTED_OUTPUT_BRANCHES[0],
            format_output_branch("14168", "29683665467-1"),
        )
        with self.assertRaises(ReleaseWorkflowError):
            format_output_branch("not-a-version", "1-2")
        with self.assertRaises(ReleaseWorkflowError):
            format_output_branch("14168", "29683665467")

    def _manifest_with_contract(self, *, digest_version=None, mode: str = "new") -> dict:
        return build_tracked_manifest(
            gamever="14170",
            mode=mode,
            build_id="123456789-1",
            source_sha="1" * 40,
            candidate_sha256="a" * 64,
            bin_manifest_sha256="b" * 64,
            tracked_output_manifest_sha256="c" * 64,
            workflow_run_url="https://github.com/HLND2T/CS2_VibeSignatures/actions/runs/1",
            analysis_config_path="configs/14170.yaml",
            analysis_config_sha256="d" * 64,
            analysis_config_contract_digest_version=digest_version,
            analysis_config_contract_sha256="sha256:" + "e" * 64,
        )

    def _write_oldgamever_fixture(self, root: Path, *, major_update: bool = False) -> Path:
        repo = root / "repo"
        config = repo / "configs" / "14168.yaml"
        snapshot = repo / "gamesymbols" / "14168.yaml"
        config.parent.mkdir(parents=True)
        snapshot.parent.mkdir(parents=True)
        config.write_text(
            "modules:\n"
            "  - name: server\n"
            "    path_windows: game/bin/win64/server.dll\n"
            "    skills:\n"
            "      - name: find-Test\n"
            "        platform: windows\n"
            "        expected_output:\n"
            "          - Test.{platform}.yaml\n",
            encoding="utf-8",
        )
        contract = load_contract(config, "14168", repo / "bin")
        document = build_snapshot_document(
            "14168",
            contract.config_sha256,
            {"server/Test.windows.yaml": {"func_name": "Test", "func_rva": "0x10"}},
            last_publish_time="2026-01-02T03:04:05Z",
            binaries={
                "server": {
                    "windows": {
                        "path": "game/bin/win64/server.dll",
                        "sha256": "1" * 64,
                        "md5": "2" * 32,
                        "crc32": "3" * 8,
                        "crc64": "4" * 16,
                        "size": 3,
                    }
                }
            },
        )
        snapshot.write_bytes(canonical_snapshot_bytes(document))
        major_line = "    major_update: true\n" if major_update else ""
        (repo / "download.yaml").write_text(
            f"downloads:\n  - tag: '14168'\n  - tag: '14168b'\n{major_line}",
            encoding="utf-8",
        )
        return repo

    def test_non_major_build_restores_nearest_trusted_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._write_oldgamever_fixture(Path(tmp))

            result = prepare_oldgamever_baseline(repo_root=repo, gamever="14168b", bindir="bin")

            self.assertEqual("14168", result["oldgamever"])
            restored = repo / "bin" / "14168" / "server" / "Test.windows.yaml"
            self.assertEqual("func_name: Test\nfunc_rva: '0x10'\n", restored.read_text(encoding="utf-8"))

    def test_major_update_explicitly_disables_oldgamever(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._write_oldgamever_fixture(Path(tmp), major_update=True)

            result = prepare_oldgamever_baseline(repo_root=repo, gamever="14168b", bindir="bin")

            self.assertEqual("none", result["oldgamever"])
            self.assertFalse((repo / "bin" / "14168").exists())

    def test_release_metadata_separates_human_notes_from_machine_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for mode in ("new", "republish"):
                with self.subTest(mode=mode):
                    output_dir = Path(tmp) / mode
                    output_dir.mkdir()
                    assets = [output_dir / "gamedata-14170.7z", output_dir / "gamebin-14170.7z"]
                    for asset in assets:
                        asset.write_bytes(asset.name.encode("utf-8"))

                    provenance_path, checksum_path, notes_path = write_release_metadata(
                        output_dir=output_dir,
                        manifest=self._manifest_with_contract(digest_version=2, mode=mode),
                        output_merge_sha="2" * 40,
                        tag_sha="3" * 40,
                        repository="HLND2T/CS2_VibeSignatures",
                        assets=assets,
                    )

                    provenance = provenance_path.read_text(encoding="utf-8")
                    checksums = checksum_path.read_text(encoding="utf-8")
                    notes = notes_path.read_text(encoding="utf-8")
                    self.assertTrue(notes.startswith("## CS2 gamedata 14170\n"))
                    self.assertIn(f"- Build mode: `{mode}`", notes)
                    self.assertIn("- Build ID: `123456789-1`", notes)
                    self.assertIn("/commit/" + "1" * 40, notes)
                    self.assertIn("/commit/" + "2" * 40, notes)
                    self.assertIn("/commit/" + "3" * 40, notes)
                    self.assertIn("`gamedata-14170.7z`", notes)
                    self.assertIn("`gamebin-14170.7z`", notes)
                    self.assertIn("`SHA256SUMS-14170.txt`", notes)
                    self.assertIn("`release-provenance-14170.json`", notes)
                    self.assertNotIn('"schema_version":', notes)
                    self.assertNotEqual(provenance, notes)
                    self.assertNotIn(notes_path.name, checksums)

    def test_non_major_build_fails_without_trusted_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "download.yaml").write_text("downloads:\n  - tag: '14168b'\n", encoding="utf-8")

            with self.assertRaisesRegex(ReleaseWorkflowError, "no trusted old-version snapshot"):
                prepare_oldgamever_baseline(repo_root=repo, gamever="14168b", bindir="bin")

    def test_stage_writes_canonical_tracked_and_private_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReleaseFixture(Path(tmp))
            pending = fixture.stage()
            tracked_path = fixture.repo / "release-manifests" / f"{fixture.gamever}.json"
            tracked = load_tracked_manifest(tracked_path)

            self.assertEqual(fixture.source_sha, tracked["source_sha"])
            self.assertEqual(inventory_sha256(pending["bin_files"]), tracked["bin_manifest_sha256"])
            self.assertEqual("configs/14170.yaml", tracked["analysis_config_path"])
            self.assertEqual(
                hashlib.sha256(fixture.analysis_config.read_bytes()).hexdigest(),
                tracked["analysis_config_sha256"],
            )
            self.assertEqual(4, tracked["schema_version"])
            self.assertEqual(2, tracked["analysis_config_contract_digest_version"])
            self.assertEqual(
                load_contract(fixture.analysis_config, fixture.gamever, fixture.repo / "bin").config_sha256,
                tracked["analysis_config_contract_sha256"],
            )
            self.assertEqual("gamedata/14170", tracked["gamedata_path"])
            self.assertEqual(pending["gamedata_manifest_sha256"], tracked["gamedata_manifest_sha256"])
            self.assertFalse((fixture.staging / fixture.gamever / fixture.build_id / "gamedata").exists())
            self.assertEqual(canonical_json_bytes(tracked), tracked_path.read_bytes())
            self.assertNotIn("timestamp", tracked)
            self.assertNotIn(str(fixture.root), tracked_path.read_text(encoding="utf-8"))

    def test_stage_rejects_snapshot_binary_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReleaseFixture(Path(tmp))
            (fixture.bin_source / "client" / "client.dll").write_bytes(b"changed")

            with self.assertRaisesRegex(ReleaseWorkflowError, "snapshot binary hash mismatch"):
                fixture.stage()

            self.assertFalse((fixture.staging / fixture.gamever / fixture.build_id).exists())

    def test_stage_rejects_snapshot_crc64_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReleaseFixture(Path(tmp))
            document = parse_snapshot_bytes(fixture.candidate.read_bytes())
            document["binaries"]["client"]["windows"]["crc64"] = "0" * 16
            fixture.candidate.write_bytes(canonical_snapshot_bytes(document))

            with self.assertRaisesRegex(ReleaseWorkflowError, "snapshot binary hash mismatch"):
                fixture.stage()

            self.assertFalse((fixture.staging / fixture.gamever / fixture.build_id).exists())

    def test_legacy_contract_manifest_is_v1_only_for_schema_1_snapshot(self) -> None:
        legacy_manifest = self._manifest_with_contract()
        schema_1 = build_snapshot_document(
            "14170",
            "sha256:" + "e" * 64,
            {},
            schema_version=1,
            config_digest_version=1,
        )
        schema_2 = build_snapshot_document(
            "14170",
            "sha256:" + "e" * 64,
            {},
            schema_version=2,
            config_digest_version=2,
        )

        self.assertEqual(2, legacy_manifest["schema_version"])
        self.assertEqual(1, manifest_config_digest_version(legacy_manifest, schema_1))
        with self.assertRaisesRegex(ReleaseWorkflowError, "lacks digest version"):
            manifest_config_digest_version(legacy_manifest, schema_2)

    def test_manifest_and_snapshot_digest_version_mismatch_is_rejected(self) -> None:
        manifest = self._manifest_with_contract(digest_version=2)
        schema_1 = build_snapshot_document(
            "14170",
            "sha256:" + "e" * 64,
            {},
            schema_version=1,
            config_digest_version=1,
        )

        with self.assertRaisesRegex(ReleaseWorkflowError, "does not match snapshot"):
            manifest_config_digest_version(manifest, schema_1)

    def test_finalize_binds_ready_state_and_pr_index_to_head_sha(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReleaseFixture(Path(tmp))
            fixture.stage()
            stage_dir = fixture.finalize_and_index()

            index, pending, loaded_dir = load_indexed_pending(fixture.staging, 42, fixture.head_sha)

            self.assertEqual(stage_dir, loaded_dir)
            self.assertEqual(fixture.head_sha, pending["pr_head_sha"])
            self.assertEqual(fixture.build_id, index["build_id"])
            self.assertTrue((stage_dir / "READY").is_file())

    def test_event_head_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReleaseFixture(Path(tmp))
            fixture.stage()
            fixture.finalize_and_index()

            with self.assertRaisesRegex(ReleaseWorkflowError, "event identity"):
                load_indexed_pending(fixture.staging, 42, "3" * 40)

    def test_tampered_tracked_output_is_rejected_when_finalizing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReleaseFixture(Path(tmp))
            fixture.stage()
            output = fixture.repo / "gamedata" / fixture.gamever / "fixture" / "nested" / "gamedata.txt"
            output.write_text("tampered\n", encoding="utf-8")
            fixture.git("add", "--", output.relative_to(fixture.repo).as_posix())

            with self.assertRaisesRegex(ReleaseWorkflowError, "tracked output manifest hash mismatch"):
                finalize_stage(
                    repo_root=fixture.repo,
                    staging_root=fixture.staging,
                    gamever=fixture.gamever,
                    build_id=fixture.build_id,
                    pr_head_sha=fixture.head_sha,
                )

    def test_untracked_other_version_is_excluded_from_tracked_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReleaseFixture(Path(tmp))
            cache = fixture.repo / "gamedata" / "14169" / "fixture" / "other.json"
            cache.parent.mkdir(parents=True)
            cache.write_bytes(b"cache")

            pending = fixture.stage()
            fixture.finalize_and_index()

            self.assertNotIn(
                cache.relative_to(fixture.repo).as_posix(), {item["path"] for item in pending["tracked_files"]}
            )

    def test_worktree_line_endings_do_not_change_index_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReleaseFixture(Path(tmp))
            fixture.stage()
            output = fixture.repo / "gamedata" / fixture.gamever / "fixture" / "nested" / "gamedata.txt"
            output.write_bytes(b"gamedata\r\n")

            fixture.finalize_and_index()

    def test_disallowed_generated_output_path_is_rejected(self) -> None:
        rejected = ("config.yaml", "dist/nested/gamedata.json", "gamedata/14171/module/output.json")
        for path in rejected:
            with self.subTest(path=path), self.assertRaisesRegex(ReleaseWorkflowError, "disallowed paths"):
                validate_output_paths(
                    ["gamesymbols/14170.yaml", "release-manifests/14170.json", path],
                    "14170",
                )

        validate_output_paths(
            [
                "gamesymbols/14170.yaml",
                "gamedata/14170/module/output.json",
                "release-manifests/14170.json",
            ],
            "14170",
        )

    def test_reparse_point_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "file.txt").write_text("data", encoding="utf-8")
            with patch("release_workflow_lib.hashing._is_reparse_point", return_value=True):
                with self.assertRaisesRegex(ReleaseWorkflowError, "reparse points"):
                    reject_reparse_points(root)

    def test_contained_path_preserves_lexical_root_spelling(self) -> None:
        root = Path("root-alias").absolute()
        target = root / "child"
        resolved_root = Path("resolved-root").absolute()
        resolved_target = resolved_root / "child"
        resolved_paths = {root: resolved_root, target: resolved_target}

        with patch.object(Path, "resolve", autospec=True, side_effect=lambda path, strict=False: resolved_paths[path]):
            actual = contained_path(root, "child")

        self.assertEqual(target, actual)

    def test_promote_bin_swaps_verified_directory_and_finalizes_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReleaseFixture(Path(tmp))
            fixture.stage()
            stage_dir = fixture.finalize_and_index()
            accepted = fixture.root / "persisted" / "bin" / fixture.gamever
            accepted.mkdir(parents=True)
            (accepted / "old.dll").write_bytes(b"old")

            state = promote_bin(
                persisted_root=fixture.root / "persisted",
                stage_dir=stage_dir,
                gamever=fixture.gamever,
                build_id=fixture.build_id,
            )

            self.assertTrue((stage_dir / "PROMOTION_STARTED").is_file())
            self.assertEqual(file_inventory(stage_dir / "bin" / fixture.gamever), file_inventory(accepted))
            self.assertTrue(Path(state["backup"]).is_dir())
            provenance = fixture.root / "release-provenance.json"
            provenance.write_text("{}\n", encoding="utf-8")
            finalize_promotion(
                staging_root=fixture.staging,
                pr_number=42,
                event_head_sha=fixture.head_sha,
                output_merge_sha="4" * 40,
                release_provenance=provenance,
            )
            self.assertFalse(Path(state["backup"]).exists())
            self.assertTrue((stage_dir / "PROMOTION_COMPLETE").is_file())
            self.assertFalse((fixture.staging / "pr-index" / "42.json").exists())
            self.assertTrue((fixture.staging / "completed" / fixture.gamever / f"{fixture.build_id}.json").is_file())

    def test_promote_bin_is_idempotent_after_successful_swap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReleaseFixture(Path(tmp))
            fixture.stage()
            stage_dir = fixture.finalize_and_index()

            kwargs = {
                "persisted_root": fixture.root / "persisted",
                "stage_dir": stage_dir,
                "gamever": fixture.gamever,
                "build_id": fixture.build_id,
            }
            first = promote_bin(**kwargs)
            second = promote_bin(**kwargs)

            self.assertEqual(first["accepted"], second["accepted"])
            self.assertEqual(first["backup"], second["backup"])


if __name__ == "__main__":
    unittest.main()
