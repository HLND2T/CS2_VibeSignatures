import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from release_workflow_lib.hashing import load_json_object, sha256_file, write_canonical_json
from release_workflow_lib.legacy_cleanup import migrate_legacy_completed
from release_workflow_lib.promotion import cleanup_completed, finalize_promotion, promote_bin
from tests.test_release_workflow import ReleaseFixture


def _finalize_fixture(fixture: ReleaseFixture) -> Path:
    fixture.stage()
    stage_dir = fixture.finalize_and_index()
    promote_bin(
        persisted_root=fixture.root / "persisted",
        stage_dir=stage_dir,
        gamever=fixture.gamever,
        build_id=fixture.build_id,
    )
    provenance = fixture.root / "release-provenance.json"
    provenance.write_text("{}\n", encoding="utf-8")
    finalize_promotion(
        staging_root=fixture.staging,
        pr_number=42,
        event_head_sha=fixture.head_sha,
        output_merge_sha="4" * 40,
        release_provenance=provenance,
    )
    return stage_dir


class TestCompletedReleaseCleanup(unittest.TestCase):
    def test_cleanup_ignores_a_newer_accepted_bin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReleaseFixture(Path(tmp))
            stage_dir = _finalize_fixture(fixture)
            accepted = fixture.root / "persisted" / "bin" / fixture.gamever
            (accepted / "newer.dll").write_bytes(b"newer")

            result = cleanup_completed(
                staging_root=fixture.staging,
                persisted_root=fixture.root / "persisted",
                gamever=fixture.gamever,
                build_id=fixture.build_id,
            )

            self.assertEqual("removed", result["status"])
            self.assertFalse(stage_dir.exists())
            self.assertTrue((fixture.staging / "completed" / fixture.gamever / f"{fixture.build_id}.json").is_file())

    def test_cleanup_resumes_after_atomic_trash_rename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReleaseFixture(Path(tmp))
            stage_dir = _finalize_fixture(fixture)
            trash = fixture.staging / "cleanup-trash" / fixture.gamever / fixture.build_id
            trash.parent.mkdir(parents=True)
            os.replace(stage_dir, trash)

            result = cleanup_completed(
                staging_root=fixture.staging,
                persisted_root=fixture.root / "persisted",
                gamever=fixture.gamever,
                build_id=fixture.build_id,
            )

            self.assertEqual("resumed", result["status"])
            self.assertFalse(trash.exists())

    def test_cleanup_retries_readonly_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReleaseFixture(Path(tmp))
            stage_dir = _finalize_fixture(fixture)
            readonly = (
                stage_dir
                / "bin"
                / fixture.gamever
                / "client"
                / "client.dll.bsproj"
                / ".git"
                / "objects"
                / "ab"
                / "readonly-object"
            )
            readonly.parent.mkdir(parents=True)
            readonly.write_bytes(b"git object")
            os.chmod(readonly, stat.S_IREAD)

            result = cleanup_completed(
                staging_root=fixture.staging,
                persisted_root=fixture.root / "persisted",
                gamever=fixture.gamever,
                build_id=fixture.build_id,
            )

            self.assertEqual("removed", result["status"])
            self.assertFalse(stage_dir.exists())

    def test_legacy_stage_requires_explicit_provenance_migration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReleaseFixture(Path(tmp))
            fixture.stage()
            stage_dir = fixture.finalize_and_index()
            pending = load_json_object(stage_dir / "manifest.json")
            for field in ("gamedata_path", "gamedata_manifest_sha256", "generator_contract_sha256"):
                pending.pop(field)
            pending["schema_version"] = 3
            write_canonical_json(stage_dir / "manifest.json", pending)
            (stage_dir / "READY").write_text(f"{sha256_file(stage_dir / 'manifest.json')}\n", encoding="ascii")
            state = promote_bin(
                persisted_root=fixture.root / "persisted",
                stage_dir=stage_dir,
                gamever=fixture.gamever,
                build_id=fixture.build_id,
            )
            backup = Path(state["backup"]) if state.get("backup") else None
            if backup and backup.exists():
                shutil.rmtree(backup)
            output_merge_sha = "4" * 40
            write_canonical_json(
                stage_dir / "PROMOTION_COMPLETE",
                {"schema_version": 3, "output_merge_sha": output_merge_sha},
            )
            (fixture.staging / "pr-index" / "42.json").unlink()
            provenance = fixture.root / "legacy-provenance.json"
            write_canonical_json(
                provenance,
                {
                    "schema_version": 3,
                    "gamever": fixture.gamever,
                    "build_id": fixture.build_id,
                    "source_sha": fixture.source_sha,
                    "output_merge_sha": output_merge_sha,
                    "candidate_sha256": pending["candidate_sha256"],
                    "bin_manifest_sha256": pending["bin_manifest_sha256"],
                    "tracked_output_manifest_sha256": pending["tracked_output_manifest_sha256"],
                },
            )

            record = migrate_legacy_completed(
                staging_root=fixture.staging,
                persisted_root=fixture.root / "persisted",
                gamever=fixture.gamever,
                build_id=fixture.build_id,
                release_provenance=provenance,
                expected_provenance_sha256=sha256_file(provenance),
            )
            result = cleanup_completed(
                staging_root=fixture.staging,
                persisted_root=fixture.root / "persisted",
                gamever=fixture.gamever,
                build_id=fixture.build_id,
            )

            self.assertEqual(0, record["schema_version"])
            self.assertEqual("removed", result["status"])


if __name__ == "__main__":
    unittest.main()
