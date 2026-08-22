import tempfile
import unittest
import zipfile
from pathlib import Path

from release_workflow_lib.hashing import validate_output_paths
from release_workflow_lib.promotion import cleanup_completed, finalize_promotion, promote_bin
from tests.test_release_workflow import ReleaseFixture


class TestReleaseGamedataSmoke(unittest.TestCase):
    def test_non_publishing_versioned_gamedata_release_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ReleaseFixture(Path(tmp))
            fixture.stage()
            stage_dir = fixture.finalize_and_index()
            validate_output_paths(
                [
                    f"gamesymbols/{fixture.gamever}.yaml",
                    f"gamedata/{fixture.gamever}/fixture/nested/gamedata.txt",
                    f"release-manifests/{fixture.gamever}.json",
                ],
                fixture.gamever,
            )

            archive = fixture.root / f"gamedata-{fixture.gamever}.zip"
            version_root = fixture.repo / "gamedata" / fixture.gamever
            with zipfile.ZipFile(archive, "w") as output:
                for path in sorted(version_root.rglob("*")):
                    if path.is_file():
                        output.write(path, Path("gamedata") / fixture.gamever / path.relative_to(version_root))
            with zipfile.ZipFile(archive) as output:
                names = output.namelist()
            self.assertEqual(
                [
                    f"gamedata/{fixture.gamever}/fixture/nested/gamedata.txt",
                    f"gamedata/{fixture.gamever}/fixture/nested/gamedata.txt.metadata.json",
                ],
                names,
            )
            self.assertFalse(any(name.startswith("dist/") for name in names))

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
            result = cleanup_completed(
                staging_root=fixture.staging,
                persisted_root=fixture.root / "persisted",
                gamever=fixture.gamever,
                build_id=fixture.build_id,
            )
            self.assertEqual("removed", result["status"])


if __name__ == "__main__":
    unittest.main()
