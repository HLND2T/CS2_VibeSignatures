import tempfile
import unittest
from pathlib import Path

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.promotion import _version_lock
from release_workflow_lib.promote_staged_yaml import promote_staged_yaml


class TestPromoteStagedYaml(unittest.TestCase):
    gamever = "14180"

    def _write_staged_run(
        self,
        persisted: Path,
        pr_number: int,
        run: str,
        *,
        gamever: str | None = "14180",
    ) -> Path:
        run_dir = persisted / "pr-yaml-staging" / str(pr_number) / run
        (run_dir / "server").mkdir(parents=True, exist_ok=True)
        (run_dir / "server" / "server.yaml").write_bytes(b"yaml-data\n")
        (run_dir / "gamever.txt").write_text(gamever or "", encoding="utf-8")
        return run_dir

    def test_promote_copies_yaml_overlay_under_shared_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            persisted = root / "persisted"
            self._write_staged_run(persisted, pr_number=7, run="1234-1")

            result = promote_staged_yaml(persisted_root=persisted, pr_number=7)

            self.assertEqual(self.gamever, result["gamever"])
            self.assertEqual(1, result["promoted_files"])
            accepted = persisted / "bin" / self.gamever
            self.assertTrue((accepted / "server" / "server.yaml").is_file())
            # gamever.txt is a routing marker, never copied into accepted bin.
            self.assertFalse((accepted / "gamever.txt").exists())

    def test_promote_selects_numeric_latest_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            persisted = root / "persisted"
            self._write_staged_run(persisted, pr_number=7, run="999-1")
            self._write_staged_run(persisted, pr_number=7, run="1000-1")

            result = promote_staged_yaml(persisted_root=persisted, pr_number=7)

            # 1000 > 999 numerically; a lexicographic sort would pick "999-1".
            self.assertIn("1000-1", result["staged_run"])

    def test_promote_requires_staged_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            persisted = root / "persisted"
            with self.assertRaisesRegex(ReleaseWorkflowError, "staged YAML directory does not exist"):
                promote_staged_yaml(persisted_root=persisted, pr_number=7)

    def test_promote_requires_gamever_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            persisted = root / "persisted"
            run_dir = persisted / "pr-yaml-staging" / "7" / "1234-1"
            (run_dir / "server").mkdir(parents=True)
            (run_dir / "server" / "server.yaml").write_bytes(b"yaml\n")
            with self.assertRaisesRegex(ReleaseWorkflowError, "missing gamever.txt"):
                promote_staged_yaml(persisted_root=persisted, pr_number=7)

    def test_promote_shares_promotion_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            persisted = root / "persisted"
            self._write_staged_run(persisted, pr_number=7, run="1234-1")
            lock_path = persisted / "release-staging" / "locks" / f"{self.gamever}.lock"
            with _version_lock(lock_path):
                with self.assertRaisesRegex(ReleaseWorkflowError, "unable to acquire per-version promotion lock"):
                    promote_staged_yaml(persisted_root=persisted, pr_number=7)
            # Lock released: promotion succeeds.
            result = promote_staged_yaml(persisted_root=persisted, pr_number=7)
            self.assertEqual(1, result["promoted_files"])


if __name__ == "__main__":
    unittest.main()
