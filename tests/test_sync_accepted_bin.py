import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from release_workflow_lib.binary_cache import IDA_DATABASE_SUFFIXES, version_lock
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.sync_accepted_bin import _filtered_inventory, sync_accepted_bin


class TestSyncAcceptedBin(unittest.TestCase):
    gamever = "14180"

    def _write_source(self, root: Path, *, marker: bytes = b"v1") -> None:
        for relative, prefix in (
            ("server/server.dll", b"server-"),
            ("engine/libengine2.so", b"engine-"),
        ):
            binary = root / "bin" / self.gamever / relative
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(prefix + marker)
            # Warm IDA side files must never reach the accepted tree.
            Path(f"{binary}.i64").write_bytes(b"idb-" + prefix + marker)
            binsync = binary.parent / f"{binary.name}.bsproj"
            (binsync / ".git").mkdir(parents=True)
            (binsync / ".git" / "HEAD").write_bytes(b"ref: refs/heads/binsync/__root__\n")
            (binsync / "symbols.toml").write_bytes(b"symbols = []\n")
            Path(f"{binary}.binsync.json").write_bytes(b"{}\n")
        (root / "bin" / self.gamever / "server" / "server.yaml").write_bytes(b"yaml-" + marker)

    def test_sync_creates_accepted_tree_without_recoverable_analysis_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            persisted = root / "persisted"
            self._write_source(repo)
            source_root = repo / "bin" / self.gamever

            result = sync_accepted_bin(
                repo_root=repo,
                persisted_root=persisted,
                gamever=self.gamever,
            )

            self.assertTrue(result["synced"])
            accepted = persisted / "bin" / self.gamever
            self.assertTrue((accepted / "server" / "server.dll").is_file())
            self.assertTrue((accepted / "engine" / "libengine2.so").is_file())
            self.assertFalse((accepted / "server" / "server.yaml").exists())
            # No recoverable IDA or BinSync state leaked into the accepted tree.
            self.assertFalse((accepted / "server" / "server.dll.i64").exists())
            self.assertFalse((accepted / "engine" / "libengine2.so.i64").exists())
            self.assertFalse((accepted / "server" / "server.dll.bsproj").exists())
            self.assertFalse((accepted / "engine" / "libengine2.so.bsproj").exists())
            self.assertFalse((accepted / "server" / "server.dll.binsync.json").exists())
            self.assertFalse((accepted / "engine" / "libengine2.so.binsync.json").exists())
            # Accepted tree equals the filtered source inventory.
            self.assertEqual(
                _filtered_inventory(source_root),
                _filtered_inventory(accepted),
            )

    def test_sync_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            persisted = root / "persisted"
            self._write_source(repo)

            first = sync_accepted_bin(repo_root=repo, persisted_root=persisted, gamever=self.gamever)
            second = sync_accepted_bin(repo_root=repo, persisted_root=persisted, gamever=self.gamever)

            self.assertTrue(first["synced"])
            self.assertFalse(second["synced"])
            # The idempotent second call is proven by the no-hash skeleton fast
            # path, so it never computes a content hash.
            self.assertRegex(first["hash"], r"^[0-9a-f]{64}$")
            self.assertIsNone(second["hash"])

    def test_sync_fast_path_skips_full_inventory(self) -> None:
        # An already-in-sync accepted tree must be detected from path+size alone;
        # the full-tree SHA-256 inventory (the expensive part) is never computed.
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            persisted = root / "persisted"
            self._write_source(repo)
            first = sync_accepted_bin(repo_root=repo, persisted_root=persisted, gamever=self.gamever)
            self.assertTrue(first["synced"])

            with patch("release_workflow_lib.sync_accepted_bin._filtered_inventory") as inventory:
                second = sync_accepted_bin(repo_root=repo, persisted_root=persisted, gamever=self.gamever)

            self.assertFalse(second["synced"])
            self.assertIsNone(second["hash"])
            inventory.assert_not_called()

    def test_sync_replaces_changed_accepted_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            persisted = root / "persisted"
            self._write_source(repo)
            accepted = persisted / "bin" / self.gamever
            (accepted / "server").mkdir(parents=True)
            (accepted / "server" / "server.dll").write_bytes(b"stale")

            result = sync_accepted_bin(repo_root=repo, persisted_root=persisted, gamever=self.gamever)

            self.assertTrue(result["synced"])
            self.assertTrue(result["replaced"])
            self.assertEqual(
                (repo / "bin" / self.gamever / "server" / "server.dll").read_bytes(),
                (accepted / "server" / "server.dll").read_bytes(),
            )
            # Old accepted tree was transactionally moved to a backup.
            self.assertTrue(Path(result["backup"]).is_dir())

    def test_sync_rewrites_when_accepted_tree_has_stale_recoverable_state(self) -> None:
        # A target tree that gained recoverable analysis state must be treated as
        # different and rewritten, dropping that state from the filtered copy.
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            persisted = root / "persisted"
            self._write_source(repo)
            first = sync_accepted_bin(repo_root=repo, persisted_root=persisted, gamever=self.gamever)
            accepted = persisted / "bin" / self.gamever
            binary = accepted / "server" / "server.dll"
            stale_paths = [Path(f"{binary}{suffix}") for suffix in IDA_DATABASE_SUFFIXES]
            for stale_path in stale_paths:
                stale_path.write_bytes(b"stale-idb")
            stale_repo = binary.parent / f"{binary.name}.bsproj"
            stale_repo.mkdir(exist_ok=True)
            (stale_repo / "symbols.toml").write_bytes(b"stale-binsync")
            stale_sidecar = Path(f"{binary}.binsync.json")
            stale_sidecar.write_bytes(b"{}\n")

            result = sync_accepted_bin(repo_root=repo, persisted_root=persisted, gamever=self.gamever)

            self.assertTrue(first["synced"])
            self.assertTrue(result["synced"])
            self.assertTrue(result["replaced"])
            for stale_path in stale_paths:
                self.assertFalse(stale_path.exists())
            self.assertFalse(stale_repo.exists())
            self.assertFalse(stale_sidecar.exists())

    def test_sync_requires_existing_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with self.assertRaisesRegex(ReleaseWorkflowError, "sync source tree does not exist"):
                sync_accepted_bin(
                    repo_root=root / "repo",
                    persisted_root=root / "persisted",
                    gamever=self.gamever,
                )

    def test_sync_uses_dedicated_binary_cache_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            persisted = root / "persisted"
            self._write_source(repo)
            lock_path = persisted / "binary-cache" / "locks" / f"{self.gamever}.lock"
            with version_lock(lock_path):
                with self.assertRaisesRegex(ReleaseWorkflowError, "unable to acquire per-version binary cache lock"):
                    sync_accepted_bin(repo_root=repo, persisted_root=persisted, gamever=self.gamever)
            # Lock released: sync succeeds.
            result = sync_accepted_bin(repo_root=repo, persisted_root=persisted, gamever=self.gamever)
            self.assertTrue(result["synced"])


if __name__ == "__main__":
    unittest.main()
