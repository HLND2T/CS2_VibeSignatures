import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from release_workflow_lib.binary_cache import IDA_DATABASE_SUFFIXES, version_lock
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.legacy_yaml_cleanup import cleanup_legacy_accepted_yaml
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


class TestLegacyAcceptedYamlCleanup(unittest.TestCase):
    gamever = "14180"

    def _accepted_tree(self, persisted: Path) -> Path:
        accepted = persisted / "bin" / self.gamever
        (accepted / "server").mkdir(parents=True)
        (accepted / "server" / "server.dll").write_bytes(b"binary")
        (accepted / "server" / "A.windows.yaml").write_bytes(b"name: A\n")
        (accepted / "engine").mkdir()
        (accepted / "engine" / "B.linux.yml").write_bytes(b"name: B\n")
        return accepted

    def test_cleanup_backs_up_exact_yaml_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            persisted = Path(temporary) / "persisted"
            accepted = self._accepted_tree(persisted)

            first = cleanup_legacy_accepted_yaml(persisted_root=persisted, gamever=self.gamever)
            second = cleanup_legacy_accepted_yaml(persisted_root=persisted, gamever=self.gamever)

            self.assertEqual("cleaned", first["status"])
            self.assertEqual("already-clean", second["status"])
            self.assertEqual(2, first["file_count"])
            self.assertTrue((accepted / "server" / "server.dll").is_file())
            self.assertFalse(any(path.suffix.lower() in {".yaml", ".yml"} for path in accepted.rglob("*")))
            backup = Path(first["backup_root"]) / "payload"
            self.assertEqual(b"name: A\n", (backup / "server" / "A.windows.yaml").read_bytes())
            self.assertEqual(b"name: B\n", (backup / "engine" / "B.linux.yml").read_bytes())

    def test_cleanup_resumes_after_partial_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            persisted = Path(temporary) / "persisted"
            accepted = self._accepted_tree(persisted)
            original_unlink = Path.unlink
            calls = 0

            def interrupt_once(path: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated interruption")
                original_unlink(path)

            with patch(
                "release_workflow_lib.legacy_yaml_cleanup._delete_yaml_path",
                side_effect=interrupt_once,
            ):
                with self.assertRaisesRegex(OSError, "simulated interruption"):
                    cleanup_legacy_accepted_yaml(persisted_root=persisted, gamever=self.gamever)

            state = persisted / "binary-cache" / "legacy-yaml-cleanup" / f"{self.gamever}.json"
            self.assertTrue(state.is_file())
            result = cleanup_legacy_accepted_yaml(persisted_root=persisted, gamever=self.gamever)
            self.assertEqual("cleaned", result["status"])
            self.assertFalse(state.exists())
            self.assertFalse(any(path.suffix.lower() in {".yaml", ".yml"} for path in accepted.rglob("*")))

    def test_cleanup_recovers_abandoned_incoming_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            persisted = Path(temporary) / "persisted"
            self._accepted_tree(persisted)

            with patch("release_workflow_lib.legacy_yaml_cleanup.os.replace", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    cleanup_legacy_accepted_yaml(persisted_root=persisted, gamever=self.gamever)

            backup_parent = persisted / "accepted-bin-legacy-yaml" / self.gamever
            self.assertEqual(1, len(list(backup_parent.glob(".*.incoming"))))
            result = cleanup_legacy_accepted_yaml(persisted_root=persisted, gamever=self.gamever)
            self.assertEqual("cleaned", result["status"])
            self.assertFalse(list(backup_parent.glob(".*.incoming")))

    def test_cleanup_rejects_damaged_backup_on_idempotent_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            persisted = Path(temporary) / "persisted"
            self._accepted_tree(persisted)
            first = cleanup_legacy_accepted_yaml(persisted_root=persisted, gamever=self.gamever)
            backup_yaml = Path(first["backup_root"]) / "payload" / "server" / "A.windows.yaml"
            backup_yaml.write_bytes(b"tampered\n")

            with self.assertRaisesRegex(ReleaseWorkflowError, "backup payload"):
                cleanup_legacy_accepted_yaml(persisted_root=persisted, gamever=self.gamever)

    def test_cleanup_rejects_yaml_that_reappears_after_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            persisted = Path(temporary) / "persisted"
            accepted = self._accepted_tree(persisted)
            cleanup_legacy_accepted_yaml(persisted_root=persisted, gamever=self.gamever)
            (accepted / "server" / "unexpected.yaml").write_bytes(b"reappeared\n")

            with self.assertRaisesRegex(ReleaseWorkflowError, "reappeared"):
                cleanup_legacy_accepted_yaml(persisted_root=persisted, gamever=self.gamever)

    def test_cleanup_requires_binary_only_allowlist_before_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            persisted = Path(temporary) / "persisted"
            accepted = self._accepted_tree(persisted)
            stale_idb = accepted / "server" / "server.dll.i64"
            stale_idb.write_bytes(b"stale")

            with self.assertRaisesRegex(ReleaseWorkflowError, "excluded analysis state"):
                cleanup_legacy_accepted_yaml(persisted_root=persisted, gamever=self.gamever)

            stale_idb.unlink()
            result = cleanup_legacy_accepted_yaml(persisted_root=persisted, gamever=self.gamever)
            self.assertEqual("cleaned", result["status"])


if __name__ == "__main__":
    unittest.main()
