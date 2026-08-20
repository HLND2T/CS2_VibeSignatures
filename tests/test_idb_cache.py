import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

import idb_cache


class TestIdbCache(unittest.TestCase):
    def _configured_binaries(self, root: Path, gamever: str, _config_path: Path):
        return [
            ("server", "windows", Path(root) / "bin" / gamever / "server" / "server.dll"),
            ("engine", "linux", Path(root) / "bin" / gamever / "engine" / "libengine2.so"),
        ]

    def _write_source(self, root: Path, gamever: str, *, marker: bytes = b"v1") -> None:
        for relative, prefix in (
            ("server/server.dll", b"server-"),
            ("engine/libengine2.so", b"engine-"),
        ):
            binary = root / "bin" / gamever / relative
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(prefix + marker)
            Path(f"{binary}.i64").write_bytes(b"idb-" + prefix + marker)

    def _patch_config(self):
        return patch.multiple(
            idb_cache,
            resolve_analysis_config=lambda gamever, repo_root: Path(repo_root) / "configs" / f"{gamever}.yaml",
            iter_configured_binaries=self._configured_binaries,
        )

    def test_publish_probe_and_restore_verified_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            destination = root / "destination"
            persisted = root / "persisted"
            gamever = "14180"
            self._write_source(source, gamever)

            with self._patch_config():
                published = idb_cache.publish_cache(
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="100-1",
                )
                probed = idb_cache.probe_cache(
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                )
                restored = idb_cache.restore_cache(
                    repo_root=destination,
                    persisted_root=persisted,
                    gamever=gamever,
                    generation=published["generation"],
                    expected_cache_key=published["cache_key"],
                    ida_version="9.2",
                )

            self.assertTrue(probed["cache_hit"])
            self.assertEqual(published["generation"], probed["generation"])
            self.assertEqual(published["generation"], restored["generation"])
            self.assertEqual(
                b"server-v1",
                (destination / "bin" / gamever / "server" / "server.dll").read_bytes(),
            )
            self.assertEqual(
                b"idb-server-v1",
                (destination / "bin" / gamever / "server" / "server.dll.i64").read_bytes(),
            )

    def test_publish_requires_every_configured_i64(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            gamever = "14180"
            self._write_source(source, gamever)
            (source / "bin" / gamever / "engine" / "libengine2.so.i64").unlink()

            with self._patch_config(), self.assertRaisesRegex(idb_cache.IdbCacheError, "warm IDB is missing"):
                idb_cache.publish_cache(
                    repo_root=source,
                    persisted_root=root / "persisted",
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="101-1",
                )

    def test_publish_preserves_primary_failure_when_incoming_cleanup_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            gamever = "14180"
            self._write_source(source, gamever)
            (source / "bin" / gamever / "engine" / "libengine2.so.i64").unlink()
            stderr = io.StringIO()

            with (
                self._patch_config(),
                patch.object(idb_cache, "remove_tree", side_effect=OSError("cleanup denied")),
                redirect_stderr(stderr),
                self.assertRaisesRegex(idb_cache.IdbCacheError, "warm IDB is missing"),
            ):
                idb_cache.publish_cache(
                    repo_root=source,
                    persisted_root=root / "persisted",
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="101-2",
                )

            self.assertIn("failed to remove incomplete cache publication", stderr.getvalue())
            self.assertIn("cleanup denied", stderr.getvalue())

    def test_restore_rejects_tampered_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            persisted = root / "persisted"
            gamever = "14180"
            self._write_source(source, gamever)

            with self._patch_config():
                published = idb_cache.publish_cache(
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="102-1",
                )

            payload = (
                persisted
                / "idb-cache"
                / gamever
                / "generations"
                / published["generation"]
                / "payload"
                / "server"
                / "server.dll.i64"
            )
            payload.write_bytes(b"tampered")

            with self.assertRaisesRegex(idb_cache.IdbCacheError, "inventory"):
                idb_cache.restore_cache(
                    repo_root=root / "destination",
                    persisted_root=persisted,
                    gamever=gamever,
                    generation=published["generation"],
                    expected_cache_key=published["cache_key"],
                    ida_version="9.2",
                )

    def test_restore_rejects_manifest_identity_that_disagrees_with_cache_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            persisted = root / "persisted"
            gamever = "14180"
            self._write_source(source, gamever)

            with self._patch_config():
                published = idb_cache.publish_cache(
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="102-2",
                )
            manifest_path = (
                persisted / "idb-cache" / gamever / "generations" / published["generation"] / "manifest.json"
            )
            manifest = idb_cache.load_json_object(manifest_path)
            manifest["binaries"][0]["module"] = "tampered"
            idb_cache.write_canonical_json(manifest_path, manifest)

            with self.assertRaisesRegex(idb_cache.IdbCacheError, "manifest identity"):
                idb_cache.restore_cache(
                    repo_root=root / "destination",
                    persisted_root=persisted,
                    gamever=gamever,
                    generation=published["generation"],
                    expected_cache_key=published["cache_key"],
                    ida_version="9.2",
                )

    def test_explicit_generation_is_stable_after_ready_moves(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            persisted = root / "persisted"
            destination = root / "destination"
            gamever = "14180"
            self._write_source(source, gamever, marker=b"v1")

            with self._patch_config():
                first = idb_cache.publish_cache(
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="103-1",
                )
                self._write_source(source, gamever, marker=b"v2")
                second = idb_cache.publish_cache(
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="104-1",
                )
                idb_cache.restore_cache(
                    repo_root=destination,
                    persisted_root=persisted,
                    gamever=gamever,
                    generation=first["generation"],
                    expected_cache_key=first["cache_key"],
                    ida_version="9.2",
                )

            self.assertNotEqual(first["cache_key"], second["cache_key"])
            self.assertEqual(
                b"server-v1",
                (destination / "bin" / gamever / "server" / "server.dll").read_bytes(),
            )

    def test_restore_rejects_consumer_ida_version_mismatch_before_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            destination = root / "destination"
            persisted = root / "persisted"
            gamever = "14180"
            self._write_source(source, gamever)

            with self._patch_config():
                published = idb_cache.publish_cache(
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="105-1",
                )
                with self.assertRaisesRegex(idb_cache.IdbCacheError, "IDA version mismatch"):
                    idb_cache.restore_cache(
                        repo_root=destination,
                        persisted_root=persisted,
                        gamever=gamever,
                        generation=published["generation"],
                        expected_cache_key=published["cache_key"],
                        ida_version="9.1",
                    )

            self.assertFalse((destination / "bin").exists())

    def test_restore_rejects_reparse_component_on_target_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            destination = root / "destination"
            persisted = root / "persisted"
            gamever = "14180"
            self._write_source(source, gamever)

            with self._patch_config():
                published = idb_cache.publish_cache(
                    repo_root=source,
                    persisted_root=persisted,
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="106-1",
                )

            # Create a junction at destination/bin/<gamever> pointing inside the
            # destination root so contained_path still accepts it but the restore
            # reparse-component check must reject it.
            bin_root = destination / "bin"
            bin_root.mkdir(parents=True, exist_ok=True)
            link = bin_root / gamever
            link_target = destination / "bin" / f"{gamever}-link-target"
            link_target.mkdir(parents=True, exist_ok=True)
            if os.name == "nt":
                result = os.system(f'cmd /c mklink /j "{link}" "{link_target}"')
                if result != 0:
                    self.skipTest("unable to create a junction on this host")
            else:
                try:
                    link.symlink_to(link_target, target_is_directory=True)
                except OSError as exc:
                    self.skipTest(f"unable to create a symlink on this host: {exc}")

            with self.assertRaisesRegex(idb_cache.IdbCacheError, "reparse"):
                idb_cache.restore_cache(
                    repo_root=destination,
                    persisted_root=persisted,
                    gamever=gamever,
                    generation=published["generation"],
                    expected_cache_key=published["cache_key"],
                    ida_version="9.2",
                )

    def test_prune_removes_only_old_unprotected_generations_and_incoming(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            persisted = root / "persisted"
            gamever = "14180"
            published = []
            with self._patch_config():
                for index in range(4):
                    self._write_source(source, gamever, marker=f"v{index}".encode())
                    published.append(
                        idb_cache.publish_cache(
                            repo_root=source,
                            persisted_root=persisted,
                            gamever=gamever,
                            ida_version="9.2",
                            generation_suffix=f"20{index}-1",
                        )
                    )
            generations_root = persisted / "idb-cache" / gamever / "generations"
            now = 10_000_000.0
            for index, generation in enumerate(published):
                path = generations_root / generation["generation"]
                age = (len(published) - index + 1) * 3600
                os.utime(path, (now - age, now - age))
            recent_incoming = generations_root / ".incoming-recent"
            stale_incoming = generations_root / ".incoming-stale"
            recent_incoming.mkdir()
            stale_incoming.mkdir()
            os.utime(recent_incoming, (now - 1800, now - 1800))
            os.utime(stale_incoming, (now - 7200, now - 7200))

            result = idb_cache.prune_cache(
                persisted_root=persisted,
                gamever=gamever,
                keep_generations=1,
                generation_min_age_hours=1,
                incoming_max_age_hours=1,
                now=now,
            )

            ready_generation = published[-1]["generation"]
            self.assertTrue((generations_root / ready_generation).is_dir())
            self.assertEqual(3, len(result["removed_generations"]))
            self.assertEqual([".incoming-stale"], result["removed_incoming"])
            self.assertTrue(recent_incoming.is_dir())

    def test_publish_builds_payload_inventory_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source"
            gamever = "14180"
            self._write_source(source, gamever)

            with (
                self._patch_config(),
                patch.object(idb_cache, "file_inventory", wraps=idb_cache.file_inventory) as inventory,
            ):
                idb_cache.publish_cache(
                    repo_root=source,
                    persisted_root=root / "persisted",
                    gamever=gamever,
                    ida_version="9.2",
                    generation_suffix="106-1",
                )

            inventory.assert_called_once()


if __name__ == "__main__":
    unittest.main()
