import tempfile
import unittest
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
                )

            self.assertNotEqual(first["cache_key"], second["cache_key"])
            self.assertEqual(
                b"server-v1",
                (destination / "bin" / gamever / "server" / "server.dll").read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
