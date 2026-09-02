from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from source_artifact_accepted_bin import AcceptedBinBridgeError, restore_accepted_bin, verify_workspace
from tests.gamesymbol_snapshot_test_support import write_binary, write_config, write_source_binary_lock


class SourceArtifactAcceptedBinTests(unittest.TestCase):
    def _repository(self, root: Path) -> Path:
        write_config(
            root / "configs" / "1.yaml",
            [{"name": "server", "path_windows": "game/bin/server.dll", "skills": []}],
        )
        (root / "download.yaml").write_text(
            "downloads:\n  - tag: '1'\n    manifests: {'1': '1'}\n",
            encoding="utf-8",
        )
        binary = root / "bin" / "1" / "server" / "server.dll"
        write_binary(binary, b"trusted binary")
        write_source_binary_lock(root, "1")
        return binary

    def test_restore_and_verify_require_exact_source_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            persisted = Path(temporary) / "persisted"
            binary = self._repository(root)
            cached = persisted / "bin" / "1" / "server" / "server.dll"
            cached.parent.mkdir(parents=True)
            shutil.copy2(binary, cached)
            shutil.rmtree(root / "bin" / "1")

            result = restore_accepted_bin(repo_root=root, persisted_root=persisted, gamever="1", required=True)

            self.assertTrue(result["cache_hit"])
            self.assertRegex(result["binary_lock_sha256"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(result["binary_lock_sha256"], verify_workspace(repo_root=root, gamever="1")["binary_lock_sha256"])

    def test_invalid_cache_is_a_miss_or_required_failure_without_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            persisted = Path(temporary) / "persisted"
            self._repository(root)
            shutil.rmtree(root / "bin" / "1")
            cached = persisted / "bin" / "1" / "server" / "server.dll"
            write_binary(cached, b"corrupt")

            result = restore_accepted_bin(repo_root=root, persisted_root=persisted, gamever="1", required=False)

            self.assertFalse(result["cache_hit"])
            self.assertFalse((root / "bin" / "1").exists())
            with self.assertRaisesRegex(AcceptedBinBridgeError, "unavailable or invalid"):
                restore_accepted_bin(repo_root=root, persisted_root=persisted, gamever="1", required=True)


if __name__ == "__main__":
    unittest.main()
