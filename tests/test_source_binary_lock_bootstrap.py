from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from binary_hashing import hash_file
from source_binary_lock_bootstrap import SourceBinaryLockBootstrapError, bootstrap_binary_locks
from tests.gamesymbol_snapshot_test_support import write_binary, write_config, write_yaml


class SourceBinaryLockBootstrapTests(unittest.TestCase):
    def test_builds_and_checks_lock_from_historical_snapshot_blob(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_config(
                root / "configs" / "1234.yaml",
                [
                    {
                        "name": "server",
                        "path_windows": "game/bin/win64/server.dll",
                        "skills": [],
                    }
                ],
            )
            (root / "download.yaml").write_text(
                "downloads:\n  - tag: '1234'\n    manifests:\n      '100': '200'\n",
                encoding="utf-8",
            )
            binary = root / "bin" / "1234" / "server" / "server.dll"
            write_binary(binary, b"trusted-binary")
            write_yaml(
                root / "gamesymbols" / "1234.yaml",
                {
                    "binaries": {
                        "server": {
                            "windows": {
                                "path": "game/bin/win64/server.dll",
                                **hash_file(binary),
                            }
                        }
                    }
                },
            )
            subprocess.run(["git", "-C", str(root), "init", "-b", "main"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.com"], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-m", "snapshot"], check=True, capture_output=True)
            revision = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            report = bootstrap_binary_locks(
                repo_root=root,
                snapshot_revision=revision,
                verify_local_binaries=True,
            )

            self.assertEqual(1, report["game_version_count"])
            self.assertEqual(1, report["binary_count"])
            lock_path = root / "binary_locks" / "1234.json"
            self.assertTrue(lock_path.is_file())
            checked = bootstrap_binary_locks(
                repo_root=root,
                snapshot_revision=revision,
                check=True,
                verify_local_binaries=True,
            )
            self.assertEqual(report, checked)

            lock_path.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(SourceBinaryLockBootstrapError, "drifted"):
                bootstrap_binary_locks(
                    repo_root=root,
                    snapshot_revision=revision,
                    check=True,
                )


if __name__ == "__main__":
    unittest.main()
