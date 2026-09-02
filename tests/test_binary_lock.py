from __future__ import annotations

import copy
import subprocess
import tempfile
import unittest
from pathlib import Path

import binary_lock
from gamesymbol_snapshot_lib.config import load_contract
from tests.gamesymbol_snapshot_test_support import write_binary, write_config


class BinaryLockTests(unittest.TestCase):
    def _fixture(self, root: Path):
        game_version = "1"
        config_path = root / "configs" / f"{game_version}.yaml"
        write_config(
            config_path,
            [
                {
                    "name": "server",
                    "path_windows": "game/bin/win64/server.dll",
                    "path_linux": "game/bin/linuxsteamrt64/libserver.so",
                    "skills": [],
                }
            ],
        )
        download_payload = (
            "downloads:\n"
            "  - tag: '1'\n"
            "    branch: test_branch\n"
            "    manifests:\n"
            "      '100': '200'\n"
            "      '101': '201'\n"
        ).encode()
        (root / "download.yaml").write_bytes(download_payload)
        binary_root = root / "bin" / game_version
        write_binary(binary_root / "server" / "server.dll", b"windows-binary")
        write_binary(binary_root / "server" / "libserver.so", b"linux-binary")
        contract = load_contract(
            config_path,
            game_version,
            root / "bin",
            artifactdir=root / "bin_artifacts",
        )
        return game_version, contract, download_payload, binary_root

    def test_build_write_load_and_verify_are_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            game_version, contract, download_payload, binary_root = self._fixture(root)
            document = binary_lock.build_binary_lock_from_root(
                game_version=game_version,
                download_payload=download_payload,
                binary_targets=contract.binary_targets,
                binary_root=binary_root,
            )
            lock_path = root / "binary_locks" / f"{game_version}.json"
            binary_lock.write_binary_lock(lock_path, document)

            context = binary_lock.load_binary_lock(
                lock_path,
                game_version=game_version,
                download_payload=download_payload,
                binary_targets=contract.binary_targets,
            )

            self.assertEqual(document, context.document)
            self.assertEqual(binary_lock.canonical_json_bytes(document), context.raw_bytes)
            self.assertEqual("sha256:" + binary_lock.sha256_bytes(context.raw_bytes), context.sha256)
            self.assertEqual(document["binaries"], binary_lock.verify_binary_root(context.document, binary_root))
            self.assertEqual(
                {
                    "app_id": "730",
                    "branch": "test_branch",
                    "manifests": {"100": "200", "101": "201"},
                    "os": "all-platform",
                },
                document["download"],
            )

    def test_rejects_download_target_and_binary_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            game_version, contract, download_payload, binary_root = self._fixture(root)
            document = binary_lock.build_binary_lock_from_root(
                game_version=game_version,
                download_payload=download_payload,
                binary_targets=contract.binary_targets,
                binary_root=binary_root,
            )

            drifted_download = download_payload.replace(b"'200'", b"'999'")
            with self.assertRaisesRegex(binary_lock.BinaryLockError, "download identity mismatch"):
                binary_lock.validate_binary_lock(
                    document,
                    game_version=game_version,
                    download_payload=drifted_download,
                    binary_targets=contract.binary_targets,
                )

            forged = copy.deepcopy(document)
            forged["binaries"]["server"]["windows"]["path"] = "game/bin/win64/client.dll"
            with self.assertRaisesRegex(binary_lock.BinaryLockError, "binary target mismatch"):
                binary_lock.validate_binary_lock(
                    forged,
                    game_version=game_version,
                    download_payload=download_payload,
                    binary_targets=contract.binary_targets,
                )

            (binary_root / "server" / "server.dll").write_bytes(b"corrupt-binary")
            with self.assertRaisesRegex(binary_lock.BinaryLockError, "binary identity mismatch"):
                binary_lock.verify_binary_root(document, binary_root)

    def test_loads_lock_from_immutable_git_blob(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            game_version, contract, download_payload, binary_root = self._fixture(root)
            document = binary_lock.build_binary_lock_from_root(
                game_version=game_version,
                download_payload=download_payload,
                binary_targets=contract.binary_targets,
                binary_root=binary_root,
            )
            lock_path = root / "binary_locks" / f"{game_version}.json"
            binary_lock.write_binary_lock(lock_path, document)
            subprocess.run(["git", "-C", str(root), "init", "-b", "main"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.com"], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-m", "source"], check=True, capture_output=True)
            source_sha = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            lock_path.write_text("{}\n", encoding="utf-8")

            context = binary_lock.load_binary_lock_from_revision(
                repo_root=root,
                revision=source_sha,
                game_version=game_version,
                download_payload=download_payload,
                binary_targets=contract.binary_targets,
            )

            self.assertEqual(document, context.document)


if __name__ == "__main__":
    unittest.main()
