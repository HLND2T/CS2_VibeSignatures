import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from gamesymbol_snapshot_lib.codec import SCHEMA_VERSION
from gamesymbol_snapshot_lib.operations import pack_snapshot
from gamesymbol_store import (
    DirectorySymbolStore,
    InvalidSymbolPathError,
    SnapshotCanonicalError,
    SnapshotConfigMismatchError,
    SnapshotGameVersionMismatchError,
    SnapshotSymbolStore,
    SymbolNotFoundError,
)
from tests.gamesymbol_snapshot_test_support import module, skill, write_binary, write_config, write_yaml


class StoreWorkspace:
    def __init__(self, root: Path):
        self.root = root
        self.config = root / "config.yaml"
        self.bindir = root / "bin"
        self.gamever = "14199"
        outputs = [
            "ITest_vtable.{platform}.yaml",
            "ITest_First.{platform}.yaml",
            "ITest_Second.{platform}.yaml",
        ]
        write_config(self.config, [module("server", [skill("find-vtable", outputs)], linux=False)])
        self._write_symbols()
        write_binary(self.bindir / self.gamever / "server/server.dll")
        self.snapshot = root / "candidate" / f"{self.gamever}.yaml"
        pack_snapshot(self.gamever, self.bindir, self.config, self.snapshot)

    def _write_symbols(self) -> None:
        root = self.bindir / self.gamever / "server"
        write_yaml(root / "ITest_vtable.windows.yaml", {"vtable_size": "0x18", "vtable_numvfunc": 2})
        write_yaml(root / "ITest_First.windows.yaml", {"func_name": "ITest_First", "vfunc_index": 0})
        write_yaml(root / "ITest_Second.windows.yaml", {"func_name": "ITest_Second", "vfunc_index": 1})

    def open(self) -> SnapshotSymbolStore:
        return SnapshotSymbolStore.open(
            self.snapshot,
            expected_game_version=self.gamever,
            config_path=self.config,
        )


class TestSnapshotSymbolStore(unittest.TestCase):
    def test_exact_glob_order_and_payload_copy(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = StoreWorkspace(Path(temp_dir))
            store = workspace.open()

            payload = store.require("server", "ITest_First.windows.yaml")
            payload["vfunc_index"] = 99

            self.assertTrue(store.contains("server", "ITest_First.windows.yaml"))
            self.assertEqual(0, store.require("server", "ITest_First.windows.yaml")["vfunc_index"])
            self.assertEqual(
                [
                    "server/ITest_First.windows.yaml",
                    "server/ITest_Second.windows.yaml",
                    "server/ITest_vtable.windows.yaml",
                ],
                [entry.path for entry in store.glob_module("server", "ITest_*.windows.yaml")],
            )
            self.assertTrue(store.candidate_sha256.startswith("sha256:"))
            self.assertEqual(SCHEMA_VERSION, store.schema_version)
            self.assertEqual(2, store.config_digest_version)
            binaries = store.binaries
            self.assertGreater(binaries["server"]["windows"]["size"], 0)
            binaries["server"]["windows"]["size"] = 0
            self.assertGreater(store.binaries["server"]["windows"]["size"], 0)

    def test_missing_and_unsafe_queries_are_typed(self) -> None:
        with TemporaryDirectory() as temp_dir:
            store = StoreWorkspace(Path(temp_dir)).open()

            self.assertIsNone(store.get("server", "Missing.windows.yaml"))
            with self.assertRaises(SymbolNotFoundError):
                store.require("server", "Missing.windows.yaml")
            with self.assertRaises(InvalidSymbolPathError):
                store.get("../server", "ITest_First.windows.yaml")
            with self.assertRaises(InvalidSymbolPathError):
                store.glob_module("server", "**/*.yaml")

    def test_rejects_game_config_and_canonical_mismatches(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = StoreWorkspace(Path(temp_dir))
            with self.assertRaises(SnapshotGameVersionMismatchError):
                SnapshotSymbolStore.open(
                    workspace.snapshot,
                    expected_game_version="14200",
                    config_path=workspace.config,
                )

            changed_config = workspace.root / "changed.yaml"
            write_config(changed_config, [module("server", [skill("changed", ["Other.{platform}.yaml"])])])
            with self.assertRaises(SnapshotConfigMismatchError):
                SnapshotSymbolStore.open(
                    workspace.snapshot,
                    expected_game_version=workspace.gamever,
                    config_path=changed_config,
                )

            noncanonical = workspace.root / "noncanonical.yaml"
            noncanonical.write_bytes(b"\n" + workspace.snapshot.read_bytes())
            with self.assertRaises(SnapshotCanonicalError):
                SnapshotSymbolStore.open(
                    noncanonical,
                    expected_game_version=workspace.gamever,
                    config_path=workspace.config,
                )

    def test_directory_and_snapshot_backends_have_query_parity(self) -> None:
        with TemporaryDirectory() as temp_dir:
            workspace = StoreWorkspace(Path(temp_dir))
            directory = DirectorySymbolStore(workspace.bindir, workspace.gamever)
            snapshot = workspace.open()

            self.assertEqual(
                [(entry.path, entry.payload) for entry in directory.iter_module("server")],
                [(entry.path, entry.payload) for entry in snapshot.iter_module("server")],
            )
            shutil.rmtree(workspace.bindir / workspace.gamever)
            self.assertEqual(1, snapshot.require("server", "ITest_Second.windows.yaml")["vfunc_index"])


if __name__ == "__main__":
    unittest.main()
