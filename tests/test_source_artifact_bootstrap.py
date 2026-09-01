import json
import tempfile
import unittest
from pathlib import Path

import yaml

from gamesymbol_snapshot_lib.operations import pack_snapshot
from ida_analyze_util import canonical_symbol_yaml_bytes
from source_artifact_bootstrap import (
    SourceArtifactBootstrapError,
    _reject_casefold_collisions,
    bootstrap_source_artifacts,
)
from tests.gamesymbol_snapshot_test_support import write_binary, write_config, write_yaml


class BootstrapWorkspace:
    def __init__(self, root: Path):
        self.root = root
        self.gamever = "14199"
        self.config = root / "configs" / f"{self.gamever}.yaml"
        self.snapshot = root / "gamesymbols" / f"{self.gamever}.yaml"
        self.bindir = root / "bin"
        self.seed_artifacts = root / "seed_artifacts"
        self.destination = root / "bin_artifacts"
        write_config(
            self.config,
            [
                {
                    "name": "server",
                    "path_windows": "game/bin/win64/server.dll",
                    "skills": [
                        {
                            "name": "find-Example",
                            "platform": "windows",
                            "expected_output": ["Example.{platform}.yaml"],
                        }
                    ],
                    "symbols": [{"name": "Example", "category": "func", "platform": "windows"}],
                }
            ],
        )
        write_yaml(
            self.seed_artifacts / self.gamever / "server" / "Example.windows.yaml",
            {"func_sig": "AA ?? CC", "func_rva": "0x10", "func_name": "Example"},
        )
        write_binary(self.bindir / self.gamever / "server" / "server.dll")
        pack_snapshot(
            self.gamever,
            self.bindir,
            self.config,
            self.snapshot,
            artifactdir=self.seed_artifacts,
        )


class SourceArtifactBootstrapTests(unittest.TestCase):
    def test_materializes_only_snapshot_payload_and_records_stable_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = BootstrapWorkspace(Path(temporary))
            private_yaml = workspace.bindir / workspace.gamever / "server" / "Example.windows.yaml"
            write_yaml(private_yaml, {"func_name": "PrivateDrift", "func_rva": "0x999"})
            report_path = workspace.root / "bootstrap-report.json"

            result = bootstrap_source_artifacts(
                repo_root=workspace.root,
                artifact_root=workspace.destination,
                report_path=report_path,
            )

            artifact = workspace.destination / workspace.gamever / "server" / "Example.windows.yaml"
            self.assertEqual(
                canonical_symbol_yaml_bytes(
                    {"func_sig": "AA ?? CC", "func_rva": "0x10", "func_name": "Example"},
                    category="func",
                ),
                artifact.read_bytes(),
            )
            self.assertEqual("PrivateDrift", yaml.safe_load(private_yaml.read_text())["func_name"])
            self.assertEqual(1, result["game_version_count"])
            self.assertEqual(1, result["file_count"])
            self.assertTrue(result["aggregate_inventory_sha256"].startswith("sha256:"))
            self.assertEqual(result, json.loads(report_path.read_text(encoding="utf-8")))

    def test_check_mode_leaves_destination_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = BootstrapWorkspace(Path(temporary))

            result = bootstrap_source_artifacts(
                repo_root=workspace.root,
                artifact_root=workspace.destination,
                publish=False,
            )

            self.assertFalse(result["published"])
            self.assertFalse(workspace.destination.exists())

    def test_rejects_noncanonical_snapshot_without_partial_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = BootstrapWorkspace(Path(temporary))
            workspace.snapshot.write_bytes(b"\n" + workspace.snapshot.read_bytes())

            with self.assertRaises(Exception):
                bootstrap_source_artifacts(repo_root=workspace.root, artifact_root=workspace.destination)

            self.assertFalse(workspace.destination.exists())
            self.assertEqual([], list(workspace.root.glob(".bin_artifacts.bootstrap-*")))

    def test_requires_one_snapshot_for_every_configured_gamever(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = BootstrapWorkspace(Path(temporary))
            write_config(workspace.root / "configs" / "14200.yaml", [])

            with self.assertRaisesRegex(SourceArtifactBootstrapError, "missing snapshots: 14200"):
                bootstrap_source_artifacts(repo_root=workspace.root, artifact_root=workspace.destination)

    def test_rejects_existing_destination_and_casefold_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = BootstrapWorkspace(Path(temporary))
            workspace.destination.mkdir()

            with self.assertRaisesRegex(SourceArtifactBootstrapError, "already exists"):
                bootstrap_source_artifacts(repo_root=workspace.root, artifact_root=workspace.destination)

        with self.assertRaisesRegex(SourceArtifactBootstrapError, "casefold collision"):
            _reject_casefold_collisions(
                ["14199/server/A.windows.yaml", "14199/Server/a.windows.yaml"],
                label="artifact path",
            )


if __name__ == "__main__":
    unittest.main()
