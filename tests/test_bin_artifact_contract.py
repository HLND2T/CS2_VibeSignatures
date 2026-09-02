import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from bin_artifact_contract import (
    ArtifactContractError,
    build_game_artifact_inventory,
    validate_repository_artifact_contract,
)
from ida_analyze_util import canonical_symbol_yaml_bytes
from tests.gamesymbol_snapshot_test_support import write_binary, write_config, write_yaml


class BinArtifactContractTests(unittest.TestCase):
    def _workspace(self, root: Path) -> tuple[Path, Path, Path]:
        config = root / "configs" / "1.yaml"
        artifact = root / "bin_artifacts" / "1" / "server" / "Example.windows.yaml"
        write_config(
            config,
            [
                {
                    "name": "server",
                    "path_windows": "game/bin/win64/server.dll",
                    "skills": [{"name": "find", "expected_output": ["Example.{platform}.yaml"]}],
                    "symbols": [{"name": "Example", "category": "func", "platform": "windows"}],
                }
            ],
        )
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(canonical_symbol_yaml_bytes({"func_name": "Example", "func_rva": "0x10"}, category="func"))
        write_binary(root / "bin" / "1" / "server" / "server.dll")
        return config, artifact, root / "bin_artifacts"

    def test_accepts_canonical_required_artifact_and_reports_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config, _artifact, artifact_root = self._workspace(Path(temporary))

            report = build_game_artifact_inventory(
                repo_root=Path(temporary),
                config_path=config,
                game_version="1",
                artifact_root=artifact_root,
                require_tracked=False,
            )

            self.assertEqual(1, report.file_count)
            self.assertTrue(report.inventory_sha256.startswith("sha256:"))

    def test_rejects_extra_yaml_and_noncanonical_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config, artifact, artifact_root = self._workspace(Path(temporary))
            write_yaml(artifact.parent / "Extra.windows.yaml", {"func_name": "Extra"})
            with self.assertRaisesRegex(ArtifactContractError, "extra/stale"):
                build_game_artifact_inventory(
                    repo_root=Path(temporary),
                    config_path=config,
                    game_version="1",
                    artifact_root=artifact_root,
                    require_tracked=False,
                )
            (artifact.parent / "Extra.windows.yaml").unlink()
            artifact.write_bytes(b"func_rva: 0X10\nfunc_name: Example\n")
            with self.assertRaisesRegex(ArtifactContractError, "not canonical"):
                build_game_artifact_inventory(
                    repo_root=Path(temporary),
                    config_path=config,
                    game_version="1",
                    artifact_root=artifact_root,
                    require_tracked=False,
                )

    def test_require_tracked_compares_git_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _artifact, artifact_root = self._workspace(root)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
            report = build_game_artifact_inventory(
                repo_root=root,
                config_path=config,
                game_version="1",
                artifact_root=artifact_root,
                require_tracked=True,
            )
            self.assertEqual(1, report.file_count)

    def test_require_tracked_rejects_canonical_bytes_that_differ_from_git(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, artifact, artifact_root = self._workspace(root)
            self._git_init_and_commit(root)
            source_sha = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            artifact.write_bytes(
                canonical_symbol_yaml_bytes({"func_name": "Example", "func_rva": "0x20"}, category="func")
            )

            with self.assertRaisesRegex(ArtifactContractError, "differs from Git index blob"):
                build_game_artifact_inventory(
                    repo_root=root,
                    config_path=config,
                    game_version="1",
                    artifact_root=artifact_root,
                    require_tracked=True,
                )

            subprocess.run(["git", "add", str(artifact.relative_to(root))], cwd=root, check=True)
            report = build_game_artifact_inventory(
                repo_root=root,
                config_path=config,
                game_version="1",
                artifact_root=artifact_root,
                require_tracked=True,
            )
            self.assertEqual(1, report.file_count)
            with self.assertRaisesRegex(ArtifactContractError, "differs from Git revision blob"):
                build_game_artifact_inventory(
                    repo_root=root,
                    config_path=config,
                    game_version="1",
                    artifact_root=artifact_root,
                    require_tracked=True,
                    git_revision=source_sha,
                )

    def test_require_tracked_rejects_non_regular_git_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, artifact, artifact_root = self._workspace(root)
            self._git_init_and_commit(root)
            subprocess.run(
                ["git", "update-index", "--chmod=+x", str(artifact.relative_to(root))],
                cwd=root,
                check=True,
            )

            with self.assertRaisesRegex(ArtifactContractError, "mode must be 100644"):
                build_game_artifact_inventory(
                    repo_root=root,
                    config_path=config,
                    game_version="1",
                    artifact_root=artifact_root,
                    require_tracked=True,
                )

    def test_rejects_artifact_root_link_before_resolving_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config, _artifact, artifact_root = self._workspace(root)
            target = root / "real-bin-artifacts"
            artifact_root.rename(target)
            try:
                if os.name == "nt":
                    result = subprocess.run(
                        ["cmd", "/c", "mklink", "/J", str(artifact_root), str(target)],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if result.returncode:
                        self.skipTest(f"unable to create a junction on this host: {result.stderr}")
                else:
                    artifact_root.symlink_to(target, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"unable to create an artifact-root link on this host: {exc}")

            with self.assertRaisesRegex(ArtifactContractError, "link/reparse"):
                build_game_artifact_inventory(
                    repo_root=root,
                    config_path=config,
                    game_version="1",
                    artifact_root=artifact_root,
                    require_tracked=False,
                )

    def test_repository_contract_rejects_unconfigured_and_legacy_tracked_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._workspace(root)
            self._git_init_and_commit(root)
            extra = root / "bin_artifacts" / "2" / "server" / "Extra.windows.yaml"
            extra.parent.mkdir(parents=True, exist_ok=True)
            extra.write_bytes(canonical_symbol_yaml_bytes({"func_name": "Extra"}, category="func"))
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "extra"], cwd=root, check=True)
            with self.assertRaisesRegex(ArtifactContractError, "unconfigured GAMEVER"):
                validate_repository_artifact_contract(repo_root=root, game_versions=["1"])

            subprocess.run(["git", "rm", "-q", str(extra.relative_to(root))], cwd=root, check=True)
            legacy = root / "gamesymbols" / "1.yaml"
            legacy.parent.mkdir(parents=True, exist_ok=True)
            legacy.write_text("files: {}\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "legacy"], cwd=root, check=True)
            with self.assertRaisesRegex(ArtifactContractError, "legacy generated outputs"):
                validate_repository_artifact_contract(repo_root=root, game_versions=["1"])

    @staticmethod
    def _git_init_and_commit(root: Path) -> None:
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)


if __name__ == "__main__":
    unittest.main()
