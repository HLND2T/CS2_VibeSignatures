import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bin_artifact_contract import build_game_artifact_inventory
from analysis_config import (
    AnalysisConfigError,
    analysis_config_repo_path,
    analysis_config_sha256,
    default_analysis_config_path,
    read_analysis_config_at_revision,
    resolve_analysis_config,
)


class AnalysisConfigTests(unittest.TestCase):
    def test_repo_path_validates_gamever(self):
        self.assertEqual("configs/14168b.yaml", analysis_config_repo_path("14168b"))
        for value in ("141", "14168/other", "../14168", "14168B", "14168bb"):
            with self.subTest(value=value), self.assertRaises(AnalysisConfigError):
                analysis_config_repo_path(value)

    def test_implicit_path_is_anchored_to_repo_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "configs" / "14168.yaml"
            config.parent.mkdir()
            config.write_bytes(b"modules: []\n")
            with patch("pathlib.Path.cwd", return_value=root.parent):
                resolved = resolve_analysis_config("14168", repo_root=root)
            self.assertEqual(config.resolve(), resolved)
            self.assertEqual(config.resolve(), default_analysis_config_path("14168", repo_root=root))

    def test_explicit_absolute_and_relative_paths_win(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            explicit = root / "scratch.yaml"
            explicit.write_bytes(b"scratch\n")
            missing_default_root = root / "repo"
            with patch("pathlib.Path.cwd", return_value=root):
                self.assertEqual(
                    explicit.resolve(),
                    resolve_analysis_config("14168", "scratch.yaml", repo_root=missing_default_root),
                )
            self.assertEqual(
                explicit.resolve(), resolve_analysis_config("14168", explicit, repo_root=missing_default_root)
            )

    def test_missing_paths_fail_without_fallback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "config.yaml").write_bytes(b"modules: []\n")
            with self.assertRaisesRegex(AnalysisConfigError, "configs.*14168.yaml"):
                resolve_analysis_config("14168", repo_root=root)
            with self.assertRaisesRegex(AnalysisConfigError, "missing.yaml"):
                resolve_analysis_config("14168", root / "missing.yaml", repo_root=root)

    def test_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with self.assertRaisesRegex(AnalysisConfigError, "not a plain file"):
                resolve_analysis_config("14168", root)

    def test_sha256_uses_exact_bytes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.yaml"
            data = b"# comment\r\nmodules: []\r\n"
            path.write_bytes(data)
            self.assertEqual(hashlib.sha256(data).hexdigest(), analysis_config_sha256(path))


class HistoricalAnalysisConfigTests(unittest.TestCase):
    def _git(self, root: Path, *args: str) -> str:
        result = subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True)
        return result.stdout.strip()

    def _commit(self, root: Path, message: str) -> str:
        self._git(root, "add", ".")
        self._git(
            root,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-m",
            message,
        )
        return self._git(root, "rev-parse", "HEAD")

    def test_reads_versioned_then_validated_legacy_fallback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._git(root, "init", "-q")
            legacy = b"modules: []\n# legacy\n"
            (root / "config.yaml").write_bytes(legacy)
            legacy_sha = self._commit(root, "legacy")

            legacy_result = read_analysis_config_at_revision(
                legacy_sha, "14168", allow_legacy_root=True, repo_root=root
            )
            self.assertTrue(legacy_result.used_legacy_root)
            self.assertEqual("config.yaml", legacy_result.repository_path)
            self.assertEqual(legacy, legacy_result.data)

            configs = root / "configs"
            configs.mkdir()
            versioned = b"modules: []\n# versioned\n"
            (configs / "14168.yaml").write_bytes(versioned)
            versioned_sha = self._commit(root, "versioned")
            result = read_analysis_config_at_revision(versioned_sha, "14168", allow_legacy_root=True, repo_root=root)
            self.assertFalse(result.used_legacy_root)
            self.assertEqual("configs/14168.yaml", result.repository_path)
            self.assertEqual(versioned, result.data)
            self.assertEqual(hashlib.sha256(versioned).hexdigest(), result.sha256)

    def test_missing_historical_config_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._git(root, "init", "-q")
            (root / "README.md").write_text("test\n", encoding="utf-8")
            revision = self._commit(root, "empty")
            with self.assertRaisesRegex(AnalysisConfigError, "configs/14168.yaml"):
                read_analysis_config_at_revision(revision, "14168", allow_legacy_root=False, repo_root=root)


class RepositoryMigrationFixtureTests(unittest.TestCase):
    def test_14167_and_14168_configs_validate_source_owned_artifacts(self):
        root = Path(__file__).resolve().parents[1]
        for gamever in ("14167", "14168"):
            with self.subTest(gamever=gamever):
                report = build_game_artifact_inventory(
                    repo_root=root,
                    config_path=root / "configs" / f"{gamever}.yaml",
                    game_version=gamever,
                    artifact_root=root / "bin_artifacts",
                    require_tracked=True,
                )
                self.assertEqual(gamever, report.game_version)
                self.assertGreater(report.file_count, 0)


if __name__ == "__main__":
    unittest.main()
