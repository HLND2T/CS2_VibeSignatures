from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from release_bundle import _create_archive
from release_workflow_lib.hashing import canonical_json_bytes, inventory_sha256, sha256_bytes

import pages_legacy_input as pli

REPO_ROOT = Path(__file__).resolve().parents[1]
GAME_VERSION = "14178b"


def _load_tool():
    spec = importlib.util.spec_from_file_location("legacy_inputs_tool", REPO_ROOT / "pages" / "legacy_inputs_tool.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["legacy_inputs_tool"] = module
    spec.loader.exec_module(module)
    return module


legacy_tool = _load_tool()


def _git(cwd: Path, *arguments: str) -> str:
    result = subprocess.run(["git", *arguments], cwd=cwd, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def _sources_document(game_versions: list[str], excluded: list[dict] | None = None) -> dict:
    return {
        "schemaVersion": 1,
        "releases": [
            {
                "tag": version,
                "releaseId": 100,
                "assetId": 200,
                "assetName": f"gamedata-{version}.7z",
                "assetSize": 300,
                "sha256": "9" * 64,
                "apiDigest": None,
            }
            for version in sorted(game_versions, key=pli._version_key)
        ],
        "excluded": excluded or [],
    }


def _dataset(game_version: str, file_count: int = 1) -> dict:
    return {
        "schemaVersion": 3,
        "source": {
            "gameVersion": game_version,
            "snapshotSchemaVersion": 5,
            "fileCount": file_count,
            "lastPublishTime": "2026-08-31T10:18:36Z",
        },
        "binaries": {},
        "modules": [],
        "records": [{} for _ in range(file_count)],
    }


class ExtractorTests(unittest.TestCase):
    def test_extracts_only_the_declared_gamedata_subtree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            payload = source / "gamedata" / GAME_VERSION / "Plugin" / "data.jsonc"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b'{"gamever":"14178b"}\n')
            unrelated = source / "bin_artifacts" / GAME_VERSION / "server"
            unrelated.mkdir(parents=True)
            (unrelated / "Symbol.yaml").write_text("func_name: Symbol\n", encoding="utf-8", newline="\n")
            archive = root / "gamedata-14178b.7z"
            _create_archive(source, archive)

            destination = root / "extracted"
            legacy_tool._extract_version(archive, destination, GAME_VERSION)
            extracted = destination / "gamedata" / GAME_VERSION
            self.assertEqual(b'{"gamever":"14178b"}\n', (extracted / "Plugin" / "data.jsonc").read_bytes())
            self.assertFalse((destination / "bin_artifacts").exists())

    def test_rejects_an_archive_without_the_declared_subtree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / "other").mkdir(parents=True)
            (source / "other" / "data.txt").write_text("x", encoding="utf-8")
            archive = root / "gamedata-14178b.7z"
            _create_archive(source, archive)
            with self.assertRaises(legacy_tool.LegacyInputToolError):
                legacy_tool._extract_version(archive, root / "out", GAME_VERSION)

    def test_classifies_nanazip_directory_entries(self) -> None:
        output = (
            "Path = gamedata\\14178b\\Plugin\r\nSize = 0\r\nAttributes = D\r\n\r\n"
            "Path = gamedata\\14178b\\Plugin\\data.jsonc\r\nSize = 5\r\nAttributes = A\r\n\r\n"
        )
        self.assertEqual({"gamedata/14178b/Plugin"}, legacy_tool._directory_paths(output))

    def test_enforces_entry_and_byte_limits(self) -> None:
        with self.assertRaises(legacy_tool.LegacyInputToolError):
            legacy_tool._enforce_limits([{"path": "a", "size": 1}] * (legacy_tool.MAX_ARCHIVE_ENTRIES + 1))
        with self.assertRaises(legacy_tool.LegacyInputToolError):
            legacy_tool._enforce_limits([{"path": "a", "size": legacy_tool.MAX_EXTRACTED_BYTES + 1}])

    def test_cross_check_reports_both_sides(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release = root / "release"
            tracked = root / "tracked"
            release_file = release / "Plugin" / "data.jsonc"
            tracked_file = tracked / GAME_VERSION / "Plugin" / "data.jsonc"
            for target in (release_file, tracked_file):
                target.parent.mkdir(parents=True)
                target.write_bytes(b"same")
            self.assertEqual([], legacy_tool._cross_check(release, tracked, GAME_VERSION))
            tracked_file.write_bytes(b"different")
            differences = legacy_tool._cross_check(release, tracked, GAME_VERSION)
            self.assertEqual(1, len(differences))
            self.assertEqual(f"gamedata/{GAME_VERSION}/Plugin/data.jsonc", differences[0]["path"])
            self.assertIsNotNone(differences[0]["releaseSha256"])
            self.assertIsNotNone(differences[0]["trackedSha256"])
            self.assertNotEqual(differences[0]["releaseSha256"], differences[0]["trackedSha256"])


class SourcesTests(unittest.TestCase):
    def test_loads_the_repository_sources_mapping(self) -> None:
        document = legacy_tool._load_sources(legacy_tool.DEFAULT_SOURCES)
        self.assertEqual(14, len(document["releases"]))
        self.assertTrue(all(asset["assetName"].endswith(".7z") for asset in document["releases"]))

    def test_rejects_unsorted_release_tags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sources.json"
            document = _sources_document(["14178", "14178b"])
            document["releases"].reverse()
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(legacy_tool.LegacyInputToolError):
                legacy_tool._load_sources(path)


class ContentSourceTests(unittest.TestCase):
    def _repository(self, root: Path) -> Path:
        repository = root / "source"
        repository.mkdir()
        _git(root, "init", "-q", str(repository))
        _git(repository, "config", "user.name", "test")
        _git(repository, "config", "user.email", "test@example.invalid")
        (repository / "gamedata" / GAME_VERSION / "Plugin").mkdir(parents=True)
        (repository / "gamedata" / GAME_VERSION / "Plugin" / "data.jsonc").write_bytes(b"payload")
        _git(repository, "add", "--all")
        _git(repository, "commit", "-q", "-m", "source")
        return repository

    def test_accepts_a_clean_worktree_at_the_declared_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(Path(temporary))
            legacy_tool._verify_content_source(repository, _git(repository, "rev-parse", "HEAD"))

    def test_rejects_a_mismatched_commit_and_a_dirty_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self._repository(Path(temporary))
            with self.assertRaises(legacy_tool.LegacyInputToolError):
                legacy_tool._verify_content_source(repository, "0" * 40)
            (repository / "gamedata" / GAME_VERSION / "Plugin" / "data.jsonc").write_bytes(b"dirty")
            with self.assertRaises(legacy_tool.LegacyInputToolError):
                legacy_tool._verify_content_source(repository, _git(repository, "rev-parse", "HEAD"))


class SelectTests(unittest.TestCase):
    def _archive_repository(self, root: Path, body: bytes) -> tuple[Path, str, dict]:
        repository = root / "archive"
        repository.mkdir()
        _git(root, "init", "-q", str(repository))
        _git(repository, "config", "user.name", "test")
        _git(repository, "config", "user.email", "test@example.invalid")
        digest = sha256_bytes(body)
        (repository / "gamesymbols").mkdir()
        (repository / "gamesymbols" / f"{GAME_VERSION}.{digest}.json").write_bytes(body)
        (repository / "gamedata" / GAME_VERSION / "Plugin").mkdir(parents=True)
        (repository / "gamedata" / GAME_VERSION / "Plugin" / "data.jsonc").write_bytes(b"payload")
        _git(repository, "add", "--all")
        _git(repository, "commit", "-q", "-m", "archive")
        commit = _git(repository, "rev-parse", "HEAD")
        index = {
            "schemaVersion": 4,
            "versions": [
                {
                    "gameVersion": GAME_VERSION,
                    "url": f"{GAME_VERSION}.{digest}.json",
                    "sha256": digest,
                    "size": len(body),
                    "snapshotSchemaVersion": 5,
                    "fileCount": 1,
                    "lastPublishTime": "2026-08-31T10:18:36Z",
                }
            ],
        }
        return repository, commit, index

    def _namespace(self, root: Path, repository: Path, commit: str, index: dict) -> argparse.Namespace:
        from release_workflow_lib.hashing import file_inventory

        index_path = root / "index.json"
        index_path.write_bytes(canonical_json_bytes(index))
        sources_path = root / "sources.json"
        sources_path.write_text(json.dumps(_sources_document([GAME_VERSION])), encoding="utf-8")
        archive_report = root / "archive-report.json"
        archive_report.write_bytes(
            canonical_json_bytes(
                {
                    "archiveCommit": commit,
                    "contentSource": {
                        "kind": "release-assets",
                        "commit": None,
                        "subtree": "gamedata",
                        "inventorySha256": inventory_sha256(file_inventory(repository / "gamedata")),
                        "selectionReason": "release assets",
                        "differences": [],
                    },
                }
            )
        )
        return argparse.Namespace(
            sources=str(sources_path),
            reproduced_index=str(index_path),
            archive_root=str(repository),
            archive_report=str(archive_report),
            archive_commit=commit,
            source_archive_commit="e" * 40,
            import_base_commit="d" * 40,
            source_commit="c" * 40,
            manifest_out=str(root / "legacy-inputs.json"),
            report=str(root / "report.json"),
        )

    def test_builds_a_valid_pinned_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, commit, index = self._archive_repository(root, canonical_json_bytes(_dataset(GAME_VERSION)))
            legacy_tool.select(self._namespace(root, repository, commit, index))
            manifest = pli.parse_legacy_inputs((root / "legacy-inputs.json").read_bytes(), "manifest")
            self.assertEqual(commit, manifest["archiveCommit"])
            self.assertEqual(["14178b"], [item["gameVersion"] for item in manifest["gamesymbols"]["selected"]])
            self.assertEqual("release-assets", manifest["importProvenance"]["gamedataSource"]["kind"])

    def test_rejects_an_archive_commit_that_does_not_match_the_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, commit, index = self._archive_repository(root, canonical_json_bytes(_dataset(GAME_VERSION)))
            namespace = self._namespace(root, repository, commit, index)
            namespace.archive_commit = "0" * 40
            with self.assertRaises(legacy_tool.LegacyInputToolError):
                legacy_tool.select(namespace)

    def test_rejects_a_snapshot_whose_body_is_not_indexable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy_body = b'{"schemaVersion":2,"source":{"gameVersion":"14178b"}}'
            repository, commit, index = self._archive_repository(root, legacy_body)
            with self.assertRaises(legacy_tool.LegacyInputToolError):
                legacy_tool.select(self._namespace(root, repository, commit, index))
            self.assertFalse((root / "legacy-inputs.json").exists())

    def test_rejects_a_body_that_disagrees_with_the_index_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, commit, index = self._archive_repository(
                root, canonical_json_bytes(_dataset(GAME_VERSION, file_count=2))
            )
            index["versions"][0]["fileCount"] = 1
            with self.assertRaises(legacy_tool.LegacyInputToolError):
                legacy_tool.select(self._namespace(root, repository, commit, index))


class AssembleCommitTests(unittest.TestCase):
    def _repository(self, root: Path) -> Path:
        repository = root / "worktree"
        repository.mkdir()
        _git(root, "init", "-q", str(repository))
        _git(repository, "config", "user.name", "test")
        _git(repository, "config", "user.email", "test@example.invalid")
        (repository / "gamesymbols").mkdir()
        baseline_name = f"14178b.{'a' * 64}.json"
        (repository / "gamesymbols" / baseline_name).write_bytes(b"baseline")
        _git(repository, "add", "--all")
        _git(repository, "commit", "-q", "-m", "baseline")
        return repository

    def test_adds_gamedata_preserves_baseline_and_reuses_the_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = self._repository(root)
            imported_root = root / "imported" / GAME_VERSION
            payload = imported_root / "Plugin" / "data.jsonc"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"payload")

            first = legacy_tool._assemble_archive_commit(
                worktree=repository,
                imported={GAME_VERSION: imported_root},
                candidate_ref="refs/heads/candidate",
            )
            self.assertEqual(
                b"payload", (repository / "gamedata" / GAME_VERSION / "Plugin" / "data.jsonc").read_bytes()
            )
            self.assertEqual(b"baseline", next((repository / "gamesymbols").iterdir()).read_bytes())
            self.assertEqual(first, _git(repository, "rev-parse", "refs/heads/candidate"))

            second = legacy_tool._assemble_archive_commit(
                worktree=repository,
                imported={GAME_VERSION: imported_root},
                candidate_ref="refs/heads/candidate",
            )
            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
