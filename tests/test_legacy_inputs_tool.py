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
from release_workflow_lib.hashing import canonical_json_bytes, sha256_bytes

import pages_legacy_input as pli

REPO_ROOT = Path(__file__).resolve().parents[1]
GAMESYMBOL_SHA = "a" * 64
GAMESYMBOL_BYTES = b'{"schemaVersion":3}\n'


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


class ExtractorTests(unittest.TestCase):
    def test_extracts_only_the_declared_gamedata_subtree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            payload = source / "gamedata" / "14178b" / "Plugin" / "data.jsonc"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b'{"gamever":"14178b"}\n')
            unrelated = source / "bin_artifacts" / "14178b" / "server"
            unrelated.mkdir(parents=True)
            (unrelated / "Symbol.yaml").write_text("func_name: Symbol\n", encoding="utf-8", newline="\n")
            archive = root / "gamedata-14178b.7z"
            _create_archive(source, archive)

            destination = root / "extracted"
            legacy_tool._extract_version(archive, destination, "14178b")
            extracted = destination / "gamedata" / "14178b"
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
                legacy_tool._extract_version(archive, root / "out", "14178b")

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

    def test_cross_check_reports_differences(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extracted = root / "extracted"
            reference = root / "reference"
            extracted_file = extracted / "Plugin" / "data.jsonc"
            reference_file = reference / "14178b" / "Plugin" / "data.jsonc"
            for target in (extracted_file, reference_file):
                target.parent.mkdir(parents=True)
                target.write_bytes(b"same")
            self.assertEqual([], legacy_tool._cross_check(extracted, reference, "14178b"))
            reference_file.write_bytes(b"different")
            self.assertEqual(1, len(legacy_tool._cross_check(extracted, reference, "14178b")))


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


class SelectTests(unittest.TestCase):
    def _namespace(self, root: Path, index: dict) -> argparse.Namespace:
        worktree = root / "archive"
        gamesymbol_bytes = GAMESYMBOL_BYTES
        digest = sha256_bytes(gamesymbol_bytes)
        gamesymbol_dir = worktree / "gamesymbols"
        gamesymbol_dir.mkdir(parents=True)
        (gamesymbol_dir / f"14178b.{digest}.json").write_bytes(gamesymbol_bytes)
        gamedata_file = worktree / "gamedata" / "14178b" / "Plugin" / "data.jsonc"
        gamedata_file.parent.mkdir(parents=True)
        gamedata_file.write_bytes(b"payload")
        index_path = root / "index.json"
        index_path.write_bytes(canonical_json_bytes(index))
        sources_path = root / "sources.json"
        sources_path.write_text(json.dumps(_sources_document(["14178b"])), encoding="utf-8")
        return argparse.Namespace(
            sources=str(sources_path),
            reproduced_index=str(index_path),
            archive_root=str(worktree),
            archive_commit="f" * 40,
            source_archive_commit="e" * 40,
            import_base_commit="d" * 40,
            source_commit="c" * 40,
            manifest_out=str(root / "legacy-inputs.json"),
            report=str(root / "report.json"),
        )

    def _index(self, digest: str, *, url: str | None = None, size: int | None = None) -> dict:
        return {
            "schemaVersion": 4,
            "versions": [
                {
                    "gameVersion": "14178b",
                    "url": url or f"14178b.{digest}.json",
                    "sha256": digest,
                    "size": size if size is not None else len(GAMESYMBOL_BYTES),
                    "snapshotSchemaVersion": 5,
                    "fileCount": 1,
                    "lastPublishTime": "2026-08-31T10:18:36Z",
                }
            ],
        }

    def test_builds_a_valid_pinned_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            digest = sha256_bytes(b'{"schemaVersion":3}\n')
            args = self._namespace(root, self._index(digest))
            legacy_tool.select(args)
            manifest = pli.parse_legacy_inputs(Path(args.manifest_out).read_bytes(), "manifest")
            self.assertEqual("f" * 40, manifest["archiveCommit"])
            self.assertEqual(["14178b"], [item["gameVersion"] for item in manifest["gamesymbols"]["selected"]])
            self.assertEqual(["14178b"], [item["gameVersion"] for item in manifest["gamedata"]["versions"]])

    def test_rejects_a_selected_url_absent_from_the_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._namespace(root, self._index("b" * 64))
            with self.assertRaises(legacy_tool.LegacyInputToolError):
                legacy_tool.select(args)


class AssembleCommitTests(unittest.TestCase):
    def _repository(self, root: Path) -> Path:
        repository = root / "worktree"
        repository.mkdir()
        _git(repository.parent, "init", "-q", str(repository))
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
            imported_root = root / "imported" / "14178b"
            payload = imported_root / "Plugin" / "data.jsonc"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"payload")

            first = legacy_tool._assemble_archive_commit(
                worktree=repository,
                imported={"14178b": imported_root},
                candidate_ref="refs/heads/candidate",
            )
            self.assertEqual(b"payload", (repository / "gamedata" / "14178b" / "Plugin" / "data.jsonc").read_bytes())
            self.assertEqual(b"baseline", next((repository / "gamesymbols").iterdir()).read_bytes())
            self.assertEqual(first, _git(repository, "rev-parse", "refs/heads/candidate"))

            second = legacy_tool._assemble_archive_commit(
                worktree=repository,
                imported={"14178b": imported_root},
                candidate_ref="refs/heads/candidate",
            )
            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
