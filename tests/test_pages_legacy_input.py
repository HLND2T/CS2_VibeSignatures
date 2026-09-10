from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import pages_legacy_input as pli
from release_workflow_lib.hashing import canonical_json_bytes, load_json_object, sha256_bytes

FIXTURE_DIRECTORY = Path(__file__).resolve().parent / "fixtures" / "legacy_inputs"
GAMESYMBOL_SHA = "a" * 64


def _manifest(*, gamedata_versions: dict[str, list[dict]]) -> dict:
    ordered = sorted(gamedata_versions, key=pli._version_key)
    primary = ordered[0]
    return {
        "schemaVersion": 1,
        "repository": pli.ALLOWED_REPOSITORY,
        "archiveCommit": "f" * 40,
        "gamesymbols": {
            "files": [{"path": f"gamesymbols/{primary}.{GAMESYMBOL_SHA}.json", "size": 10, "sha256": GAMESYMBOL_SHA}],
            "selected": [
                {
                    "gameVersion": primary,
                    "url": f"{primary}.{GAMESYMBOL_SHA}.json",
                    "sha256": GAMESYMBOL_SHA,
                    "size": 10,
                    "fileCount": 1,
                    "snapshotSchemaVersion": 5,
                    "lastPublishTime": "2026-08-31T10:18:36Z",
                }
            ],
        },
        "gamedata": {"versions": [{"gameVersion": gv, "files": gamedata_versions[gv]} for gv in ordered]},
        "excluded": [],
        "importProvenance": {
            "sourceArchiveCommit": "1" * 40,
            "importBaseCommit": "2" * 40,
            "selectedBasis": {
                "kind": "pre-switch-source-reproduction",
                "sourceCommit": "3" * 40,
                "indexSha256": "e" * 64,
                "indexSize": 10,
            },
            "gamedataSource": {
                "kind": "release-assets",
                "commit": None,
                "subtree": "gamedata",
                "inventorySha256": "c" * 64,
                "selectionReason": "release assets are the sole import source",
                "differences": [],
            },
            "releases": [
                {
                    "tag": gv,
                    "releaseId": 1,
                    "assetId": 2,
                    "assetName": f"gamedata-{gv}.7z",
                    "assetSize": 3,
                    "sha256": "9" * 64,
                    "apiDigest": None,
                }
                for gv in ordered
            ],
        },
    }


def _write_archive(archive_root: Path, version: str, files: dict[str, bytes]) -> list[dict]:
    records = []
    for relative, data in sorted(files.items()):
        target = archive_root / "gamedata" / version / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        records.append({"path": f"gamedata/{version}/{relative}", "size": len(data), "sha256": sha256_bytes(data)})
    return sorted(records, key=lambda item: item["path"])


def _stage(root: Path, manifest: dict, archive_root: Path) -> dict:
    manifest_path = root / "legacy-inputs.json"
    manifest_path.write_bytes(canonical_json_bytes(manifest))
    return pli.stage_legacy_gamedata(
        manifest_path=manifest_path,
        archive_root=archive_root,
        staging_root=root / "staging",
        receipt_path=root / "receipt.json",
    )


class LegacyInputsManifestTests(unittest.TestCase):
    def test_shared_fixtures_match_across_runtimes(self) -> None:
        for path in sorted(FIXTURE_DIRECTORY.glob("*.json")):
            with self.subTest(fixture=path.name):
                raw = path.read_bytes()
                if path.name == "valid.json":
                    pli.parse_legacy_inputs(raw, path.name)
                else:
                    with self.assertRaises(pli.LegacyInputError):
                        pli.parse_legacy_inputs(raw, path.name)

    def test_rejects_structurally_valid_object_with_unknown_key(self) -> None:
        import json

        value = json.loads((FIXTURE_DIRECTORY / "valid.json").read_text(encoding="utf-8"))
        value["extra"] = 1
        with self.assertRaises(pli.LegacyInputError):
            pli._validate_legacy_inputs(value, "inline")

    def test_rejects_duplicate_keys_in_raw_bytes(self) -> None:
        import json

        value = json.loads((FIXTURE_DIRECTORY / "valid.json").read_text(encoding="utf-8"))
        canonical = canonical_json_bytes(value).decode("utf-8")
        duplicated = canonical.replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1')
        self.assertNotEqual(canonical, duplicated)
        with self.assertRaises(pli.LegacyInputError):
            pli.parse_legacy_inputs(duplicated.encode("utf-8"), "inline")

    def test_rejects_non_canonical_line_endings(self) -> None:
        import json

        value = json.loads((FIXTURE_DIRECTORY / "valid.json").read_text(encoding="utf-8"))
        canonical = canonical_json_bytes(value)
        for mutated in (canonical + b"\n", canonical[:-1], canonical.replace(b"\n", b"\r\n")):
            with self.subTest(mutated=mutated[:16]):
                with self.assertRaises(pli.LegacyInputError):
                    pli.parse_legacy_inputs(mutated, "inline")


class LegacyGamedataStagingTests(unittest.TestCase):
    def test_adds_missing_version_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "archive"
            payload = b'{"gamever":"14178b"}\n'
            records = _write_archive(archive, "14178b", {"Plugin/data.jsonc": payload})
            (root / "staging" / "gamedata").mkdir(parents=True)

            receipt = _stage(root, _manifest(gamedata_versions={"14178b": records}), archive)
            self.assertEqual(["14178b"], [item["gameVersion"] for item in receipt["added"]])
            self.assertEqual(payload, (root / "staging" / "gamedata" / "14178b" / "Plugin" / "data.jsonc").read_bytes())
            self.assertEqual(receipt, load_json_object(root / "receipt.json"))
            self.assertEqual(
                canonical_json_bytes(receipt),
                (root / "receipt.json").read_bytes(),
            )

            second = _stage(root, _manifest(gamedata_versions={"14178b": records}), archive)
            self.assertEqual([], second["added"])
            self.assertEqual(["14178b"], second["skipped_existing"])

    def test_preserves_existing_version_without_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "archive"
            records = _write_archive(archive, "14178b", {"Plugin/data.jsonc": b"archive-bytes"})
            existing = root / "staging" / "gamedata" / "14178b" / "Plugin" / "data.jsonc"
            existing.parent.mkdir(parents=True)
            existing.write_bytes(b"local-bytes")

            receipt = _stage(root, _manifest(gamedata_versions={"14178b": records}), archive)
            self.assertEqual([], receipt["added"])
            self.assertEqual(["14178b"], receipt["skipped_existing"])
            self.assertEqual(b"local-bytes", existing.read_bytes())

    def test_rejects_archive_inventory_drift_without_touching_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "archive"
            _write_archive(archive, "14178b", {"Plugin/data.jsonc": b"bytes"})
            (root / "staging" / "gamedata").mkdir(parents=True)
            drifted = [{"path": "gamedata/14178b/Plugin/data.jsonc", "size": 5, "sha256": "0" * 64}]

            with self.assertRaises(pli.LegacyInputError):
                _stage(root, _manifest(gamedata_versions={"14178b": drifted}), archive)
            self.assertEqual([], list((root / "staging" / "gamedata").iterdir()))

    def test_rolls_back_added_versions_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "archive"
            first_gamedata = _write_archive(archive, "14178", {"Plugin/a.jsonc": b"a"})
            second_gamedata = _write_archive(archive, "14178b", {"Plugin/b.jsonc": b"b"})
            staging_gamedata = root / "staging" / "gamedata"
            staging_gamedata.mkdir(parents=True)
            (staging_gamedata / "14178b").write_bytes(b"not-a-directory")

            manifest = _manifest(gamedata_versions={"14178": first_gamedata, "14178b": second_gamedata})
            with self.assertRaises(pli.LegacyInputError):
                _stage(root, manifest, archive)
            self.assertFalse((staging_gamedata / "14178").exists())
            self.assertEqual(b"not-a-directory", (staging_gamedata / "14178b").read_bytes())


if __name__ == "__main__":
    unittest.main()
