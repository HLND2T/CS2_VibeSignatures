import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import vdf

from gamedata_contract import expected_inventory_paths, metadata_companion_path
from gamedata_metadata import (
    compute_file_metadata,
    upgrade_file_metadata_v1,
    upgrade_metadata_tree_v1,
    validate_file_metadata,
    write_file_metadata,
)


def _by_name(meta):
    return {entry["name"]: entry for entry in meta["entries"]}


class TestMetadataCompanionPath(unittest.TestCase):
    def test_companion_path(self) -> None:
        self.assertEqual("payload/final.json.metadata.json", metadata_companion_path("payload/final.json"))

    def test_expected_inventory_paths_includes_metadata(self) -> None:
        module = SimpleNamespace(directory="fixture", output_paths=("payload/final.json",))
        paths = expected_inventory_paths([module], "14170")
        self.assertEqual(
            [
                "gamedata/14170/fixture/payload/final.json",
                "gamedata/14170/fixture/payload/final.json.metadata.json",
            ],
            paths,
        )

    def test_legacy_expected_inventory_paths_excludes_metadata(self) -> None:
        module = SimpleNamespace(directory="fixture", output_paths=("payload/final.json",))
        paths = expected_inventory_paths([module], "14170", include_metadata=False)
        self.assertEqual(["gamedata/14170/fixture/payload/final.json"], paths)


class TestJsoncMetadata(unittest.TestCase):
    def test_document_fields_and_vtable_sections_are_not_entries(self) -> None:
        payload = """{
  "$schema": "https://example.invalid/gamedata.schema.json",
  "csgo": {
    "VTables": {
      "CServerSideClient": {"library": "engine2", "windows": "OLD"}
    }
  },
  "citadel": {
    "VTables": {
      "CLuaVM": {"library": "vscript", "linux": "OLD"}
    }
  }
}
"""
        meta = compute_file_metadata(
            before_text=payload,
            after_text=payload,
            rel_path="plugify-plugin-s2sdk/assets/gamedata.jsonc",
            gamever="1",
            yaml_data={},
            alias_to_name_map={},
        )

        self.assertEqual({"CServerSideClient", "CLuaVM"}, set(_by_name(meta)))
        self.assertEqual({"total": 2, "covered": 0, "updated": 0}, meta["summary"])

    def test_three_way_classification(self) -> None:
        before = '{\n  "Changed": {"lib": "server", "windows": "AA", "linux": "BB"},\n  "Same": {"lib": "server", "windows": "CC"},\n  "UpstreamOnly": {"lib": "server", "windows": "DD"}\n}\n'
        after = '{\n  "Changed": {"lib": "server", "windows": "AA2", "linux": "BB"},\n  "Same": {"lib": "server", "windows": "CC"},\n  "UpstreamOnly": {"lib": "server", "windows": "DD"}\n}\n'
        yaml_data = {"Changed": {"library": "server"}, "Same": {"library": "server"}}
        meta = compute_file_metadata(
            before_text=before,
            after_text=after,
            rel_path="fixture/gamedata.jsonc",
            gamever="1",
            yaml_data=yaml_data,
            alias_to_name_map={},
        )
        self.assertEqual({"total": 3, "covered": 2, "updated": 1}, meta["summary"])
        by_name = _by_name(meta)

        self.assertTrue(by_name["Changed"]["covered"])
        self.assertTrue(by_name["Changed"]["updated"])
        self.assertEqual([2], by_name["Changed"]["covered_lines"])
        change = by_name["Changed"]["changes"][0]
        self.assertEqual(["Changed", "windows"], change["path"])
        self.assertEqual("AA", change["before"])
        self.assertEqual("AA2", change["after"])
        self.assertEqual(2, change["line"])

        self.assertTrue(by_name["Same"]["covered"])
        self.assertFalse(by_name["Same"]["updated"])
        self.assertEqual([3], by_name["Same"]["covered_lines"])
        self.assertNotIn("changes", by_name["Same"])

        self.assertFalse(by_name["UpstreamOnly"]["covered"])
        self.assertFalse(by_name["UpstreamOnly"]["updated"])
        self.assertEqual([], by_name["UpstreamOnly"]["covered_lines"])

    def test_line_number_matches_value_line(self) -> None:
        before = '{\n  "Sym": {\n    "windows": "OLD"\n  }\n}\n'
        after = '{\n  "Sym": {\n    "windows": "NEW"\n  }\n}\n'
        meta = compute_file_metadata(
            before_text=before,
            after_text=after,
            rel_path="fixture/gamedata.jsonc",
            gamever="1",
            yaml_data={"Sym": {"library": "server"}},
            alias_to_name_map={},
        )
        change = _by_name(meta)["Sym"]["changes"][0]
        self.assertEqual(3, change["line"])

    def test_covered_unchanged_does_not_emit_changes(self) -> None:
        before = '{"Sym": {"windows": "SAME"}}'
        after = '{"Sym": {"windows": "SAME"}}'
        meta = compute_file_metadata(
            before_text=before,
            after_text=after,
            rel_path="fixture/gamedata.json",
            gamever="1",
            yaml_data={"Sym": {"library": "server"}},
            alias_to_name_map={},
        )
        self.assertEqual({"total": 1, "covered": 1, "updated": 0}, meta["summary"])
        self.assertNotIn("changes", _by_name(meta)["Sym"])
        self.assertEqual([1], _by_name(meta)["Sym"]["covered_lines"])


class TestFlatTxtMetadata(unittest.TestCase):
    def test_flat_key_value_diff_and_line(self) -> None:
        before = "a=1\nb=2\nc=3\n"
        after = "a=1\nb=20\nc=3\n"
        meta = compute_file_metadata(
            before_text=before,
            after_text=after,
            rel_path="fixture/gamedata.txt",
            gamever="1",
            yaml_data={},
            alias_to_name_map={},
        )
        self.assertEqual({"total": 3, "covered": 3, "updated": 1}, meta["summary"])
        by_name = _by_name(meta)
        self.assertTrue(by_name["b"]["covered"])
        self.assertTrue(by_name["b"]["updated"])
        self.assertEqual([2], by_name["b"]["covered_lines"])
        change = by_name["b"]["changes"][0]
        self.assertEqual(["b"], change["path"])
        self.assertEqual("2", change["before"])
        self.assertEqual("20", change["after"])
        self.assertEqual(2, change["line"])
        self.assertFalse(by_name["a"]["updated"])


class TestVdfMetadata(unittest.TestCase):
    def test_vdf_diff_and_line(self) -> None:
        before_data = {
            "Games": {"csgo": {"Signatures": {"Sym": {"library": "server", "windows": "OLD", "linux": "KEEP"}}}}
        }
        after_data = {
            "Games": {"csgo": {"Signatures": {"Sym": {"library": "server", "windows": "NEW", "linux": "KEEP"}}}}
        }
        before = vdf.dumps(before_data, pretty=True)
        after = vdf.dumps(after_data, pretty=True)
        meta = compute_file_metadata(
            before_text=before,
            after_text=after,
            rel_path="fixture/gamedata.txt",
            gamever="1",
            yaml_data={"Sym": {"library": "server"}},
            alias_to_name_map={},
        )
        entry = _by_name(meta)["Sym"]
        self.assertTrue(entry["covered"])
        self.assertTrue(entry["updated"])
        change = entry["changes"][0]
        self.assertEqual("OLD", change["before"])
        self.assertEqual("NEW", change["after"])
        expected_line = next(i for i, line in enumerate(after.splitlines(), 1) if '"windows"' in line)
        self.assertEqual(expected_line, change["line"])
        self.assertIn(expected_line, entry["covered_lines"])

    def test_vdf_covered_lines_include_every_scalar_leaf(self) -> None:
        payload = vdf.dumps(
            {"Games": {"csgo": {"Signatures": {"Sym": {"library": "server", "windows": "AA", "linux": "BB"}}}}},
            pretty=True,
        )
        meta = compute_file_metadata(
            before_text=payload,
            after_text=payload,
            rel_path="fixture/gamedata.txt",
            gamever="1",
            yaml_data={"Sym": {"library": "server"}},
            alias_to_name_map={},
        )

        expected = [
            index
            for index, line in enumerate(payload.splitlines(), 1)
            if any(field in line for field in ('"library"', '"windows"', '"linux"'))
        ]
        self.assertEqual(expected, _by_name(meta)["Sym"]["covered_lines"])


class TestMetadataV2Upgrade(unittest.TestCase):
    def test_upgrade_preserves_v1_diff_and_adds_covered_lines(self) -> None:
        after = '{\n  "Changed": {"windows": "NEW"},\n  "Same": {"windows": "KEEP"}\n}\n'
        source = {
            "schema_version": 1,
            "gamever": "14176",
            "file": "fixture/gamedata.jsonc",
            "summary": {"total": 2, "covered": 2, "updated": 1},
            "entries": [
                {
                    "name": "Changed",
                    "covered": True,
                    "updated": True,
                    "changes": [{"path": ["Changed", "windows"], "before": "OLD", "after": "NEW", "line": 2}],
                },
                {"name": "Same", "covered": True, "updated": False},
            ],
        }

        upgraded = upgrade_file_metadata_v1(source, after_text=after)

        self.assertEqual(2, upgraded["schema_version"])
        self.assertEqual([2], _by_name(upgraded)["Changed"]["covered_lines"])
        self.assertEqual([3], _by_name(upgraded)["Same"]["covered_lines"])
        self.assertEqual(source["entries"][0]["changes"], _by_name(upgraded)["Changed"]["changes"])

    def test_tree_upgrade_validates_every_file_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            valid_payload = root / "fixture" / "valid.json"
            valid_payload.parent.mkdir(parents=True)
            valid_payload.write_text('{"Sym": 1}\n', encoding="utf-8")
            valid_metadata = {
                "schema_version": 1,
                "gamever": "14176",
                "file": "fixture/valid.json",
                "summary": {"total": 1, "covered": 1, "updated": 0},
                "entries": [{"name": "Sym", "covered": True, "updated": False}],
            }
            valid_path = Path(str(valid_payload) + ".metadata.json")
            valid_path.write_text(json.dumps(valid_metadata), encoding="utf-8")
            invalid_path = root / "fixture" / "missing.json.metadata.json"
            invalid_path.write_text(json.dumps({**valid_metadata, "file": "fixture/missing.json"}), encoding="utf-8")

            with self.assertRaises(FileNotFoundError):
                upgrade_metadata_tree_v1(root, gamever="14176")

            self.assertEqual(1, json.loads(valid_path.read_text(encoding="utf-8"))["schema_version"])

    def test_validator_rejects_updated_line_outside_coverage(self) -> None:
        metadata = {
            "schema_version": 2,
            "gamever": "1",
            "file": "fixture/out.json",
            "summary": {"total": 1, "covered": 1, "updated": 1},
            "entries": [{
                "name": "Sym",
                "covered": True,
                "covered_lines": [1],
                "updated": True,
                "changes": [{"path": ["Sym"], "before": 1, "after": 2, "line": 2}],
            }],
        }

        with self.assertRaisesRegex(ValueError, "line is not covered"):
            validate_file_metadata(metadata, after_text="{\n  \"Sym\": 2\n}\n", rel_path="fixture/out.json", gamever="1")


class TestWriteFileMetadata(unittest.TestCase):
    def test_write_is_atomic_json_document(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            metadata_path = Path(temp_dir) / "out.json.metadata.json"
            result = write_file_metadata(
                before_text='{"Sym": {"windows": "OLD"}}',
                after_text='{"Sym": {"windows": "NEW"}}',
                rel_path="fixture/out.json",
                gamever="14170",
                yaml_data={"Sym": {"library": "server"}},
                alias_to_name_map={},
                metadata_path=metadata_path,
            )
            self.assertEqual("14170", result["gamever"])
            document = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(2, document["schema_version"])
            self.assertEqual("fixture/out.json", document["file"])
            self.assertEqual(1, document["summary"]["updated"])


if __name__ == "__main__":
    unittest.main()
