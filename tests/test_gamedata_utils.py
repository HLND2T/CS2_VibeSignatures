import json
import tempfile
import unittest
from pathlib import Path

import gamedata_utils


class TestJsoncPreservingSave(unittest.TestCase):
    def _write_temp_jsonc(self, content: str) -> Path:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        path = Path(temp_dir.name) / "gamedata.jsonc"
        path.write_text(content, encoding="utf-8")
        return path

    def _load_clean_json(self, content: str) -> object:
        return json.loads(gamedata_utils.strip_jsonc_comments(content))

    def test_save_jsonc_preserves_comments_and_replaces_only_changed_string(self) -> None:
        original = (
            "{\n"
            "    // keep file comment\n"
            "    \"CEntityInstance::AcceptInput\": {\n"
            "        // keep platform comment\n"
            "        \"windows\": \"old sig\", // keep trailing comment\n"
            "        \"linux\": \"same sig\"\n"
            "    }\n"
            "}\n"
        )
        path = self._write_temp_jsonc(original)

        data = gamedata_utils.load_jsonc(path)
        data["CEntityInstance::AcceptInput"]["windows"] = "new sig"

        gamedata_utils.save_jsonc(path, data)

        updated = path.read_text(encoding="utf-8")
        expected = original.replace("\"old sig\"", "\"new sig\"")
        self.assertEqual(expected, updated)
        self.assertEqual(data, self._load_clean_json(updated))

    def test_save_jsonc_preserves_block_comments_and_comment_like_string_content(self) -> None:
        original = (
            "{\n"
            "    \"url\": \"https://example.test/a//b/*not-comment*/\",\n"
            "    /* keep block comment */\n"
            "    \"value\": 1\n"
            "}\n"
        )
        path = self._write_temp_jsonc(original)

        data = gamedata_utils.load_jsonc(path)
        data["value"] = 2

        gamedata_utils.save_jsonc(path, data)

        updated = path.read_text(encoding="utf-8")
        expected = original.replace("\"value\": 1", "\"value\": 2")
        self.assertEqual(expected, updated)
        self.assertEqual(data, self._load_clean_json(updated))

    def test_save_jsonc_replaces_nested_integer_without_reformatting_siblings(self) -> None:
        original = (
            "{\n"
            "    \"$schema\": \"schema.json\",\n"
            "    \"csgo\": {\n"
            "        \"Offsets\": {\n"
            "            \"Foo\": {\n"
            "                \"win64\": 1,\n"
            "                \"linuxsteamrt64\": 2 // keep linux comment\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        path = self._write_temp_jsonc(original)

        data = gamedata_utils.load_jsonc(path)
        data["csgo"]["Offsets"]["Foo"]["win64"] = 3

        gamedata_utils.save_jsonc(path, data)

        updated = path.read_text(encoding="utf-8")
        expected = original.replace("\"win64\": 1", "\"win64\": 3")
        self.assertEqual(expected, updated)
        self.assertEqual(data, self._load_clean_json(updated))

    def test_save_jsonc_falls_back_to_plain_json_for_new_key(self) -> None:
        original = (
            "{\n"
            "    // this comment cannot be preserved when adding a key\n"
            "    \"existing\": 1\n"
            "}\n"
        )
        path = self._write_temp_jsonc(original)

        data = gamedata_utils.load_jsonc(path)
        data["added"] = True

        gamedata_utils.save_jsonc(path, data)

        updated = path.read_text(encoding="utf-8")
        self.assertNotIn("// this comment cannot be preserved", updated)
        self.assertEqual(data, json.loads(updated))
        self.assertTrue(updated.endswith("\n"))

    def test_save_jsonc_uses_supplied_original_content(self) -> None:
        original = (
            "{\n"
            "    // supplied source comment\n"
            "    \"value\": \"old\"\n"
            "}\n"
        )
        path = self._write_temp_jsonc("{\"value\":\"seed\"}\n")

        data = {"value": "new"}
        gamedata_utils.save_jsonc(path, data, original_content=original)

        updated = path.read_text(encoding="utf-8")
        expected = original.replace("\"old\"", "\"new\"")
        self.assertEqual(expected, updated)
        self.assertEqual(data, self._load_clean_json(updated))


if __name__ == "__main__":
    unittest.main()
