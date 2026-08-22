import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from gamesymbol_metadata import (
    MetadataGenerationError,
    extract_alias_subset,
    generate_metadata,
    normalize_alias_list,
)


class TestNormalizeAliasList(unittest.TestCase):
    def test_none_is_empty(self) -> None:
        self.assertEqual([], normalize_alias_list(None))

    def test_string_becomes_single_element_list(self) -> None:
        self.assertEqual(["Foo::Bar"], normalize_alias_list("Foo::Bar"))

    def test_list_filters_non_strings_and_empty(self) -> None:
        self.assertEqual(["a", "c"], normalize_alias_list(["a", "", 3, None, "c"]))

    def test_non_list_non_string_is_empty(self) -> None:
        self.assertEqual([], normalize_alias_list(42))


class TestExtractAliasSubset(unittest.TestCase):
    def test_extracts_only_aliased_symbols(self) -> None:
        raw = {
            "modules": [
                {
                    "name": "engine",
                    "path_windows": "game/bin/win64/engine.dll",
                    "skills": [{"name": "find-a"}],
                    "symbols": [
                        {"name": "FuncA", "category": "func", "alias": ["FuncA::Real"]},
                        {"name": "FuncB", "category": "func"},
                    ],
                },
                {"name": "no_symbols", "skills": [{"name": "find-b"}]},
            ]
        }
        self.assertEqual(
            {"modules": [{"name": "engine", "symbols": [{"name": "FuncA", "alias": ["FuncA::Real"]}]}]},
            extract_alias_subset(raw),
        )

    def test_ignores_invalid_entries(self) -> None:
        raw = {
            "modules": [
                {"name": ""},
                "not-a-mapping",
                {
                    "name": "engine",
                    "symbols": [{"name": "A", "alias": ["x"]}, {"name": ""}, "bad"],
                },
            ]
        }
        self.assertEqual(
            {"modules": [{"name": "engine", "symbols": [{"name": "A", "alias": ["x"]}]}]},
            extract_alias_subset(raw),
        )

    def test_missing_modules_is_empty(self) -> None:
        self.assertEqual({"modules": []}, extract_alias_subset({}))

    def test_string_alias_normalized_to_list(self) -> None:
        raw = {"modules": [{"name": "m", "symbols": [{"name": "s", "alias": "SingleAlias"}]}]}
        self.assertEqual(
            {"modules": [{"name": "m", "symbols": [{"name": "s", "alias": ["SingleAlias"]}]}]},
            extract_alias_subset(raw),
        )


class TestGenerateMetadata(unittest.TestCase):
    def test_writes_parseable_metadata(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            config.write_text(
                yaml.safe_dump(
                    {"modules": [{"name": "engine", "symbols": [{"name": "FuncA", "alias": ["Real"]}]}]},
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            output = root / "gamesymbols" / "1.metadata.yaml"
            generate_metadata("1", config, output)
            parsed = yaml.safe_load(output.read_text(encoding="utf-8"))
            self.assertEqual(
                {"modules": [{"name": "engine", "symbols": [{"name": "FuncA", "alias": ["Real"]}]}]},
                parsed,
            )

    def test_rejects_non_mapping_config(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "config.yaml"
            config.write_text("- just\n- a\n- list\n", encoding="utf-8")
            output = root / "1.metadata.yaml"
            with self.assertRaises(MetadataGenerationError):
                generate_metadata("1", config, output)


if __name__ == "__main__":
    unittest.main()
