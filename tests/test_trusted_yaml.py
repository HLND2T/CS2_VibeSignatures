import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import yaml

import trusted_yaml


class TestTrustedYaml(unittest.TestCase):
    def tearDown(self) -> None:
        trusted_yaml.clear_yaml_file_cache()

    def test_selected_loader_matches_safe_loader_for_yaml_features(self) -> None:
        documents = (
            b"",
            "message: 你好\nitems: &items [one, two]\nalias: *items\n",
            b"\xef\xbb\xbfmessage: bom\n",
        )
        for document in documents:
            with self.subTest(document=document):
                expected = yaml.load(document, Loader=yaml.SafeLoader)
                self.assertEqual(expected, trusted_yaml.load_yaml(document))

        with self.assertRaises(yaml.YAMLError):
            trusted_yaml.load_yaml("invalid: [")

    def test_file_cache_returns_defensive_copies_and_invalidates_on_rewrite(self) -> None:
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "config.yaml"
            path.write_text("value: one\n", encoding="utf-8")
            original_loader = trusted_yaml.load_yaml
            with patch.object(trusted_yaml, "load_yaml", wraps=original_loader) as loader:
                first = trusted_yaml.load_yaml_file(path, cache=True)
                first["value"] = "mutated"
                second = trusted_yaml.load_yaml_file(path, cache=True)
                first_stat = path.stat()
                path.write_text("value: two\n", encoding="utf-8")
                os.utime(path, ns=(first_stat.st_atime_ns, first_stat.st_mtime_ns + 1_000_000))
                third = trusted_yaml.load_yaml_file(path, cache=True)

        self.assertEqual("one", second["value"])
        self.assertEqual("two", third["value"])
        self.assertEqual(2, loader.call_count)


class TestRepositoryYamlCompatibility(unittest.TestCase):
    def test_selected_loader_matches_safe_loader_for_repository_fixtures(self) -> None:
        fixture_paths = (
            Path("configs/14172.yaml"),
            Path("gamesymbols/14172.yaml"),
            Path("ida_preprocessor_scripts/references/client/CAM_Command_CommandHandler.windows.yaml"),
        )
        for fixture_path in fixture_paths:
            with self.subTest(fixture=fixture_path):
                raw = fixture_path.read_bytes()
                self.assertEqual(yaml.load(raw, Loader=yaml.SafeLoader), trusted_yaml.load_yaml(raw))


if __name__ == "__main__":
    unittest.main()
