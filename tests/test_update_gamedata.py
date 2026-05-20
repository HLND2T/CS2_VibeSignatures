import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import update_gamedata


class TestLoadAllYamlData(unittest.TestCase):
    def test_load_all_yaml_data_skips_symbol_on_non_matching_platform(self) -> None:
        config = {
            "modules": [
                {
                    "name": "engine",
                    "symbols": [
                        {"name": "CommonGlobal", "category": "gv"},
                        {
                            "name": "WindowsOnlyGlobal",
                            "category": "gv",
                            "platform": "windows",
                        },
                    ],
                }
            ]
        }

        with TemporaryDirectory() as temp_dir:
            engine_dir = Path(temp_dir) / "14141" / "engine"
            engine_dir.mkdir(parents=True)
            (engine_dir / "CommonGlobal.windows.yaml").write_text(
                "gv_name: CommonGlobal\ngv_va: '0x180100000'\n",
                encoding="utf-8",
            )
            (engine_dir / "CommonGlobal.linux.yaml").write_text(
                "gv_name: CommonGlobal\ngv_va: '0x100000'\n",
                encoding="utf-8",
            )
            (engine_dir / "WindowsOnlyGlobal.windows.yaml").write_text(
                "gv_name: WindowsOnlyGlobal\ngv_va: '0x180200000'\n",
                encoding="utf-8",
            )

            yaml_data, missing_symbols = update_gamedata.load_all_yaml_data(
                config,
                temp_dir,
                "14141",
                ["windows", "linux"],
                debug=True,
            )

        self.assertIn("windows", yaml_data["WindowsOnlyGlobal"])
        self.assertNotIn("linux", yaml_data["WindowsOnlyGlobal"])
        self.assertFalse(
            any(
                item["name"] == "WindowsOnlyGlobal" and item["platform"] == "linux"
                for item in missing_symbols
            )
        )


if __name__ == "__main__":
    unittest.main()
