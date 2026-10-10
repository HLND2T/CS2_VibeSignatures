import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import vdf

from gamedata_contract import discover_generator_modules
from update_gamedata import _seed_output_root


class TestCS2ACGamedata(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        contracts = discover_generator_modules(root / "gamedata-generators")
        self.contract = next((item for item in contracts if item.directory == "cs2ac"), None)
        self.assertIsNotNone(self.contract, "CS2AC must be discovered as an enabled generator")
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)
        self.path = self.output / "gamedata/cs2ac.games.txt"
        self.path.parent.mkdir()

    def run_update(self, sections, data, aliases=None, platforms=("windows", "linux"), debug=True, libraries=None):
        self.path.write_text(vdf.dumps({"Games": {"csgo": sections}}, pretty=True), encoding="utf-8-sig")
        result = self.contract.module.update(data, libraries or {}, platforms, self.output, aliases or {}, debug)
        raw = self.path.read_text(encoding="utf-8-sig")
        return result, vdf.loads(raw)["Games"]["csgo"], raw

    def test_discovery_and_static_seed(self):
        self.assertEqual("CS2AC", self.contract.name)
        self.assertEqual(("gamedata/cs2ac.games.txt",), self.contract.output_paths)
        self.assertEqual((), self.contract.download_sources)
        _seed_output_root([self.contract], self.output)
        for source, target in self.contract.static_sources:
            self.assertEqual(
                (self.contract.source_dir / source).read_bytes(),
                (self.output / self.contract.directory / target).read_bytes(),
            )
        self.assertTrue((self.output / "cs2ac/gamedata/cs2ac.games.txt").is_file())

    def test_signatures_aliases_and_offsets_on_both_platforms(self):
        sections = {
            "Signatures": {
                "Function": {"library": "server", "windows": "old", "linux": "old"},
                "Global": {"library": "server", "windows": "old", "linux": "old"},
                "Owner::Method": {"windows": "old", "linux": "old"},
            },
            "Offsets": {"Virtual": {}, "Member": {}},
        }
        data = {
            "Canonical": {"library": "server", "windows": {"func_sig": "48 ?? AB"}, "linux": {"func_sig": "55 ?? CD"}},
            "Global": {"library": "server", "windows": {"gv_sig": "49 ??"}, "linux": {"gv_sig": "4C ??"}},
            "Owner_Method": {"library": "server", "windows": {"func_sig": "AA"}, "linux": {"func_sig": "BB"}},
            "Virtual": {"windows": {"vfunc_index": 0, "struct_member_offset": 99}, "linux": {"vfunc_index": 42}},
            "Member": {"windows": {"struct_member_offset": 72}, "linux": {"struct_member_offset": 80}},
        }
        result, output, raw = self.run_update(
            sections, data, {"Function": "Canonical"}, libraries={"Owner_Method": "server"}
        )
        self.assertEqual((10, 0), result[:2])
        self.assertEqual(10, len(result[2]))
        self.assertEqual([], result[3])
        self.assertEqual(r"\x48\x2A\xAB", output["Signatures"]["Function"]["windows"])
        self.assertEqual(r"\x55\x2A\xCD", output["Signatures"]["Function"]["linux"])
        self.assertEqual(r"\x49\x2A", output["Signatures"]["Global"]["windows"])
        self.assertEqual(r"\x4C\x2A", output["Signatures"]["Global"]["linux"])
        self.assertEqual({"windows": "0", "linux": "42"}, output["Offsets"]["Virtual"])
        self.assertEqual({"windows": "72", "linux": "80"}, output["Offsets"]["Member"])
        self.assertNotIn(r"\\x", raw)

    def test_missing_data_preserves_values_and_reports_reasons(self):
        entries = {
            "UnknownLibrary": {"windows": "keep", "linux": "keep"},
            "WrongLibrary": {"library": "server", "windows": "keep", "linux": "keep"},
            "Missing": {"library": "server", "windows": "keep", "linux": "keep"},
            "Incomplete": {"library": "server", "windows": "keep", "linux": "keep"},
        }
        data = {
            "WrongLibrary": {"library": "engine", "windows": {"func_sig": "AA"}},
            "Incomplete": {"library": "server", "windows": {"func_rva": 100}},
            "Offset": {"windows": {"func_rva": 100}},
        }
        sections = {"Signatures": entries, "Offsets": {"Offset": {"windows": "7", "linux": "8"}}}
        result, output, _ = self.run_update(sections, data)
        self.assertEqual(sections, output)
        self.assertEqual((0, 10), result[:2])
        self.assertEqual([], result[2])
        self.assertEqual(10, len(result[3]))
        for diagnostic in result[3]:
            self.assertTrue(diagnostic["reason"])
            self.assertIn(diagnostic["platform"], ("windows", "linux"))

    def test_single_platform_and_debug_disabled(self):
        sections = {
            "Signatures": {"Function": {"library": "server", "windows": "old", "linux": "keep"}},
            "Offsets": {"Missing": {"windows": "7"}},
        }
        data = {"Function": {"library": "server", "windows": {"func_sig": "AA"}, "linux": {"func_sig": "BB"}}}
        result, output, _ = self.run_update(sections, data, platforms=("windows",), debug=False)
        self.assertEqual((1, 1, [], []), result)
        self.assertEqual(r"\xAA", output["Signatures"]["Function"]["windows"])
        self.assertEqual("keep", output["Signatures"]["Function"]["linux"])


if __name__ == "__main__":
    unittest.main()
