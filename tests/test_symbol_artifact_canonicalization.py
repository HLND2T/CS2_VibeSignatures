from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

import ida_analyze_util as util


class SymbolArtifactCanonicalizationTests(unittest.TestCase):
    def test_function_bytes_use_source2_field_order_and_canonical_scalars(self) -> None:
        payload = {
            "func_sig": "aa ? cc",
            "func_size": 32,
            "func_rva": "0X10",
            "func_va": 0x180000010,
            "func_name": "  名称  ",
        }

        raw = util.canonical_symbol_yaml_bytes(payload, category="func")

        self.assertEqual(
            (
                "func_name: 名称\nfunc_va: '0x180000010'\nfunc_rva: '0x10'\nfunc_size: '0x20'\nfunc_sig: AA ?? CC\n"
            ).encode("utf-8"),
            raw,
        )
        self.assertNotIn(b"\r\n", raw)
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))

    def test_source2_vfunc_slot_and_index_contract_is_64_bit(self) -> None:
        normalized = util.normalize_symbol_artifact(
            {
                "vfunc_index": "8",
                "vfunc_offset": 0x40,
                "vtable_name": "IFoo",
                "func_name": "IFoo_Bar",
            },
            category="vfunc",
        )
        self.assertEqual(8, normalized["vfunc_index"])
        self.assertEqual("0x40", normalized["vfunc_offset"])

        for payload in (
            {
                "func_name": "IFoo_Bar",
                "vtable_name": "IFoo",
                "vfunc_offset": 0x40,
                "vfunc_index": 7,
            },
            {
                "func_name": "IFoo_Bar",
                "vtable_name": "IFoo",
                "vfunc_offset": 0x44,
                "vfunc_index": 8,
            },
            {
                "func_name": "IFoo_Bar",
                "vtable_name": "IFoo",
                "vfunc_offset": 0x40,
                "vfunc_index": 8,
                "vfunc_slot_size": 4,
            },
        ):
            with self.subTest(payload=payload), self.assertRaises(util.SymbolArtifactError):
                util.normalize_symbol_artifact(payload, category="vfunc")

    def test_vtable_entries_are_sorted_and_match_x64_pointer_size(self) -> None:
        payload = {
            "vtable_entries": {"1": "0X180002000", 0: 0x180001000},
            "vtable_size": "0x10",
            "vtable_numvfunc": 2,
            "vtable_va": 0x180100000,
            "vtable_symbol": "??_7IFoo@@6B@",
            "vtable_class": "IFoo",
        }

        raw = util.canonical_symbol_yaml_bytes(payload, category="vtable")
        document = yaml.safe_load(raw)

        self.assertEqual([0, 1], list(document["vtable_entries"]))
        self.assertEqual("0x180001000", document["vtable_entries"][0])
        self.assertLess(raw.index(b"  0:"), raw.index(b"  1:"))

        payload["vtable_size"] = "0x18"
        with self.assertRaisesRegex(util.SymbolArtifactError, "vtable_size"):
            util.canonical_symbol_yaml_bytes(payload, category="vtable")

    def test_unknown_fields_invalid_identities_and_wildcard_patch_bytes_fail_closed(self) -> None:
        cases = [
            ({"func_name": "A", "unexpected": 1}, "func"),
            ({"gv_name": " "}, "gv"),
            ({"patch_name": "P", "patch_bytes": "90 ??"}, "patch"),
            ({"struct_name": "S", "offset": 8}, "structmember"),
        ]
        for payload, category in cases:
            with self.subTest(payload=payload), self.assertRaises(util.SymbolArtifactError):
                util.canonical_symbol_yaml_bytes(payload, category=category)

    def test_file_finalizer_is_atomic_and_does_not_rewrite_stable_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "Global.windows.yaml"
            path.write_bytes(b"\xef\xbb\xbfgv_sig: aa ? cc\ngv_name: Global\n")

            changed = util.canonicalize_symbol_yaml_file(path, category="gv")

            self.assertTrue(changed)
            self.assertEqual(b"gv_name: Global\ngv_sig: AA ?? CC\n", path.read_bytes())
            with patch("ida_analyze_util.os.replace") as replace:
                changed_again = util.canonicalize_symbol_yaml_file(path, category="gv")
            self.assertFalse(changed_again)
            replace.assert_not_called()


if __name__ == "__main__":
    unittest.main()
