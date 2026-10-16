from __future__ import annotations

import hashlib
import unittest

import yaml

from gamesymbol_snapshot_lib.anchor_drift import accepted_anchor_drift, anchor_only_drift, format_anchor_drift
from ida_analyze_util import canonical_symbol_yaml_bytes

# Each fixture carries the category's full optional field matrix -- anchor fields
# and policy switches alike -- so a subtest can mutate one value in place instead
# of adding a key, which would be rejected as a resized payload.
GV_PAYLOAD = {
    "gv_name": "gpGlobals",
    "gv_va": "0x182226f08",
    "gv_rva": "0x2226f08",
    "gv_sig": "48 89 15 ?? ?? ?? ?? 48 89 42 ??",
    "gv_sig_va": "0x180b7f32c",
    "gv_inst_offset": 0,
    "gv_inst_length": 7,
    "gv_inst_disp": 3,
    "gv_sig_allow_across_function_boundary": True,
}

VFUNC_PAYLOAD = {
    "func_name": "CClientInput_CreateMove",
    "func_va": "0x180b6b580",
    "func_rva": "0xb6b580",
    "func_size": "0x109",
    "func_sig": "48 89 5C 24 ?? 48 89 7C 24 ??",
    "vtable_name": "CClientInput",
    "vfunc_offset": "0x40",
    "vfunc_index": 8,
    "vfunc_slot_size": 8,
    "vfunc_sig": "48 FF 60 40 CC CC 48 89 5C 24 ??",
    "vfunc_sig_disp": 0,
    "vfunc_sig_max_match": 1,
    "vfunc_sig_allow_across_function_boundary": True,
}

STRUCT_PAYLOAD = {
    "struct_name": "CClientInput",
    "member_name": "m_viewangles",
    "offset": "0x688",
    "size": 8,
    "offset_sig": "F2 0F 11 86 ?? ?? ?? ?? 89 86 ?? ?? ?? ??",
    "offset_sig_disp": 0,
    "offset_sig_max_match": 1,
    "offset_sig_allow_across_function_boundary": True,
}

FUNC_PAYLOAD = {
    "func_name": "CCSPlayerController_Respawn",
    "func_va": "0x180b6b000",
    "func_rva": "0xb6b000",
    "func_size": "0x80",
    "func_sig": "48 89 5C 24 ?? 57 48 83 EC ??",
    "func_sig_allow_across_function_boundary": True,
    "func_sig_resolve_jmp_thunk": True,
    "func_sig_skip_degenerate": True,
}

PATCH_PAYLOAD = {
    "patch_name": "OnServerVoiceData_IsPlayingDemo_Callee",
    "patch_va": "0x180b456a7",
    "patch_rva": "0xb456a7",
    "patch_sig": "FF 90 50 01 00 00 84 C0 74 ??",
    "patch_sig_disp": 0,
    "patch_bytes": "31 C0 90",
}

VTABLE_PAYLOAD = {
    "vtable_class": "CClientInput",
    "vtable_symbol": "??_7CClientInput@@6B@",
    "vtable_va": "0x181000000",
    "vtable_rva": "0x1000000",
    "vtable_size": "0x10",
    "vtable_numvfunc": 2,
    "pointer_size": 8,
    "vtable_entries": {0: "0x180b6b000", 1: "0x180b6b100"},
}


def canonical(payload: dict) -> bytes:
    return canonical_symbol_yaml_bytes(payload)


class AnchorOnlyDriftTests(unittest.TestCase):
    NUMERIC_ANCHOR_CASES = (
        (GV_PAYLOAD, "gv_sig", ("gv_sig_va", "gv_inst_offset", "gv_inst_length", "gv_inst_disp")),
        (VFUNC_PAYLOAD, "vfunc_sig", ("vfunc_sig_disp",)),
        (STRUCT_PAYLOAD, "offset_sig", ("offset_sig_disp",)),
    )

    def assert_drift(self, payload: dict, overrides: dict, accepted: bool) -> None:
        expected = canonical(payload)
        actual = canonical({**payload, **overrides})
        self.assertNotEqual(expected, actual)
        changed = anchor_only_drift(expected, actual)
        if accepted:
            self.assertEqual(set(overrides), set(changed or {}))
        else:
            self.assertIsNone(changed)

    def test_global_anchor_fields_drift(self):
        for field, value in (
            ("gv_sig", "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ??"),
            ("gv_sig_va", "0x180d0b0bb"),
            ("gv_inst_offset", 4),
            ("gv_inst_length", 10),
            ("gv_inst_disp", 2),
        ):
            with self.subTest(field=field):
                self.assert_drift(GV_PAYLOAD, {field: value}, accepted=True)

    def test_global_resolved_facts_and_policy_stay_pinned(self):
        for overrides in (
            {"gv_va": "0x182226f10", "gv_rva": "0x2226f10"},
            {"gv_name": "gpOtherGlobals"},
            {"gv_sig_allow_across_function_boundary": False},
        ):
            with self.subTest(overrides=overrides):
                self.assert_drift(GV_PAYLOAD, overrides, accepted=False)

    def test_vfunc_anchor_fields_drift(self):
        for field, value in (
            ("vfunc_sig", "FF 90 40 00 00 00 8B 3B"),
            ("vfunc_sig_disp", 6),
        ):
            with self.subTest(field=field):
                self.assert_drift(VFUNC_PAYLOAD, {field: value}, accepted=True)

    def test_vfunc_resolved_facts_and_policy_stay_pinned(self):
        for overrides in (
            {"vfunc_offset": "0x48", "vfunc_index": 9},
            {"func_va": "0x180b6b590", "func_rva": "0xb6b590"},
            {"func_size": "0x110"},
            {"func_sig": "48 89 5C 24 ?? 55 48 83 EC ??"},
            {"vtable_name": "CClientInputOther"},
            {"vfunc_sig_max_match": 2},
            {"vfunc_sig_allow_across_function_boundary": False},
        ):
            with self.subTest(overrides=overrides):
                self.assert_drift(VFUNC_PAYLOAD, overrides, accepted=False)

    def test_struct_member_anchor_fields_drift(self):
        for field, value in (
            ("offset_sig", "89 46 ?? 89 56 ?? 0F 84 ?? ?? ?? ??"),
            ("offset_sig_disp", 3),
        ):
            with self.subTest(field=field):
                self.assert_drift(STRUCT_PAYLOAD, {field: value}, accepted=True)

    def test_struct_member_resolved_facts_and_policy_stay_pinned(self):
        for overrides in (
            {"offset": "0x690"},
            {"size": 4},
            {"struct_name": "CClientInputOther"},
            {"member_name": "m_viewangles_other"},
            {"offset_sig_max_match": 2},
            {"offset_sig_allow_across_function_boundary": False},
        ):
            with self.subTest(overrides=overrides):
                self.assert_drift(STRUCT_PAYLOAD, overrides, accepted=False)

    def test_categories_without_an_anchor_spec_stay_byte_exact(self):
        for payload, overrides in (
            (FUNC_PAYLOAD, {"func_sig": "48 89 5C 24 ?? 57 48 83 EC 20"}),
            (PATCH_PAYLOAD, {"patch_sig": "FF 90 50 01 00 00 84 C0 75 ??"}),
            (PATCH_PAYLOAD, {"patch_sig_disp": 2}),
            (VTABLE_PAYLOAD, {"vtable_entries": {0: "0x180b6b000", 1: "0x180b6b200"}}),
        ):
            with self.subTest(overrides=overrides):
                self.assert_drift(payload, overrides, accepted=False)

    def test_missing_resolved_fact_fails_closed(self):
        # Without the resolved address or slot the signature is the only truth, so
        # the tolerant path must never apply.
        for payload, dropped, signature in (
            (GV_PAYLOAD, ("gv_va", "gv_rva"), "gv_sig"),
            (VFUNC_PAYLOAD, ("vfunc_offset", "vfunc_index"), "vfunc_sig"),
            (STRUCT_PAYLOAD, ("offset",), "offset_sig"),
        ):
            with self.subTest(dropped=dropped):
                stripped = {key: value for key, value in payload.items() if key not in dropped}
                self.assert_drift(stripped, {signature: "90 90"}, accepted=False)

    def test_incoherent_global_anchor_fails_closed(self):
        # The 4-byte displacement operand must stay inside the anchored instruction.
        for overrides in (
            {"gv_inst_disp": 4},
            {"gv_inst_length": 6},
        ):
            with self.subTest(overrides=overrides):
                self.assert_drift(GV_PAYLOAD, overrides, accepted=False)

    def test_zero_numeric_anchor_fields_are_valid(self):
        # The remaining numeric anchors are already zero in their fixture, and a
        # zero-length anchored instruction is incoherent by construction.
        for field, zero in (("gv_sig_va", "0x0"), ("gv_inst_disp", 0)):
            with self.subTest(field=field):
                self.assert_drift(GV_PAYLOAD, {field: zero}, accepted=True)

    def test_optional_numeric_anchor_fields_can_be_omitted(self):
        for payload, signature, fields in (
            (GV_PAYLOAD, "gv_sig", ("gv_inst_disp",)),
            (VFUNC_PAYLOAD, "vfunc_sig", ("vfunc_sig_disp",)),
            (STRUCT_PAYLOAD, "offset_sig", ("offset_sig_disp",)),
        ):
            with self.subTest(signature=signature):
                stripped = {key: value for key, value in payload.items() if key not in fields}
                self.assert_drift(stripped, {signature: "90 90"}, accepted=True)

    def test_invalid_numeric_anchor_fails_closed(self):
        for payload, _signature, fields in self.NUMERIC_ANCHOR_CASES:
            expected = canonical(payload)
            for field in fields:
                for value in (None, True, -1, "", "not-an-offset", "-0x1"):
                    with self.subTest(field=field, value=value):
                        actual = yaml.safe_dump({**payload, field: value}).encode("utf-8")
                        self.assertIsNone(anchor_only_drift(expected, actual))
                        self.assertIsNone(anchor_only_drift(actual, expected))

    def test_unchanged_null_numeric_anchor_with_signature_drift_fails_closed(self):
        for payload, signature, fields in self.NUMERIC_ANCHOR_CASES:
            for field in fields:
                with self.subTest(field=field):
                    nulled = {**payload, field: None}
                    expected = yaml.safe_dump(nulled).encode("utf-8")
                    actual = yaml.safe_dump({**nulled, signature: "90 90"}).encode("utf-8")
                    self.assertIsNone(anchor_only_drift(expected, actual))

    def test_resized_payload_fails_closed(self):
        expected = canonical(VFUNC_PAYLOAD)
        actual = canonical({key: value for key, value in VFUNC_PAYLOAD.items() if key != "vfunc_sig_disp"})
        self.assertIsNone(anchor_only_drift(expected, actual))

    def test_unparseable_payload_fails_closed(self):
        expected = canonical(GV_PAYLOAD)
        for actual in (b"\xff\n", b"- 1\n", b"gv_name: [unclosed\n", b"1: 2\n"):
            with self.subTest(actual=actual):
                self.assertIsNone(anchor_only_drift(expected, actual))

    def test_identical_payload_is_not_drift(self):
        expected = canonical(GV_PAYLOAD)
        self.assertIsNone(anchor_only_drift(expected, expected))


class AcceptedAnchorDriftTests(unittest.TestCase):
    GLOBAL_KEY = "server/G.windows.yaml"
    FUNC_KEY = "server/A.windows.yaml"

    def setUp(self):
        self.expected_blobs = {self.GLOBAL_KEY: canonical(GV_PAYLOAD), self.FUNC_KEY: canonical(FUNC_PAYLOAD)}
        self.actual_blobs = dict(self.expected_blobs)
        self.unreadable: set[str] = set()

    @staticmethod
    def _fingerprints(blobs: dict[str, bytes]) -> dict[str, tuple[int, str]]:
        return {key: (len(raw), f"sha256:{hashlib.sha256(raw).hexdigest()}") for key, raw in blobs.items()}

    def _accepted(self) -> dict[str, dict] | None:
        def read(blobs: dict[str, bytes], key: str) -> bytes | None:
            return None if key in self.unreadable else blobs.get(key)

        return accepted_anchor_drift(
            self._fingerprints(self.expected_blobs),
            self._fingerprints(self.actual_blobs),
            read_expected=lambda key: read(self.expected_blobs, key),
            read_actual=lambda key: read(self.actual_blobs, key),
        )

    def _drift_the_global(self) -> None:
        self.actual_blobs[self.GLOBAL_KEY] = canonical({**GV_PAYLOAD, "gv_sig_va": "0x180d0b0bb"})

    def test_identical_inventory_reports_no_drift(self):
        self.assertIsNone(self._accepted())

    def test_anchor_only_difference_is_reported(self):
        self._drift_the_global()
        drift = self._accepted()
        self.assertEqual({self.GLOBAL_KEY}, set(drift or {}))
        self.assertEqual("gv_sig_va 0x180b7f32c -> 0x180d0b0bb", format_anchor_drift(drift[self.GLOBAL_KEY]))

    def test_one_non_anchor_difference_fails_the_whole_inventory(self):
        self._drift_the_global()
        self.actual_blobs[self.FUNC_KEY] = canonical({**FUNC_PAYLOAD, "func_rva": "0xb6b004"})
        self.assertIsNone(self._accepted())

    def test_key_set_change_fails_closed(self):
        self.actual_blobs["server/Extra.windows.yaml"] = canonical(FUNC_PAYLOAD)
        self.assertIsNone(self._accepted())

    def test_unreadable_payload_fails_closed(self):
        self._drift_the_global()
        self.assertIsNotNone(self._accepted())
        self.unreadable = {self.GLOBAL_KEY}
        self.assertIsNone(self._accepted())


if __name__ == "__main__":
    unittest.main()
