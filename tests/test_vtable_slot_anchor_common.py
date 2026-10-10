import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as N
from unittest.mock import AsyncMock, patch

import yaml

from ida_preprocessor_scripts import _vtable_slot_anchor_common as anchor

FIELDS = ["func_name", "func_va", "func_rva", "func_size", "func_sig", "vtable_name", "vfunc_offset", "vfunc_index"]
TARGET = "CSchemaSystem_Target"


def _desired(fields=FIELDS):
    return [(TARGET, list(fields))]


class SelectionTests(unittest.TestCase):
    def test_lowest_twin_slot_handles_distinct_and_folded_twins(self):
        distinct = {21: 0x10, 22: 0x20, 23: 0x30, 24: 0x40}
        self.assertEqual(22, anchor.select_lowest_string_slot(distinct, {0x20, 0x40, 0x999}, 2))
        folded = {21: 0x10, 22: 0x20, 23: 0x30, 24: 0x20}
        self.assertEqual(22, anchor.select_lowest_string_slot(folded, {0x20}, 2))

    def test_twin_slot_count_mismatch_fails_closed(self):
        entries = {22: 0x20, 24: 0x40, 26: 0x60}
        self.assertIsNone(anchor.select_lowest_string_slot(entries, {0x20}, 2))
        self.assertIsNone(anchor.select_lowest_string_slot(entries, {0x20, 0x40, 0x60}, 2))
        self.assertIsNone(anchor.select_lowest_string_slot(entries, set(), 2))

    def test_receiver_vcall_requires_one_aligned_vtable_slot(self):
        entries = {index: 0x1000 + index for index in range(30)}
        self.assertEqual(28, anchor.select_receiver_vcall_slot(entries, [224]))
        self.assertEqual(28, anchor.select_receiver_vcall_slot(entries, [224, 224]))
        for invalid in ([], [224, 232], [225], [-8], [8 * 30], None):
            with self.subTest(offsets=invalid):
                self.assertIsNone(anchor.select_receiver_vcall_slot(entries, invalid))


class _Args:
    def __init__(self, items):
        self._items = items

    def size(self):
        return len(self._items)

    def __getitem__(self, index):
        return self._items[index]


class ReceiverProbeTests(unittest.TestCase):
    def _hexrays(self, statements, argidx=(0,)):
        hx = N(
            **{
                name: name
                for name in ("cot_cast", "cot_var", "cot_num", "cot_ptr", "cot_add", "cot_idx", "cot_asg", "cot_call")
            },
            CV_FAST=0,
        )

        class Visitor:
            def __init__(self, flags):
                pass

            def apply_to(self, body, parent):
                for expr in body:
                    self.visit_expr(expr)

        hx.ctree_visitor_t = Visitor
        hx.decompile = lambda va: N(argidx=list(argidx), body=statements)
        return hx

    @staticmethod
    def _ty(ptr=False, objsize=1, size=8):
        return N(is_ptr=lambda: ptr, get_ptrarr_objsize=lambda: objsize, get_size=lambda: size)

    def _var(self, index):
        return N(op="cot_var", v=N(idx=index), type=self._ty())

    def _num(self, value):
        return N(op="cot_num", numval=lambda: value, type=self._ty())

    def _vtable(self, receiver):
        return N(op="cot_ptr", x=N(op="cot_cast", x=self._var(receiver), type=self._ty()), type=self._ty())

    def _slot(self, receiver, offset):
        # *(*(_QWORD *)receiver + offset)
        address = N(op="cot_add", x=self._vtable(receiver), y=self._num(offset), type=self._ty())
        return N(op="cot_ptr", x=address, type=self._ty())

    def _call(self, callee, receiver):
        return N(op="cot_call", x=callee, a=_Args([self._var(receiver)]), type=self._ty())

    def _probe(self, statements):
        with patch.dict("sys.modules", {"ida_hexrays": self._hexrays(statements)}):
            return anchor._probe_receiver_vcall_offsets(0x1000)

    def test_hoisted_slot_load_is_resolved_and_other_receivers_ignored(self):
        hoisted = N(op="cot_asg", x=self._var(5), y=self._slot(0, 224), type=self._ty())
        statements = [
            self._call(N(op="cot_ptr", x=self._vtable(2), type=self._ty()), receiver=2),
            hoisted,
            self._call(self._var(5), receiver=0),
        ]
        self.assertEqual([224], self._probe(statements))

    def test_inline_and_indexed_slot_forms(self):
        indexed = N(op="cot_idx", x=self._vtable(0), y=self._num(28), type=self._ty(size=8))
        self.assertEqual([224], self._probe([self._call(self._slot(0, 224), receiver=0)]))
        self.assertEqual([224], self._probe([self._call(indexed, receiver=0)]))

    def test_vtable_of_other_object_called_with_receiver_is_ignored(self):
        self.assertEqual([], self._probe([self._call(self._slot(3, 224), receiver=0)]))

    def test_ambiguous_hoisted_variable_is_ignored(self):
        statements = [
            N(op="cot_asg", x=self._var(5), y=self._slot(0, 224), type=self._ty()),
            N(op="cot_asg", x=self._var(5), y=self._slot(0, 232), type=self._ty()),
            self._call(self._var(5), receiver=0),
        ]
        self.assertEqual([], self._probe(statements))


class SkillTests(unittest.IsolatedAsyncioTestCase):
    def _write_vtable(self, directory, entries):
        payload = {"vtable_class": "CSchemaSystem", "vtable_entries": {k: hex(v) for k, v in entries.items()}}
        Path(directory, "CSchemaSystem_vtable.linux.yaml").write_text(yaml.safe_dump(payload), encoding="utf-8")
        return str(Path(directory, f"{TARGET}.linux.yaml"))

    @staticmethod
    def _sig(func_va):
        return {"func_va": func_va, "func_rva": func_va, "func_size": "0xa0", "func_sig": "8B 97 ?? ?? ?? ??"}

    async def test_twin_skill_writes_lowest_slot_yaml(self):
        with TemporaryDirectory() as directory:
            output = self._write_vtable(directory, {22: 0x3AE70, 23: 0x3A100, 24: 0x3AF10})
            session = AsyncMock()
            with (
                patch.object(
                    anchor, "_collect_xref_func_starts_for_string", AsyncMock(return_value={0x3AE70, 0x3AF10})
                ),
                patch.object(
                    anchor,
                    "preprocess_gen_func_sig_via_mcp",
                    AsyncMock(side_effect=lambda **kw: self._sig(kw["func_va"])),
                ),
            ):
                ok = await anchor.preprocess_string_twin_vfunc_skill(
                    session, [output], directory, "linux", 0, TARGET, "CSchemaSystem", "twin", 2, _desired()
                )
            self.assertTrue(ok)
            data = yaml.safe_load(Path(output).read_text(encoding="utf-8"))
            self.assertEqual(FIELDS, list(data))
            self.assertEqual(("0x3ae70", "0xb0", 22), (data["func_va"], data["vfunc_offset"], data["vfunc_index"]))

    async def test_twin_skill_fails_closed_without_writing(self):
        with TemporaryDirectory() as directory:
            output = self._write_vtable(directory, {22: 0x3AE70, 24: 0x3AF10})
            with patch.object(anchor, "_collect_xref_func_starts_for_string", AsyncMock(return_value={0x3AE70})):
                ok = await anchor.preprocess_string_twin_vfunc_skill(
                    AsyncMock(), [output], directory, "linux", 0, TARGET, "CSchemaSystem", "twin", 2, _desired()
                )
            self.assertFalse(ok)
            self.assertFalse(Path(output).exists())

    async def test_receiver_skill_requires_unique_caller_and_writes_slot(self):
        with TemporaryDirectory() as directory:
            output = self._write_vtable(directory, {index: 0x5F000 + index for index in range(30)})
            sig = AsyncMock(side_effect=lambda **kw: self._sig(kw["func_va"]))
            with (
                patch.object(anchor, "_collect_xref_func_starts_for_string", AsyncMock(return_value={0x10, 0x20})),
                patch.object(anchor, "preprocess_gen_func_sig_via_mcp", sig),
            ):
                self.assertFalse(
                    await anchor.preprocess_receiver_vcall_vfunc_skill(
                        AsyncMock(), [output], directory, "linux", 0, TARGET, "CSchemaSystem", "caller", _desired()
                    )
                )
            with (
                patch.object(anchor, "_collect_xref_func_starts_for_string", AsyncMock(return_value={0x7D2B0})),
                patch.object(anchor, "parse_mcp_result", return_value={"result": "[224]"}),
                patch.object(anchor, "preprocess_gen_func_sig_via_mcp", sig),
            ):
                ok = await anchor.preprocess_receiver_vcall_vfunc_skill(
                    AsyncMock(), [output], directory, "linux", 0, TARGET, "CSchemaSystem", "caller", _desired()
                )
            self.assertTrue(ok)
            data = yaml.safe_load(Path(output).read_text(encoding="utf-8"))
            self.assertEqual(
                (hex(0x5F000 + 28), "0xe0", 28), (data["func_va"], data["vfunc_offset"], data["vfunc_index"])
            )

    async def test_unsupported_desired_field_is_rejected(self):
        with TemporaryDirectory() as directory:
            output = self._write_vtable(directory, {22: 0x3AE70, 24: 0x3AF10})
            with (
                patch.object(
                    anchor, "_collect_xref_func_starts_for_string", AsyncMock(return_value={0x3AE70, 0x3AF10})
                ),
                patch.object(
                    anchor,
                    "preprocess_gen_func_sig_via_mcp",
                    AsyncMock(side_effect=lambda **kw: self._sig(kw["func_va"])),
                ),
            ):
                ok = await anchor.preprocess_string_twin_vfunc_skill(
                    AsyncMock(),
                    [output],
                    directory,
                    "linux",
                    0,
                    TARGET,
                    "CSchemaSystem",
                    "twin",
                    2,
                    _desired(FIELDS + ["vfunc_sig"]),
                )
            self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
