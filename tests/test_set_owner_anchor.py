import unittest
from unittest.mock import AsyncMock, patch

from ida_preprocessor_scripts import _set_owner_anchor as anchor


class SetOwnerAnchorTests(unittest.TestCase):
    def test_rejects_neighbor_and_accepts_owner_handle_comparison(self):
        neighbor = dict(argument_count=1, compares_owner=False, handle_mask=True, handle_shift=True)
        setter = dict(argument_count=2, compares_owner=True, handle_mask=True, handle_shift=True)
        self.assertFalse(anchor.is_owner_setter(neighbor))
        self.assertTrue(anchor.is_owner_setter(setter))
        for field in ("compares_owner", "handle_mask", "handle_shift"):
            self.assertFalse(anchor.is_owner_setter({**setter, field: False}))

    def test_requires_one_semantically_verified_slot(self):
        sites = [dict(insn_va=0x100, vfunc_offset=424), dict(insn_va=0x110, vfunc_offset=424)]
        self.assertEqual(sites, anchor.select_anchors(sites))
        for invalid in ([], sites + [dict(insn_va=0x120, vfunc_offset=432)]):
            with self.assertRaises(ValueError):
                anchor.select_anchors(invalid)

    def test_llm_must_return_verified_current_instruction_and_offset(self):
        sites = [dict(insn_va=0x100, vfunc_offset=424)]

        def result(va=0x100, offset=424):
            return {"found_vcall": [dict(func_name=anchor.SYMBOL, insn_va=hex(va), vfunc_offset=hex(offset))]}

        self.assertEqual([], anchor.validate_result(result(), sites))
        for invalid in (result(va=0x200), result(offset=416), {}, {"found_vcall": result()["found_vcall"] * 2}):
            self.assertTrue(anchor.validate_result(invalid, sites))


class SetOwnerReuseTests(unittest.IsolatedAsyncioTestCase):
    async def test_unique_signature_outside_verified_callsite_is_not_reused(self):
        sites = [dict(insn_va=0x100, vfunc_offset=424)]
        old = dict(vfunc_sig="4C 8B A8 A0 01 00 00", vfunc_offset="0x1a0", vfunc_index=52)
        self.assertFalse(await anchor.can_reuse(AsyncMock(), old, sites))
        old.update(vfunc_offset="0x1a8", vfunc_index=53)
        with patch.object(anchor, "find_signature_matches", new=AsyncMock(return_value=[0x200])):
            self.assertFalse(await anchor.can_reuse(AsyncMock(), old, sites))
        with patch.object(anchor, "find_signature_matches", new=AsyncMock(return_value=[0x100])):
            self.assertTrue(await anchor.can_reuse(AsyncMock(), old, sites))
        with patch.object(anchor, "find_signature_matches", new=AsyncMock(return_value=[0x100, 0x200])):
            self.assertFalse(await anchor.can_reuse(AsyncMock(), old, sites))


class SetOwnerProbeTests(unittest.TestCase):
    def test_live_probe_reads_callee_arguments_and_handle_comparison(self):
        from types import SimpleNamespace as N

        hx = N(
            **{
                name: name
                for name in (
                    "cot_cast",
                    "cot_num",
                    "cot_var",
                    "cot_band",
                    "cot_ushr",
                    "cot_sshr",
                    "cot_ne",
                    "cit_if",
                    "CV_FAST",
                )
            }
        )

        def var(index):
            return N(op=hx.cot_var, v=N(idx=index))

        def num(value):
            return N(op=hx.cot_num, numval=lambda: value)

        mask = N(op=hx.cot_band, x=var(2), y=num(0x1FF))
        shift = N(op=hx.cot_ushr, x=var(2), y=num(9))
        comparison = N(op=hx.cit_if, cif=N(expr=N(op=hx.cot_ne, x=var(1), y=var(2))))

        class Visitor:
            def __init__(self, flags):
                pass

            def apply_to(self, body, parent):
                for expr in body.expressions:
                    self.visit_expr(expr)
                for insn in body.instructions:
                    self.visit_insn(insn)

        hx.ctree_visitor_t = Visitor

        def callee(nargs, instructions):
            return N(
                get_lvars=lambda: [N(is_arg_var=i < nargs) for i in range(3)],
                body=N(expressions=[mask, shift], instructions=instructions),
            )

        bodies = {0x2000: callee(1, []), 0x3000: callee(2, [comparison]), 0x4000: callee(2, [])}
        hx.decompile = bodies.get
        functions = N(get_func=lambda va: N(start_ea=va))
        instructions = {0x1000: ("mov", 416), 0x1007: ("mov", 424), 0x100E: ("mov", 432)}
        idc = N(
            o_displ=4,
            print_insn_mnem=lambda ea: instructions[ea][0],
            get_operand_type=lambda ea, operand: 4,
            get_operand_value=lambda ea, operand: instructions[ea][1],
        )
        modules = dict(ida_funcs=functions, ida_hexrays=hx, idautils=N(FuncItems=lambda va: instructions), idc=idc)
        with patch.dict("sys.modules", modules):
            sites = anchor._probe_sites(0x1000, {52: 0x2000, 53: 0x3000, 54: 0x4000})
        self.assertEqual([0x1007], [site["insn_va"] for site in sites if anchor.is_owner_setter(site["facts"])])
        functions.get_func = lambda va: N(start_ea=va - 1)
        with patch.dict("sys.modules", modules), self.assertRaisesRegex(ValueError, "function entry"):
            anchor._probe_sites(0x1000, {})


class SetOwnerFinderTests(unittest.IsolatedAsyncioTestCase):
    async def test_rejects_old_slot_and_validates_llm_before_generation(self):
        import importlib.util
        from pathlib import Path
        from tempfile import TemporaryDirectory
        import yaml

        spec = importlib.util.spec_from_file_location(
            "set_owner_finder", "ida_preprocessor_scripts/find-CBaseEntity_SetOwner.py"
        )
        finder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(finder)
        sites = [dict(insn_va=0x100, vfunc_offset=424)]
        for reusable in (False, True):
            with self.subTest(reusable=reusable), TemporaryDirectory() as directory:
                old = Path(directory) / "old.yaml"
                old.write_text(yaml.safe_dump(dict(vfunc_index=52)))
                old_map = {"output.yaml": str(old)}
                with (
                    patch.object(finder, "load_anchors", AsyncMock(return_value=sites)),
                    patch.object(finder, "can_reuse", AsyncMock(return_value=reusable)),
                    patch.object(finder, "preprocess_common_skill", AsyncMock(return_value=True)) as common,
                ):
                    result = await finder.preprocess_skill(
                        "session", "find-CBaseEntity_SetOwner", ["output.yaml"], old_map, directory, "linux", 0
                    )
                self.assertTrue(result)
                kwargs = common.call_args.kwargs
                self.assertEqual(old_map if reusable else {}, kwargs["old_yaml_map"])
                self.assertTrue(
                    kwargs["llm_result_validator"](
                        {"found_vcall": [dict(func_name=anchor.SYMBOL, insn_va="0x100", vfunc_offset="0x1a0")]}
                    )
                )
                self.assertEqual(
                    [],
                    kwargs["llm_result_validator"](
                        {"found_vcall": [dict(func_name=anchor.SYMBOL, insn_va="0x100", vfunc_offset="0x1a8")]}
                    ),
                )
        with (
            patch.object(finder, "load_anchors", AsyncMock(side_effect=ValueError("ambiguous"))),
            patch.object(finder, "preprocess_common_skill", AsyncMock()) as common,
        ):
            self.assertFalse(
                await finder.preprocess_skill(
                    "session", "find-CBaseEntity_SetOwner", ["output.yaml"], {}, ".", "linux", 0
                )
            )
            common.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
