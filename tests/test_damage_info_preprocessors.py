"""Exercise VScript binding discovery without an IDA installation."""

import json
import re
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from tests.ida_preprocessor_test_support import load_module, py_eval_payload


FINDER = load_module(
    Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts/find-CreateDamageInfo.py",
    "damage_info_factory_finder",
)


def _run_binding_scan(*, linux=False, named=True, wrong_descriptor=False, clobbered=False, early_call=False):
    source, help_ea, name_ea, array_ea, descriptor, callback, wrapper = range(0x1000, 0x8000, 0x1000)
    reg, mem, imm = 1, 2, 3

    def operand(kind=0, value=0):
        return SimpleNamespace(type=kind, addr=value, value=value, reg=value)

    instructions = [
        ("lea", operand(reg, 0), operand(mem, help_ea)),
        ("mov", operand(mem, descriptor + 0x10), operand(reg, 0)),
        ("movddup" if linux else "lea", operand(reg, 1), operand(mem, array_ea if linux else name_ea)),
        ("lea", operand(reg, 0), operand(mem, wrapper)),
        ("mov", operand(mem, descriptor + 0x38), operand(reg, 0)),
        ("lea", operand(reg, 0), operand(mem, callback)),
    ]
    if clobbered:
        instructions.append(("xor", operand(reg, 0), operand(reg, 0)))
    if early_call:
        instructions.append(("call", operand(), operand()))
    instructions.extend(
        [
            ("mov", operand(mem, descriptor + (0x48 if wrong_descriptor else 0x40)), operand(reg, 0)),
            ("call", operand(), operand()),
        ]
    )
    strings = {help_ea: FINDER.HELP_STRING, name_ea: "CreateDamageInfo" if named else "DestroyDamageInfo"}

    class String:
        ea = help_ea

        def __str__(self):
            return FINDER.HELP_STRING

    class Insn:
        def get_canon_feature(self):
            return 1

    def decode(insn, ea):
        _, dst, src = instructions[ea - source]
        insn.ops = [dst, src]
        return 1

    def get_func(ea):
        if source <= ea < source + len(instructions):
            return SimpleNamespace(start_ea=source, end_ea=source + len(instructions))
        if ea in (callback, wrapper):
            return SimpleNamespace(start_ea=ea, end_ea=ea + 32)
        return None

    modules = {
        "idaapi": SimpleNamespace(
            o_reg=reg, o_mem=mem, o_imm=imm, CF_CHG1=1, insn_t=Insn, decode_insn=decode, get_func=get_func
        ),
        "ida_bytes": SimpleNamespace(is_loaded=lambda ea: ea == array_ea, get_qword=lambda ea: name_ea),
        "idautils": SimpleNamespace(
            Strings=lambda: [String()],
            XrefsTo=lambda ea: [SimpleNamespace(frm=source)],
            Heads=lambda start, end: range(start, end),
        ),
        "idc": SimpleNamespace(
            print_insn_mnem=lambda ea: instructions[ea - source][0],
            get_strlit_contents=lambda ea: strings[ea].encode() if ea in strings else None,
        ),
    }
    code = FINDER._CALLBACK_PY_EVAL.replace("__HELP__", json.dumps(FINDER.HELP_STRING))
    # MCP evaluates with separate global/local namespaces, as Python 3.11 does here.
    globals_dict, locals_dict = {}, {}
    with patch.dict("sys.modules", modules):
        exec(code, globals_dict, locals_dict)
    return json.loads(locals_dict["result"]), callback


class TestDamageInfoBindingScan(unittest.TestCase):
    def test_linux_getter_rejects_entry_and_accepts_later_read(self):
        module = load_module(
            Path(FINDER.__file__).with_name("find-CTakeDamageInfo_m_hScriptInstance.py"),
            "damage_info_script_handle_validator",
        )
        for address, rejected in (("0x1000", True), ("0x104A", False), ("invalid", True)):
            with self.subTest(address=address):
                result = {"found_struct_offset": [{"insn_va": address}]}
                self.assertEqual(bool(module._validate_linux_getter_result(result, 0x1000)), rejected)

    def test_windows_and_linux_select_native_callback_instead_of_wrapper(self):
        for linux in (False, True):
            with self.subTest(linux=linux):
                results, callback = _run_binding_scan(linux=linux)
                self.assertEqual([item["func_va"] for item in results], [hex(callback)])

    def test_missing_name_wrong_descriptor_and_clobbered_pointer_fail_closed(self):
        for kwargs in ({"named": False}, {"wrong_descriptor": True}, {"clobbered": True}, {"early_call": True}):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(_run_binding_scan(**kwargs)[0], [])


class TestDamageInfoBindingOutput(unittest.IsolatedAsyncioTestCase):
    async def test_member_validation_accepts_current_instruction_shapes(self):
        for member, platform, instruction, size in (
            ("m_hScriptInstance", "windows", "mov     rax, [rcx+0E0h]", 8),
            ("m_hScriptInstance", "linux", "mov     rsi, [rbx+0E0h]", 8),
            ("m_AttackerInfo", "windows", "mov     [rbx+0E8h], r15b", 1),
            ("m_AttackerInfo", "linux", "lea     rdi, [rbx+0E8h]", None),
        ):
            module = load_module(
                Path(FINDER.__file__).with_name(f"find-CTakeDamageInfo_{member}.py"),
                f"damage_info_{member}_{platform}",
            )
            with (
                TemporaryDirectory() as tmpdir,
                patch.object(module, "preprocess_common_skill", new_callable=AsyncMock) as common,
            ):
                (Path(tmpdir) / "CTakeDamageInfo_GetScriptInstance.linux.yaml").write_text(
                    "func_va: '0x1000'\n", encoding="utf-8"
                )
                await module.preprocess_skill(None, "unused", [], {}, tmpdir, platform, 0)
            kwargs = common.call_args.kwargs
            spec = kwargs["llm_decompile_specs"][0]
            self.assertTrue(any(re.fullmatch(rule["regex"], instruction) for rule in spec["instruction_rules"]))
            self.assertEqual(spec.get("expected_size"), size)
            self.assertEqual("size" in kwargs["generate_yaml_desired_fields"][0][1], size is not None)

    async def test_missing_or_ambiguous_binding_does_not_reuse_stale_signature_or_write_output(self):
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            output = root / "CreateDamageInfo.windows.yaml"
            for candidates in ([], [{"func_va": "0x5000"}, {"func_va": "0x6000"}]):
                session = SimpleNamespace(call_tool=AsyncMock(return_value=py_eval_payload(candidates)))
                with patch.object(FINDER, "preprocess_gen_func_sig_via_mcp", new_callable=AsyncMock) as generate:
                    self.assertFalse(
                        await FINDER.preprocess_skill(
                            session,
                            "find-CreateDamageInfo",
                            [str(output)],
                            {"CreateDamageInfo": "stale-signature.yaml"},
                            str(root),
                            "windows",
                            0,
                        )
                    )
                    generate.assert_not_awaited()
                self.assertFalse(output.exists())
