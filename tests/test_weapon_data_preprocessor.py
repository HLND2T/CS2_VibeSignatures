import importlib
import json
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch

import yaml

from tests.ida_preprocessor_test_support import load_module, py_eval_payload


LOOKUP = "GetCSWeaponDataFromKey"
LEGACY_ANCHOR = "CSmokeGrenadeProjectile_GetCSWeaponData"
CREATE = "CSmokeGrenadeProjectile_Create"


def _instruction(mnemonic, operands=(), values=(), kinds=()):
    return {
        "mnemonic": mnemonic,
        "operands": operands,
        "values": values,
        "kinds": kinds,
    }


def _string_lookup(start):
    return {
        start: _instruction("test", ("rsi", "rsi")),
        start + 4: _instruction("xor", ("edx", "31415926h"), (0, 0x31415926), (1, 4)),
        start + 8: _instruction("imul", ("eax", "[rcx]", "5BD1E995h"), (0, 0, 0x5BD1E995), (1, 2, 4)),
        start + 12: _instruction("jmp", ("sub_TableLookup",), (0x3000,), (6,)),
    }


class _IdaSession:
    def __init__(self, instructions):
        self.instructions = instructions
        self.calls = []

    async def call_tool(self, name, arguments):
        self.calls.append(name)
        if name != "py_eval":
            raise AssertionError(f"unexpected IDA operation: {name}")
        instructions = self.instructions

        def get_func(address):
            for start in (0x1000, 0x2000, 0x3000, 0x4000):
                if start <= address < start + 0x100:
                    return types.SimpleNamespace(start_ea=start, end_ea=start + 0x100)
            return None

        def decode(insn, address):
            item = instructions[address]
            insn.ops = [
                types.SimpleNamespace(type=kind, addr=value, value=value)
                for kind, value in zip(item["kinds"], item["values"])
            ]
            return True

        idaapi = types.SimpleNamespace(
            get_func=get_func,
            insn_t=lambda: types.SimpleNamespace(ops=[]),
            decode_insn=decode,
            o_near=6,
            o_far=7,
            o_imm=4,
            o_reg=1,
        )
        idautils = types.SimpleNamespace(
            Heads=lambda start, end: sorted(address for address in instructions if start <= address < end),
        )
        idc = types.SimpleNamespace(
            print_insn_mnem=lambda address: instructions[address]["mnemonic"],
            print_operand=lambda address, index: instructions[address]["operands"][index],
            get_operand_value=lambda address, index: instructions[address]["values"][index],
        )
        # Match MCP's separate globals/persistent locals, including unrelated stale data.
        namespace = {"source_func": None, "targets": [0x3000]}
        with patch.dict("sys.modules", {"idaapi": idaapi, "idautils": idautils, "idc": idc}):
            exec(arguments["code"], {}, namespace)
        return py_eval_payload(json.loads(namespace["result"]))


class TestWeaponDataPreprocessor(unittest.IsolatedAsyncioTestCase):
    async def _run_case(
        self,
        instructions,
        *,
        expected_va=None,
        expected_wrapper_va=None,
        signature_available=True,
        source_present=True,
        platform="linux",
    ):
        for finder, source, source_va, output_name in (
            (f"find-{LEGACY_ANCHOR}", CREATE, 0x1000, LEGACY_ANCHOR),
            (f"find-{LOOKUP}-noinline", LEGACY_ANCHOR, 0x2000, LOOKUP),
            (f"find-{LOOKUP}-inlined", CREATE, 0x1000, LOOKUP),
        ):
            if platform == "windows" and finder.endswith("-noinline"):
                continue
            with self.subTest(finder=finder), TemporaryDirectory() as temp:
                module = load_module(Path("ida_preprocessor_scripts") / f"{finder}.py", finder.replace("-", "_"))
                artifact_dir = Path(temp)
                output = artifact_dir / f"{output_name}.{platform}.yaml"
                if source_present:
                    (artifact_dir / f"{source}.{platform}.yaml").write_text(
                        yaml.safe_dump({"func_name": source, "func_va": hex(source_va)}), encoding="utf-8"
                    )
                session = _IdaSession(instructions)
                result_va = expected_wrapper_va if output_name == LEGACY_ANCHOR and expected_wrapper_va else expected_va
                generated = (
                    {"func_va": hex(result_va or 0x2000), "func_size": "0x100", "func_sig": "55 31 D2"}
                    if signature_available
                    else None
                )
                util = importlib.import_module("ida_analyze_util")
                generate_signature = AsyncMock(return_value=generated)
                with (
                    patch.object(util, "preprocess_gen_func_sig_via_mcp", generate_signature),
                    patch.object(module, "preprocess_common_skill", AsyncMock(return_value=False), create=True),
                ):
                    result = await module.preprocess_skill(
                        session=session,
                        skill_name=finder,
                        expected_outputs=[str(output)],
                        # A unique old match can still refer to the internal table lookup.
                        old_yaml_map={LOOKUP: {"func_va": "0x3000", "func_sig": "85 D2 0F 84"}},
                        new_binary_dir=str(artifact_dir),
                        platform=platform,
                        image_base=0,
                        llm_config={"model": "must-not-be-called"},
                    )
                if expected_va is None:
                    self.assertFalse(result)
                    self.assertFalse(output.exists())
                    if signature_available:
                        generate_signature.assert_not_awaited()
                else:
                    self.assertTrue(result)
                    actual = yaml.safe_load(output.read_text(encoding="utf-8"))
                    expected_name = LEGACY_ANCHOR if expected_wrapper_va and output_name == LEGACY_ANCHOR else LOOKUP
                    self.assertEqual(expected_name, actual["func_name"])
                    self.assertEqual(hex(result_va), actual["func_va"])
                    self.assertEqual(hex(result_va), actual["func_rva"])
                    self.assertEqual("55 31 D2", actual["func_sig"])
                    self.assertEqual(hex(result_va), hex(int(generate_signature.await_args.kwargs["func_va"])))

    async def test_uses_string_lookup_itself_instead_of_its_internal_tail_target(self):
        instructions = {
            0x1000: _instruction("mov", ("edi", "1"), (0, 1), (1, 4)),
            0x1005: _instruction("call", ("sub_StringLookup",), (0x2000,), (6,)),
            **_string_lookup(0x2000),
            0x3000: _instruction("test", ("edx", "edx")),
        }
        await self._run_case(instructions, expected_va=0x2000)

    async def test_follows_a_real_intermediate_wrapper(self):
        instructions = {
            0x1000: _instruction("call", ("sub_Wrapper",), (0x2000,), (6,)),
            0x2000: _instruction("test", ("rdi", "rdi")),
            0x2010: _instruction("mov", ("edi", "1"), (0, 1), (1, 4)),
            0x2015: _instruction("call", ("sub_StringLookup",), (0x4000,), (6,)),
            **_string_lookup(0x4000),
        }
        await self._run_case(instructions, expected_va=0x4000, expected_wrapper_va=0x2000)

    async def test_does_not_accept_the_internal_hash_table_lookup(self):
        instructions = {
            0x1000: _instruction("mov", ("edi", "1"), (0, 1), (1, 4)),
            0x1005: _instruction("call", ("sub_TableLookup",), (0x2000,), (6,)),
            0x2000: _instruction("test", ("edx", "edx")),
            0x2004: _instruction("imul", ("eax", "eax", "85EBCA6Bh"), (0, 0, 0x85EBCA6B), (1, 1, 4)),
        }
        await self._run_case(instructions)

    async def test_ambiguous_string_lookups_fail_without_writing(self):
        instructions = {
            0x1000: _instruction("call", ("sub_Wrapper",), (0x2000,), (6,)),
            0x2000: _instruction("mov", ("edi", "1"), (0, 1), (1, 4)),
            0x2005: _instruction("call", ("sub_LookupA",), (0x3000,), (6,)),
            0x200A: _instruction("mov", ("edi", "1"), (0, 1), (1, 4)),
            0x200F: _instruction("call", ("sub_LookupB",), (0x4000,), (6,)),
            **_string_lookup(0x3000),
            **_string_lookup(0x4000),
        }
        await self._run_case(instructions)

    async def test_missing_source_fails_without_writing(self):
        await self._run_case({}, source_present=False)

    async def test_windows_lookup_uses_the_hash_callee_and_rejects_unrelated_create_calls(self):
        instructions = {
            0x1000: _instruction("mov", ("ecx", "1"), (0, 1), (1, 4)),
            0x1005: _instruction("call", ("sub_StringLookup",), (0x2000,), (6,)),
            0x1010: _instruction("call", ("sub_Unrelated",), (0x4000,), (6,)),
            0x2000: _instruction("test", ("rdx", "rdx")),
            0x2004: _instruction("mov", ("r8d", "31415926h"), (0, 0x31415926), (1, 4)),
            0x2008: _instruction("mov", ("rcx", "r9"), (0, 0), (1, 1)),
            0x200C: _instruction("call", ("sub_Hash",), (0x3000,), (6,)),
            0x3000: _instruction("imul", ("eax", "5BD1E995h"), (0, 0x5BD1E995), (1, 4)),
            0x4000: _instruction("test", ("rdx", "rdx")),
        }
        await self._run_case(instructions, expected_va=0x2000, platform="windows")

    async def test_windows_rejects_seed_without_murmur_hash_callee(self):
        instructions = {
            0x1000: _instruction("mov", ("ecx", "1"), (0, 1), (1, 4)),
            0x1005: _instruction("call", ("sub_Lookalike",), (0x2000,), (6,)),
            0x2000: _instruction("test", ("rdx", "rdx")),
            0x2004: _instruction("mov", ("r8d", "31415926h"), (0, 0x31415926), (1, 4)),
        }
        await self._run_case(instructions, platform="windows")

    async def test_signature_failure_does_not_write_a_partial_artifact(self):
        instructions = {
            0x1000: _instruction("mov", ("edi", "1"), (0, 1), (1, 4)),
            0x1005: _instruction("call", ("sub_StringLookup",), (0x2000,), (6,)),
            **_string_lookup(0x2000),
        }
        await self._run_case(instructions, signature_available=False)


if __name__ == "__main__":
    unittest.main()
