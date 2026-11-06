import copy
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from ida_analyze_util import _build_llm_decompile_specs_map, _validate_llm_decompile_dependency_policy
from tests.ida_preprocessor_test_support import load_module, py_eval_payload


class TestCheckParmPredecessorSelection(unittest.IsolatedAsyncioTestCase):
    async def test_selects_current_helper_only_for_matching_platform(self):
        module = load_module(
            "ida_preprocessor_scripts/find-CCSBotManager_StartFrame-decompiles.py", "find_checkparm_selection"
        )
        with tempfile.TemporaryDirectory() as directory:
            artifact_dir = Path(directory) / "server"
            artifact_dir.mkdir()
            helper = artifact_dir / "CCSBotManager_StartFrame_ShouldUpdate.linux.yaml"
            helper.write_text("func_va: '0x1000'\n", encoding="utf-8")
            for platform, predecessor in (
                ("windows", "CCSBotManager_StartFrame"),
                ("linux", "CCSBotManager_StartFrame_ShouldUpdate"),
            ):
                with self.subTest(platform=platform):
                    common = AsyncMock(return_value=True)
                    with patch.object(module, "preprocess_common_skill", common):
                        self.assertTrue(
                            await module.preprocess_skill(
                                session=object(),
                                skill_name="find-CCSBotManager_StartFrame-decompiles",
                                expected_outputs=[f"ICommandLine_CheckParm.{platform}.yaml"],
                                old_yaml_map={},
                                new_binary_dir=str(artifact_dir),
                                platform=platform,
                                image_base=0,
                            )
                        )
                    specs = common.await_args.kwargs["llm_decompile_specs"]
                    normalized = _build_llm_decompile_specs_map(specs)
                    self.assertIsNotNone(normalized)
                    self.assertEqual(
                        {"ICommandLine_CheckParm", "ICommandLine_HasParm"},
                        {spec["symbol_name"] for spec in specs},
                    )
                    for spec in specs:
                        reference = Path("ida_preprocessor_scripts") / spec["reference_yaml_paths"][0]
                        self.assertIn(f"func_name: {predecessor}\n", reference.read_text(encoding="utf-8"))
                    self.assertTrue(
                        _validate_llm_decompile_dependency_policy(
                            normalized,
                            {
                                "_expected_inputs": [f"CCSBotManager_StartFrame.{platform}.yaml"],
                                "_optional_inputs": [f"CCSBotManager_StartFrame_ShouldUpdate.{platform}.yaml"],
                            },
                            str(artifact_dir),
                            platform,
                        )
                    )
            helper.unlink()
            common = AsyncMock(return_value=True)
            with patch.object(module, "preprocess_common_skill", common):
                await module.preprocess_skill(object(), "finder", [], {}, str(artifact_dir), "linux", 0)
            self.assertEqual(common.await_args.kwargs["llm_decompile_specs"], module.LLM_DECOMPILE)


def _operand(kind, text="", value=0):
    return {"kind": kind, "text": text, "value": value}


def _instruction(mnemonic, *operands):
    return {"mnem": mnemonic, "ops": list(operands)}


def _gate_instructions(platform, slot=0x18):
    """The two query sequences decoded from the 14196 binaries."""
    if platform == "windows":
        return [
            _instruction("mov", _operand("reg", "r9"), _operand("displ", "[rdx+18h]", slot)),
            _instruction("mov", _operand("reg", "edx"), _operand("imm", value=0xFFFFFFFFC53340BC)),
            _instruction("call", _operand("reg", "r9")),
            _instruction("test", _operand("reg", "rax"), _operand("reg", "rax")),
            _instruction("jnz", _operand("near", value=0x9000)),
            _instruction("call", _operand("mem", "CommandLine", 0x8000)),
            _instruction("mov", _operand("reg", "edx"), _operand("imm", value=0x2237A36D)),
            _instruction("mov", _operand("reg", "rcx"), _operand("phrase", "[rax]")),
            _instruction("mov", _operand("reg", "r8"), _operand("displ", "[rcx+20h]", slot + 8)),
            _instruction("mov", _operand("reg", "rcx"), _operand("reg", "rax")),
            _instruction("call", _operand("reg", "r8")),
        ]
    return [
        _instruction("mov", _operand("reg", "esi"), _operand("imm", value=0xC53340BC)),
        _instruction("mov", _operand("reg", "rdi"), _operand("reg", "rax")),
        _instruction("mov", _operand("reg", "rax"), _operand("phrase", "[rax]")),
        _instruction("call", _operand("displ", "[rax+18h]", slot)),
        _instruction("test", _operand("reg", "rdx"), _operand("reg", "rdx")),
        _instruction("jz", _operand("near", value=0x3000)),
        _instruction("ret"),
        _instruction("call", _operand("near", value=0x8000)),
        _instruction("mov", _operand("reg", "esi"), _operand("imm", value=0x2237A36D)),
        _instruction("mov", _operand("reg", "rdi"), _operand("reg", "rax")),
        _instruction("mov", _operand("reg", "rax"), _operand("phrase", "[rax]")),
        _instruction("call", _operand("displ", "[rax+20h]", slot + 8)),
    ]


def _scan_with_helper(platform):
    return {
        "source": {"func_va": 0x1000, "instructions": [_instruction("call", _operand("near", value=0x2000))]},
        "callees": [{"func_va": 0x2000, "instructions": _gate_instructions(platform)}],
    }


class TestShouldUpdateInstructionGate(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.module = load_module(
            "ida_preprocessor_scripts/find-CCSBotManager_StartFrame_ShouldUpdate.py", "find_should_update"
        )

    def test_embedded_scan_returns_compact_proof_with_separate_namespaces(self):
        for platform in ("windows", "linux"):
            with self.subTest(platform=platform):
                scan = _scan_with_helper(platform)
                if platform == "windows":
                    scan["source"]["instructions"] = _gate_instructions(platform)
                scan["source"]["instructions"].extend(_instruction("nop") for _ in range(200))
                functions = {function["func_va"]: function for function in [scan["source"], *scan["callees"]]}
                instructions = {}
                heads = {}
                for start, function in functions.items():
                    heads[start] = []
                    for offset, instruction in enumerate(function["instructions"]):
                        instructions[start + offset] = instruction
                        heads[start].append(start + offset)
                kinds = {
                    name: index
                    for index, name in enumerate(("void", "reg", "imm", "displ", "phrase", "near", "far", "mem"))
                }

                def decode(insn, ea):
                    operands = instructions[ea]["ops"]
                    insn.ops = [types.SimpleNamespace(type=kinds[op["kind"]]) for op in operands]
                    insn.ops.extend(types.SimpleNamespace(type=0) for _ in range(2 - len(insn.ops)))
                    return 1

                idaapi = types.SimpleNamespace(
                    **{f"o_{name}": value for name, value in kinds.items()},
                    insn_t=types.SimpleNamespace,
                    decode_insn=decode,
                    get_func=lambda address: types.SimpleNamespace(start_ea=address) if address in functions else None,
                )
                idc = types.SimpleNamespace(
                    print_insn_mnem=lambda ea: instructions[ea]["mnem"],
                    print_operand=lambda ea, index: instructions[ea]["ops"][index]["text"],
                    get_operand_value=lambda ea, index: instructions[ea]["ops"][index]["value"],
                )
                local_namespace = {}
                with patch.dict(
                    sys.modules,
                    {
                        "idaapi": idaapi,
                        "idautils": types.SimpleNamespace(FuncItems=lambda address: heads[address]),
                        "idc": idc,
                    },
                ):
                    exec(self.module._build_scan_code(0x1000, platform), {}, local_namespace)
                encoded = local_namespace["result"]
                self.assertLess(len(encoded), 4000)
                proof = json.loads(encoded)
                self.assertEqual(0x1000, proof["source_va"])
                self.assertEqual(None if platform == "windows" else 0x2000, proof["func_va"])

    def test_recognizes_inline_gate_and_unique_direct_callee_on_both_abis(self):
        for platform in ("windows", "linux"):
            with self.subTest(platform=platform):
                scan = _scan_with_helper(platform)
                self.assertEqual(0x2000, self.module._resolve_gate(scan, platform)[1])
                scan["source"]["instructions"] = _gate_instructions(platform)
                self.assertEqual(("verified inline command-line gate", None), self.module._resolve_gate(scan, platform))
                # The rule follows the binary, rather than fixing Windows to inline.
                self.assertTrue(self.module._has_command_line_gate(scan["source"], platform))

    def test_accepts_shifted_interface_slots(self):
        for platform in ("windows", "linux"):
            scan = _scan_with_helper(platform)
            scan["callees"][0]["instructions"] = _gate_instructions(platform, slot=0x30)
            self.assertEqual(0x2000, self.module._resolve_gate(scan, platform)[1])

    def test_rejects_entity_counter_missing_hashes_and_wrong_abi(self):
        scan = _scan_with_helper("windows")
        # The former false positive traverses entity handles and counts matches.
        scan["callees"][0]["instructions"] = [
            _instruction("call", _operand("near", value=0x180C86720)),
            _instruction("mov", _operand("reg", "r15d"), _operand("imm", value=0xFFFF)),
            _instruction("call", _operand("displ", "[rax+558h]", 0x558)),
            _instruction("inc", _operand("reg", "ebp")),
            _instruction("mov", _operand("reg", "eax"), _operand("reg", "ebp")),
        ]
        self.assertIsNone(self.module._resolve_gate(scan, "windows")[1])
        scan = _scan_with_helper("linux")
        self.assertIsNone(self.module._resolve_gate(scan, "windows")[1])
        scan["callees"][0]["instructions"] = _gate_instructions("linux")[:4]
        self.assertIsNone(self.module._resolve_gate(scan, "linux")[1])

    def test_rejects_hash_constants_without_verified_virtual_dispatch(self):
        for change in ("direct-call", "stack-call", "slot-gap", "hash-clobber", "dispatch-clobber", "branch"):
            with self.subTest(change=change):
                scan = _scan_with_helper("windows")
                instructions = scan["callees"][0]["instructions"]
                if change == "direct-call":
                    instructions[2] = _instruction("call", _operand("near", value=0x3000))
                elif change == "stack-call":
                    instructions[0]["ops"][1]["text"] = "[rsp+18h]"
                elif change == "slot-gap":
                    instructions[8]["ops"][1]["value"] += 8
                elif change == "hash-clobber":
                    instructions.insert(2, _instruction("xor", _operand("reg", "dx"), _operand("reg", "dx")))
                elif change == "dispatch-clobber":
                    instructions.insert(2, _instruction("xor", _operand("reg", "r9d"), _operand("reg", "r9d")))
                else:
                    instructions.insert(2, _instruction("jmp", _operand("near", value=0x3000)))
                self.assertIsNone(self.module._resolve_gate(scan, "windows")[1])

    def test_rejects_ambiguity_and_functions_outside_the_direct_call_graph(self):
        scan = _scan_with_helper("linux")
        duplicate = copy.deepcopy(scan["callees"][0])
        duplicate["func_va"] = 0x3000
        scan["callees"].append(duplicate)
        self.assertEqual(0x2000, self.module._resolve_gate(scan, "linux")[1])
        scan["source"]["instructions"].append(_instruction("call", _operand("near", value=0x3000)))
        self.assertIsNone(self.module._resolve_gate(scan, "linux")[1])

    async def _run_finder(self, scan, platform="linux", generated=None, malformed_source=False):
        with tempfile.TemporaryDirectory() as directory:
            artifact_dir = Path(directory)
            (artifact_dir / f"CCSBotManager_StartFrame.{platform}.yaml").write_text(
                "func_va: '0x9999'\n" if malformed_source else "func_va: '0x1000'\n", encoding="utf-8"
            )
            output = artifact_dir / f"CCSBotManager_StartFrame_ShouldUpdate.{platform}.yaml"
            session = AsyncMock()
            reason, func_va = self.module._resolve_gate(scan, platform)
            session.call_tool.return_value = py_eval_payload(
                {"source_va": scan["source"]["func_va"], "reason": reason, "func_va": func_va}
            )
            with patch.object(self.module, "preprocess_gen_func_sig_via_mcp", AsyncMock(return_value=generated)) as sig:
                result = await self.module.preprocess_skill(
                    session,
                    "finder",
                    [str(output)],
                    {"CCSBotManager_StartFrame_ShouldUpdate": {"func_va": "0xdead", "func_sig": "bad"}},
                    str(artifact_dir),
                    platform,
                    0,
                    llm_config={"model": "must-not-be-called"},
                )
            return result, output.read_text() if output.exists() else None, sig

    async def test_writes_verified_callee_and_ignores_historical_signature(self):
        generated = {"func_va": "0x2000", "func_rva": "0x2000", "func_size": "0x5f", "func_sig": "55 48 89 E5"}
        result, content, sig = await self._run_finder(_scan_with_helper("linux"), generated=generated)
        self.assertTrue(result)
        self.assertIn("func_name: CCSBotManager_StartFrame_ShouldUpdate\n", content)
        self.assertIn("func_va: '0x2000'", content)
        self.assertEqual(0x2000, sig.await_args.kwargs["func_va"])

    async def test_inline_gate_never_writes_a_helper_even_with_historical_output(self):
        scan = _scan_with_helper("windows")
        scan["source"]["instructions"] = _gate_instructions("windows")
        result, content, sig = await self._run_finder(scan, platform="windows")
        self.assertFalse(result)
        self.assertIsNone(content)
        sig.assert_not_awaited()

    async def test_rejects_stale_source_and_failed_signature_generation(self):
        for malformed_source in (True, False):
            result, content, sig = await self._run_finder(_scan_with_helper("linux"), malformed_source=malformed_source)
            self.assertFalse(result)
            self.assertIsNone(content)
            self.assertEqual(0 if malformed_source else 1, sig.await_count)
