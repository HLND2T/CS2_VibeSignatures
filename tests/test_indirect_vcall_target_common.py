import unittest
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

from ida_preprocessor_scripts._indirect_vcall_target_common import _build_indirect_vcall_target_py_eval
from ida_skill_preprocessor import _get_preprocess_entry


class TestIndirectVcallTargetCommon(unittest.TestCase):
    def test_build_py_eval_embeds_resolve_load_then_branch_mode(self) -> None:
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                code = _build_indirect_vcall_target_py_eval(
                    func_va=0x1000,
                    allowed_mnemonics=("call", "jmp"),
                    resolve_load_then_branch=enabled,
                )
                self.assertIn(f"resolve_load_then_branch = {enabled}", code)
                self.assertNotIn("__RESOLVE_LOAD_THEN_BRANCH__", code)

    def test_build_py_eval_embeds_cfg_backward_search(self) -> None:
        # Register-indirect (`jmp/call reg`) resolution must use a
        # control-flow-aware backward walk (FlowChart + predecessor chain) so it
        # can see past an early-out guard that clobbers the branch register on a
        # not-taken path, rather than a linear last-load-per-register scan.
        code = _build_indirect_vcall_target_py_eval(
            func_va=0x1000,
            allowed_mnemonics=("call", "jmp"),
            resolve_load_then_branch=True,
        )
        self.assertIn("FlowChart", code)
        self.assertIn("FC_PREDS", code)
        self.assertIn(".preds()", code)
        self.assertIn("_resolve_reg_branch", code)
        # exec-scoping bridge so the top-level helpers see each other under
        # py_eval's distinct globals/locals (repo-wide py_eval convention).
        self.assertIn("globals().update(locals())", code)
        # the superseded linear heuristic must not linger
        self.assertNotIn("reg_last_load", code)
        # the emitted py_eval body must still be valid Python
        compile(code, "<pyeval>", "exec")

    def test_pyeval_resolves_reg_branch_past_early_out_guard(self) -> None:
        # Regression: the emitted py_eval body must resolve a register-indirect
        # branch (`jmp reg`) to its vtable slot even when an early-out guard
        # clobbers the branch register on a NOT-taken path -- and it must do so
        # under `exec(code, globals, locals)` with DISTINCT dicts (how py_eval
        # runs it), where a top-level def lands in locals and is invisible to a
        # sibling top-level function body (which resolves names via globals).
        import sys
        import types
        import json as _json

        # IDA operand type constants (values only need to be internally
        # consistent with the stub namespace below).
        O_VOID, O_REG, O_PHRASE, O_DISPL, O_NEAR = 0, 1, 3, 4, 7

        class _Op:
            def __init__(self, type=O_VOID, reg=0, addr=0):
                self.type = type
                self.reg = reg
                self.addr = addr

        class _Insn:
            def __init__(self):
                self.ops = [_Op() for _ in range(8)]

        # Linux/GCC guard idiom, one instruction per ea:
        #   0: mov rax,[rdi]        load off 0 into reg0 (vtable ptr)
        #   1: lea rdx, X           write reg2
        #   2: mov rax,[rax+0x128]  load off 0x128 into reg0  <-- the slot
        #   3: cmp rax, rdx
        #   4: jnz 6
        #   5: mov eax, -1          non-load clobber of reg0 (not-taken path)
        #   6: jmp rax              branch through reg0 (jnz target)
        prog = {
            0: ("mov", [_Op(O_REG, 0), _Op(O_PHRASE, 7, 0)]),
            1: ("lea", [_Op(O_REG, 2), _Op(O_NEAR, 0, 0x9999)]),
            2: ("mov", [_Op(O_REG, 0), _Op(O_DISPL, 0, 0x128)]),
            3: ("cmp", [_Op(O_REG, 0), _Op(O_REG, 2)]),
            4: ("jnz", [_Op(O_NEAR, 0, 6)]),
            5: ("mov", [_Op(O_REG, 0), _Op(O_VOID)]),
            6: ("jmp", [_Op(O_REG, 0)]),
        }

        def _decode(insn, ea):
            ops = prog[ea][1]
            insn.ops = list(ops) + [_Op() for _ in range(8 - len(ops))]
            return True

        def _heads(start, end):
            return [ea for ea in sorted(prog) if start <= ea < end]

        class _Block:
            def __init__(self, bid, start, end, preds):
                self.id = bid
                self.start_ea = start
                self.end_ea = end
                self._preds = preds

            def preds(self):
                return iter(self._preds)

        # A: [0,5) ends at jnz; B: [5,6) early-out; C: [6,7) jmp rax.
        # C's only predecessor is A (the jnz-taken edge) -- B is NOT a pred of C,
        # so the clobber at ea 5 must never be visited.
        block_a = _Block(0, 0, 5, [])
        block_b = _Block(1, 5, 6, [block_a])
        block_c = _Block(2, 6, 7, [block_a])
        flow = [block_a, block_b, block_c]

        func = types.SimpleNamespace(start_ea=0, end_ea=7)
        idaapi_stub = types.SimpleNamespace(
            o_void=O_VOID,
            o_reg=O_REG,
            o_phrase=O_PHRASE,
            o_displ=O_DISPL,
            FC_PREDS=1,
            insn_t=_Insn,
            decode_insn=_decode,
            get_func=lambda ea: func,
            add_func=lambda ea: None,
            FlowChart=lambda f, flags=0: list(flow),
        )
        idc_stub = types.SimpleNamespace(print_insn_mnem=lambda ea: prog[ea][0])
        idautils_stub = types.SimpleNamespace(Heads=_heads)

        code = _build_indirect_vcall_target_py_eval(
            func_va=0,
            allowed_mnemonics=("call", "jmp"),
            resolve_load_then_branch=True,
        )
        # globals hold idaapi/idc/idautils (as the MCP host injects them), so
        # nested/closure name resolution mirrors the real py_eval environment.
        exec_globals = {"idaapi": idaapi_stub, "idc": idc_stub, "idautils": idautils_stub}
        exec_locals: dict = {}
        with patch.dict(
            sys.modules,
            {"idaapi": idaapi_stub, "idc": idc_stub, "idautils": idautils_stub},
        ):
            exec(code, exec_globals, exec_locals)  # must not raise NameError

        parsed = _json.loads(exec_locals["result"])
        self.assertEqual(len(parsed["targets"]), 1)
        self.assertEqual(parsed["targets"][0]["vfunc_offset"], "0x128")
        self.assertEqual(parsed["targets"][0]["vfunc_index"], 37)


class TestSendStringCmdTailDispatch(unittest.IsolatedAsyncioTestCase):
    async def _run_finder(self, platform, indirect_targets, direct_targets):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / f"CEngineClient_ExecuteClientCmd.{platform}.yaml"
            source.write_text("func_name: CEngineClient_ServerCmd\nfunc_va: '0x1000'\n", encoding="utf-8")
            output = root / f"INetworkGameClient_SendStringCmd.{platform}.yaml"
            with (
                patch(
                    "ida_preprocessor_scripts._indirect_vcall_target_common.IndirectVcallTargetLocator.collect_targets",
                    new_callable=AsyncMock,
                    side_effect=indirect_targets,
                ) as indirect,
                patch(
                    "ida_preprocessor_scripts._direct_branch_target_common.DirectBranchTargetLocator.collect_targets",
                    new_callable=AsyncMock,
                    return_value=direct_targets,
                ) as direct,
            ):
                result = await _get_preprocess_entry("find-INetworkGameClient_SendStringCmd")(
                    session=object(),
                    skill_name="find-INetworkGameClient_SendStringCmd",
                    expected_outputs=[str(output)],
                    old_yaml_map={},
                    new_binary_dir=directory,
                    platform=platform,
                    image_base=0,
                )
            payload = yaml.safe_load(output.read_text(encoding="utf-8")) if output.exists() else None
            return result, payload, indirect, direct

    @staticmethod
    def _slot(offset):
        return {
            "source_ea": "0x2010",
            "source_mnemonic": "jmp",
            "vfunc_offset": hex(offset),
            "vfunc_index": offset // 8,
        }

    async def test_linux_follows_unique_external_tail_jump(self):
        result, payload, indirect, direct = await self._run_finder(
            "linux",
            [[], [self._slot(0x130)]],
            [{"target_va": "0x1000"}, {"target_va": "0x2000"}],
        )
        self.assertTrue(result)
        self.assertEqual(
            {
                "func_name": "INetworkGameClient_SendStringCmd",
                "vtable_name": "INetworkGameClient",
                "vfunc_offset": "0x130",
                "vfunc_index": 38,
            },
            payload,
        )
        direct.assert_awaited_once_with(source_func_va="0x1000", allowed_mnemonics=("jmp",))
        self.assertEqual("0x2000", indirect.await_args.kwargs["source_func_va"])
        self.assertEqual(("jmp",), indirect.await_args.kwargs["allowed_mnemonics"])

    async def test_windows_keeps_direct_virtual_dispatch(self):
        result, payload, indirect, direct = await self._run_finder("windows", [[self._slot(0x130)]], [])
        self.assertTrue(result)
        self.assertEqual(38, payload["vfunc_index"])
        self.assertEqual(1, indirect.await_count)
        direct.assert_not_awaited()

    async def test_linux_rejects_missing_or_ambiguous_tail_targets(self):
        for targets in (None, [], [{"target_va": "0x1000"}], [{"target_va": "0x2000"}, {"target_va": "0x3000"}]):
            with self.subTest(targets=targets):
                result, payload, indirect, _ = await self._run_finder("linux", [[]], targets)
                self.assertFalse(result)
                self.assertIsNone(payload)
                self.assertEqual(1, indirect.await_count)

    async def test_linux_rejects_missing_or_ambiguous_virtual_slots(self):
        for slots in (None, [], [self._slot(0x130), self._slot(0x140)]):
            with self.subTest(slots=slots):
                result, payload, _, _ = await self._run_finder("linux", [[], slots], [{"target_va": "0x2000"}])
                self.assertFalse(result)
                self.assertIsNone(payload)

    async def test_linux_does_not_follow_after_scan_failure_or_ambiguity(self):
        for slots in (None, [self._slot(0x130), self._slot(0x140)]):
            with self.subTest(slots=slots):
                result, payload, _, direct = await self._run_finder("linux", [slots], [{"target_va": "0x2000"}])
                self.assertFalse(result)
                self.assertIsNone(payload)
                direct.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
