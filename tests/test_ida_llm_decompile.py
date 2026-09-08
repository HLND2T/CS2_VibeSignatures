import asyncio
import io
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from types import SimpleNamespace

import ida_llm_decompile
from ida_preprocessor_scripts import _connect_client_anchor as anchor_helper


class TestConnectClientAnchor(unittest.TestCase):
    def candidate(self, address, failures=(), *, verified=True, client_var=1):
        return {
            "insn_va": address,
            "target_va": address + 1,
            "client_var": client_var,
            "failure_calls": list(failures),
            "verified": verified,
            "insn_disasm": "call sub_client",
        }

    def test_first_acquisition_wins_over_final_fallback(self):
        first = self.candidate(0x1000, [0x3000])
        final = self.candidate(0x3000)
        self.assertEqual(first, anchor_helper.select_anchor([final, first]))

    def test_invalid_first_call_does_not_promote_later_fallback(self):
        with self.assertRaisesRegex(ValueError, "unsupported data flow"):
            anchor_helper.select_anchor([self.candidate(0x1000, [0x3000], verified=False), self.candidate(0x3000)])

    def test_missing_or_ambiguous_roots_fail_closed(self):
        for candidates in ([], [self.candidate(0x1000), self.candidate(0x2000)]):
            with self.subTest(candidates=candidates), self.assertRaises(ValueError):
                anchor_helper.select_anchor(candidates)

    def test_reference_address_and_wrong_live_call_rejected(self):
        anchor = self.candidate(0x1000)
        for address in (0x68D81C, 0x3000, 0x1000):
            result = {"found_call": [{"func_name": anchor_helper.SYMBOL, "insn_va": hex(address)}]}
            self.assertEqual(address != 0x1000, bool(anchor_helper.validate_result(result, anchor)))

    def test_ctree_probe_recognizes_single_call_and_nested_fallback_chain(self):
        # Small ctree fixtures exercise the actual IDA probe, including its live
        # owner/xref checks. Callee names are deliberately absent.
        names = (
            "cot_cast",
            "cot_var",
            "cot_lnot",
            "cot_eq",
            "cot_ne",
            "cot_num",
            "cot_lor",
            "cot_asg",
            "cot_call",
            "cot_obj",
            "cot_tern",
            "cit_expr",
            "cit_if",
            "cit_block",
        )
        hx = SimpleNamespace(**{name: index for index, name in enumerate(names)}, CV_FAST=0)

        def node(op, **kwargs):
            return SimpleNamespace(op=getattr(hx, op), **kwargs)

        def var():
            return node("cot_var", v=SimpleNamespace(idx=1))

        def call(ea):
            return node("cot_call", ea=ea, x=node("cot_obj", obj_ea=ea + 1))

        def assignment(ea):
            return node("cot_asg", x=var(), y=call(ea))

        def block(*items):
            return node("cit_block", cblock=list(items))

        log = node("cit_expr", cexpr=node("cot_obj", obj_ea=0x9000))
        final_if = node("cit_if", cif=SimpleNamespace(expr=node("cot_lnot", x=var()), ithen=block(log), ielse=None))
        final_block = block(node("cit_expr", cexpr=assignment(0x3000)), final_if)
        outer_if = node(
            "cit_if",
            cif=SimpleNamespace(expr=node("cot_lor", x=var(), y=assignment(0x2000)), ithen=block(), ielse=final_block),
        )

        class Visitor:
            def __init__(self, *_):
                pass

            def apply_to(self, current, _):
                if current is None:
                    return
                if isinstance(current, SimpleNamespace):
                    if hasattr(current, "op"):
                        method = "visit_insn" if current.op >= hx.cit_expr else "visit_expr"
                        getattr(self, method, lambda _: 0)(current)
                    for value in vars(current).values():
                        self.apply_to(value, None)
                elif isinstance(current, list):
                    for value in current:
                        self.apply_to(value, None)

        hx.ctree_visitor_t = Visitor
        modules = {
            "ida_hexrays": hx,
            "ida_bytes": SimpleNamespace(
                get_strlit_contents=lambda ea, *_: (
                    b"NETWORK_DISCONNECT_REJECT_SERVERFULL: Cannot get free client" if ea == 0x9000 else b""
                )
            ),
            "ida_funcs": SimpleNamespace(get_func=lambda ea: SimpleNamespace(start_ea=ea if ea % 2 else 0x100)),
            "ida_lines": SimpleNamespace(tag_remove=lambda text: text),
            "idautils": SimpleNamespace(CodeRefsFrom=lambda ea, _: [ea + 1]),
            "idc": SimpleNamespace(
                STRTYPE_C=0, print_insn_mnem=lambda _: "call", generate_disasm_line=lambda *_: "call sub_client"
            ),
        }
        for body, expected in (
            (final_block, 0x3000),
            (block(node("cit_expr", cexpr=assignment(0x1000)), outer_if), 0x1000),
        ):
            hx.decompile = lambda _: SimpleNamespace(body=body)
            with patch.dict("sys.modules", modules):
                candidates = anchor_helper._probe_anchor(0x100)
            self.assertEqual(expected, anchor_helper.select_anchor(candidates)["insn_va"])

        # A non-unique first call must not silently select the final allocator.
        modules["idautils"].CodeRefsFrom = lambda ea, _: [1, 2] if ea == 0x1000 else [ea + 1]
        with patch.dict("sys.modules", modules), self.assertRaises(ValueError):
            anchor_helper.select_anchor(anchor_helper._probe_anchor(0x100))

        # Unsupported outer copy/ternary assignments must block inner allocators.
        modules["idautils"].CodeRefsFrom = lambda ea, _: [ea + 1]
        for value in (var(), node("cot_tern", x=var(), y=call(0x1000), z=call(0x2000))):
            hx.decompile = lambda _: SimpleNamespace(
                body=block(node("cit_expr", ea=0x900, cexpr=node("cot_asg", x=var(), y=value)), outer_if)
            )
            with patch.dict("sys.modules", modules), self.assertRaisesRegex(ValueError, "unsupported data flow"):
                anchor_helper.select_anchor(anchor_helper._probe_anchor(0x100))

        # An initial acquisition separated from its test is unsupported; the
        # recognizable final fallback must not become the new first acquisition.
        hx.decompile = lambda _: SimpleNamespace(
            body=block(node("cit_expr", cexpr=assignment(0x1000)), block(), final_block)
        )
        with patch.dict("sys.modules", modules), self.assertRaises(ValueError):
            anchor_helper.select_anchor(anchor_helper._probe_anchor(0x100))

    def test_validator_accepts_common_address_formats_and_reports_missing_or_invalid_entries(self):
        anchor = self.candidate(0x1000)
        for value in ("1000h", "0x1_000", "4096", "invalid", None):
            result = {"found_call": [{"func_name": anchor_helper.SYMBOL, "insn_va": value}]}
            self.assertEqual(value in ("invalid", None), bool(anchor_helper.validate_result(result, anchor)))
        self.assertTrue(anchor_helper.validate_result({}, anchor))


class TestFinderValidation(unittest.IsolatedAsyncioTestCase):
    async def test_real_but_wrong_call_receives_feedback_and_retries(self):
        requests = []

        async def transport(**kwargs):
            requests.append(kwargs["messages"])
            address = "0x1000" if len(requests) == 1 else "0x2000"
            return f"found_call:\n  - func_name: Target\n    insn_va: '{address}'\n    insn_disasm: call sub_target\n"

        def validate(result):
            if result["found_call"][0]["insn_va"] != "0x2000":
                return ["Choose the first acquisition, not the fallback allocator"]
            return []

        result = await ida_llm_decompile.call_llm_decompile(
            model="test",
            symbol_name_list=["Target"],
            expected_result_sections={"Target": ["found_call"]},
            disasm_code=".text:00001000 call sub_target\n.text:00002000 call sub_target",
            call_llm_text_func=transport,
            result_validator=validate,
            max_retries=2,
        )
        self.assertEqual("0x2000", result["found_call"][0]["insn_va"])
        self.assertEqual(2, len(requests))
        self.assertIn("first acquisition", requests[1][-1]["content"])


class TestLlmTransportTimeout(unittest.IsolatedAsyncioTestCase):
    async def test_transport_timeout_is_reported_as_retryable_failure(self) -> None:
        async def stalled_transport(**_kwargs):
            await asyncio.sleep(0.05)

        with patch.object(ida_llm_decompile, "LLM_DECOMPILE_TIMEOUT_SECONDS", 0.001):
            succeeded, content, retry_delay = await ida_llm_decompile._call_llm_transport_attempt(
                stalled_transport,
                {},
                attempt_index=0,
                retry_settings=(1, 0.0, 2.0, 8.0),
                symbol_name_text="target",
                debug=False,
            )

        self.assertFalse(succeeded)
        self.assertIsNone(content)
        self.assertIsNone(retry_delay)

    async def test_sync_transport_invocation_is_bounded_by_timeout(self) -> None:
        def stalled_transport(**_kwargs):
            time.sleep(0.05)
            return "late response"

        with patch.object(ida_llm_decompile, "LLM_DECOMPILE_TIMEOUT_SECONDS", 0.001):
            succeeded, content, retry_delay = await ida_llm_decompile._call_llm_transport_attempt(
                stalled_transport,
                {},
                attempt_index=0,
                retry_settings=(1, 0.0, 2.0, 8.0),
                symbol_name_text="target",
                debug=False,
            )

        self.assertFalse(succeeded)
        self.assertIsNone(content)
        self.assertIsNone(retry_delay)


class TestLlmDebugOutput(unittest.TestCase):
    def test_multiline_debug_output_is_bounded(self) -> None:
        output = io.StringIO()
        with (
            patch.object(ida_llm_decompile, "LLM_DECOMPILE_DEBUG_TEXT_LIMIT", 32),
            redirect_stdout(output),
        ):
            ida_llm_decompile._debug_print_multiline("payload", "x" * 1_000, debug=True)

        rendered = output.getvalue()
        self.assertIn("truncated", rendered)
        self.assertIn("sha256:", rendered)
        self.assertLess(len(rendered), 300)
