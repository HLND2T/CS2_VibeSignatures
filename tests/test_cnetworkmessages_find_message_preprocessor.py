import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as N
from unittest.mock import AsyncMock, patch

import yaml

from ida_preprocessor_test_support import load_module, py_eval_payload


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "ida_preprocessor_scripts/find-CNetworkMessages_FindNetworkMessage-14197.py"
)
SIGNATURE_GENERATOR = "ida_preprocessor_scripts._vtable_slot_anchor_common.preprocess_gen_func_sig_via_mcp"
PARTIAL_NAME = "CNetworkMessages_FindNetworkMessagePartial"


class TestNetworkMessageComparisonProbe(unittest.TestCase):
    def _probe(self, target_names, partial_names):
        finder = load_module(SCRIPT, "network_message_comparisons_14197")
        names = {}

        def function(symbols, base):
            if symbols is None:
                return None
            calls = []
            for index, symbol in enumerate(symbols):
                address = base + index
                names[address] = symbol
                calls.append(N(op="call", x=N(op="cast", x=N(op="obj", obj_ea=address))))
            return N(body=calls)

        functions = {0x1000: function(target_names, 0x8000), 0x2000: function(partial_names, 0x9000)}

        class Visitor:
            def __init__(self, flags):
                pass

            def apply_to(self, body, parent):
                for expression in body:
                    self.visit_expr(expression)

        hx = N(
            decompile=functions.get,
            ctree_visitor_t=Visitor,
            CV_FAST=0,
            cot_cast="cast",
            cot_obj="obj",
            cot_call="call",
        )
        ida_names = N(
            get_name=names.get,
            demangle_name=lambda name, flags: {
                "_Z14V_stristr_fastPKcS0_": "V_stristr_fast(char const *, char const *)",
            }.get(name),
        )
        with patch.dict("sys.modules", {"ida_hexrays": hx, "ida_name": ida_names}):
            return finder._probe_network_message_comparisons(0x1000, 0x2000)

    def test_accepts_current_platform_comparator_names(self):
        self.assertTrue(self._probe(["V_stricmp_fast"], ["?V_stristr_fast@@YAPEBDPEBD0@Z"]))
        self.assertTrue(self._probe(["_V_stricmp_fast"], ["__Z14V_stristr_fastPKcS0_"]))

    def test_rejects_wrong_missing_or_mixed_comparison_calls(self):
        for target_names, partial_names in (
            ([], ["V_stristr_fast"]),
            (["V_stristr_fast"], ["V_stricmp_fast"]),
            (["V_stricmp_fast", "V_stristr_fast"], ["V_stristr_fast"]),
            (["SomeV_stricmp_fastHelper"], ["V_stristr_fast"]),
            (["V_stricmp_fast"], []),
        ):
            with self.subTest(target=target_names, partial=partial_names):
                self.assertFalse(self._probe(target_names, partial_names))

    def test_rejects_unavailable_decompilations(self):
        self.assertFalse(self._probe(None, ["V_stristr_fast"]))
        self.assertFalse(self._probe(["V_stricmp_fast"], None))


class TestFindNetworkMessageSkill(unittest.IsolatedAsyncioTestCase):
    async def _run(self, directory, *, platform="linux", partial_index=10, mutation=None, probe=True, fail_sig=False):
        finder = load_module(SCRIPT, "find_network_message_skill_14197")
        entries = {partial_index - 1: "0x1000", partial_index: "0x2000"}
        partial = {
            "func_name": PARTIAL_NAME,
            "func_va": "0x2000",
            "vtable_name": "CNetworkMessages",
            "vfunc_index": partial_index,
            "vfunc_offset": hex(partial_index * 8),
        }
        if mutation:
            mutation(entries, partial)
        Path(directory, f"CNetworkMessages_vtable.{platform}.yaml").write_text(
            yaml.safe_dump({"vtable_entries": entries}), encoding="utf-8"
        )
        Path(directory, f"{PARTIAL_NAME}.{platform}.yaml").write_text(yaml.safe_dump(partial), encoding="utf-8")
        output = Path(directory, f"{finder.TARGET_FUNCTION_NAMES[0]}.{platform}.yaml")
        session = AsyncMock()
        if isinstance(probe, Exception):
            session.call_tool.side_effect = probe
        else:
            session.call_tool.return_value = py_eval_payload(probe)
        signature = None if fail_sig else {"func_rva": "0x1000", "func_size": "0x80", "func_sig": "48 89 5C 24 ?? 57"}
        with patch(SIGNATURE_GENERATOR, AsyncMock(return_value=signature)) as generate:
            result = await finder.preprocess_skill(
                session=session,
                skill_name=SCRIPT.stem,
                expected_outputs=[str(output)],
                old_yaml_map={str(output): "obsolete-signature.yaml"},
                new_binary_dir=directory,
                platform=platform,
                image_base=0,
            )
        payload = yaml.safe_load(output.read_text(encoding="utf-8")) if output.exists() else None
        return result, payload, session, generate

    async def test_derives_the_preceding_slot_after_a_shift_on_both_platforms(self):
        for platform, partial_index in (("windows", 12), ("linux", 18)):
            with self.subTest(platform=platform), TemporaryDirectory() as directory:
                result, payload, _session, generate = await self._run(
                    directory, platform=platform, partial_index=partial_index
                )
                self.assertTrue(result)
                self.assertEqual(partial_index - 1, payload["vfunc_index"])
                self.assertEqual(hex((partial_index - 1) * 8), payload["vfunc_offset"])
                self.assertEqual("0x1000", payload["func_va"])
                self.assertIs(True, payload["func_sig_allow_across_function_boundary"])
                self.assertIs(True, generate.await_args.kwargs["allow_across_function_boundary"])

    async def test_rejects_stale_metadata_missing_predecessors_and_folded_entries(self):
        mutations = (
            lambda entries, partial: partial.update(func_va="0x9999"),
            lambda entries, partial: partial.update(vfunc_offset="0x10"),
            lambda entries, partial: partial.update(vtable_name="OtherInterface"),
            lambda entries, partial: partial.update(func_name="OtherFunction"),
            lambda entries, partial: entries.pop(9),
            lambda entries, partial: entries.update({9: "0x2000"}),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), TemporaryDirectory() as directory:
                result, payload, session, generate = await self._run(directory, mutation=mutation)
                self.assertFalse(result)
                self.assertIsNone(payload)
                session.call_tool.assert_not_awaited()
                generate.assert_not_awaited()
        with TemporaryDirectory() as directory:
            result, payload, session, generate = await self._run(directory, partial_index=0)
            self.assertFalse(result)
            self.assertIsNone(payload)
            session.call_tool.assert_not_awaited()
            generate.assert_not_awaited()

    async def test_rejects_failed_or_malformed_comparison_probes(self):
        for probe in (None, False, 1, "true", RuntimeError("IDA unavailable")):
            with self.subTest(probe=probe), TemporaryDirectory() as directory:
                result, payload, _session, generate = await self._run(directory, probe=probe)
                self.assertFalse(result)
                self.assertIsNone(payload)
                generate.assert_not_awaited()

    async def test_fails_closed_when_signature_generation_fails(self):
        with TemporaryDirectory() as directory:
            result, payload, _session, _generate = await self._run(directory, fail_sig=True)
        self.assertFalse(result)
        self.assertIsNone(payload)


if __name__ == "__main__":
    unittest.main()
