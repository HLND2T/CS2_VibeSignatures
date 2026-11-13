import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as N
from unittest.mock import AsyncMock, patch

import yaml

from ida_preprocessor_test_support import FakeCallToolResult, load_module, py_eval_payload


SCRIPT = (
    Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts/find-CNetworkMessages_FindNetworkMessage-14197.py"
)
SIGNATURE_GENERATOR = "ida_preprocessor_scripts._vtable_slot_anchor_common.preprocess_gen_func_sig_via_mcp"
PARTIAL_NAME = "CNetworkMessages_FindNetworkMessagePartial"


class TestNetworkMessageComparisonProbe(unittest.TestCase):
    def _probe(self, target_names, partial_names, *, bindings=None):
        finder = load_module(SCRIPT, "network_message_comparisons_14197")
        names = {}

        def function(symbols, base):
            if symbols is None:
                return None
            if isinstance(symbols, Exception):
                return symbols
            calls = []
            for index, symbol in enumerate(symbols):
                address = base + index
                if isinstance(symbol, str):
                    names[address] = symbol
                    callee = N(op="obj", obj_ea=address)
                else:
                    callee = symbol
                calls.append(N(op="call", ea=address + 0x100, x=N(op="cast", x=callee)))
            return N(body=calls)

        functions = {0x1000: function(target_names, 0x8000), 0x2000: function(partial_names, 0x9000)}

        class Visitor:
            def __init__(self, flags):
                pass

            def apply_to(self, body, parent):
                for expression in body:
                    self.visit_expr(expression)

        def decompile(address):
            result = functions.get(address)
            if isinstance(result, Exception):
                raise result
            return result

        hx = N(
            decompile=decompile,
            get_hexrays_version=lambda: "test-decompiler",
            ctree_visitor_t=Visitor,
            CV_FAST=0,
            cot_cast="cast",
            cot_obj="obj",
            cot_call="call",
            cot_helper="helper",
        )
        ida_names = N(
            get_name=names.get,
            demangle_name=lambda name, flags: {
                "_Z14V_stristr_fastPKcS0_": "V_stristr_fast(char const *, char const *)",
            }.get(name),
        )
        with (
            patch.dict(
                "sys.modules",
                {
                    "ida_hexrays": hx,
                    "ida_name": ida_names,
                    "idaapi": N(get_kernel_version=lambda: "test-ida"),
                    "ida_nalt": N(
                        retrieve_input_file_md5=lambda: b"\xab" * 16,
                        get_input_file_path=lambda: "/test/library",
                        get_import_module_qty=lambda: 0,
                    ),
                },
            ),
            patch.object(
                finder,
                "_resolve_imported_comparison_names",
                side_effect=lambda target, imports: (bindings or {}).get(target, []),
                create=True,
            ),
        ):
            return finder._probe_network_message_comparisons(0x1000, 0x2000)

    def test_accepts_current_platform_comparator_names(self):
        self.assertTrue(self._probe(["V_stricmp_fast"], ["?V_stristr_fast@@YAPEBDPEBD0@Z"])["valid"])
        self.assertTrue(self._probe(["_V_stricmp_fast"], ["__Z14V_stristr_fastPKcS0_"])["valid"])

    def test_rejects_wrong_missing_or_mixed_comparison_calls(self):
        for target_names, partial_names in (
            ([], ["V_stristr_fast"]),
            (["V_stristr_fast"], ["V_stricmp_fast"]),
            (["V_stricmp_fast", "V_stristr_fast"], ["V_stristr_fast"]),
            (["SomeV_stricmp_fastHelper"], ["V_stristr_fast"]),
            (["V_stricmp_fast"], []),
        ):
            with self.subTest(target=target_names, partial=partial_names):
                self.assertFalse(self._probe(target_names, partial_names)["valid"])

    def test_rejects_unavailable_decompilations(self):
        self.assertFalse(self._probe(None, ["V_stristr_fast"])["valid"])
        self.assertFalse(self._probe(["V_stricmp_fast"], None)["valid"])

    def test_reports_call_targets_names_and_database_identity(self):
        report = self._probe(["_V_stricmp_fast"], ["__Z14V_stristr_fastPKcS0_"])
        self.assertEqual("ab" * 16, report["context"]["input_md5"])
        self.assertEqual("test-ida", report["context"]["ida_version"])
        self.assertEqual("0x1000", report["exact"]["func_va"])
        self.assertEqual("_V_stricmp_fast", report["exact"]["calls"][0]["raw_name"])
        self.assertEqual("0x8000", report["exact"]["calls"][0]["target_va"])
        self.assertEqual(["V_stristr_fast"], report["partial"]["comparisons"])

    def test_records_decompiler_exceptions_without_skipping_the_other_role(self):
        report = self._probe(RuntimeError("cannot decompile"), ["V_stristr_fast"])
        self.assertFalse(report["valid"])
        self.assertIn("cannot decompile", report["exact"]["error"])
        self.assertEqual(["V_stristr_fast"], report["partial"]["comparisons"])

    def test_does_not_read_helper_union_fields_from_an_indirect_callee(self):
        class Indirect:
            op = "ptr"

            @property
            def helper(self):
                raise AssertionError("callee is not a helper")

        report = self._probe([Indirect()], ["V_stristr_fast"])
        self.assertFalse(report["valid"])
        self.assertIsNone(report["exact"]["error"])
        self.assertEqual("ptr", report["exact"]["calls"][0]["kind"])

    def test_accepts_unnamed_plt_stubs_only_with_the_correct_import_identity(self):
        bindings = {
            0x8000: [{"target_va": "0x5000", "name": "V_stricmp_fast"}],
            0x9000: [{"target_va": "0x6000", "name": "_Z14V_stristr_fastPKcS0_"}],
        }
        report = self._probe(["sub_8000"], ["sub_9000"], bindings=bindings)
        self.assertTrue(report["valid"])
        self.assertEqual(bindings[0x8000], report["exact"]["calls"][0]["import_bindings"])
        bindings[0x8000] = bindings[0x9000]
        self.assertFalse(self._probe(["sub_8000"], ["sub_9000"], bindings=bindings)["valid"])


class TestImportedComparisonTargets(unittest.TestCase):
    def _resolve(
        self,
        *,
        target=0x8000,
        segment=".plt",
        refs=(0x1000, 0x5000),
        flags=0,
        thunk=(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
        feature=3,
        earlier_feature=0,
        count=2,
    ):
        finder = load_module(SCRIPT, "network_message_imports_14197")
        imports = {0x5000: "V_stricmp_fast", 0x6000: "_Z14V_stristr_fastPKcS0_"}

        class Instruction:
            def get_canon_feature(self):
                return self.feature

        def decode(insn, address):
            insn.feature = feature if address == 0x8000 + count - 1 else earlier_feature
            return 1

        modules = {
            "ida_idaapi": N(BADADDR=0xFFFFFFFFFFFFFFFF),
            "ida_funcs": N(
                FUNC_THUNK=8,
                get_func=lambda address: N(start_ea=0x8000, flags=flags),
                calc_thunk_func_target=lambda fn: thunk,
            ),
            "ida_segment": N(getseg=lambda address: N(), get_segm_name=lambda seg: segment),
            "idautils": N(
                FuncItems=lambda address: range(0x8000, 0x8000 + count),
                CodeRefsFrom=lambda address, flow: refs,
                DataRefsFrom=lambda address: [0x9000],
            ),
            "ida_bytes": N(get_qword=lambda address: 0x5000),
            "ida_ua": N(insn_t=Instruction, decode_insn=decode),
            "ida_idp": N(CF_JUMP=1, CF_STOP=2, CF_CALL=4),
        }
        with patch.dict("sys.modules", modules):
            return finder._resolve_imported_comparison_names(target, imports)

    def test_resolves_direct_import_plt_got_and_native_thunk_targets(self):
        for kwargs in (
            dict(target=0x5000),
            {},
            dict(segment=".text", flags=8, thunk=(0x5000, 0xFFFFFFFFFFFFFFFF)),
            dict(segment=".text", flags=8, thunk=[0x5000, 0xFFFFFFFFFFFFFFFF]),
        ):
            with self.subTest(kwargs=kwargs):
                self.assertEqual([{"target_va": "0x5000", "name": "V_stricmp_fast"}], self._resolve(**kwargs))

    def test_rejects_arbitrary_wrappers_nonterminal_jumps_and_oversized_stubs(self):
        for kwargs in (
            dict(segment=".text"),
            dict(feature=1),
            dict(earlier_feature=4),
            dict(count=5),
            dict(segment=".text", flags=8, thunk=(0x8000, 0xFFFFFFFFFFFFFFFF)),
        ):
            with self.subTest(kwargs=kwargs):
                self.assertEqual([], self._resolve(**kwargs))

    def test_rejects_ambiguous_import_bindings(self):
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self._resolve(refs=(0x5000, 0x6000))


def _valid_probe():
    return {
        "valid": True,
        "context": {},
        "exact": {"func_va": "0x1000", "comparisons": ["V_stricmp_fast"], "calls": [], "error": None},
        "partial": {"func_va": "0x2000", "comparisons": ["V_stristr_fast"], "calls": [], "error": None},
    }


class TestFindNetworkMessageSkill(unittest.IsolatedAsyncioTestCase):
    async def _run(
        self,
        directory,
        *,
        platform="linux",
        partial_index=10,
        mutation=None,
        probe=True,
        fail_sig=False,
        stderr=None,
        debug=False,
    ):
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
            session.call_tool.return_value = (
                FakeCallToolResult({"result": "", "stderr": stderr})
                if stderr
                else py_eval_payload(_valid_probe() if probe is True else probe)
            )
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
                debug=debug,
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

    async def test_rejects_inconsistent_structured_reports(self):
        for field, value in (("func_va", "0x9999"), ("comparisons", ["V_stristr_fast"]), ("error", "failed")):
            report = _valid_probe()
            report["exact"][field] = value
            with self.subTest(field=field), TemporaryDirectory() as directory:
                result, payload, _, generate = await self._run(directory, probe=report)
                self.assertFalse(result)
                self.assertIsNone(payload)
                generate.assert_not_awaited()

    async def test_surfaces_ida_python_stderr_before_signature_generation(self):
        output = io.StringIO()
        with TemporaryDirectory() as directory, redirect_stdout(output):
            result, _, _, generate = await self._run(directory, stderr="decompiler import failed", debug=True)
        self.assertFalse(result)
        self.assertIn("decompiler import failed", output.getvalue())
        generate.assert_not_awaited()

    async def test_logs_structured_failure_evidence(self):
        report = _valid_probe()
        report["valid"] = False
        report["exact"]["comparisons"] = []
        report["exact"]["calls"] = [{"raw_name": "unresolved_comparator"}]
        output = io.StringIO()
        with TemporaryDirectory() as directory, redirect_stdout(output):
            result, _, _, generate = await self._run(directory, probe=report, debug=True)
        self.assertFalse(result)
        self.assertIn("unresolved_comparator", output.getvalue())
        generate.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
