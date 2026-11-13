import importlib
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as N
from unittest.mock import AsyncMock, Mock, patch

import yaml

from ida_preprocessor_test_support import load_module, py_eval_payload


SCRIPTS = Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts"
REMOVE = "CNetworkSystem_RemoveNetChannel"
BY_ADDRESS = "CNetworkSystem_RemoveNetChannelByAddress"


def var(index):
    return N(op="var", v=N(idx=index))


def number(value):
    return N(op="num", numval=lambda: value)


def pointer(expr):
    return N(op="ptr", x=expr)


def add(left, right):
    left.type = N(is_ptr=lambda: False)
    return N(op="add", x=left, y=right)


def field(offset=104, receiver=0):
    return pointer(add(var(receiver), number(offset)))


class Arguments(list):
    def size(self):
        return len(self)


def call(target, args, site=0x3000):
    return N(op="call", x=N(op="obj", obj_ea=target), a=Arguments(args), ea=site)


def assignment(index, source):
    return N(op="asg", x=var(index), y=source)


class TestChannelCallProof(unittest.TestCase):
    def _probe(self, body, mode, *, target=0x2000, fields=(104,), argc=3, local_arrays=(), debug=False):
        helper = importlib.import_module("ida_preprocessor_scripts._network_channel_remove_common")

        class Visitor:
            def __init__(self, flags):
                pass

            def apply_to(self, expressions, parent):
                def visit(expr):
                    self.visit_expr(expr)
                    for name in ("x", "y"):
                        if hasattr(expr, name):
                            visit(getattr(expr, name))
                    for arg in getattr(expr, "a", []):
                        visit(arg)

                for expression in expressions:
                    visit(expression)

        ops = ("cast", "obj", "ptr", "idx", "num", "add", "call", "asg", "var", "memptr", "ref", "preinc")
        locals_ = [N(type=lambda index=index: N(is_array=lambda: index in local_arrays)) for index in range(12)]
        hx = N(
            decompile=lambda address: N(body=body, argidx=list(range(argc)), get_lvars=lambda: locals_),
            ctree_visitor_t=Visitor,
            CV_FAST=0,
            **{f"cot_{op}": op for op in ops},
        )
        with patch.dict(
            "sys.modules",
            {
                "ida_hexrays": hx,
                "idc": N(STRTYPE_C=0),
                "ida_bytes": N(
                    get_strlit_contents=lambda address, length, string_type: (
                        b"CloseSocket" if address == 0x8000 else b"Other"
                    )
                ),
            },
        ):
            return helper._probe_channel_calls(0x1000, mode, target, list(fields), debug=debug)

    def test_recovers_one_helper_across_repeated_literal_close_calls(self):
        literal = N(op="obj", obj_ea=0x8000)
        body = [
            call(0x2000, [var(0), var(1), number(1000), literal, number(1)]),
            call(0x2000, [var(0), var(1), number(1000), literal, number(1)], 0x3010),
        ]
        self.assertEqual([0x2000], self._probe(body, "close_helper")["helper_vas"])

    def test_ignores_wrong_literal_or_receiver_when_recovering_helper(self):
        for receiver, literal in ((var(1), 0x8000), (var(0), 0x8100)):
            self.assertIsNone(
                self._probe(
                    [call(0x2000, [receiver, var(1), number(0), N(op="obj", obj_ea=literal), number(1)])],
                    "close_helper",
                )
            )

    def test_proves_remove_calls_the_helper_on_this_and_reads_current_fields(self):
        body = [field(), call(0x2000, [var(0), var(4), var(5), var(6), number(1)])]
        self.assertEqual([104], self._probe(body, "remove")["receiver_fields"])
        self.assertIsNone(self._probe(body, "remove", argc=2))
        self.assertIsNone(self._probe(body, "remove", target=0x9000))
        self.assertIsNone(self._probe([assignment(0, var(1))] + body, "remove"))

    def test_accepts_lookup_result_and_local_alias(self):
        lookup = call(0x5000, [var(0), var(1), N(op="ref", x=var(8))], 0x3010)
        body = [assignment(4, lookup), assignment(5, var(4)), call(0x2000, [var(0), var(5), number(0)], 0x3020)]
        self.assertEqual([0x3020], self._probe(body, "by_address")["call_vas"])

    def test_accepts_inlined_collection_lookup_with_zero_fallback(self):
        loaded_channel = pointer(add(field(), var(9)))
        body = [assignment(4, loaded_channel), assignment(4, number(0)), call(0x2000, [var(0), var(4), number(0)])]
        self.assertIsNotNone(self._probe(body, "by_address"))
        self.assertIsNone(self._probe(body, "by_address", fields=(184,)))

    def test_accepts_decayed_local_address_arrays_but_rejects_runtime_pointers(self):
        body = [
            assignment(4, call(0x5000, [var(0), var(1), var(8)], 0x3010)),
            call(0x2000, [var(0), var(4), number(0)], 0x3020),
        ]
        self.assertIsNotNone(self._probe(body, "by_address", local_arrays=(8,)))
        self.assertIsNone(self._probe(body, "by_address"))

    def test_reports_the_failed_channel_source_condition(self):
        body = [
            assignment(4, call(0x5000, [var(0), var(1), var(8)], 0x3010)),
            call(0x2000, [var(0), var(4), number(0)], 0x3020),
        ]
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertIsNone(self._probe(body, "by_address", debug=True))
        self.assertIn("by_address at 0x1000", output.getvalue())
        self.assertIn("lookup address is not a local object", output.getvalue())

    def test_reports_an_unexpected_argument_count(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertIsNone(self._probe([], "remove", argc=4, debug=True))
        self.assertIn("expected 3 arguments, found 4", output.getvalue())

    def test_rejects_foreign_receivers_unproven_sources_and_nonzero_flags(self):
        for source in (
            number(0),
            var(1),
            pointer(add(field(receiver=1), var(9))),
            call(0x5000, [var(1), var(1), var(8)]),
            call(0x5000, [var(0), var(2), var(8)]),
        ):
            with self.subTest(source=source):
                self.assertIsNone(
                    self._probe([assignment(4, source), call(0x2000, [var(0), var(4), number(0)])], "by_address")
                )
        source = pointer(add(field(), var(9)))
        for receiver, flag in ((var(1), number(0)), (var(0), number(1)), (var(0), var(2))):
            self.assertIsNone(
                self._probe([assignment(4, source), call(0x2000, [receiver, var(4), flag])], "by_address")
            )

    def test_rejects_cycles_mutations_unknown_assignments_and_duplicate_dispatches(self):
        proven = assignment(4, pointer(add(field(), var(9))))
        dispatch = call(0x2000, [var(0), var(4), number(0)])
        for extra in (
            assignment(4, var(8)),
            N(op="preinc", x=var(4)),
            N(op="ref", x=var(4)),
            call(0x2000, [var(0), var(4), number(0)], 0x3010),
        ):
            self.assertIsNone(self._probe([proven, extra, dispatch], "by_address"))
        self.assertIsNone(self._probe([assignment(4, var(5)), assignment(5, var(4)), dispatch], "by_address"))


def seed(directory, index=7, *, stale=False):
    Path(directory, "CNetworkSystem_vtable.linux.yaml").write_text(
        yaml.safe_dump({"vtable_entries": {index: "0x2000", index + 1: "0x2100", index + 5: "0x2500"}}),
        encoding="utf-8",
    )
    Path(directory, f"{REMOVE}.linux.yaml").write_text(
        yaml.safe_dump(
            dict(
                func_name=REMOVE,
                func_va="0x9999" if stale else "0x2000",
                vtable_name="CNetworkSystem",
                vfunc_index=index,
                vfunc_offset=hex(index * 8),
            )
        ),
        encoding="utf-8",
    )


class TestThreadIdImportRepair(unittest.TestCase):
    def _repair(self, *, imports=None, apply=None, parse_ok=True, call_kind="near"):
        helper = importlib.import_module("ida_preprocessor_scripts._network_channel_remove_common")
        if imports is None:
            imports = [{"name": "ThreadGetCurrentId", "binding_kind": "elf_relocation"}]
        reader = Mock(return_value={"relocations": {0x9000: "ThreadGetCurrentId"}})
        resolver = Mock(return_value=imports)
        apply = apply if apply is not None else Mock(return_value=True)
        dirty = Mock()
        parse = Mock(return_value=parse_ok)
        with patch.dict(
            "sys.modules",
            {
                "ida_hexrays": N(mark_cfunc_dirty=dirty),
                "ida_idp": N(CF_CALL=1),
                "ida_loader": N(get_path=lambda kind: "/test/network.so", PATH_TYPE_CMD=0),
                "ida_nalt": N(
                    get_input_file_path=lambda: "/test/network.so",
                    get_imagebase=lambda: 0,
                    retrieve_input_file_md5=lambda: b"\xab" * 16,
                ),
                "ida_typeinf": N(tinfo_t=lambda: N(), parse_decl=parse, apply_tinfo=apply, PT_SIL=1, TINFO_DEFINITE=2),
                "ida_ua": N(
                    insn_t=lambda: N(ops=[N(type=call_kind, addr=0x5000)], get_canon_feature=lambda: 1),
                    decode_insn=lambda insn, site: 5,
                    o_near="near",
                ),
                "idautils": N(FuncItems=lambda address: [0x1010] if address == 0x1000 else []),
            },
        ):
            result = helper._repair_thread_id_import((0x1000, 0x1100), reader, resolver)
        return result, apply, dirty, parse, reader

    def test_repairs_phantom_arguments_before_repeating_the_strict_pair_proof(self):
        # Native replay: the zero-argument thread-id PLT acquired a five-argument
        # inferred prototype, making removal forward incoming rcx/r8 as a4/a5.
        state = {"argc": 5}
        body = [field(), call(0x2000, [var(0), var(4), var(5), var(6), number(1)])]
        proof = TestChannelCallProof()
        self.assertIsNone(proof._probe(body, "remove", argc=state["argc"]))

        def correct_import(address, prototype, flags):
            state["argc"] = 3
            return True

        result, apply, dirty, parse, reader = self._repair(apply=Mock(side_effect=correct_import))
        self.assertEqual({"normalized_targets": [0x5000]}, result)
        self.assertEqual([104], proof._probe(body, "remove", argc=state["argc"])["receiver_fields"])
        self.assertEqual([0x1000, 0x1100], [args[0][0] for args in dirty.call_args_list])
        self.assertEqual("unsigned long long __fastcall ThreadGetCurrentId(void);", parse.call_args.args[2])
        reader.assert_called_once_with(["/test/network.so", "/test/network.so"], 0, b"\xab" * 16)

    def test_does_not_retype_unverified_lookalike_ambiguous_or_indirect_calls(self):
        for imports in (
            [],
            [{"name": "ThreadGetCurrentId"}],
            [{"name": "OtherThreadGetCurrentId", "binding_kind": "elf_relocation"}],
            [{"name": "ThreadGetCurrentId", "binding_kind": "elf_relocation"}] * 2,
        ):
            with self.subTest(imports=imports):
                result, apply, dirty, _, _ = self._repair(imports=imports)
                self.assertEqual([], result["normalized_targets"])
                apply.assert_not_called()
                dirty.assert_not_called()
        result, apply, _, _, _ = self._repair(call_kind="indirect")
        self.assertEqual([], result["normalized_targets"])
        apply.assert_not_called()

    def test_fails_when_the_verified_prototype_cannot_be_parsed_or_applied(self):
        with self.assertRaisesRegex(ValueError, "unable to parse"):
            self._repair(parse_ok=False)
        with self.assertRaisesRegex(ValueError, "unable to apply"):
            self._repair(apply=Mock(return_value=False))


class TestChannelProbeTransport(unittest.IsolatedAsyncioTestCase):
    async def test_import_repair_is_linux_only_and_reports_transport_errors(self):
        helper = importlib.import_module("ida_preprocessor_scripts._network_channel_remove_common")
        session = AsyncMock()
        await helper.repair_channel_imports(session, (0x1000, 0x1100), "windows")
        session.call_tool.assert_not_awaited()
        with patch.object(helper, "parse_mcp_result", return_value={"stderr": "ELF identity mismatch"}):
            with self.assertRaisesRegex(ValueError, "ELF identity mismatch"):
                await helper.repair_channel_imports(session, (0x1000, 0x1100), "linux")
        for payload in (None, {"normalized_targets": [True]}, {"normalized_targets": [0x5000, 0x5000]}):
            session.call_tool.return_value = py_eval_payload(payload)
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                await helper.repair_channel_imports(session, (0x1000, 0x1100), "linux")

    async def test_relays_ida_diagnostics_only_in_debug_mode(self):
        helper = importlib.import_module("ida_preprocessor_scripts._network_channel_remove_common")
        for debug in (False, True):
            session = AsyncMock()
            session.call_tool.return_value = py_eval_payload(None)
            diagnostic = "channel-removal by_address: source rejected"
            with patch.object(
                helper, "parse_mcp_result", return_value={"result": "null", "stdout": diagnostic, "stderr": ""}
            ):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertIsNone(await helper.probe_channel_calls(session, 0x1000, "by_address", debug=debug))
                self.assertEqual(diagnostic + "\n" if debug else "", output.getvalue())

    async def test_surfaces_ida_python_errors(self):
        helper = importlib.import_module("ida_preprocessor_scripts._network_channel_remove_common")
        with patch.object(helper, "parse_mcp_result", return_value={"result": "", "stderr": "IDA Python failed"}):
            with self.assertRaisesRegex(ValueError, "IDA Python failed"):
                await helper.probe_channel_calls(AsyncMock(), 0x1000, "close_helper")

    async def test_rejects_malformed_probe_data(self):
        helper = importlib.import_module("ida_preprocessor_scripts._network_channel_remove_common")
        for mode, payload in (
            ("close_helper", True),
            ("close_helper", {"helper_vas": [True]}),
            ("remove", {"receiver_fields": [-1], "call_vas": [0x1000]}),
            ("by_address", {"call_vas": []}),
            ("by_address", {"call_vas": [0x1000, 0x1000]}),
        ):
            with self.subTest(mode=mode, payload=payload):
                session = AsyncMock()
                session.call_tool.return_value = py_eval_payload(payload)
                with self.assertRaises(ValueError):
                    await helper.probe_channel_calls(session, 0x1000, mode)


class TestRemovePairResolver(unittest.IsolatedAsyncioTestCase):
    async def _run(self, directory, *, mutation=None):
        helper = importlib.import_module("ida_preprocessor_scripts._network_channel_remove_common")
        seed(directory)
        if mutation in ("ambiguous", "folded", "missing"):
            path = Path(directory, "CNetworkSystem_vtable.linux.yaml")
            table = yaml.safe_load(path.read_text(encoding="utf-8"))
            if mutation == "ambiguous":
                table["vtable_entries"][13] = "0x2600"
            elif mutation == "folded":
                table["vtable_entries"][8] = "0x2000"
            else:
                table["vtable_entries"].pop(8)
            path.write_text(yaml.safe_dump(table), encoding="utf-8")

        async def probe(session, func_va, mode, **kwargs):
            if mutation == "transport":
                raise RuntimeError("IDA unavailable")
            if mode == "close_helper":
                return {"helper_vas": [0x5000, 0x5100] if mutation == "helpers" else [0x5000]}
            if mode == "remove":
                return {"receiver_fields": [104], "call_vas": [0x3000]}
            return None if mutation == "pair" else {"call_vas": [0x3010]}

        with (
            patch.object(
                helper,
                "_collect_xref_func_starts_for_string",
                AsyncMock(return_value=set() if mutation == "owners" else {0x1000, 0x1100}),
            ),
            patch.object(
                helper, "_collect_single_call_or_jump_xref_func_starts_for_ea", AsyncMock(return_value={0x2000, 0x2500})
            ),
            patch.object(helper, "probe_channel_calls", AsyncMock(side_effect=probe)),
            patch.object(helper, "repair_channel_imports", AsyncMock()),
        ):
            return await helper.resolve_remove_pair(AsyncMock(), directory, "linux")

    async def test_resolves_only_the_candidate_with_an_adjacent_proven_caller(self):
        with TemporaryDirectory() as directory:
            entries, slot = await self._run(directory)
        self.assertEqual(7, slot)
        self.assertEqual(0x2100, entries[slot + 1])

    async def test_rejects_missing_or_ambiguous_helpers_failed_pair_and_transport(self):
        for mutation in ("owners", "helpers", "pair", "transport", "ambiguous", "folded", "missing"):
            with self.subTest(mutation=mutation), TemporaryDirectory() as directory:
                self.assertIsNone(await self._run(directory, mutation=mutation))


class TestChannelFinders(unittest.IsolatedAsyncioTestCase):
    async def _run(self, target, *, stale=False, failed=False, outside=False):
        finder = load_module(SCRIPTS / f"find-{target}-14197.py", f"{target}_14197")
        with TemporaryDirectory() as directory:
            seed(directory, index=11, stale=stale)
            output = Path(directory, "nested" if outside else "", f"{target}.linux.yaml")
            with (
                patch.object(finder, "resolve_remove_pair", AsyncMock(return_value=({11: 0x2000, 12: 0x2100}, 11))),
                patch.object(finder, "_write_slot_func_yaml", AsyncMock(return_value=not failed)) as write,
            ):
                result = await finder.preprocess_skill(AsyncMock(), "finder", [str(output)], {}, directory, "linux", 0)
            return result, write

    async def test_signs_current_pair_slots_for_both_roles(self):
        for target, expected in ((REMOVE, 11), (BY_ADDRESS, 12)):
            result, write = await self._run(target)
            self.assertTrue(result)
            self.assertEqual(expected, write.call_args.kwargs["slot"])

    async def test_rejects_stale_remove_anchor_failed_signature_and_outside_output(self):
        self.assertFalse((await self._run(BY_ADDRESS, stale=True))[0])
        for target in (REMOVE, BY_ADDRESS):
            self.assertFalse((await self._run(target, failed=True))[0])
            result, write = await self._run(target, outside=True)
            self.assertFalse(result)
            write.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
