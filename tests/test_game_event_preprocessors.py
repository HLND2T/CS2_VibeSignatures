import importlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as N
from unittest.mock import AsyncMock, patch

import yaml

from ida_preprocessor_test_support import load_module, py_eval_payload


SCRIPTS = Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts"
VTABLE = "CGameEventSystem"
POST = "CGameEventSystem_PostEventAbstract2"
SIBLING = "CGameEventSystem_PostEntityEventAbstract"
LOCAL = "IGameEventSystem_PostEventAbstract_Local"
GENERATOR = "ida_preprocessor_scripts._vtable_slot_anchor_common.preprocess_gen_func_sig_via_mcp"


def _seed_anchor(directory, platform, name, index, address, entries):
    Path(directory, f"{VTABLE}_vtable.{platform}.yaml").write_text(
        yaml.safe_dump({"vtable_entries": entries}), encoding="utf-8"
    )
    Path(directory, f"{name}.{platform}.yaml").write_text(
        yaml.safe_dump(
            {
                "func_name": name,
                "func_va": hex(address),
                "vtable_name": VTABLE,
                "vfunc_index": index,
                "vfunc_offset": hex(index * 8),
            }
        ),
        encoding="utf-8",
    )


class TestReceiverVcallSites(unittest.TestCase):
    def _probe(self, *, hoisted=False, extra_offset=None, foreign=False, unknown_assignment=False, include_sites=True):
        helper = importlib.import_module("ida_preprocessor_scripts._vtable_slot_anchor_common")

        class Arguments(list):
            def size(self):
                return len(self)

        def variable(index):
            return N(op="var", v=N(idx=index))

        def slot(offset, site):
            table = N(op="ptr", x=variable(7), type=N(is_ptr=lambda: False))
            return N(op="ptr", x=N(op="add", x=table, y=N(op="num", numval=lambda: offset)), ea=site)

        target = slot(0x70, 0x1100)
        body = []
        if hoisted:
            body.append(N(op="asg", x=variable(20), y=target))
            if unknown_assignment:
                body.append(N(op="asg", x=variable(20), y=N(op="obj", obj_ea=0x9000)))
            target = variable(20)
        body.append(
            N(op="call", x=target, a=Arguments([variable(8 if foreign else 7)]), ea=0x1110 if hoisted else 0x1100)
        )
        if extra_offset is not None:
            body.append(N(op="call", x=slot(extra_offset, 0x1200), a=Arguments([variable(7)]), ea=0x1200))

        class Visitor:
            def __init__(self, flags):
                pass

            def apply_to(self, expressions, parent):
                for expression in expressions:
                    self.visit_expr(expression)

        hx = N(
            decompile=lambda address: N(argidx=[7], body=body),
            ctree_visitor_t=Visitor,
            CV_FAST=0,
            cot_cast="cast",
            cot_var="var",
            cot_idx="idx",
            cot_num="num",
            cot_ptr="ptr",
            cot_add="add",
            cot_asg="asg",
            cot_call="call",
        )
        with patch.dict("sys.modules", {"ida_hexrays": hx, "ida_idaapi": N(BADADDR=-1)}):
            if include_sites:
                return helper._probe_receiver_vcall_offsets(0x1000, include_sites=True)
            return helper._probe_receiver_vcall_offsets(0x1000)

    def test_default_result_remains_an_offset_list(self):
        self.assertEqual([0x70], self._probe(include_sites=False))
        self.assertEqual([0x70], self._probe(hoisted=True, include_sites=False))

    def test_returns_direct_and_hoisted_slot_load_sites(self):
        expected = [{"offset": 0x70, "inst_vas": [0x1100]}]
        self.assertEqual(expected, self._probe())
        self.assertEqual(expected, self._probe(hoisted=True))

    def test_groups_repeated_calls_by_slot_and_preserves_distinct_offsets(self):
        self.assertEqual([{"offset": 0x70, "inst_vas": [0x1100, 0x1200]}], self._probe(extra_offset=0x70))
        self.assertEqual([0x70, 0x78], [entry["offset"] for entry in self._probe(extra_offset=0x78)])

    def test_ignores_foreign_receivers_and_unproven_function_pointer_assignments(self):
        self.assertEqual([], self._probe(foreign=True))
        self.assertEqual([], self._probe(hoisted=True, unknown_assignment=True))


class TestPostEventAbstract2Finder(unittest.IsolatedAsyncioTestCase):
    async def _run(self, directory, *, platform="linux", target_index=6, users=None, stale=False, fail_sig=False):
        finder = load_module(SCRIPTS / f"find-{POST}-14197.py", "post_event_abstract2_14197")
        entries = {target_index: "0x1000", 10: "0x2000", 12: "0x3000"}
        _seed_anchor(directory, platform, SIBLING, 10, 0x9999 if stale else 0x2000, entries)
        output = Path(directory, f"{POST}.{platform}.yaml")
        users = {0x1000, 0x2000, 0x8000} if users is None else users
        signature = None if fail_sig else {"func_rva": "0x1000", "func_size": "0x80", "func_sig": "55 48 89 E5 41 57"}
        with (
            patch.object(finder, "_collect_xref_func_starts_for_string", AsyncMock(return_value=users)) as collect,
            patch(GENERATOR, AsyncMock(return_value=signature)),
        ):
            result = await finder.preprocess_skill(
                session=AsyncMock(),
                skill_name="finder",
                expected_outputs=[str(output)],
                old_yaml_map={str(output): "obsolete-signature.yaml"},
                new_binary_dir=directory,
                platform=platform,
                image_base=0,
            )
        payload = yaml.safe_load(output.read_text(encoding="utf-8")) if output.exists() else None
        return result, payload, collect

    async def test_excludes_the_validated_sibling_and_derives_platform_specific_slots(self):
        for platform, index, users in (("linux", 6, {0x1000, 0x2000}), ("windows", 8, {0x1000})):
            with self.subTest(platform=platform), TemporaryDirectory() as directory:
                result, payload, _collect = await self._run(
                    directory, platform=platform, target_index=index, users=users
                )
                self.assertTrue(result)
                self.assertEqual(index, payload["vfunc_index"])
                self.assertEqual("0x1000", payload["func_va"])

    async def test_rejects_missing_or_ambiguous_remaining_candidates(self):
        for users in (set(), {0x2000}, {0x1000, 0x3000}):
            with self.subTest(users=users), TemporaryDirectory() as directory:
                result, payload, _collect = await self._run(directory, users=users)
                self.assertFalse(result)
                self.assertIsNone(payload)

    async def test_rejects_stale_sibling_metadata_and_signature_failure(self):
        for kwargs in ({"stale": True}, {"fail_sig": True}):
            with self.subTest(kwargs=kwargs), TemporaryDirectory() as directory:
                result, payload, collect = await self._run(directory, **kwargs)
                self.assertFalse(result)
                self.assertIsNone(payload)
                if kwargs.get("stale"):
                    collect.assert_not_awaited()


class TestLocalEventInterfaceFinder(unittest.IsolatedAsyncioTestCase):
    async def _run(self, directory, *, probe=None, signature_results=None, stale=False):
        finder = load_module(SCRIPTS / f"find-{LOCAL}-14197.py", "local_event_interface_14197")
        _seed_anchor(directory, "linux", POST, 6, 0x9999 if stale else 0x1600, {4: "0x1400", 6: "0x1600"})
        output = Path(directory, f"{LOCAL}.linux.yaml")
        session = AsyncMock()
        if isinstance(probe, Exception):
            session.call_tool.side_effect = probe
        else:
            session.call_tool.return_value = py_eval_payload(
                [{"offset": 0x20, "inst_vas": [0x3000, 0x3010]}] if probe is None else probe
            )
        results = [None, {"vfunc_sig": "48 8B 40 20 48 85 C0"}] if signature_results is None else signature_results
        with patch.object(finder, "preprocess_gen_vfunc_sig_via_mcp", AsyncMock(side_effect=results)) as generate:
            result = await finder.preprocess_skill(
                session=session,
                skill_name="finder",
                expected_outputs=[str(output)],
                old_yaml_map={},
                new_binary_dir=directory,
                platform="linux",
                image_base=0,
            )
        payload = yaml.safe_load(output.read_text(encoding="utf-8")) if output.exists() else None
        return result, payload, session, generate

    async def test_signs_a_proven_slot_load_when_the_first_site_is_not_unique(self):
        with TemporaryDirectory() as directory:
            result, payload, _session, generate = await self._run(directory)
        self.assertTrue(result)
        self.assertEqual(4, payload["vfunc_index"])
        self.assertEqual("0x20", payload["vfunc_offset"])
        self.assertEqual([0x3000, 0x3010], [call.kwargs["inst_va"] for call in generate.await_args_list])

    async def test_rejects_ambiguous_malformed_unaligned_or_missing_slot_probes(self):
        for probe in (
            [],
            True,
            [{"offset": 0x20, "inst_vas": []}],
            [{"offset": 0x21, "inst_vas": [0x3000]}],
            [{"offset": 0x80, "inst_vas": [0x3000]}],
            [{"offset": 0x20, "inst_vas": [True]}],
            [{"offset": 0x20, "inst_vas": [0x3000]}, {"offset": 0x30, "inst_vas": [0x3010]}],
            RuntimeError("IDA unavailable"),
        ):
            with self.subTest(probe=probe), TemporaryDirectory() as directory:
                result, payload, _session, generate = await self._run(directory, probe=probe)
                self.assertFalse(result)
                self.assertIsNone(payload)
                generate.assert_not_awaited()

    async def test_rejects_stale_source_metadata_and_exhausted_signature_candidates(self):
        for kwargs in ({"stale": True}, {"signature_results": [None, None]}):
            with self.subTest(kwargs=kwargs), TemporaryDirectory() as directory:
                result, payload, session, _generate = await self._run(directory, **kwargs)
                self.assertFalse(result)
                self.assertIsNone(payload)
                if kwargs.get("stale"):
                    session.call_tool.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
