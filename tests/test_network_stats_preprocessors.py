import importlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as N
from unittest.mock import AsyncMock, patch

import yaml

from ida_preprocessor_test_support import load_module, py_eval_payload


SCRIPTS = Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts"
SENDER = "CNetworkSystem_SendNetworkStats"
ANCHOR = "CNetworkMessages_FindNetworkGroup"


def _seed_anchor(directory, platform, index=4):
    entries = {index + delta: hex(0x1400 + delta * 0x100) for delta in range(4)}
    Path(directory, f"CNetworkMessages_vtable.{platform}.yaml").write_text(
        yaml.safe_dump({"vtable_entries": entries}), encoding="utf-8"
    )
    Path(directory, f"{ANCHOR}.{platform}.yaml").write_text(
        yaml.safe_dump(
            {
                "func_name": ANCHOR,
                "func_va": "0x1400",
                "vtable_name": "CNetworkMessages",
                "vfunc_index": index,
                "vfunc_offset": hex(index * 8),
            }
        ),
        encoding="utf-8",
    )


def _metrics(index=4):
    return {
        "receiver": 0x7000,
        "calls": [{"offset": (index + delta + 1) * 8, "inst_va": 0x3000 + delta * 0x10} for delta in range(3)],
    }


class TestStatsVcallProbe(unittest.TestCase):
    def _probe(self, records, *, scale=1, indexed=False, arities=(1, 2, 2)):
        helper = importlib.import_module("ida_preprocessor_scripts._network_stats_common")

        class Arguments(list):
            def size(self):
                return len(self)

        calls = []
        for offset, inst_va, argc, receiver, first_arg in records:
            table = N(
                op="ptr",
                x=N(op="obj", obj_ea=receiver),
                type=N(is_ptr=lambda: scale != 1, get_ptrarr_objsize=lambda: scale),
            )
            step = offset // (8 if indexed else scale)
            number = N(op="num", numval=lambda value=step: value)
            callee = (
                N(op="idx", x=table, y=number, type=N(get_size=lambda: 8))
                if indexed
                else N(op="ptr", x=N(op="add", x=table, y=number))
            )
            args = Arguments([N(op="obj", obj_ea=first_arg)] + [N(op="var") for _ in range(argc - 1)])
            calls.append(N(op="call", x=N(op="cast", x=callee), a=args, ea=inst_va))

        class Visitor:
            def __init__(self, flags):
                pass

            def apply_to(self, body, parent):
                for expression in body:
                    self.visit_expr(expression)

        hx = N(
            decompile=lambda address: N(body=calls),
            ctree_visitor_t=Visitor,
            CV_FAST=0,
            cot_cast="cast",
            cot_obj="obj",
            cot_ptr="ptr",
            cot_idx="idx",
            cot_num="num",
            cot_add="add",
            cot_call="call",
        )
        with patch.dict("sys.modules", {"ida_hexrays": hx}):
            return helper._probe_stats_group_calls(0x1000, [0x80, 0x88, 0x90], list(arities))

    @staticmethod
    def _records(receiver=0x7000, arities=(1, 2, 2)):
        return [
            (offset, 0x3000 + index * 0x10, arities[index], receiver, receiver)
            for index, offset in enumerate((0x80, 0x88, 0x90))
        ]

    def test_accepts_one_shared_receiver_on_both_color_abis(self):
        for arities in ((1, 2, 2), (1, 2, 3)):
            with self.subTest(arities=arities):
                data = self._probe(self._records(arities=arities), arities=arities)
                self.assertEqual(0x7000, data["receiver"])
                self.assertEqual([0x3000, 0x3010, 0x3020], [call["inst_va"] for call in data["calls"]])

    def test_accepts_scaled_and_indexed_vtable_loads(self):
        self.assertIsNotNone(self._probe(self._records(), scale=8))
        self.assertIsNotNone(self._probe(self._records(), indexed=True))

    def test_rejects_mixed_receivers_duplicate_calls_and_multiple_complete_groups(self):
        mixed = self._records()
        mixed[-1] = (0x90, 0x3020, 2, 0x8000, 0x8000)
        wrong_this = self._records()
        wrong_this[-1] = (0x90, 0x3020, 2, 0x7000, 0x8000)
        for records in (
            mixed,
            wrong_this,
            self._records() + [(0x88, 0x4000, 2, 0x7000, 0x7000)],
            self._records() + self._records(receiver=0x8000),
            self._records()[:-1],
        ):
            with self.subTest(records=records):
                self.assertIsNone(self._probe(records))

    def test_rejects_wrong_call_arity(self):
        self.assertIsNone(self._probe(self._records(arities=(2, 2, 2))))
        self.assertIsNone(self._probe(self._records(arities=(1, 2, 3))))


class TestStatsProbeTransport(unittest.IsolatedAsyncioTestCase):
    async def test_rejects_malformed_probe_payloads(self):
        helper = importlib.import_module("ida_preprocessor_scripts._network_stats_common")
        for payload in (
            True,
            {"receiver": True, "calls": _metrics()["calls"]},
            {"receiver": 0x7000, "calls": []},
            {"receiver": 0x7000, "calls": [{"offset": 8, "inst_va": 0x3000}] * 3},
        ):
            with self.subTest(payload=payload):
                session = AsyncMock()
                session.call_tool.return_value = py_eval_payload(payload)
                with self.assertRaises(ValueError):
                    await helper.probe_stats_group_calls(session, 0x1000, [5, 6, 7], "linux")


class TestStatsLayoutAnchor(unittest.TestCase):
    def test_rejects_stale_anchors_missing_getters_and_folded_roles(self):
        helper = importlib.import_module("ida_preprocessor_scripts._network_stats_common")
        for mutation in ("stale_va", "stale_offset", "wrong_class", "missing_anchor", "missing_getter", "folded"):
            with self.subTest(mutation=mutation), TemporaryDirectory() as directory:
                _seed_anchor(directory, "linux")
                anchor_path = Path(directory, f"{ANCHOR}.linux.yaml")
                table_path = Path(directory, "CNetworkMessages_vtable.linux.yaml")
                anchor = yaml.safe_load(anchor_path.read_text(encoding="utf-8"))
                table = yaml.safe_load(table_path.read_text(encoding="utf-8"))
                if mutation == "stale_va":
                    anchor["func_va"] = "0x9999"
                elif mutation == "stale_offset":
                    anchor["vfunc_offset"] = "0x10"
                elif mutation == "wrong_class":
                    anchor["vtable_name"] = "OtherInterface"
                elif mutation == "missing_anchor":
                    anchor = {}
                elif mutation == "missing_getter":
                    table["vtable_entries"].pop(7)
                else:
                    table["vtable_entries"][7] = table["vtable_entries"][6]
                anchor_path.write_text(yaml.safe_dump(anchor), encoding="utf-8")
                table_path.write_text(yaml.safe_dump(table), encoding="utf-8")
                self.assertIsNone(helper.load_group_slots(directory, "linux"))


class TestSendNetworkStatsFinder(unittest.IsolatedAsyncioTestCase):
    async def _run(self, directory, *, owners=None, error_owners=None, callers=None, matches=None, fail_sig=False):
        finder = load_module(SCRIPTS / f"find-{SENDER}-14197.py", "send_network_stats_14197")
        _seed_anchor(directory, "linux")
        output = Path(directory, f"{SENDER}.linux.yaml")
        owners = {0x1000} if owners is None else owners
        error_owners = {0x1000, 0x2000, 0x4000} if error_owners is None else error_owners
        callers = {0x2000} if callers is None else callers
        matches = {0x1000: _metrics()} if matches is None else matches

        async def signature(**kwargs):
            if fail_sig:
                return None
            address = kwargs["func_va"]
            return {"func_va": hex(address), "func_rva": hex(address), "func_size": "0x90", "func_sig": "55 48 89 E5 41 57"}

        with (
            patch.object(finder, "_collect_xref_func_starts_for_string", AsyncMock(side_effect=[owners, error_owners])),
            patch.object(finder, "_collect_single_call_or_jump_xref_func_starts_for_ea", AsyncMock(return_value=callers)) as caller_probe,
            patch.object(finder, "probe_stats_group_calls", AsyncMock(side_effect=lambda **kwargs: matches.get(kwargs["func_va"]))),
            patch.object(finder, "preprocess_gen_func_sig_via_mcp", AsyncMock(side_effect=signature)) as generate,
        ):
            result = await finder.preprocess_skill(
                session=AsyncMock(), skill_name="finder", expected_outputs=[str(output)], old_yaml_map={},
                new_binary_dir=directory, platform="linux", image_base=0,
            )
        payload = yaml.safe_load(output.read_text(encoding="utf-8")) if output.exists() else None
        return result, payload, caller_probe, generate

    async def test_resolves_fused_sender_without_probing_callers(self):
        with TemporaryDirectory() as directory:
            result, payload, callers, _generate = await self._run(directory)
        self.assertTrue(result)
        self.assertEqual("0x1000", payload["func_va"])
        callers.assert_not_awaited()

    async def test_resolves_the_unique_sender_calling_an_extracted_serializer(self):
        with TemporaryDirectory() as directory:
            result, payload, callers, _generate = await self._run(directory, matches={0x2000: _metrics()})
        self.assertTrue(result)
        self.assertEqual("0x2000", payload["func_va"])
        callers.assert_awaited_once()

    async def test_rejects_ambiguous_senders_missing_anchors_and_failed_signatures(self):
        cases = (
            {"owners": set()},
            {"owners": {0x1000, 0x3000}},
            {"error_owners": set()},
            {"matches": {}},
            {"matches": {0x2000: _metrics(), 0x4000: _metrics()}, "callers": {0x2000, 0x4000}},
            {"fail_sig": True},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), TemporaryDirectory() as directory:
                result, payload, _callers, _generate = await self._run(directory, **kwargs)
                self.assertFalse(result)
                self.assertIsNone(payload)


class TestNetworkGroupInterfaceFinder(unittest.IsolatedAsyncioTestCase):
    async def _run(self, directory, *, platform="linux", index=4, probe=None, fail_signature=None, bad_sender=False):
        finder = load_module(SCRIPTS / f"find-{SENDER}-decompiles-14197.py", "network_group_interfaces_14197")
        _seed_anchor(directory, platform, index=index)
        Path(directory, f"{SENDER}.{platform}.yaml").write_text(
            yaml.safe_dump({"func_name": "OtherFunction" if bad_sender else SENDER, "func_va": "0x2000"}),
            encoding="utf-8",
        )
        outputs = [Path(directory, f"{name}.{platform}.yaml") for name in finder.TARGET_FUNCTION_NAMES]
        generated_calls = []

        async def signature(**kwargs):
            generated_calls.append(kwargs)
            return None if len(generated_calls) == fail_signature else {"vfunc_sig": "FF 50 28 48 85 C0"}

        probe_mock = AsyncMock(return_value=_metrics(index)) if probe is None else AsyncMock(side_effect=probe)
        with (
            patch.object(finder, "probe_stats_group_calls", probe_mock),
            patch.object(finder, "preprocess_gen_vfunc_sig_via_mcp", AsyncMock(side_effect=signature)),
        ):
            result = await finder.preprocess_skill(
                session=AsyncMock(), skill_name="finder", expected_outputs=[str(path) for path in outputs],
                old_yaml_map={}, new_binary_dir=directory, platform=platform, image_base=0,
            )
        payloads = [yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else None for path in outputs]
        return result, payloads, generated_calls

    async def test_emits_current_slots_and_signs_the_actual_call_sites_on_both_platforms(self):
        for platform, index in (("windows", 8), ("linux", 12)):
            with self.subTest(platform=platform), TemporaryDirectory() as directory:
                result, payloads, calls = await self._run(directory, platform=platform, index=index)
                self.assertTrue(result)
                self.assertEqual([index + 1, index + 2, index + 3], [payload["vfunc_index"] for payload in payloads])
                self.assertEqual([0x3000, 0x3010, 0x3020], [call["inst_va"] for call in calls])
                self.assertEqual([(index + delta) * 8 for delta in (1, 2, 3)], [call["vfunc_offset"] for call in calls])

    async def test_rejects_failed_probes_and_stale_sender_identity(self):
        for kwargs in ({"bad_sender": True}, {"probe": RuntimeError("IDA unavailable")}):
            with self.subTest(kwargs=kwargs), TemporaryDirectory() as directory:
                result, payloads, calls = await self._run(directory, **kwargs)
                self.assertFalse(result)
                self.assertEqual([None, None, None], payloads)
                self.assertEqual([], calls)

    async def test_does_not_emit_partial_outputs_when_a_signature_fails(self):
        with TemporaryDirectory() as directory:
            result, payloads, _calls = await self._run(directory, fail_signature=2)
        self.assertFalse(result)
        self.assertEqual([None, None, None], payloads)


if __name__ == "__main__":
    unittest.main()
