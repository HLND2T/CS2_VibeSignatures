import importlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as N
from unittest.mock import AsyncMock, patch

import yaml

from ida_preprocessor_test_support import load_module


SCRIPTS = Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts"
NAME = "INetworkMessages_FindNetworkMessageById"
PRIORITY = "CNetworkMessages_RegisterFieldChangeCallbackPriority"
INFO = "INetworkMessages_GetNetMessageInfo"


class TestGlobalReceiverResultFlow(unittest.TestCase):
    def _probe(self, mode="local"):
        helper = importlib.import_module("ida_preprocessor_scripts._global_receiver_vcalls_common")

        class Arguments(list):
            def size(self):
                return len(self)

        def var(index):
            return N(op="var", v=N(idx=index))

        def call(offset, site, argument, receiver=0x7000):
            def receiver_expr():
                if mode in ("array", "pointer_array"):
                    return N(
                        op="idx",
                        x=N(op="obj", obj_ea=receiver - 16, type=N(is_array=lambda: mode == "array")),
                        y=N(op="num", numval=lambda: 2),
                        type=N(get_size=lambda: 8),
                    )
                return N(op="obj", obj_ea=receiver)

            table = N(op="ptr", x=receiver_expr(), type=N(is_ptr=lambda: False))
            target = N(op="ptr", x=N(op="add", x=table, y=N(op="num", numval=lambda: offset)))
            return N(op="call", x=target, ea=site, a=Arguments([receiver_expr(), argument]))

        lookup = call(0x98, 0x3000, var(0))
        assignments = [N(op="asg", x=var(1), y=lookup)]
        argument = var(1)
        if mode == "alias":
            assignments.append(N(op="asg", x=var(2), y=var(1)))
            argument = var(2)
        elif mode == "nested":
            assignments = []
            argument = lookup
        elif mode == "missing":
            assignments = []
        elif mode == "wrong":
            argument = var(3)
        elif mode == "ambiguous":
            assignments.append(N(op="asg", x=var(1), y=var(0)))
        elif mode == "repeated":
            assignments.append(N(op="asg", x=var(1), y=lookup))
        elif mode in ("mutated", "escaped"):
            assignments.append(N(op="preinc" if mode == "mutated" else "ref", x=var(1)))
        elif mode == "cycle":
            assignments = [N(op="asg", x=var(1), y=var(2)), N(op="asg", x=var(2), y=var(1))]
        consumer = call(0x30, 0x3010, argument, 0x8000 if mode == "receiver" else 0x7000)

        class Visitor:
            def __init__(self, flags):
                pass

            def apply_to(self, body, parent):
                for expr in body:
                    self.visit_expr(expr)

        hx = N(
            decompile=lambda address: N(body=assignments + [lookup, consumer]),
            ctree_visitor_t=Visitor,
            CV_FAST=0,
            **{
                f"cot_{op}": op
                for op in ("cast", "obj", "ptr", "idx", "num", "add", "call", "asg", "var", "preinc", "ref")
            },
        )
        with patch.dict("sys.modules", {"ida_hexrays": hx}):
            return helper._probe_global_receiver_calls(0x1000, [0x98, 0x30], [2, 2], (0, 1, 1))

    def test_accepts_single_assignment_alias_and_nested_return_flow(self):
        for mode in ("local", "alias", "nested", "array"):
            with self.subTest(mode=mode):
                self.assertEqual(0x7000, self._probe(mode)["receiver"])

    def test_rejects_unproven_or_ambiguous_return_flow_and_other_receivers(self):
        for mode in (
            "missing",
            "wrong",
            "ambiguous",
            "repeated",
            "cycle",
            "receiver",
            "pointer_array",
            "mutated",
            "escaped",
        ):
            with self.subTest(mode=mode):
                self.assertIsNone(self._probe(mode))


class TestByIdFinder(unittest.IsolatedAsyncioTestCase):
    async def _run(self, *, index=18, mutation=None, receivers=(0x7000, 0x7000), fail_first=False, fail_all=False):
        finder = load_module(SCRIPTS / f"find-{NAME}-14197.py", "by_id_14197")
        with TemporaryDirectory() as directory:
            engine = Path(directory, "engine")
            network = Path(directory, "networksystem")
            engine.mkdir()
            network.mkdir()
            table = {index: "0x1400", index + 1: "0x1500", 6: "0x1600"}
            priority = dict(
                func_name=PRIORITY,
                func_va="0x1400",
                vtable_name="CNetworkMessages",
                vfunc_index=index,
                vfunc_offset=hex(index * 8),
            )
            info = dict(func_name=INFO, vtable_name="INetworkMessages", vfunc_index=6, vfunc_offset="0x30")
            if mutation == "priority":
                priority["func_va"] = "0x9999"
            elif mutation == "missing_slot":
                table.pop(index + 1)
            elif mutation == "info_offset":
                info["vfunc_offset"] = "0x38"
            elif mutation == "info_class":
                info["vtable_name"] = "OtherInterface"
            for root, name, payload in (
                (network, "CNetworkMessages_vtable", {"vtable_entries": table}),
                (network, PRIORITY, priority),
                (engine, INFO, info),
            ):
                (root / f"{name}.linux.yaml").write_text(yaml.safe_dump(payload), encoding="utf-8")
            output = engine / f"{NAME}.linux.yaml"
            if mutation == "output":
                output = network / f"{NAME}.linux.yaml"
            matches = {
                0x1000 + i * 0x100: {
                    "receiver": receiver,
                    "calls": [
                        {"offset": (index + 1) * 8, "inst_va": 0x3000 + i * 0x10},
                        {"offset": 0x30, "inst_va": 0x4000 + i * 0x10},
                    ],
                }
                for i, receiver in enumerate(receivers)
            }
            calls = []

            async def signature(**kwargs):
                calls.append(kwargs)
                return None if fail_all or (fail_first and len(calls) == 1) else {"vfunc_sig": "FF 90 98 00 00 00"}

            probe = AsyncMock(side_effect=lambda **kwargs: matches.get(kwargs["func_va"]))
            if mutation == "transport":
                probe.side_effect = RuntimeError("IDA unavailable")
            with (
                patch.object(finder, "_collect_xref_func_starts_for_string", AsyncMock(return_value=set(matches))),
                patch.object(finder, "probe_global_receiver_calls", probe),
                patch.object(finder, "preprocess_gen_vfunc_sig_via_mcp", AsyncMock(side_effect=signature)),
            ):
                result = await finder.preprocess_skill(
                    AsyncMock(), "finder", [str(output)], {}, str(engine), "linux", 0
                )
            payload = yaml.safe_load(output.read_text(encoding="utf-8")) if output.exists() else None
            return result, payload, calls, probe

    async def test_derives_shifted_slot_and_accepts_equivalent_call_contexts(self):
        result, payload, calls, probe = await self._run(index=20)
        self.assertTrue(result)
        self.assertEqual(21, payload["vfunc_index"])
        self.assertEqual(0x3000, calls[0]["inst_va"])
        self.assertEqual((0, 1, 1), probe.call_args.kwargs["result_flow"])

    async def test_tries_next_proven_site_if_first_signature_is_not_unique(self):
        result, payload, calls, _ = await self._run(fail_first=True)
        self.assertTrue(result)
        self.assertEqual([0x3000, 0x3010], [call["inst_va"] for call in calls])

    async def test_rejects_stale_metadata_missing_context_and_conflicting_receivers(self):
        cases = [
            dict(mutation=value)
            for value in ("priority", "missing_slot", "info_offset", "info_class", "transport", "output")
        ]
        cases += [dict(receivers=()), dict(receivers=(0x7000, 0x8000)), dict(fail_all=True)]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                result, payload, _, _ = await self._run(**kwargs)
                self.assertFalse(result)
                self.assertIsNone(payload)


if __name__ == "__main__":
    unittest.main()
