import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as N
from unittest.mock import AsyncMock, patch

import yaml

from ida_preprocessor_test_support import load_module, py_eval_payload


SCRIPT = (
    Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts/find-CNetworkMessages_vtable-decompiles-14197.py"
)
SIGNATURE_GENERATOR = "ida_preprocessor_scripts._vtable_slot_anchor_common.preprocess_gen_func_sig_via_mcp"
CALLBACK_NAME = "CNetworkMessages_RegisterNetworkFieldChangeCallbackInternal"


class TestRegistrationBytePairProbe(unittest.TestCase):
    def _probe(
        self,
        *,
        setter_offset=456,
        getter_offset=456,
        setter_width=1,
        getter_width=1,
        getter_receiver=2,
        setter_value=9,
        setter_statements=1,
        getter_statements=1,
        member_access=False,
        setter_scale=1,
        getter_scale=1,
    ):
        finder = load_module(SCRIPT, "registration_byte_pair_14197")

        def field(receiver, offset, width, scale):
            argument = N(
                op="var", v=N(idx=receiver), type=N(is_ptr=lambda: scale != 1, get_ptrarr_objsize=lambda: scale)
            )
            value_type = N(get_size=lambda: width)
            if member_access:
                return N(op="memptr", x=argument, m=offset, type=value_type)
            address = N(op="add", x=argument, y=N(op="num", numval=lambda: offset))
            return N(op="ptr", x=address, type=value_type)

        assignment = N(
            op="asg",
            x=field(4, setter_offset, setter_width, setter_scale),
            y=N(op="cast", x=N(op="var", v=N(idx=setter_value))),
        )
        setter_statement = N(op="expr", cexpr=assignment)
        getter_statement = N(
            op="return",
            creturn=N(expr=N(op="cast", x=field(getter_receiver, getter_offset, getter_width, getter_scale))),
        )
        functions = {
            0x1000: N(argidx=[4, 9], body=N(cblock=[setter_statement] * setter_statements)),
            0x2000: N(argidx=[2], body=N(cblock=[getter_statement] * getter_statements)),
        }
        hx = N(
            decompile=functions.get,
            cot_cast="cast",
            cot_var="var",
            cot_num="num",
            cot_add="add",
            cot_ptr="ptr",
            cot_memptr="memptr",
            cot_asg="asg",
            cit_expr="expr",
            cit_return="return",
        )
        with patch.dict("sys.modules", {"ida_hexrays": hx}):
            return finder._probe_registration_byte_pair(0x1000, 0x2000)

    def test_accepts_matching_byte_fields_with_different_local_argument_indices(self):
        self.assertEqual(456, self._probe())
        self.assertEqual(789, self._probe(setter_offset=789, getter_offset=789))

    def test_accepts_typed_member_access(self):
        self.assertEqual(456, self._probe(member_access=True))

    def test_accounts_for_pointer_arithmetic_scaling(self):
        self.assertEqual(456, self._probe(setter_offset=57, setter_scale=8))
        self.assertIsNone(self._probe(setter_scale=8))

    def test_rejects_different_fields_widths_receivers_and_values(self):
        for kwargs in (
            {"getter_offset": 457},
            {"setter_width": 4},
            {"getter_width": 4},
            {"getter_receiver": 7},
            {"setter_value": 4},
            {"setter_offset": 0, "getter_offset": 0},
            {"setter_offset": -8, "getter_offset": -8},
        ):
            with self.subTest(kwargs=kwargs):
                self.assertIsNone(self._probe(**kwargs))

    def test_rejects_complex_or_missing_bodies(self):
        for kwargs in (
            {"setter_statements": 0},
            {"setter_statements": 2},
            {"getter_statements": 0},
            {"getter_statements": 2},
        ):
            with self.subTest(kwargs=kwargs):
                self.assertIsNone(self._probe(**kwargs))


class TestRegistrationBytePairSkill(unittest.IsolatedAsyncioTestCase):
    async def _run(self, directory, *, platform="linux", callback_index=4, mutation=None, probe=456, fail_sig=False):
        finder = load_module(SCRIPT, "registration_byte_pair_skill_14197")
        entries = {callback_index: "0x1400", callback_index + 1: "0x1500", callback_index + 2: "0x1600"}
        callback = {
            "func_name": CALLBACK_NAME,
            "func_va": "0x1400",
            "vtable_name": "CNetworkMessages",
            "vfunc_index": callback_index,
            "vfunc_offset": hex(callback_index * 8),
        }
        if mutation:
            mutation(entries, callback)
        Path(directory, f"CNetworkMessages_vtable.{platform}.yaml").write_text(
            yaml.safe_dump({"vtable_entries": entries}), encoding="utf-8"
        )
        Path(directory, f"{CALLBACK_NAME}.{platform}.yaml").write_text(yaml.safe_dump(callback), encoding="utf-8")
        outputs = [Path(directory, f"{name}.{platform}.yaml") for name in finder.TARGET_FUNCTION_NAMES]
        session = AsyncMock()
        if isinstance(probe, Exception):
            session.call_tool.side_effect = probe
        else:
            session.call_tool.return_value = py_eval_payload(probe)

        async def generate_signature(**kwargs):
            if fail_sig:
                return None
            return {"func_rva": kwargs["func_va"], "func_size": "0x8", "func_sig": "0F B6 81 ?? ?? ?? ?? C3"}

        with patch(SIGNATURE_GENERATOR, AsyncMock(side_effect=generate_signature)) as generate:
            result = await finder.preprocess_skill(
                session=session,
                skill_name=SCRIPT.stem,
                expected_outputs=[str(path) for path in outputs],
                old_yaml_map={str(path): "obsolete-slot.yaml" for path in outputs},
                new_binary_dir=directory,
                platform=platform,
                image_base=0,
            )
        payloads = [yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else None for path in outputs]
        return result, payloads, session, generate

    async def test_derives_shifted_slots_from_the_current_callback_on_both_platforms(self):
        for platform, index in (("windows", 10), ("linux", 20)):
            with self.subTest(platform=platform), TemporaryDirectory() as directory:
                result, payloads, _session, _generate = await self._run(
                    directory, platform=platform, callback_index=index
                )
                self.assertTrue(result)
                self.assertEqual([index + 1, index + 2], [payload["vfunc_index"] for payload in payloads])
                self.assertEqual(["0x1500", "0x1600"], [payload["func_va"] for payload in payloads])

    async def test_rejects_stale_callback_metadata_and_missing_or_folded_slots(self):
        mutations = (
            lambda entries, callback: callback.update(func_va="0x9999"),
            lambda entries, callback: callback.update(vfunc_offset="0x10"),
            lambda entries, callback: callback.update(vtable_name="OtherInterface"),
            lambda entries, callback: callback.update(func_name="OtherCallback"),
            lambda entries, callback: entries.pop(6),
            lambda entries, callback: entries.update({6: "0x1500"}),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), TemporaryDirectory() as directory:
                result, payloads, session, generate = await self._run(directory, mutation=mutation)
                self.assertFalse(result)
                self.assertEqual([None, None], payloads)
                session.call_tool.assert_not_awaited()
                generate.assert_not_awaited()

    async def test_rejects_invalid_probe_results_and_transport_errors_without_emitting(self):
        for probe in (None, False, True, "456", -1, RuntimeError("IDA unavailable")):
            with self.subTest(probe=probe), TemporaryDirectory() as directory:
                result, payloads, _session, generate = await self._run(directory, probe=probe)
                self.assertFalse(result)
                self.assertEqual([None, None], payloads)
                generate.assert_not_awaited()

    async def test_fails_closed_when_signature_generation_fails(self):
        with TemporaryDirectory() as directory:
            result, payloads, _session, _generate = await self._run(directory, fail_sig=True)
        self.assertFalse(result)
        self.assertEqual([None, None], payloads)


if __name__ == "__main__":
    unittest.main()
