import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as N
from unittest.mock import AsyncMock, patch

import yaml


SCRIPT = Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts/find-CSchemaSystem_SchemaSystemIsReady.py"
SPEC = importlib.util.spec_from_file_location("schema_system_ready", SCRIPT)
ready = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ready)


class ReadyGetterTests(unittest.TestCase):
    def _probe(self, *, size=1, receiver=0, statements=1):
        argument = N(op="var", v=N(idx=receiver))
        address = N(op="add", x=argument, y=N(op="num", numval=lambda: 393))
        load = N(op="ptr", x=address, type=N(get_size=lambda: size))
        statement = N(op="return", creturn=N(expr=N(op="cast", x=load)))
        hx = N(
            cot_cast="cast",
            cot_var="var",
            cot_num="num",
            cot_add="add",
            cot_ptr="ptr",
            cit_return="return",
            decompile=lambda addr: N(argidx=[0], body=N(cblock=[statement] * statements)),
        )
        with patch.dict("sys.modules", {"ida_hexrays": hx}):
            return ready._probe_ready_getter(0x1000)

    def test_accepts_byte_getter_on_this(self):
        self.assertTrue(self._probe())

    def test_rejects_other_receivers_word_loads_and_complex_bodies(self):
        self.assertFalse(self._probe(size=4))
        self.assertFalse(self._probe(receiver=1))
        self.assertFalse(self._probe(statements=2))
        self.assertFalse(self._probe(statements=0))


class ReadySkillTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, directory, platform, entries, users, getter=True):
        Path(directory, f"CSchemaSystem_vtable.{platform}.yaml").write_text(
            yaml.safe_dump({"vtable_entries": entries}), encoding="utf-8"
        )
        output = Path(directory, f"CSchemaSystem_SchemaSystemIsReady.{platform}.yaml")
        session = AsyncMock()
        if getter is None:
            session.call_tool.side_effect = RuntimeError("IDA unavailable")
        with (
            patch.object(ready, "_collect_xref_func_starts_for_string", AsyncMock(return_value=users)),
            patch.object(ready, "parse_mcp_result", return_value={"result": "true" if getter else "false"}),
            patch(
                "ida_preprocessor_scripts._vtable_slot_anchor_common.preprocess_gen_func_sig_via_mcp",
                AsyncMock(
                    return_value={"func_rva": "0x1000", "func_size": "0x8", "func_sig": "0F B6 81 ?? ?? ?? ?? C3"}
                ),
            ),
        ):
            ok = await ready.preprocess_skill(
                session=session,
                skill_name="find-CSchemaSystem_SchemaSystemIsReady",
                expected_outputs=[str(output)],
                old_yaml_map={str(output): "obsolete-misidentified-function.yaml"},
                new_binary_dir=directory,
                platform=platform,
                image_base=0,
            )
        return ok, yaml.safe_load(output.read_text(encoding="utf-8")) if output.exists() else None

    async def test_uses_current_anchor_slot_on_both_platforms_even_after_a_shift(self):
        for platform, slot in (("windows", 26), ("linux", 31)):
            with self.subTest(platform=platform), TemporaryDirectory() as directory:
                ok, data = await self._run(directory, platform, {slot: 0x1000, slot + 1: 0x2000}, {0x2000})
                self.assertTrue(ok)
                self.assertEqual("0x1000", data["func_va"])
                self.assertEqual(slot, data["vfunc_index"])
                self.assertEqual(hex(slot * 8), data["vfunc_offset"])

    async def test_fails_closed_for_ambiguous_anchor_missing_predecessor_or_non_getter(self):
        cases = (
            ({26: 0x1000, 27: 0x2000}, set(), True),
            ({26: 0x1000, 27: 0x2000, 28: 0x3000}, {0x2000, 0x3000}, True),
            ({27: 0x2000}, {0x2000}, True),
            ({26: 0x1000, 27: 0x2000}, {0x2000}, False),
            ({26: 0x1000, 27: 0x2000}, {0x2000}, None),
        )
        for entries, users, getter in cases:
            with self.subTest(entries=entries, users=users, getter=getter), TemporaryDirectory() as directory:
                ok, data = await self._run(directory, "linux", entries, users, getter)
                self.assertFalse(ok)
                self.assertIsNone(data)


if __name__ == "__main__":
    unittest.main()
