import importlib.util
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from ida_preprocessor_scripts import _convar_function


def load_finder(name):
    path = Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts" / f"find-{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestRespondCvarSlot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.finder = load_finder("CServerSideClient_ProcessRespondCvarValue")

    def test_registration_evidence_tracks_slot_changes(self):
        for offset, expected in ((0, 0), (0x130, 38), (0x140, 40), (0x148, 41)):
            with self.subTest(offset=offset):
                self.assertEqual(expected, self.finder.unique_slot([{"offset": offset}], 0x278))

    def test_duplicate_evidence_is_consistent_but_conflicts_are_rejected(self):
        self.assertEqual(40, self.finder.unique_slot([{"offset": 0x140}, {"offset": 0x140}], 0x278))
        self.assertIsNone(self.finder.unique_slot([{"offset": 0x130}, {"offset": 0x140}], 0x278))

    def test_missing_unaligned_and_out_of_range_slots_are_rejected(self):
        self.assertIsNone(self.finder.unique_slot([], 0x278))
        for offset in (-8, 1, 0x141, 0x278, True, 320.0):
            with self.subTest(offset=offset):
                self.assertIsNone(self.finder.unique_slot([{"offset": offset}], 0x278))


class TestConvarReader(unittest.IsolatedAsyncioTestCase):
    async def test_ambiguous_reader_does_not_generate_or_write(self):
        response = {"result": json.dumps({"objects": [0x2000], "readers": [0x3000, 0x4000]})}
        session = SimpleNamespace(call_tool=AsyncMock(return_value=response))
        with (
            patch.object(_convar_function, "parse_mcp_result", return_value=response),
            patch.object(_convar_function, "preprocess_gen_func_sig_via_mcp", new_callable=AsyncMock) as generate,
            patch.object(_convar_function, "write_func_yaml") as write,
        ):
            success = await _convar_function.preprocess_convar_function(
                session,
                [],
                {},
                ".",
                "windows",
                0,
                convar_name="example",
                target_name="Example",
                desired_fields=[],
            )
        self.assertFalse(success)
        generate.assert_not_awaited()
        write.assert_not_called()

    async def test_reader_must_belong_to_requested_vtable(self):
        response = {"result": json.dumps({"objects": [0x2000], "readers": [0x3000]})}
        session = SimpleNamespace(call_tool=AsyncMock(return_value=response))
        with TemporaryDirectory() as directory:
            Path(directory, "Example_vtable.windows.yaml").write_text(
                "vtable_entries:\n  1: '0x4000'\n", encoding="utf-8"
            )
            with (
                patch.object(_convar_function, "parse_mcp_result", return_value=response),
                patch.object(
                    _convar_function,
                    "preprocess_gen_func_sig_via_mcp",
                    new_callable=AsyncMock,
                    return_value={"func_sig": "AA BB"},
                ),
                patch.object(_convar_function, "write_func_yaml") as write,
            ):
                success = await _convar_function.preprocess_convar_function(
                    session,
                    [],
                    {},
                    directory,
                    "windows",
                    0,
                    convar_name="example",
                    target_name="Example_Method",
                    desired_fields=[],
                    vtable_name="Example",
                )
            self.assertFalse(success)
            write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
