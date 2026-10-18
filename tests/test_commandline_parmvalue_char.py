import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch


spec = importlib.util.spec_from_file_location(
    "parmvalue_char_finder",
    Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts/find-ICommandLine_ParmValue_char.py",
)
finder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(finder)


def detail(address, procedure):
    return {"func_va": address, "procedure": procedure, "disasm_code": "call [rax+40h]"}


class TestParmValue_charChain(unittest.IsolatedAsyncioTestCase):
    async def test_inline_owner_does_not_walk_unrelated_callees(self):
        root = detail("0x1000", "const char *value = call(commandline, 3223879006, empty_string)")
        session = AsyncMock()
        with patch.object(finder, "_load_llm_decompile_target_details_via_mcp", AsyncMock(return_value=[root])):
            self.assertEqual(await finder.load_target_details(session, ["root"]), [root])
        session.call_tool.assert_not_awaited()

    async def test_deinlined_owner_is_exported_for_llm_instruction_validation(self):
        root = detail("0x1000", "return helper(this)")
        helper = detail("0x2000", "const char *value = call(commandline, 3223879006, empty_string)")
        session = AsyncMock()
        session.call_tool.return_value = {"result": json.dumps({"addresses": ["0x2000"], "overflow": False})}
        with (
            patch.object(finder, "_load_llm_decompile_target_details_via_mcp", AsyncMock(return_value=[root])),
            patch.object(finder, "parse_mcp_result", side_effect=lambda result: result),
            patch.object(finder, "_export_function_detail_via_mcp", AsyncMock(return_value=helper)),
        ):
            self.assertEqual(await finder.load_target_details(session, ["root"]), [helper])

    async def test_ambiguous_helper_owners_fail_closed(self):
        helpers = [detail("0x2000", "const char *3223879006"), detail("0x3000", "const char *3223879006")]
        self.assertEqual(finder.select_anchor_details(helpers), [])
        self.assertEqual(finder.select_anchor_details([detail("0x4000", "const char *other_token")]), [])

    async def test_truncated_call_graph_fails_closed(self):
        session = AsyncMock()
        session.call_tool.return_value = {"result": json.dumps({"addresses": [], "overflow": True})}
        with (
            patch.object(
                finder,
                "_load_llm_decompile_target_details_via_mcp",
                AsyncMock(return_value=[detail("0x1000", "helper(this)")]),
            ),
            patch.object(finder, "parse_mcp_result", side_effect=lambda result: result),
        ):
            self.assertEqual(await finder.load_target_details(session, ["root"]), [])
