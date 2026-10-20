import json
import unittest
from unittest.mock import AsyncMock, patch

from ida_preprocessor_scripts import _cvar_enumeration_common as common


class TestCvarEnumerationChain(unittest.IsolatedAsyncioTestCase):
    async def test_inline_dispatch_does_not_walk_callees(self):
        root = {"func_va": "0x1000", "procedure": "(*(_QWORD *)a1 + 96LL))(a1);"}
        session = AsyncMock()
        with patch.object(common, "_load_llm_decompile_target_details_via_mcp", AsyncMock(return_value=[root])):
            self.assertEqual(await common.load_target_details(session, ["root"]), [root])
        session.call_tool.assert_not_awaited()

    async def test_deinlined_dispatch_exports_actual_owner(self):
        root = {"func_va": "0x1000", "procedure": "helper(a1);"}
        owner = {"func_va": "0x2000", "procedure": "(*(_QWORD *)a1 + 104LL))(a1);"}
        session = AsyncMock()
        with (
            patch.object(common, "_load_llm_decompile_target_details_via_mcp", AsyncMock(return_value=[root])),
            patch.object(
                common,
                "parse_mcp_result",
                return_value={"result": json.dumps({"addresses": ["0x2000"], "overflow": False})},
            ),
            patch.object(common, "_export_function_detail_via_mcp", AsyncMock(return_value=owner)),
        ):
            self.assertEqual(await common.load_target_details(session, ["root"]), [owner])

    async def test_truncated_graph_fails_closed(self):
        root = {"func_va": "0x1000", "procedure": "helper(a1);"}
        with (
            patch.object(common, "_load_llm_decompile_target_details_via_mcp", AsyncMock(return_value=[root])),
            patch.object(
                common,
                "parse_mcp_result",
                return_value={"result": json.dumps({"addresses": ["0x2000"], "overflow": True})},
            ),
            patch.object(common, "_export_function_detail_via_mcp", AsyncMock()) as export,
        ):
            self.assertEqual(await common.load_target_details(AsyncMock(), ["root"]), [])
        export.assert_not_awaited()

    async def test_missing_helper_export_fails_closed(self):
        root = {"func_va": "0x1000", "procedure": "helper(a1);"}
        with (
            patch.object(common, "_load_llm_decompile_target_details_via_mcp", AsyncMock(return_value=[root])),
            patch.object(
                common,
                "parse_mcp_result",
                return_value={"result": json.dumps({"addresses": ["0x2000"], "overflow": False})},
            ),
            patch.object(common, "_export_function_detail_via_mcp", AsyncMock(return_value=None)),
        ):
            self.assertEqual(await common.load_target_details(AsyncMock(), ["root"]), [])

    def test_ambiguous_dispatch_owners_fail_closed(self):
        owners = [{"procedure": "(*(_QWORD *)a1 + 96LL))(a1);"}] * 2
        self.assertEqual(common.select_dispatch_owner(owners), [])
