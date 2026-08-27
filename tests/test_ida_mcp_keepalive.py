import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import ida_mcp_keepalive


class TestKeepaliveWorkerDuring(unittest.IsolatedAsyncioTestCase):
    async def test_forwards_py_eval_and_stops_after_context(self) -> None:
        keepalive_called = asyncio.Event()

        async def record_keepalive(*_args, **_kwargs) -> None:
            keepalive_called.set()

        session = SimpleNamespace(call_tool=AsyncMock(side_effect=record_keepalive))

        with patch.object(ida_mcp_keepalive, "WORKER_KEEPALIVE_INTERVAL_SECONDS", 0.001):
            async with ida_mcp_keepalive.keepalive_worker_during(
                session,
                debug=False,
                activity="llm_decompile",
            ):
                await asyncio.wait_for(keepalive_called.wait(), timeout=1)
            keepalive_count = session.call_tool.await_count
            await asyncio.sleep(0.005)

        self.assertGreaterEqual(keepalive_count, 1)
        self.assertEqual(keepalive_count, session.call_tool.await_count)
        self.assertTrue(
            all(
                call.kwargs == {"name": "py_eval", "arguments": {"code": "1"}}
                for call in session.call_tool.await_args_list
            )
        )

    async def test_keepalive_failure_does_not_replace_foreground_result(self) -> None:
        keepalive_called = asyncio.Event()

        async def fail_keepalive(*_args, **_kwargs) -> None:
            keepalive_called.set()
            raise RuntimeError("worker unavailable")

        session = SimpleNamespace(call_tool=AsyncMock(side_effect=fail_keepalive))

        with (
            patch.object(ida_mcp_keepalive, "WORKER_KEEPALIVE_INTERVAL_SECONDS", 0.001),
            patch("builtins.print") as mock_print,
        ):
            async with ida_mcp_keepalive.keepalive_worker_during(
                session,
                debug=True,
                activity="llm_decompile",
            ):
                await asyncio.wait_for(keepalive_called.wait(), timeout=1)
                result = "foreground result"

        self.assertEqual("foreground result", result)
        mock_print.assert_called()
