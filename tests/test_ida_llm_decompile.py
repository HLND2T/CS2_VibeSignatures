import asyncio
import io
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import ida_llm_decompile


class TestLlmTransportTimeout(unittest.IsolatedAsyncioTestCase):
    async def test_transport_timeout_is_reported_as_retryable_failure(self) -> None:
        async def stalled_transport(**_kwargs):
            await asyncio.sleep(0.05)

        with patch.object(ida_llm_decompile, "LLM_DECOMPILE_TIMEOUT_SECONDS", 0.001):
            succeeded, content, retry_delay = await ida_llm_decompile._call_llm_transport_attempt(
                stalled_transport,
                {},
                attempt_index=0,
                retry_settings=(1, 0.0, 2.0, 8.0),
                symbol_name_text="target",
                debug=False,
            )

        self.assertFalse(succeeded)
        self.assertIsNone(content)
        self.assertIsNone(retry_delay)

    async def test_sync_transport_invocation_is_bounded_by_timeout(self) -> None:
        def stalled_transport(**_kwargs):
            time.sleep(0.05)
            return "late response"

        with patch.object(ida_llm_decompile, "LLM_DECOMPILE_TIMEOUT_SECONDS", 0.001):
            succeeded, content, retry_delay = await ida_llm_decompile._call_llm_transport_attempt(
                stalled_transport,
                {},
                attempt_index=0,
                retry_settings=(1, 0.0, 2.0, 8.0),
                symbol_name_text="target",
                debug=False,
            )

        self.assertFalse(succeeded)
        self.assertIsNone(content)
        self.assertIsNone(retry_delay)


class TestLlmDebugOutput(unittest.TestCase):
    def test_multiline_debug_output_is_bounded(self) -> None:
        output = io.StringIO()
        with (
            patch.object(ida_llm_decompile, "LLM_DECOMPILE_DEBUG_TEXT_LIMIT", 32),
            redirect_stdout(output),
        ):
            ida_llm_decompile._debug_print_multiline("payload", "x" * 1_000, debug=True)

        rendered = output.getvalue()
        self.assertIn("truncated", rendered)
        self.assertIn("sha256:", rendered)
        self.assertLess(len(rendered), 300)
