import asyncio
import unittest
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

