import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import ida_llm_utils


class TestRequireNonemptyText(unittest.TestCase):
    def test_require_nonempty_text_returns_stripped_text(self) -> None:
        self.assertEqual("hello", ida_llm_utils.require_nonempty_text("  hello  ", "value"))

    def test_require_nonempty_text_raises_value_error_for_blank_text(self) -> None:
        with self.assertRaises(ValueError):
            ida_llm_utils.require_nonempty_text("   ", "value")


class TestCreateOpenAiClient(unittest.TestCase):
    def test_create_openai_client_raises_runtime_error_when_api_key_missing(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "LLM API key required"):
            ida_llm_utils.create_openai_client(
                None,
                api_key_required_message="LLM API key required",
            )

    @patch("ida_llm_utils.AsyncOpenAI")
    def test_create_openai_client_uses_trimmed_api_key_and_base_url(self, mock_openai) -> None:
        mock_client = object()
        mock_openai.return_value = mock_client

        client = ida_llm_utils.create_openai_client(
            "  test-api-key  ",
            "  https://example.invalid/v1  ",
            api_key_required_message="unused",
        )

        self.assertIs(mock_client, client)
        mock_openai.assert_called_once_with(
            api_key="test-api-key",
            base_url="https://example.invalid/v1",
        )


class TestNormalizeOptionalEffort(unittest.TestCase):
    def test_normalize_optional_effort_defaults_to_medium(self) -> None:
        self.assertEqual("medium", ida_llm_utils.normalize_optional_effort(None))
        self.assertEqual("medium", ida_llm_utils.normalize_optional_effort("   "))

    def test_normalize_optional_effort_rejects_unknown_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "effort must be one of"):
            ida_llm_utils.normalize_optional_effort("turbo")


class TestExtractFirstMessageText(unittest.TestCase):
    def test_extract_first_message_text_supports_string_content(self) -> None:
        response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="hello from llm"),
                )
            ]
        )

        self.assertEqual("hello from llm", ida_llm_utils.extract_first_message_text(response))

    def test_extract_first_message_text_supports_text_parts(self) -> None:
        response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=[
                            SimpleNamespace(text="hello "),
                            {"text": "from "},
                            SimpleNamespace(text="parts"),
                        ]
                    ),
                )
            ]
        )

        self.assertEqual("hello from parts", ida_llm_utils.extract_first_message_text(response))

    def test_extract_first_message_text_raises_value_error_on_empty_choices(self) -> None:
        response = SimpleNamespace(choices=[])

        with self.assertRaises(ValueError):
            ida_llm_utils.extract_first_message_text(response)


class TestCallLlmText(unittest.IsolatedAsyncioTestCase):
    async def test_call_llm_text_invokes_chat_completions_and_returns_first_message_text(self) -> None:
        response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="found_vcall:\n  []"),
                )
            ]
        )
        create = AsyncMock(return_value=response)
        client = SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(create=create),
            )
        )
        messages = [{"role": "user", "content": "hello"}]

        text = await ida_llm_utils.call_llm_text(
            client,
            model="  gpt-4o-mini  ",
            messages=messages,
            temperature=0.25,
        )

        self.assertEqual("found_vcall:\n  []", text)
        create.assert_awaited_once_with(
            model="gpt-4o-mini",
            messages=messages,
            reasoning_effort="medium",
            temperature=0.25,
        )

    async def test_call_llm_text_omits_temperature_when_not_configured(self) -> None:
        response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="found_vcall:\n  []"),
                )
            ]
        )
        create = AsyncMock(return_value=response)
        client = SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(create=create),
            )
        )
        messages = [{"role": "user", "content": "hello"}]

        text = await ida_llm_utils.call_llm_text(
            client,
            model="gpt-4o-mini",
            messages=messages,
        )

        self.assertEqual("found_vcall:\n  []", text)
        create.assert_awaited_once_with(
            model="gpt-4o-mini",
            messages=messages,
            reasoning_effort="medium",
        )

    async def test_call_llm_text_forwards_reasoning_effort_to_sdk(self) -> None:
        response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="done"))])
        create = AsyncMock(return_value=response)
        client = SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(create=create),
            )
        )
        messages = [{"role": "user", "content": "hello"}]

        text = await ida_llm_utils.call_llm_text(
            client,
            model="gpt-5.4",
            messages=messages,
        )

        self.assertEqual("done", text)
        create.assert_awaited_once_with(
            model="gpt-5.4",
            messages=messages,
            reasoning_effort="medium",
        )

    async def test_call_llm_text_strips_internal_message_ids_for_chat_completions(self) -> None:
        response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="done"))])
        create = AsyncMock(return_value=response)
        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))

        await ida_llm_utils.call_llm_text(
            client,
            model="gpt-5.4",
            messages=[{"id": "msg_stable", "role": "user", "content": "hello"}],
        )

        self.assertEqual(
            [{"role": "user", "content": "hello"}],
            create.call_args.kwargs["messages"],
        )

    @patch("ida_llm_utils.create_openai_client")
    async def test_call_llm_text_creates_request_client_when_missing(
        self,
        mock_create_openai_client,
    ) -> None:
        response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="done"))])
        create = AsyncMock(return_value=response)
        close = AsyncMock()
        client = SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(create=create),
            )
        )
        client.close = close
        mock_create_openai_client.return_value = client
        messages = [{"role": "user", "content": "hello"}]

        text = await ida_llm_utils.call_llm_text(
            model="gpt-5.4",
            messages=messages,
            api_key="test-api-key",
            base_url="https://example.invalid/v1",
        )

        self.assertEqual("done", text)
        mock_create_openai_client.assert_called_once_with(
            "test-api-key",
            "https://example.invalid/v1",
            api_key_required_message=("api_key is required for OpenAI-compatible LLM requests"),
        )
        create.assert_awaited_once_with(
            model="gpt-5.4",
            messages=messages,
            reasoning_effort="medium",
        )
        close.assert_awaited_once_with()


class TestCallLlmTextSync(unittest.TestCase):
    @patch("ida_llm_utils.call_llm_text", new_callable=AsyncMock)
    def test_call_llm_text_sync_runs_async_transport(self, mock_call_llm_text) -> None:
        mock_call_llm_text.return_value = "done"

        result = ida_llm_utils.call_llm_text_sync(
            model="gpt-5.4",
            messages=[{"role": "user", "content": "hello"}],
        )

        self.assertEqual("done", result)
        mock_call_llm_text.assert_awaited_once()


class _CodexHandler(BaseHTTPRequestHandler):
    content_type = "text/event-stream"
    sse_events = [
        'data: {"type":"response.output_text.delta","delta":"found_"}\n\n',
        'data: {"type":"response.output_text.delta","delta":"call"}\n\n',
        "data: [DONE]\n\n",
    ]
    last_path = None
    last_headers = None
    last_json_body = None
    json_bodies = []

    def do_POST(self) -> None:  # noqa: N802
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length).decode("utf-8")

        type(self).last_path = self.path
        type(self).last_headers = {k.lower(): v for k, v in self.headers.items()}
        type(self).last_json_body = json.loads(body)
        type(self).json_bodies.append(type(self).last_json_body)

        self.send_response(200)
        self.send_header("Content-Type", type(self).content_type)
        self.end_headers()
        try:
            if type(self).content_type == "text/event-stream":
                for event in type(self).sse_events:
                    self.wfile.write(event.encode("utf-8"))
            else:
                self.wfile.write(b'{"ok":true}')
        except BrokenPipeError:
            return

    def log_message(self, format: str, *args) -> None:
        return


def _serve_http(server: HTTPServer) -> None:
    server.serve_forever(poll_interval=0.01)


class TestCallLlmTextCodexHttp(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        _CodexHandler.content_type = "text/event-stream"
        _CodexHandler.sse_events = [
            'data: {"type":"response.output_text.delta","delta":"found_"}\n\n',
            'data: {"type":"response.output_text.delta","delta":"call"}\n\n',
            "data: [DONE]\n\n",
        ]
        _CodexHandler.last_path = None
        _CodexHandler.last_headers = None
        _CodexHandler.last_json_body = None
        _CodexHandler.json_bodies = []

        self._server = HTTPServer(("127.0.0.1", 0), _CodexHandler)
        self._thread = threading.Thread(target=_serve_http, args=(self._server,), daemon=True)
        self._thread.start()
        self._base_url = f"http://127.0.0.1:{self._server.server_port}/v1"

    def tearDown(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=1.0)

    async def test_call_llm_text_posts_responses_sse_with_codex_headers(self) -> None:
        result = await ida_llm_utils.call_llm_text(
            None,
            model="gpt-5.4",
            messages=[
                {"role": "system", "content": "ignored"},
                {"role": "user", "content": "Who are you?"},
            ],
            api_key="test-api-key",
            base_url=self._base_url,
            fake_as="codex",
            effort="high",
            temperature=0.2,
        )

        self.assertEqual("found_call", result)
        self.assertEqual("/v1/responses", _CodexHandler.last_path)
        self.assertEqual("text/event-stream", _CodexHandler.last_headers["accept"])
        self.assertEqual("codex-tui", _CodexHandler.last_headers["originator"])
        self.assertEqual(
            "codex-tui/0.144.1 (Windows 10.0.26200; x86_64) WindowsTerminal (codex-tui; 0.144.1)",
            _CodexHandler.last_headers["user-agent"],
        )
        self.assertEqual("high", _CodexHandler.last_json_body["reasoning"]["effort"])
        self.assertEqual(0.2, _CodexHandler.last_json_body["temperature"])
        input_items = _CodexHandler.last_json_body["input"]
        self.assertEqual("additional_tools", input_items[0]["type"])
        self.assertEqual("user", input_items[-1]["role"])
        self.assertEqual(
            [{"type": "input_text", "text": "Who are you?"}],
            input_items[-1]["content"],
        )

    async def test_call_llm_text_codex_uses_top_level_text_attribute(self) -> None:
        result = await ida_llm_utils.call_llm_text(
            None,
            model="gpt-5.4",
            messages=[{"role": "user", "content": SimpleNamespace(text="  Hello  ")}],
            api_key="test-api-key",
            base_url=self._base_url,
            fake_as="codex",
        )

        self.assertEqual("found_call", result)
        user_input = _CodexHandler.last_json_body["input"][-1]
        self.assertEqual("user", user_input["role"])
        self.assertEqual(
            [{"type": "input_text", "text": "Hello"}],
            user_input["content"],
        )

    async def test_call_llm_text_codex_preserves_message_ids_across_retries(self) -> None:
        messages = [
            {"id": "msg_initial", "role": "user", "content": "Initial prompt"},
            {"id": "msg_bad_output", "role": "assistant", "content": "bad YAML"},
            {"id": "msg_correction", "role": "user", "content": "Return corrected YAML"},
        ]

        for _ in range(2):
            await ida_llm_utils.call_llm_text(
                None,
                model="gpt-5.4",
                messages=messages,
                api_key="test-api-key",
                base_url=self._base_url,
                fake_as="codex",
                prompt_cache_key="stable-cache-key",
            )

        first_input = _CodexHandler.json_bodies[0]["input"]
        second_input = _CodexHandler.json_bodies[1]["input"]
        first_ids = [item.get("id") for item in first_input if item.get("type") == "message"]
        second_ids = [item.get("id") for item in second_input if item.get("type") == "message"]
        self.assertEqual(first_ids, second_ids)
        self.assertEqual(["msg_initial", "msg_bad_output", "msg_correction"], first_ids[-3:])
        self.assertEqual(["user", "assistant", "user"], [item["role"] for item in first_input[-3:]])
        self.assertEqual(
            ["stable-cache-key", "stable-cache-key"],
            [body["prompt_cache_key"] for body in _CodexHandler.json_bodies],
        )

    async def test_call_llm_text_rejects_non_sse_content_type(self) -> None:
        _CodexHandler.content_type = "application/json"

        with self.assertRaisesRegex(RuntimeError, "expected text/event-stream"):
            await ida_llm_utils.call_llm_text(
                None,
                model="gpt-5.4",
                messages=[{"role": "user", "content": "Who are you?"}],
                api_key="test-api-key",
                base_url=self._base_url,
                fake_as="codex",
            )

    async def test_call_llm_text_codex_avoids_completed_text_dup_after_deltas(self) -> None:
        _CodexHandler.sse_events = [
            'data: {"type":"response.output_text.delta","delta":"answer"}\n\n',
            (
                'data: {"type":"response.completed","response":{"output":[{"content":'
                '[{"type":"output_text","text":"answer"}]}]}}\n\n'
            ),
            "data: [DONE]\n\n",
        ]

        result = await ida_llm_utils.call_llm_text(
            None,
            model="gpt-5.4",
            messages=[{"role": "user", "content": "Who are you?"}],
            api_key="test-api-key",
            base_url=self._base_url,
            fake_as="codex",
        )

        self.assertEqual("answer", result)

    async def test_call_llm_text_codex_raises_on_failed_event_after_delta(self) -> None:
        _CodexHandler.sse_events = [
            'data: {"type":"response.output_text.delta","delta":"partial"}\n\n',
            'data: {"type":"response.failed","reason":"model_error"}\n\n',
            "data: [DONE]\n\n",
        ]

        with self.assertRaisesRegex(RuntimeError, r"codex transport.*response\.failed"):
            await ida_llm_utils.call_llm_text(
                None,
                model="gpt-5.4",
                messages=[{"role": "user", "content": "Who are you?"}],
                api_key="test-api-key",
                base_url=self._base_url,
                fake_as="codex",
            )

    async def test_call_llm_text_codex_uses_completed_as_fallback_without_deltas(self) -> None:
        _CodexHandler.sse_events = [
            (
                'data: {"type":"response.completed","response":{"output":[{"content":'
                '[{"type":"output_text","text":"fallback_text"}]}]}}\n\n'
            ),
            "data: [DONE]\n\n",
        ]

        result = await ida_llm_utils.call_llm_text(
            None,
            model="gpt-5.4",
            messages=[{"role": "user", "content": "Who are you?"}],
            api_key="test-api-key",
            base_url=self._base_url,
            fake_as="codex",
        )

        self.assertEqual("fallback_text", result)


if __name__ == "__main__":
    unittest.main()
