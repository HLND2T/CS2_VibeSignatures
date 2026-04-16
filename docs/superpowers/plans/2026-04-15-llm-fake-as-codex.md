# LLM Fake-As Codex Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 `ida_analyze_bin.py` 的统一 LLM 配置增加 `-llm_fake_as=codex` 与 `-llm_effort`，在 `codex` 模式下切换到手写 `/v1/responses` SSE 传输，同时保持 `LLM_DECOMPILE` 与 `vcall_finder` 共享同一套参数语义。

**Architecture:** 先在 CLI 与预处理分发层补齐 `llm_fake_as` / `llm_effort` 的入口、默认值与 env fallback，再在 `ida_llm_utils.py` 中把 SDK 调用与 `codex_http` 传输统一收口到 `call_llm_text(...)`。随后把 `ida_analyze_util.py` 和 `ida_vcall_finder.py` 改为只透传规范化后的参数，不各自复制协议逻辑。最后补 README 中的共享参数说明，并用现有 `unittest` 套件完成定向回归。

**Tech Stack:** Python 3.10, `argparse`, `httpx`, `unittest`, `unittest.mock`, `http.server`, OpenAI Python SDK, YAML utilities

---

## File Map

- `ida_analyze_bin.py`
  - 增加 `-llm_fake_as` 与 `-llm_effort`
  - 解析 `CS2VIBE_LLM_FAKE_AS` / `CS2VIBE_LLM_EFFORT`
  - 将 `llm_fake_as` / `llm_effort` 继续透传到 `process_binary(...)`、`preprocess_single_skill_via_mcp(...)` 与 `aggregate_vcall_results_for_object(...)`
- `ida_skill_preprocessor.py`
  - 扩展 `preprocess_single_skill_via_mcp(...)` 签名
  - 在 `llm_config` 中补齐 `fake_as` 与 `effort`
- `ida_llm_utils.py`
  - 新增 `normalize_optional_effort(...)`
  - 新增 `codex_http` 请求头、body、SSE 解析 helper
  - 让 `call_llm_text(...)` 在 SDK 与 `/responses` 直连之间切换
- `ida_analyze_util.py`
  - 在 `_prepare_llm_decompile_request(...)` 中解析并缓存 `fake_as` / `effort`
  - 在 `call_llm_decompile(...)` 中透传 `temperature` / `effort` / `fake_as` / `api_key` / `base_url`
  - `codex` 模式下不再创建 OpenAI SDK client
- `ida_vcall_finder.py`
  - `call_openai_for_vcalls(...)` 改为透传 `temperature` / `effort` / `fake_as`
  - `aggregate_vcall_results_for_object(...)` 与内部 helper 支持 `codex` 模式不创建 SDK client
- `tests/test_ida_analyze_bin.py`
  - 增加 CLI 解析、env fallback、默认 `medium` 与透传测试
- `tests/test_ida_preprocessor_scripts.py`
  - 增加 `llm_config` 中 `fake_as` / `effort` 的转发测试
- `tests/test_ida_llm_utils.py`
  - 增加 `normalize_optional_effort(...)`、SDK forwarding、`codex_http` 报文和 SSE 解析测试
- `tests/test_ida_analyze_util.py`
  - 增加 `call_llm_decompile(...)` 对 `effort` / `fake_as` 的转发测试
  - 增加 `_prepare_llm_decompile_request(...)` 在 `codex` 模式下跳过 client 创建的测试
- `tests/test_ida_vcall_finder.py`
  - 增加 `vcall_finder` 聚合对 `effort` / `fake_as` 的透传测试
  - 增加 `codex` 模式下跳过 `create_openai_client(...)` 的测试
- `README.md`
  - 更新共享 LLM CLI 参数与示例命令
- `README_CN.md`
  - 同步中文参数说明与示例命令

## Task 1: 锁定 CLI、env fallback 与预处理透传

**Files:**
- Modify: `tests/test_ida_analyze_bin.py`
- Modify: `tests/test_ida_preprocessor_scripts.py`
- Modify: `ida_analyze_bin.py`
- Modify: `ida_skill_preprocessor.py`

- [ ] **Step 1: 先写 CLI 参数与 env fallback 的失败测试**

```python
class TestParseArgsLlmOptions(unittest.TestCase):
    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_accepts_llm_fake_as_and_effort(self, _mock_resolve_oldgamever) -> None:
        with patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14141",
                "-llm_fake_as",
                "codex",
                "-llm_effort",
                "high",
                "-llm_temperature",
                "0.25",
            ],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual("codex", args.llm_fake_as)
        self.assertEqual("high", args.llm_effort)
        self.assertEqual(0.25, args.llm_temperature)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_uses_env_llm_fake_as_and_default_effort(self, _mock_resolve_oldgamever) -> None:
        with patch.dict(
            "os.environ",
            {
                "CS2VIBE_LLM_FAKE_AS": "codex",
            },
            clear=False,
        ), patch(
            "sys.argv",
            ["ida_analyze_bin.py", "-gamever", "14141"],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual("codex", args.llm_fake_as)
        self.assertEqual("medium", args.llm_effort)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_prefers_cli_llm_effort_over_env(self, _mock_resolve_oldgamever) -> None:
        with patch.dict(
            "os.environ",
            {"CS2VIBE_LLM_EFFORT": "low"},
            clear=False,
        ), patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14141",
                "-llm_effort",
                "xhigh",
            ],
        ):
            args = ida_analyze_bin.parse_args()

        self.assertEqual("xhigh", args.llm_effort)

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_rejects_invalid_llm_fake_as(self, _mock_resolve_oldgamever) -> None:
        with patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14141",
                "-llm_fake_as",
                "openai",
            ],
        ), patch("sys.stderr", new_callable=io.StringIO) as fake_stderr:
            with self.assertRaises(SystemExit) as exc:
                ida_analyze_bin.parse_args()

        self.assertEqual(2, exc.exception.code)
        self.assertIn("Invalid LLM fake_as", fake_stderr.getvalue())

    @patch.object(ida_analyze_bin, "resolve_oldgamever", return_value="14140")
    def test_parse_args_rejects_invalid_llm_effort(self, _mock_resolve_oldgamever) -> None:
        with patch(
            "sys.argv",
            [
                "ida_analyze_bin.py",
                "-gamever",
                "14141",
                "-llm_effort",
                "turbo",
            ],
        ), patch("sys.stderr", new_callable=io.StringIO) as fake_stderr:
            with self.assertRaises(SystemExit) as exc:
                ida_analyze_bin.parse_args()

        self.assertEqual(2, exc.exception.code)
        self.assertIn("Invalid LLM effort", fake_stderr.getvalue())
```

- [ ] **Step 2: 为透传链路写失败测试**

```python
class TestProcessBinaryLlmWiring(unittest.TestCase):
    @patch("ida_analyze_bin.os.path.exists", return_value=False)
    @patch.object(ida_analyze_bin, "run_skill", return_value=False)
    @patch.object(
        ida_analyze_bin,
        "preprocess_single_skill_via_mcp",
        new_callable=AsyncMock,
        return_value=False,
    )
    @patch.object(ida_analyze_bin, "ensure_mcp_available")
    @patch.object(ida_analyze_bin, "start_idalib_mcp")
    @patch.object(ida_analyze_bin, "quit_ida_gracefully")
    def test_process_binary_passes_effort_and_fake_as_to_preprocess(
        self,
        _mock_quit_ida,
        mock_start_idalib_mcp,
        mock_ensure_mcp_available,
        mock_preprocess,
        _mock_run_skill,
        _mock_exists,
    ) -> None:
        fake_process = object()
        mock_start_idalib_mcp.return_value = fake_process
        mock_ensure_mcp_available.return_value = (fake_process, True)

        ida_analyze_bin.process_binary(
            binary_path="/tmp/bin/14141/networksystem/networksystem.dll",
            skills=[{"name": "find-IGameSystem_vtable", "expected_output": ["IGameSystem_vtable.{platform}.yaml"], "expected_input": []}],
            agent="codex",
            host="127.0.0.1",
            port=13337,
            ida_args="",
            platform="windows",
            llm_model="gpt-4.1-mini",
            llm_apikey="test-api-key",
            llm_baseurl="https://example.invalid/v1",
            llm_temperature=0.4,
            llm_effort="high",
            llm_fake_as="codex",
        )

        self.assertEqual("high", mock_preprocess.await_args.kwargs["llm_effort"])
        self.assertEqual("codex", mock_preprocess.await_args.kwargs["llm_fake_as"])
```

```python
class TestPreprocessSingleSkillViaMcp(unittest.IsolatedAsyncioTestCase):
    async def test_forwards_llm_config_with_effort_and_fake_as(self) -> None:
        received = {}

        async def fake_preprocess_skill(
            session, skill_name, expected_outputs, old_yaml_map,
            new_binary_dir, platform, image_base, llm_config, debug=False,
        ):
            received["llm_config"] = llm_config
            return True

        with patch.object(
            ida_skill_preprocessor,
            "_get_preprocess_entry",
            return_value=fake_preprocess_skill,
        ), patch.object(
            ida_skill_preprocessor.httpx,
            "AsyncClient",
            _FakeAsyncClient,
        ), patch.object(
            ida_skill_preprocessor,
            "streamable_http_client",
            return_value=_FakeStreamableHttpClient(),
        ), patch.object(
            ida_skill_preprocessor,
            "ClientSession",
            _FakeClientSession,
        ), patch.object(
            ida_skill_preprocessor,
            "parse_mcp_result",
            return_value={"result": "0x180000000"},
        ):
            result = await ida_skill_preprocessor.preprocess_single_skill_via_mcp(
                host="127.0.0.1",
                port=13337,
                skill_name="find-CNetworkMessages_FindNetworkGroup",
                expected_outputs=["out.yaml"],
                old_yaml_map={"out.yaml": "old.yaml"},
                new_binary_dir="bin_dir",
                platform="windows",
                llm_model="gpt-4.1-mini",
                llm_apikey="test-api-key",
                llm_baseurl="https://example.invalid/v1",
                llm_temperature=0.6,
                llm_effort="high",
                llm_fake_as="codex",
                debug=True,
            )

        self.assertTrue(result)
        self.assertEqual(
            {
                "model": "gpt-4.1-mini",
                "api_key": "test-api-key",
                "base_url": "https://example.invalid/v1",
                "temperature": 0.6,
                "effort": "high",
                "fake_as": "codex",
            },
            received["llm_config"],
        )
```

- [ ] **Step 3: 运行定向测试，确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_ida_analyze_bin tests.test_ida_preprocessor_scripts -v
```

Expected: FAIL，因为当前没有 `-llm_fake_as` / `-llm_effort`，预处理透传里也还没有这两个字段。

- [ ] **Step 4: 实现 CLI 解析与预处理透传**

```python
def _parse_optional_llm_fake_as(raw_value, parser):
    if raw_value is None:
        return None
    raw_text = str(raw_value).strip().lower()
    if not raw_text:
        return None
    if raw_text != "codex":
        parser.error("Invalid LLM fake_as: must be 'codex'")
    return raw_text


def _parse_optional_llm_effort(raw_value, parser):
    allowed = {"none", "minimal", "low", "medium", "high", "xhigh"}
    if raw_value is None:
        return "medium"
    raw_text = str(raw_value).strip().lower()
    if not raw_text:
        return "medium"
    if raw_text not in allowed:
        parser.error(
            "Invalid LLM effort: must be one of none, minimal, low, medium, high, xhigh"
        )
    return raw_text


parser.add_argument(
    "-llm_fake_as",
    default=os.environ.get("CS2VIBE_LLM_FAKE_AS"),
    help="Optional transport profile for LLM workflows (currently: codex, or set CS2VIBE_LLM_FAKE_AS env var)",
)
parser.add_argument(
    "-llm_effort",
    default=os.environ.get("CS2VIBE_LLM_EFFORT"),
    help="Optional reasoning effort for LLM workflows (default: medium, or set CS2VIBE_LLM_EFFORT env var)",
)

args.llm_fake_as = _parse_optional_llm_fake_as(args.llm_fake_as, parser)
args.llm_effort = _parse_optional_llm_effort(args.llm_effort, parser)
```

```python
def _run_preprocess_single_skill_via_mcp(
    *,
    host,
    port,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    debug,
    llm_model,
    llm_apikey,
    llm_baseurl,
    llm_temperature,
    llm_effort,
    llm_fake_as,
):
    preprocess_kwargs = {
        "host": host,
        "port": port,
        "skill_name": skill_name,
        "expected_outputs": expected_outputs,
        "old_yaml_map": old_yaml_map,
        "new_binary_dir": new_binary_dir,
        "platform": platform,
        "debug": debug,
        "llm_model": llm_model,
        "llm_apikey": llm_apikey,
        "llm_baseurl": llm_baseurl,
        "llm_temperature": llm_temperature,
        "llm_effort": llm_effort,
        "llm_fake_as": llm_fake_as,
    }
```

```python
async def preprocess_single_skill_via_mcp(
    host, port, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform,
    llm_model=None, llm_apikey=None, llm_baseurl=None, llm_temperature=None,
    llm_effort=None, llm_fake_as=None,
    debug=False,
):
    llm_config = {
        "model": llm_model,
        "api_key": llm_apikey,
        "base_url": llm_baseurl,
        "temperature": llm_temperature,
        "effort": llm_effort,
        "fake_as": llm_fake_as,
    }
```

- [ ] **Step 5: 重新运行定向测试，确认通过**

Run:

```bash
uv run python -m unittest tests.test_ida_analyze_bin tests.test_ida_preprocessor_scripts -v
```

Expected: PASS，`parse_args()` 能解析 `fake_as` / `effort`，且 `llm_config` 已带上新字段。

- [ ] **Step 6: 提交这一批改动**

```bash
git add ida_analyze_bin.py ida_skill_preprocessor.py tests/test_ida_analyze_bin.py tests/test_ida_preprocessor_scripts.py
git commit -m "feat(llm): 增加fake_as与effort入口"
```

## Task 2: 用 TDD 落地共享 `codex_http` transport

**Files:**
- Modify: `tests/test_ida_llm_utils.py`
- Modify: `ida_llm_utils.py`

- [ ] **Step 1: 先为共享 helper 写失败测试**

```python
class TestNormalizeOptionalEffort(unittest.TestCase):
    def test_normalize_optional_effort_defaults_to_medium(self) -> None:
        self.assertEqual("medium", ida_llm_utils.normalize_optional_effort(None))
        self.assertEqual("medium", ida_llm_utils.normalize_optional_effort("   "))

    def test_normalize_optional_effort_rejects_unknown_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "effort must be one of"):
            ida_llm_utils.normalize_optional_effort("turbo")
```

```python
class TestCallLlmText(unittest.TestCase):
    def test_call_llm_text_forwards_reasoning_effort_to_sdk(self) -> None:
        response = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="done"))]
        )
        create = MagicMock(return_value=response)
        client = SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create))
        )

        text = ida_llm_utils.call_llm_text(
            client,
            model="gpt-5.4",
            messages=[{"role": "user", "content": "hello"}],
        )

        self.assertEqual("done", text)
        create.assert_called_once_with(
            model="gpt-5.4",
            messages=[{"role": "user", "content": "hello"}],
            reasoning_effort="medium",
        )
```

```python
class _CodexHandler(BaseHTTPRequestHandler):
    captures = []
    content_type = "text/event-stream"

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length).decode("utf-8", "replace")
        self.__class__.captures.append(
            {
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": json.loads(body),
            }
        )
        self.send_response(200)
        self.send_header("Content-Type", self.__class__.content_type)
        self.end_headers()
        self.wfile.write(b'data: {"type":"response.output_text.delta","delta":"found_"}\n\n')
        self.wfile.write(b'data: {"type":"response.output_text.delta","delta":"call"}\n\n')
        self.wfile.write(b'data: [DONE]\n\n')

    def log_message(self, *_args):
        pass


class TestCallLlmTextCodexHttp(unittest.TestCase):
    def test_call_llm_text_posts_responses_sse_with_codex_headers(self) -> None:
        _CodexHandler.captures = []
        _CodexHandler.content_type = "text/event-stream"
        server = HTTPServer(("127.0.0.1", 0), _CodexHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            text = ida_llm_utils.call_llm_text(
                None,
                model="gpt-5.4",
                messages=[
                    {"role": "system", "content": "ignored"},
                    {"role": "user", "content": "Who are you?"},
                ],
                api_key="test-api-key",
                base_url=f"http://127.0.0.1:{server.server_port}/v1",
                fake_as="codex",
                effort="high",
                temperature=0.2,
            )
        finally:
            server.shutdown()
            thread.join(timeout=2)

        self.assertEqual("found_call", text)
        capture = _CodexHandler.captures[0]
        self.assertEqual("/v1/responses", capture["path"])
        self.assertEqual("text/event-stream", capture["headers"]["accept"])
        self.assertEqual("identity", capture["headers"]["accept-encoding"])
        self.assertEqual("codex_cli_rs", capture["headers"]["originator"])
        self.assertEqual(
            "codex_cli_rs/0.80.0 (Windows 15.7.2; x86_64) Terminal",
            capture["headers"]["user-agent"],
        )
        self.assertEqual("high", capture["body"]["reasoning"]["effort"])
        self.assertEqual(0.2, capture["body"]["temperature"])
        self.assertEqual(
            [{"role": "user", "content": "Who are you?"}],
            capture["body"]["input"],
        )

    def test_call_llm_text_rejects_non_sse_content_type(self) -> None:
        _CodexHandler.captures = []
        _CodexHandler.content_type = "application/json"
        server = HTTPServer(("127.0.0.1", 0), _CodexHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaisesRegex(RuntimeError, "expected text/event-stream"):
                ida_llm_utils.call_llm_text(
                    None,
                    model="gpt-5.4",
                    messages=[{"role": "user", "content": "Who are you?"}],
                    api_key="test-api-key",
                    base_url=f"http://127.0.0.1:{server.server_port}/v1",
                    fake_as="codex",
                )
        finally:
            server.shutdown()
            thread.join(timeout=2)
```

- [ ] **Step 2: 运行 helper 测试，确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_ida_llm_utils -v
```

Expected: FAIL，因为当前没有 `normalize_optional_effort(...)`，`call_llm_text(...)` 也还不会发送 `reasoning_effort` 或改走 `/responses`。

- [ ] **Step 3: 实现 `ida_llm_utils.py` 的 transport 分流与 SSE 解析**

```python
CODEX_CLI_USER_AGENT = "codex_cli_rs/0.80.0 (Windows 15.7.2; x86_64) Terminal"
CODEX_CLI_ORIGINATOR = "codex_cli_rs"
_ALLOWED_LLM_EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh"}


def normalize_optional_effort(value: Any, name: str = "effort") -> str:
    if value is None:
        return "medium"
    text = str(value).strip().lower()
    if not text:
        return "medium"
    if text not in _ALLOWED_LLM_EFFORTS:
        allowed = ", ".join(sorted(_ALLOWED_LLM_EFFORTS))
        raise ValueError(f"{name} must be one of: {allowed}")
    return text


def _extract_text_from_message_content(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, Sequence) and not isinstance(content, (str, bytes, bytearray)):
        parts = []
        for part in content:
            if isinstance(part, Mapping):
                text = part.get("text") or part.get("content")
            else:
                text = getattr(part, "text", None)
            if text:
                parts.append(str(text).strip())
        return "\n".join(part for part in parts if part)
    return str(content or "").strip()


def _build_responses_input(messages: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    user_parts = []
    for message in messages:
        if str(message.get("role", "")).strip() != "user":
            continue
        content_text = _extract_text_from_message_content(message.get("content"))
        if content_text:
            user_parts.append(content_text)
    if not user_parts:
        raise ValueError("messages must include at least one user message")
    return [{"role": "user", "content": "\n\n".join(user_parts)}]


def _extract_text_from_response_payload(payload: Mapping[str, Any]) -> str:
    event_type = str(payload.get("type", "")).strip()
    if event_type == "response.output_text.delta":
        return str(payload.get("delta", ""))
    if event_type == "response.completed":
        response_payload = payload.get("response") or {}
        texts = []
        for item in response_payload.get("output", []) or []:
            for content in item.get("content", []) or []:
                if content.get("type") == "output_text" and content.get("text"):
                    texts.append(str(content["text"]))
        return "".join(texts)
    return ""


def _call_llm_text_via_codex_http(*, api_key, base_url, model, messages, temperature, effort):
    request_headers = {
        "Authorization": f"Bearer {require_nonempty_text(api_key, 'api_key')}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "Accept-Encoding": "identity",
        "User-Agent": CODEX_CLI_USER_AGENT,
        "Originator": CODEX_CLI_ORIGINATOR,
        "Host": urlsplit(require_nonempty_text(base_url, 'base_url')).netloc,
    }
    request_body = {
        "input": _build_responses_input(messages),
        "model": require_nonempty_text(model, "model"),
        "reasoning": {"effort": normalize_optional_effort(effort)},
        "stream": True,
    }
    normalized_temperature = normalize_optional_temperature(temperature)
    if normalized_temperature is not None:
        request_body["temperature"] = normalized_temperature

    with httpx.Client(timeout=httpx.Timeout(30.0, read=300.0), trust_env=False) as http_client:
        with http_client.stream(
            "POST",
            f"{require_nonempty_text(base_url, 'base_url').rstrip('/')}/responses",
            headers=request_headers,
            json=request_body,
        ) as response:
            response.raise_for_status()
            content_type = response.headers.get("content-type", "")
            if "text/event-stream" not in content_type:
                raise RuntimeError(f"codex transport expected text/event-stream, got {content_type!r}")
            parts = []
            for raw_line in response.iter_lines():
                if not raw_line or not raw_line.startswith("data:"):
                    continue
                data_text = raw_line[5:].strip()
                if data_text == "[DONE]":
                    break
                payload = json.loads(data_text)
                chunk = _extract_text_from_response_payload(payload)
                if chunk:
                    parts.append(chunk)
    text = "".join(parts).strip()
    if not text:
        raise RuntimeError("codex transport returned empty response text")
    return text


def call_llm_text(
    client=None,
    *,
    model,
    messages,
    temperature=None,
    effort=None,
    api_key=None,
    base_url=None,
    fake_as=None,
    debug=False,
) -> str:
    normalized_effort = normalize_optional_effort(effort)
    if fake_as == "codex":
        return _call_llm_text_via_codex_http(
            api_key=api_key,
            base_url=base_url,
            model=model,
            messages=messages,
            temperature=temperature,
            effort=normalized_effort,
        )

    request_kwargs = {
        "model": require_nonempty_text(model, "model"),
        "messages": messages,
        "reasoning_effort": normalized_effort,
    }
    normalized_temperature = normalize_optional_temperature(temperature)
    if normalized_temperature is not None:
        request_kwargs["temperature"] = normalized_temperature
    response = client.chat.completions.create(**request_kwargs)
    return extract_first_message_text(response)
```

- [ ] **Step 4: 重新运行 helper 测试，确认通过**

Run:

```bash
uv run python -m unittest tests.test_ida_llm_utils -v
```

Expected: PASS，SDK 路径会默认发送 `reasoning_effort="medium"`，`codex_http` 路径会按目标 headers/body 发 `/responses` 并正确解析 SSE。

- [ ] **Step 5: 提交共享 transport 改动**

```bash
git add ida_llm_utils.py tests/test_ida_llm_utils.py
git commit -m "feat(llm): 增加codex responses传输"
```

## Task 3: 接通 `LLM_DECOMPILE` 与 `vcall_finder`

**Files:**
- Modify: `tests/test_ida_analyze_util.py`
- Modify: `tests/test_ida_vcall_finder.py`
- Modify: `ida_analyze_util.py`
- Modify: `ida_vcall_finder.py`

- [ ] **Step 1: 先写 `LLM_DECOMPILE` 与 `vcall_finder` 的失败测试**

```python
class TestCallLlmDecompile(unittest.IsolatedAsyncioTestCase):
    async def test_call_llm_decompile_forwards_effort_and_codex_transport(self) -> None:
        response_text = """
```yaml
found_vcall: []
found_call: []
found_gv: []
found_struct_offset: []
```
""".strip()

        with patch.object(
            ida_analyze_util,
            "call_llm_text",
            return_value=response_text,
            create=True,
        ) as mock_call_llm_text:
            parsed = await ida_analyze_util.call_llm_decompile(
                client=None,
                model="gpt-5.4",
                symbol_name_list=["ILoopMode_OnLoopActivate"],
                disasm_code="call    [rax+68h]",
                procedure="(*v1->lpVtbl->OnLoopActivate)(v1);",
                api_key="test-api-key",
                base_url="https://example.invalid/v1",
                fake_as="codex",
                effort="high",
            )

        self.assertEqual([], parsed["found_vcall"])
        self.assertEqual("high", mock_call_llm_text.call_args.kwargs["effort"])
        self.assertEqual("codex", mock_call_llm_text.call_args.kwargs["fake_as"])
        self.assertEqual("test-api-key", mock_call_llm_text.call_args.kwargs["api_key"])
        self.assertEqual("https://example.invalid/v1", mock_call_llm_text.call_args.kwargs["base_url"])
```

```python
class TestPrepareLlmDecompileRequest(unittest.TestCase):
    def test_prepare_llm_decompile_request_skips_client_factory_for_codex(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text("{symbol_name_list}", encoding="utf-8")
            _write_yaml(
                preprocessor_dir / "references" / "reference.yaml",
                {"func_name": "TargetFunc", "disasm_code": "mov rax, [rcx]", "procedure": "return 0;"},
            )

            with patch.object(
                ida_analyze_util,
                "_get_preprocessor_scripts_dir",
                return_value=preprocessor_dir,
            ), patch.object(
                ida_analyze_util,
                "create_openai_client",
                side_effect=AssertionError("should not be called in codex mode"),
                create=True,
            ):
                request = ida_analyze_util._prepare_llm_decompile_request(
                    "TargetFunc",
                    {"TargetFunc": {"prompt_path": "prompt/call_llm_decompile.md", "reference_yaml_path": "references/reference.yaml"}},
                    {
                        "model": "gpt-5.4",
                        "api_key": "test-api-key",
                        "base_url": "https://example.invalid/v1",
                        "fake_as": "codex",
                        "effort": "high",
                    },
                    platform="windows",
                    debug=True,
                )

        self.assertIsNone(request["client"])
        self.assertEqual("codex", request["fake_as"])
        self.assertEqual("high", request["effort"])
```

```python
class TestCallOpenAiForVcalls(unittest.TestCase):
    @patch("ida_vcall_finder.call_llm_text")
    def test_call_openai_for_vcalls_forwards_effort_and_codex(self, mock_call_llm_text) -> None:
        mock_call_llm_text.return_value = "found_vcall: []"

        ida_vcall_finder.call_openai_for_vcalls(
            None,
            {
                "object_name": "g_pNetworkMessages",
                "module": "networksystem",
                "platform": "linux",
                "func_name": "sub_2000",
                "func_va": "0x2000",
                "disasm_code": "call    [rax+68h]",
                "procedure": "obj->vfptr[13](obj);",
            },
            "gpt-5.4",
            api_key="test-api-key",
            base_url="https://example.invalid/v1",
            fake_as="codex",
            effort="high",
        )

        self.assertEqual("codex", mock_call_llm_text.call_args.kwargs["fake_as"])
        self.assertEqual("high", mock_call_llm_text.call_args.kwargs["effort"])
```

- [ ] **Step 2: 运行这组回归测试，确认当前失败**

Run:

```bash
uv run python -m unittest tests.test_ida_analyze_util tests.test_ida_vcall_finder -v
```

Expected: FAIL，因为 `call_llm_decompile(...)`、`call_openai_for_vcalls(...)` 还没有 `effort` / `fake_as` / `api_key` / `base_url` 透传能力。

- [ ] **Step 3: 实现 `ida_analyze_util.py` 与 `ida_vcall_finder.py` 的接线**

```python
try:
    from ida_llm_utils import (
        call_llm_text,
        create_openai_client,
        normalize_optional_effort,
        normalize_optional_temperature,
    )
except Exception:
    call_llm_text = None
    create_openai_client = None
    normalize_optional_effort = None
    normalize_optional_temperature = None
```

```python
def _prepare_llm_decompile_request(...):
    ...
    temperature = llm_config.get("temperature")
    effort = (
        normalize_optional_effort(llm_config.get("effort"), "llm_config.effort")
        if callable(normalize_optional_effort)
        else str(llm_config.get("effort") or "medium").strip().lower() or "medium"
    )
    fake_as = str(llm_config.get("fake_as") or "").strip().lower() or None

    if fake_as == "codex":
        client = None
    else:
        client = create_openai_client(
            llm_config.get("api_key"),
            llm_config.get("base_url"),
            api_key_required_message="llm_config.api_key is required for llm_decompile fallback",
        )

    return {
        "client": client,
        "model": model,
        "api_key": llm_config.get("api_key"),
        "base_url": llm_config.get("base_url"),
        "fake_as": fake_as,
        "effort": effort,
        ...
    }
```

```python
async def call_llm_decompile(
    client,
    model,
    symbol_name_list,
    disasm_code,
    procedure,
    disasm_for_reference="",
    procedure_for_reference="",
    prompt_template=None,
    platform=None,
    temperature=None,
    effort=None,
    api_key=None,
    base_url=None,
    fake_as=None,
    debug=False,
):
    ...
    request_kwargs = {
        "client": client,
        "model": str(model).strip(),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "effort": effort,
        "api_key": api_key,
        "base_url": base_url,
        "fake_as": fake_as,
        "debug": debug,
    }
```

```python
def call_openai_for_vcalls(
    client,
    detail,
    model,
    *,
    temperature=None,
    effort=None,
    api_key=None,
    base_url=None,
    fake_as=None,
    debug=False,
    request_label="",
):
    request_kwargs = {
        "model": model,
        "client": client,
        "messages": [
            {"role": "system", "content": "You are a reverse engineering expert."},
            {"role": "user", "content": render_vcall_prompt(detail)},
        ],
        "effort": effort,
        "api_key": api_key,
        "base_url": base_url,
        "fake_as": fake_as,
        "debug": debug,
    }
    ...
```

```python
def _get_or_create_llm_client(client_ref, *, api_key, base_url, fake_as):
    if fake_as == "codex":
        return None
    llm_client = client_ref.get("client")
    if llm_client is None:
        llm_client = create_openai_client(
            api_key=api_key,
            base_url=base_url,
            api_key_required_message="-llm_apikey is required when -vcall_finder is enabled",
        )
        client_ref["client"] = llm_client
    return llm_client
```

- [ ] **Step 4: 重新运行 `LLM_DECOMPILE` 与 `vcall_finder` 回归测试**

Run:

```bash
uv run python -m unittest tests.test_ida_analyze_util tests.test_ida_vcall_finder -v
```

Expected: PASS，`llm_config` 中的 `temperature` / `effort` / `fake_as` 能走完整链路，且 `codex` 模式不再强依赖 SDK client。

- [ ] **Step 5: 提交接线改动**

```bash
git add ida_analyze_util.py ida_vcall_finder.py tests/test_ida_analyze_util.py tests/test_ida_vcall_finder.py
git commit -m "feat(llm): 打通codex传输接线"
```

## Task 4: 更新文档并做最终定向验证

**Files:**
- Modify: `README.md`
- Modify: `README_CN.md`
- Test: `tests/test_ida_analyze_bin.py`
- Test: `tests/test_ida_preprocessor_scripts.py`
- Test: `tests/test_ida_llm_utils.py`
- Test: `tests/test_ida_analyze_util.py`
- Test: `tests/test_ida_vcall_finder.py`

- [ ] **Step 1: 更新英文 README 的共享 LLM 参数说明**

```md
* Shared LLM CLI parameters:
  - `-llm_apikey`: required when an LLM-backed workflow is enabled, including `vcall_finder` aggregation and `LLM_DECOMPILE`
  - `-llm_baseurl`: optional custom compatible base URL
  - `-llm_model`: optional, defaults to `gpt-4o`
  - `-llm_temperature`: optional; sent only when explicitly set
  - `-llm_effort`: optional; defaults to `medium`; supports `none|minimal|low|medium|high|xhigh`
  - `-llm_fake_as`: optional; `codex` switches to direct `/v1/responses` SSE transport
  - Env fallbacks: `CS2VIBE_LLM_APIKEY`, `CS2VIBE_LLM_BASEURL`, `CS2VIBE_LLM_TEMPERATURE`, `CS2VIBE_LLM_EFFORT`, `CS2VIBE_LLM_FAKE_AS`
```

````md
```bash
uv run ida_analyze_bin.py -gamever=14141 -modules=networksystem -platform=windows -vcall_finder=g_pNetworkMessages -llm_model=gpt-5.4 -llm_apikey=your-key -llm_effort=high -llm_fake_as=codex -llm_baseurl=http://127.0.0.1:8080/v1
```
````

- [ ] **Step 2: 同步更新中文 README**

```md
* 共享 LLM CLI 参数：
  - `-llm_apikey`：启用基于 LLM 的流程时必需，包括 `vcall_finder` 聚合与 `LLM_DECOMPILE`
  - `-llm_baseurl`：可选，自定义兼容 base URL
  - `-llm_model`：可选，默认 `gpt-4o`
  - `-llm_temperature`：可选，仅在显式设置时发送
  - `-llm_effort`：可选，默认 `medium`，支持 `none|minimal|low|medium|high|xhigh`
  - `-llm_fake_as`：可选，设为 `codex` 时改走直连 `/v1/responses` 的 SSE 传输
  - 环境变量 fallback：`CS2VIBE_LLM_APIKEY`、`CS2VIBE_LLM_BASEURL`、`CS2VIBE_LLM_TEMPERATURE`、`CS2VIBE_LLM_EFFORT`、`CS2VIBE_LLM_FAKE_AS`
```

````md
```bash
uv run ida_analyze_bin.py -gamever=14141 -modules=networksystem -platform=windows -vcall_finder=g_pNetworkMessages -llm_model=gpt-5.4 -llm_apikey=your-key -llm_effort=high -llm_fake_as=codex -llm_baseurl=http://127.0.0.1:8080/v1
```
````

- [ ] **Step 3: 先跑帮助输出检查新参数是否出现**

Run:

```bash
uv run python ida_analyze_bin.py -h | rg "llm_(temperature|effort|fake_as)"
```

Expected:

```text
-llm_temperature
-llm_effort
-llm_fake_as
```

- [ ] **Step 4: 跑最终定向回归**

Run:

```bash
uv run python -m unittest \
  tests.test_ida_analyze_bin \
  tests.test_ida_preprocessor_scripts \
  tests.test_ida_llm_utils \
  tests.test_ida_analyze_util \
  tests.test_ida_vcall_finder -v
```

Expected: PASS，说明 CLI、预处理透传、共享 transport、`LLM_DECOMPILE` 和 `vcall_finder` 五块都已连通。

- [ ] **Step 5: 提交文档与最终回归结果**

```bash
git add README.md README_CN.md
git commit -m "docs(llm): 更新codex传输参数说明"
```

## Self-Review Checklist

- 规格覆盖：
  - `CS2VIBE_LLM_FAKE_AS` / `CS2VIBE_LLM_EFFORT` / `CS2VIBE_LLM_TEMPERATURE` 的入口与优先级由 Task 1 覆盖
  - `temperature` 仅显式发送、`effort` 默认 `medium` 的协议语义由 Task 1 + Task 2 覆盖
  - `codex` 模式的 `/responses` SSE 传输、headers 和 body 由 Task 2 覆盖
  - `LLM_DECOMPILE` 与 `vcall_finder` 的统一接线由 Task 3 覆盖
  - README / README_CN 的对外说明由 Task 4 覆盖
- 占位符扫描：全文无 `TBD` / `TODO` / “参考上一任务” 之类占位写法
- 类型一致性：计划统一使用 `llm_effort`、`llm_fake_as`、`fake_as`、`effort`、`reasoning_effort`、`reasoning.effort` 这组命名，不混用旧别名
