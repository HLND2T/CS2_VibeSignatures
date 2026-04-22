# llm_decompile Retry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `LLM_DECOMPILE` automatically retry transient transport, timeout, rate-limit, and 5xx failures while preserving existing fail-closed behavior.

**Architecture:** Centralize retry classification and retry execution in `ida_analyze_util.py` around `call_llm_text(...)`. Propagate the already-resolved skill `max_retries` value from `ida_analyze_bin.py` through `ida_skill_preprocessor.py` into `llm_config`, then into `call_llm_decompile(...)`.

**Tech Stack:** Python 3, `unittest`, `pytest`, existing IDA MCP preprocessing pipeline, existing `ida_llm_utils.call_llm_text` helper.

---

## File Structure

- Modify: `ida_analyze_util.py`
  - Add transient LLM error classification helpers.
  - Add retry count and backoff normalization helpers.
  - Add optional retry parameters to `_prepare_llm_decompile_request(...)` and `call_llm_decompile(...)`.
  - Wrap only `call_llm_text(**request_kwargs)` in retry logic.
- Modify: `ida_skill_preprocessor.py`
  - Accept optional `llm_max_retries`.
  - Include `max_retries` in `llm_config` only when a value is provided.
- Modify: `ida_analyze_bin.py`
  - Pass resolved `skill_max_retries` to `_run_preprocess_single_skill_via_mcp(...)`.
  - Forward it to `preprocess_single_skill_via_mcp(...)`.
- Modify: `tests/test_ida_analyze_util.py`
  - Cover retry helper classification and `call_llm_decompile(...)` retry behavior.
- Modify: `tests/test_ida_preprocessor_scripts.py`
  - Cover `preprocess_single_skill_via_mcp(...)` forwarding `llm_config["max_retries"]`.
- Modify: `tests/test_ida_analyze_bin.py`
  - Cover `process_binary(...)` forwarding resolved skill retry count into MCP preprocessing.
- No README update required because no new CLI flag or new `config.yaml` key is introduced.

## Task 1: Add LLM Retry Unit Tests

**Files:**
- Modify: `tests/test_ida_analyze_util.py`
- Later modify: `ida_analyze_util.py`

- [ ] **Step 1: Add retry tests near existing `call_llm_decompile` tests**

Insert these methods after `test_call_llm_decompile_fails_closed_when_shared_helper_raises` in `tests/test_ida_analyze_util.py`:

```python
    async def test_call_llm_decompile_retries_transient_transport_error_then_parses_yaml(
        self,
    ) -> None:
        response_text = """
```yaml
found_vcall:
  - insn_va: 0x180777700
    insn_disasm: "call    [rax+68h]"
    vfunc_offset: 0x68
    func_name: "ILoopMode_OnLoopActivate"
found_call: []
found_gv: []
found_struct_offset: []
```
""".strip()

        with patch.object(
            ida_analyze_util,
            "call_llm_text",
            side_effect=[
                RuntimeError("*** transport received error: retry your request"),
                response_text,
            ],
            create=True,
        ) as mock_call_llm_text:
            parsed = await ida_analyze_util.call_llm_decompile(
                client=object(),
                model="gpt-5.4",
                symbol_name_list=["ILoopMode_OnLoopActivate"],
                disasm_code="call    [rax+68h]",
                procedure="(*v1->lpVtbl->OnLoopActivate)(v1);",
                max_retries=2,
                retry_initial_delay=0,
            )

        self.assertEqual(
            {
                "found_vcall": [
                    {
                        "insn_va": "0x180777700",
                        "insn_disasm": "call    [rax+68h]",
                        "vfunc_offset": "0x68",
                        "func_name": "ILoopMode_OnLoopActivate",
                    }
                ],
                "found_call": [],
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            },
            parsed,
        )
        self.assertEqual(2, mock_call_llm_text.call_count)
```

```python
    async def test_call_llm_decompile_does_not_retry_non_transient_error(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "call_llm_text",
            side_effect=RuntimeError("invalid api key"),
            create=True,
        ) as mock_call_llm_text:
            parsed = await ida_analyze_util.call_llm_decompile(
                client=object(),
                model="gpt-5.4",
                symbol_name_list=["ILoopMode_OnLoopActivate"],
                disasm_code="call    [rax+68h]",
                procedure="(*v1->lpVtbl->OnLoopActivate)(v1);",
                max_retries=3,
                retry_initial_delay=0,
            )

        self.assertEqual(ida_analyze_util._empty_llm_decompile_result(), parsed)
        mock_call_llm_text.assert_called_once()
```

```python
    async def test_call_llm_decompile_returns_empty_after_retry_exhaustion(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "call_llm_text",
            side_effect=RuntimeError("HTTP 503 service unavailable"),
            create=True,
        ) as mock_call_llm_text:
            parsed = await ida_analyze_util.call_llm_decompile(
                client=object(),
                model="gpt-5.4",
                symbol_name_list=["ILoopMode_OnLoopActivate"],
                disasm_code="call    [rax+68h]",
                procedure="(*v1->lpVtbl->OnLoopActivate)(v1);",
                max_retries=3,
                retry_initial_delay=0,
            )

        self.assertEqual(ida_analyze_util._empty_llm_decompile_result(), parsed)
        self.assertEqual(3, mock_call_llm_text.call_count)
```

```python
    async def test_call_llm_decompile_max_retries_one_disables_retry(
        self,
    ) -> None:
        with patch.object(
            ida_analyze_util,
            "call_llm_text",
            side_effect=RuntimeError("HTTP 429 too many requests"),
            create=True,
        ) as mock_call_llm_text:
            parsed = await ida_analyze_util.call_llm_decompile(
                client=object(),
                model="gpt-5.4",
                symbol_name_list=["ILoopMode_OnLoopActivate"],
                disasm_code="call    [rax+68h]",
                procedure="(*v1->lpVtbl->OnLoopActivate)(v1);",
                max_retries=1,
                retry_initial_delay=0,
            )

        self.assertEqual(ida_analyze_util._empty_llm_decompile_result(), parsed)
        mock_call_llm_text.assert_called_once()
```

- [ ] **Step 2: Add helper classification tests**

Insert these synchronous tests near the parsing/helper tests in `tests/test_ida_analyze_util.py`:

```python
    def test_is_transient_llm_error_accepts_status_code_attributes(self) -> None:
        class FakeError(Exception):
            status_code = 429

        self.assertTrue(ida_analyze_util._is_transient_llm_error(FakeError()))

    def test_is_transient_llm_error_accepts_response_status_code(self) -> None:
        class FakeResponse:
            status_code = 502

        class FakeError(Exception):
            response = FakeResponse()

        self.assertTrue(ida_analyze_util._is_transient_llm_error(FakeError()))

    def test_is_transient_llm_error_rejects_client_configuration_error(self) -> None:
        self.assertFalse(
            ida_analyze_util._is_transient_llm_error(RuntimeError("invalid api key"))
        )
```

- [ ] **Step 3: Run targeted tests and confirm failure**

Run:

```bash
pytest tests/test_ida_analyze_util.py \
  -k "call_llm_decompile_retries_transient_transport_error_then_parses_yaml or call_llm_decompile_does_not_retry_non_transient_error or call_llm_decompile_returns_empty_after_retry_exhaustion or call_llm_decompile_max_retries_one_disables_retry or is_transient_llm_error" \
  -v
```

Expected: FAIL because `_is_transient_llm_error` does not exist and `call_llm_decompile(...)` does not accept retry parameters yet.

## Task 2: Implement Centralized LLM Retry

**Files:**
- Modify: `ida_analyze_util.py`
- Test: `tests/test_ida_analyze_util.py`

- [ ] **Step 1: Add `asyncio` import**

Change the import block at the top of `ida_analyze_util.py` from:

```python
import json
import math
import os
import re
import tempfile
import textwrap
from pathlib import Path
```

to:

```python
import asyncio
import json
import math
import os
import re
import tempfile
import textwrap
from pathlib import Path
```

- [ ] **Step 2: Add retry helper functions**

Insert these helpers after `_empty_llm_decompile_result()` in `ida_analyze_util.py`:

```python
def _normalize_llm_retry_attempts(value, default=3):
    try:
        attempts = int(value)
    except (TypeError, ValueError):
        attempts = int(default)
    return max(1, attempts)


def _normalize_llm_retry_delay(value, default, minimum=0.0):
    try:
        delay = float(value)
    except (TypeError, ValueError):
        delay = float(default)
    if delay < minimum:
        return minimum
    return delay


def _extract_llm_error_status_code(exc):
    for source in (exc, getattr(exc, "response", None)):
        if source is None:
            continue
        status_code = getattr(source, "status_code", None)
        if status_code is None:
            continue
        try:
            return int(status_code)
        except (TypeError, ValueError):
            continue
    return None


def _is_transient_llm_error(exc):
    status_code = _extract_llm_error_status_code(exc)
    if status_code == 429 or (
        status_code is not None and 500 <= status_code < 600
    ):
        return True

    message = str(exc or "").lower()
    retryable_fragments = (
        "transport received error",
        "timeout",
        "timed out",
        "read timeout",
        "rate limit",
        "rate_limit",
        "too many requests",
        "http 429",
        "status 429",
        "status_code=429",
        " 429",
        "http 500",
        "http 502",
        "http 503",
        "http 504",
        "status 500",
        "status 502",
        "status 503",
        "status 504",
        "server error",
        "service unavailable",
        "temporarily unavailable",
    )
    return any(fragment in message for fragment in retryable_fragments)
```

- [ ] **Step 3: Extend `call_llm_decompile(...)` signature**

In `ida_analyze_util.py`, change the end of the `call_llm_decompile(...)` signature from:

```python
    fake_as=None,
    debug=False,
):
```

to:

```python
    fake_as=None,
    max_retries=None,
    retry_initial_delay=None,
    retry_backoff_factor=None,
    retry_max_delay=None,
    debug=False,
):
```

- [ ] **Step 4: Replace the single `call_llm_text` try/except with retry loop**

In `call_llm_decompile(...)`, replace this block:

```python
    try:
        request_kwargs = {
            "client": client,
            "model": str(model).strip(),
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "debug": debug,
        }
        normalized_temperature = temperature
        if normalized_temperature is not None and callable(normalize_optional_temperature):
            normalized_temperature = normalize_optional_temperature(
                normalized_temperature,
                "temperature",
            )
        if normalized_temperature is not None:
            request_kwargs["temperature"] = normalized_temperature
        if effort is not None:
            request_kwargs["effort"] = effort
        if api_key is not None:
            request_kwargs["api_key"] = api_key
        if base_url is not None:
            request_kwargs["base_url"] = base_url
        normalized_fake_as = str(fake_as or "").strip().lower() or None
        if normalized_fake_as is not None:
            request_kwargs["fake_as"] = normalized_fake_as
        content = call_llm_text(**request_kwargs)
    except Exception as exc:
        if debug:
            print(
                f"    Preprocess: llm_decompile call failed for "
                f"{symbol_name_text}: {exc}"
            )
        return _empty_llm_decompile_result()
```

with:

```python
    request_kwargs = {
        "client": client,
        "model": str(model).strip(),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "debug": debug,
    }
    normalized_temperature = temperature
    if normalized_temperature is not None and callable(normalize_optional_temperature):
        normalized_temperature = normalize_optional_temperature(
            normalized_temperature,
            "temperature",
        )
    if normalized_temperature is not None:
        request_kwargs["temperature"] = normalized_temperature
    if effort is not None:
        request_kwargs["effort"] = effort
    if api_key is not None:
        request_kwargs["api_key"] = api_key
    if base_url is not None:
        request_kwargs["base_url"] = base_url
    normalized_fake_as = str(fake_as or "").strip().lower() or None
    if normalized_fake_as is not None:
        request_kwargs["fake_as"] = normalized_fake_as

    max_attempts = _normalize_llm_retry_attempts(max_retries, default=3)
    delay = _normalize_llm_retry_delay(retry_initial_delay, default=1.0)
    backoff_factor = _normalize_llm_retry_delay(
        retry_backoff_factor,
        default=2.0,
        minimum=1.0,
    )
    max_delay = _normalize_llm_retry_delay(retry_max_delay, default=8.0)

    content = None
    for attempt_index in range(max_attempts):
        try:
            content = call_llm_text(**request_kwargs)
            break
        except Exception as exc:
            is_last_attempt = attempt_index >= max_attempts - 1
            should_retry = _is_transient_llm_error(exc) and not is_last_attempt
            if not should_retry:
                if debug:
                    print(
                        f"    Preprocess: llm_decompile call failed for "
                        f"{symbol_name_text}: {exc}"
                    )
                return _empty_llm_decompile_result()
            if debug:
                print(
                    f"    Preprocess: llm_decompile transient failure for "
                    f"{symbol_name_text} on attempt "
                    f"{attempt_index + 1}/{max_attempts}: {exc}; "
                    f"retrying in {delay:.2f}s"
                )
            if delay > 0:
                await asyncio.sleep(delay)
            delay = min(delay * backoff_factor, max_delay)
```

- [ ] **Step 5: Run targeted retry tests**

Run:

```bash
pytest tests/test_ida_analyze_util.py \
  -k "call_llm_decompile_retries_transient_transport_error_then_parses_yaml or call_llm_decompile_does_not_retry_non_transient_error or call_llm_decompile_returns_empty_after_retry_exhaustion or call_llm_decompile_max_retries_one_disables_retry or is_transient_llm_error" \
  -v
```

Expected: PASS.

- [ ] **Step 6: Do not commit unless explicitly authorized**

Do not run `git commit` in this repository unless the user explicitly asks for commits. If commits are authorized later, use:

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "fix(preprocess): 重试 llm_decompile 瞬时错误"
```

## Task 3: Propagate Skill `max_retries` into LLM Config

**Files:**
- Modify: `ida_skill_preprocessor.py`
- Modify: `ida_analyze_bin.py`
- Test: `tests/test_ida_preprocessor_scripts.py`
- Test: `tests/test_ida_analyze_bin.py`

- [ ] **Step 1: Add preprocessor forwarding test**

In `tests/test_ida_preprocessor_scripts.py`, inside `class TestPreprocessSingleSkillViaMcp`, add this test after `test_forwards_full_llm_config_with_effort_and_fake_as`:

```python
    async def test_forwards_llm_max_retries_when_provided(self) -> None:
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
                llm_model="gpt-5.4",
                llm_fake_as="codex",
                llm_max_retries=4,
                debug=True,
            )

        self.assertTrue(result)
        self.assertEqual(4, received["llm_config"]["max_retries"])
```

- [ ] **Step 2: Add `process_binary(...)` retry propagation test**

In `tests/test_ida_analyze_bin.py`, inside `class TestProcessBinaryLlmWiring`, add:

```python
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
    def test_process_binary_passes_skill_max_retries_to_preprocess(
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
            binary_path="/tmp/bin/14141/server/server.dll",
            skills=[
                {
                    "name": "find-IGameSystem_DestroyAllGameSystems",
                    "expected_output": ["IGameSystem_DestroyAllGameSystems.{platform}.yaml"],
                    "expected_input": [],
                    "max_retries": 4,
                }
            ],
            agent="codex",
            host="127.0.0.1",
            port=13337,
            ida_args="",
            platform="windows",
            debug=False,
            max_retries=2,
            llm_model="gpt-5.4",
            llm_fake_as="codex",
        )

        self.assertEqual(4, mock_preprocess.await_args.kwargs["llm_max_retries"])
```

- [ ] **Step 3: Run propagation tests and confirm failure**

Run:

```bash
pytest tests/test_ida_preprocessor_scripts.py::TestPreprocessSingleSkillViaMcp::test_forwards_llm_max_retries_when_provided \
  tests/test_ida_analyze_bin.py::TestProcessBinaryLlmWiring::test_process_binary_passes_skill_max_retries_to_preprocess \
  -v
```

Expected: FAIL because `llm_max_retries` is not accepted or forwarded yet.

- [ ] **Step 4: Update `ida_skill_preprocessor.preprocess_single_skill_via_mcp(...)` signature and config**

In `ida_skill_preprocessor.py`, change the function signature from:

```python
    llm_model=None, llm_apikey=None, llm_baseurl=None, llm_temperature=None,
    llm_effort=None, llm_fake_as=None,
    debug=False,
):
```

to:

```python
    llm_model=None, llm_apikey=None, llm_baseurl=None, llm_temperature=None,
    llm_effort=None, llm_fake_as=None, llm_max_retries=None,
    debug=False,
):
```

Update the docstring by adding:

```python
        llm_max_retries: optional maximum total attempts for LLM decompile calls
```

Then replace the `llm_config` construction:

```python
                        llm_config = {
                            "model": llm_model,
                            "api_key": llm_apikey,
                            "base_url": llm_baseurl,
                            "temperature": llm_temperature,
                            "effort": llm_effort,
                            "fake_as": llm_fake_as,
                        }
```

with:

```python
                        llm_config = {
                            "model": llm_model,
                            "api_key": llm_apikey,
                            "base_url": llm_baseurl,
                            "temperature": llm_temperature,
                            "effort": llm_effort,
                            "fake_as": llm_fake_as,
                        }
                        if llm_max_retries is not None:
                            llm_config["max_retries"] = llm_max_retries
```

- [ ] **Step 5: Update `ida_analyze_bin._run_preprocess_single_skill_via_mcp(...)`**

In `ida_analyze_bin.py`, add `llm_max_retries` to `_run_preprocess_single_skill_via_mcp(...)`:

```python
    llm_effort,
    llm_fake_as,
    llm_max_retries,
):
```

Add it to `preprocess_kwargs`:

```python
        "llm_max_retries": llm_max_retries,
```

Update the fallback compatibility list from:

```python
                "llm_fake_as",
```

to:

```python
                "llm_fake_as",
                "llm_max_retries",
```

And add this pop in the fallback block:

```python
        fallback_kwargs.pop("llm_max_retries", None)
```

- [ ] **Step 6: Pass resolved `skill_max_retries` from `process_binary(...)`**

In `ida_analyze_bin.py`, update the `_run_preprocess_single_skill_via_mcp(...)` call inside `process_binary(...)` by adding:

```python
                    llm_max_retries=skill_max_retries,
```

Place it immediately after `llm_fake_as=llm_fake_as,` for readability.

- [ ] **Step 7: Run propagation tests**

Run:

```bash
pytest tests/test_ida_preprocessor_scripts.py::TestPreprocessSingleSkillViaMcp::test_forwards_llm_max_retries_when_provided \
  tests/test_ida_analyze_bin.py::TestProcessBinaryLlmWiring::test_process_binary_passes_skill_max_retries_to_preprocess \
  -v
```

Expected: PASS.

- [ ] **Step 8: Do not commit unless explicitly authorized**

Do not run `git commit` in this repository unless the user explicitly asks for commits. If commits are authorized later, use:

```bash
git add ida_skill_preprocessor.py ida_analyze_bin.py tests/test_ida_preprocessor_scripts.py tests/test_ida_analyze_bin.py
git commit -m "fix(preprocess): 传递 skill 重试次数给 LLM"
```

## Task 4: Wire Retry Config Through LLM Request Preparation

**Files:**
- Modify: `ida_analyze_util.py`
- Test: `tests/test_ida_analyze_util.py`

- [ ] **Step 1: Add `_prepare_llm_decompile_request(...)` retry config test**

In `tests/test_ida_analyze_util.py`, add this test near `test_prepare_llm_decompile_request_collects_multiple_references`:

```python
    async def test_prepare_llm_decompile_request_preserves_retry_config(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            preprocessor_dir = Path(temp_dir) / "ida_preprocessor_scripts"
            (preprocessor_dir / "prompt").mkdir(parents=True, exist_ok=True)
            (preprocessor_dir / "references" / "server").mkdir(
                parents=True,
                exist_ok=True,
            )
            (preprocessor_dir / "prompt" / "call_llm_decompile.md").write_text(
                "{reference_blocks}\n---\n{target_blocks}",
                encoding="utf-8",
            )
            _write_yaml(
                preprocessor_dir / "references" / "server" / "Reference.windows.yaml",
                {
                    "func_name": "ReferenceFunc",
                    "disasm_code": "call qword ptr [rax+68h]",
                    "procedure": "ref();",
                },
            )

            with patch.object(
                ida_analyze_util,
                "_get_preprocessor_scripts_dir",
                return_value=preprocessor_dir,
            ):
                request = ida_analyze_util._prepare_llm_decompile_request(
                    "TargetFunc",
                    {
                        "TargetFunc": [
                            {
                                "prompt_path": "prompt/call_llm_decompile.md",
                                "reference_yaml_path": "references/server/Reference.{platform}.yaml",
                            }
                        ]
                    },
                    {
                        "model": "gpt-5.4",
                        "fake_as": "codex",
                        "max_retries": 4,
                        "retry_initial_delay": 0.5,
                        "retry_backoff_factor": 1.5,
                        "retry_max_delay": 3,
                    },
                    platform="windows",
                )

        self.assertEqual(4, request["max_retries"])
        self.assertEqual(0.5, request["retry_initial_delay"])
        self.assertEqual(1.5, request["retry_backoff_factor"])
        self.assertEqual(3, request["retry_max_delay"])
```

- [ ] **Step 2: Add `preprocess_common_skill(...)` forwarding assertion**

Find an existing `preprocess_common_skill(...)` LLM fallback test that patches `call_llm_decompile`, such as `test_preprocess_common_skill_uses_llm_decompile_vcall_fallback_for_func_yaml`. In that test's `llm_config`, add:

```python
                        "max_retries": 4,
                        "retry_initial_delay": 0,
                        "retry_backoff_factor": 1.5,
                        "retry_max_delay": 2,
```

Then after the existing `mock_call_llm_decompile.assert_awaited_once()` assertions, add:

```python
        self.assertEqual(4, mock_call_llm_decompile.call_args.kwargs["max_retries"])
        self.assertEqual(
            0,
            mock_call_llm_decompile.call_args.kwargs["retry_initial_delay"],
        )
        self.assertEqual(
            1.5,
            mock_call_llm_decompile.call_args.kwargs["retry_backoff_factor"],
        )
        self.assertEqual(
            2,
            mock_call_llm_decompile.call_args.kwargs["retry_max_delay"],
        )
```

- [ ] **Step 3: Run request forwarding tests and confirm failure**

Run:

```bash
pytest tests/test_ida_analyze_util.py \
  -k "prepare_llm_decompile_request_preserves_retry_config or uses_llm_decompile_vcall_fallback_for_func_yaml" \
  -v
```

Expected: FAIL because `_prepare_llm_decompile_request(...)` does not preserve retry fields and `_call_llm_decompile_for_request(...)` does not forward them.

- [ ] **Step 4: Preserve retry fields in `_prepare_llm_decompile_request(...)`**

In `ida_analyze_util.py`, after effort normalization in `_prepare_llm_decompile_request(...)`, add:

```python
    max_retries = _normalize_llm_retry_attempts(
        llm_config.get("max_retries"),
        default=3,
    )
    retry_initial_delay = _normalize_llm_retry_delay(
        llm_config.get("retry_initial_delay"),
        default=1.0,
    )
    retry_backoff_factor = _normalize_llm_retry_delay(
        llm_config.get("retry_backoff_factor"),
        default=2.0,
        minimum=1.0,
    )
    retry_max_delay = _normalize_llm_retry_delay(
        llm_config.get("retry_max_delay"),
        default=8.0,
    )
```

Then add these keys to the returned request dict:

```python
        "max_retries": max_retries,
        "retry_initial_delay": retry_initial_delay,
        "retry_backoff_factor": retry_backoff_factor,
        "retry_max_delay": retry_max_delay,
```

- [ ] **Step 5: Forward retry fields in `_call_llm_decompile_for_request(...)`**

In `ida_analyze_util.py`, inside `_call_llm_decompile_for_request(...)`, add these keyword arguments to `call_llm_decompile(...)`:

```python
                max_retries=llm_request.get("max_retries"),
                retry_initial_delay=llm_request.get("retry_initial_delay"),
                retry_backoff_factor=llm_request.get("retry_backoff_factor"),
                retry_max_delay=llm_request.get("retry_max_delay"),
```

Place them immediately before `debug=debug,`.

- [ ] **Step 6: Run request forwarding tests**

Run:

```bash
pytest tests/test_ida_analyze_util.py \
  -k "prepare_llm_decompile_request_preserves_retry_config or uses_llm_decompile_vcall_fallback_for_func_yaml" \
  -v
```

Expected: PASS.

- [ ] **Step 7: Do not commit unless explicitly authorized**

Do not run `git commit` in this repository unless the user explicitly asks for commits. If commits are authorized later, use:

```bash
git add ida_analyze_util.py tests/test_ida_analyze_util.py
git commit -m "fix(preprocess): 传递 LLM 重试配置"
```

## Task 5: Run Focused Regression Checks

**Files:**
- No source changes expected.
- Test only.

- [ ] **Step 1: Run focused utility tests**

Run:

```bash
pytest tests/test_ida_analyze_util.py \
  -k "llm_decompile or transient_llm_error" \
  -v
```

Expected: PASS.

- [ ] **Step 2: Run focused preprocessor forwarding tests**

Run:

```bash
pytest tests/test_ida_preprocessor_scripts.py::TestPreprocessSingleSkillViaMcp -v
```

Expected: PASS.

- [ ] **Step 3: Run focused binary wiring tests**

Run:

```bash
pytest tests/test_ida_analyze_bin.py::TestProcessBinaryLlmWiring -v
```

Expected: PASS.

- [ ] **Step 4: Run formatting whitespace check**

Run:

```bash
git diff --check
```

Expected: no output and exit code `0`.

- [ ] **Step 5: Summarize final changed files**

Run:

```bash
git status --short
```

Expected: changed files include:

```text
M ida_analyze_util.py
M ida_skill_preprocessor.py
M ida_analyze_bin.py
M tests/test_ida_analyze_util.py
M tests/test_ida_preprocessor_scripts.py
M tests/test_ida_analyze_bin.py
?? docs/superpowers/specs/2026-04-22-llm-decompile-retry-design.md
?? docs/superpowers/plans/2026-04-22-llm-decompile-retry.md
```

The exact status may include fewer or more files if adjacent tests already changed during implementation, but no unrelated source files should be modified.

## Self-review

- Spec coverage: transient error retry, fail-closed behavior, skill `max_retries` reuse, optional backoff fields, non-transient no-retry behavior, and grouped request compatibility are each covered by a task.
- Placeholder scan: no `TBD`, `TODO`, or "implement later" placeholders remain.
- Type consistency: the propagation path consistently uses `llm_max_retries` for wrapper APIs and `max_retries` inside `llm_config` / LLM request objects.
- Policy consistency: commit commands are documented only for explicitly authorized future use; the plan itself does not require committing in the current session.
