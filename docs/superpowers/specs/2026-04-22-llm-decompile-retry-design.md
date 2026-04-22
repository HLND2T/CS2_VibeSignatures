# llm_decompile transient error retry design

## Background

`LLM_DECOMPILE` requests can fail under high request frequency with transient transport errors such as:

```text
*** transport received error: An error occurred while processing your request. You can retry your request...
```

The current `call_llm_decompile(...)` flow catches any exception from `call_llm_text(...)`, logs the failure in debug mode, and returns an empty result. Because `preprocess_common_skill(...)` caches one LLM result for all symbols in the same request group, one transient transport failure can make every symbol in that grouped fallback proceed to the existing `failed to locate` path.

## Goals

- Retry transient `llm_decompile` failures automatically.
- Cover `transport received error`, timeout, rate limit, HTTP `429`, HTTP `5xx`, and temporary service-unavailable style errors.
- Keep the existing fail-closed behavior after retries are exhausted: return `_empty_llm_decompile_result()` and let the caller continue through the current `failed to locate` path.
- Reuse the existing skill-level `max_retries` configuration when available.
- Keep retry logic centralized so every `LLM_DECOMPILE` preprocessor benefits without modifying individual skill scripts.

## Non-goals

- Do not retry non-transient programming or configuration errors.
- Do not change the LLM prompt schema or parsed response schema.
- Do not change `preprocess_common_skill(...)` result caching semantics.
- Do not add a separate `config.yaml` field for LLM retry count.
- Do not make exhausted LLM retries abort the whole binary processing flow.

## Existing Context

- `config.yaml` may define `max_retries` per skill.
- CLI `-maxretry` provides the default skill retry count.
- `process_binary(...)` resolves `skill_max_retries = skill.get("max_retries") or max_retries`.
- `run_skill(...)` already receives this resolved value for agent fallback execution.
- MCP preprocessing currently does not receive `skill_max_retries`; `_run_preprocess_single_skill_via_mcp(...)` only forwards LLM model, API key, base URL, temperature, effort, and `fake_as`.

## Proposed Approach

Implement retry in `call_llm_decompile(...)`, and propagate the already-resolved `skill_max_retries` into `llm_config`.

This keeps behavior aligned between the preprocessor path and the agent fallback path:

1. `process_binary(...)` computes the effective skill retry count once.
2. `_run_preprocess_single_skill_via_mcp(...)` receives that count.
3. `preprocess_single_skill_via_mcp(...)` places it in `llm_config["max_retries"]`.
4. `_prepare_llm_decompile_request(...)` validates and stores it in the LLM request object.
5. `_call_llm_decompile_for_request(...)` passes it to `call_llm_decompile(...)`.
6. `call_llm_decompile(...)` applies transient-error retry around `call_llm_text(**request_kwargs)`.

## Retry Count Semantics

Reuse the existing skill retry semantics: `max_retries` means maximum total attempts, not extra retries after the first call.

Examples:

- `max_retries: 1` means one LLM call and no retry.
- `max_retries: 3` means up to three LLM calls: first attempt plus two retries.
- Missing or invalid values fall back to `3`.

This avoids a confusing mismatch where skill execution would treat `3` as three total attempts while `llm_decompile` treats it as four total attempts.

## Transient Error Classification

Add a small helper, for example `_is_transient_llm_error(exc)`, that classifies exceptions by lower-cased message and common attributes.

Retryable cases:

- Message contains `transport received error`.
- Message contains timeout indicators such as `timeout`, `timed out`, or `read timeout`.
- Message contains rate-limit indicators such as `rate limit`, `rate_limit`, `too many requests`, or `429`.
- Message contains server-side status indicators such as `500`, `502`, `503`, `504`, `server error`, `service unavailable`, or `temporarily unavailable`.
- Exception exposes `status_code` or `response.status_code` with `429` or `500 <= status_code < 600`.

Non-retryable cases:

- Authentication, permission, invalid request, malformed payload, invalid model, missing API key, or other apparent client/configuration failures.
- Any exception that does not match the transient classifier.

## Backoff Behavior

Use bounded exponential backoff between attempts:

- Default initial delay: `1.0` second.
- Default backoff factor: `2.0`.
- Default maximum delay: `8.0` seconds.

Allow optional `llm_config` keys for direct callers and future tuning:

- `retry_initial_delay`
- `retry_backoff_factor`
- `retry_max_delay`

These backoff keys are optional and do not require new CLI flags or new `config.yaml` fields for this change.

For unit tests, delay should be patchable or injectable so retry behavior can be tested without sleeping.

## Logging

When `debug=True`:

- Log each retryable failure with symbol list, attempt number, maximum attempts, and next delay.
- Log non-retryable failures once and return the empty result.
- Log exhausted retry failures once, preserving the current fail-closed behavior.

Normal non-debug output should remain unchanged.

## Error Handling

If a retry eventually succeeds, parse and return the successful response exactly as today.

If all retry attempts fail:

1. Print the existing debug-style failure message.
2. Return `_empty_llm_decompile_result()`.
3. Let `preprocess_common_skill(...)` continue to the current symbol-level failure path.

No new exception should escape from `call_llm_decompile(...)` because existing callers rely on fail-closed behavior.

## Testing Plan

Add focused tests in `tests/test_ida_analyze_util.py` and related preprocessor forwarding tests as needed:

- Transient failure then success: `call_llm_text` raises `transport received error` once, succeeds on the next attempt, and parsed YAML is returned.
- Exhausted transient failure: repeated `429` or `503` errors call the helper up to `max_retries` total attempts and return an empty LLM result.
- Non-transient failure: authentication or invalid request style error is not retried.
- Skill retry propagation: resolved `skill_max_retries` is forwarded into MCP preprocessing and then into `llm_config`.
- Default behavior: direct calls without retry config still use three total attempts.
- `max_retries: 1`: transient error is not retried.

## Acceptance Criteria

- The reported `transport received error` is retried automatically.
- `config.yaml` skill-level `max_retries` controls `llm_decompile` total attempts for that skill when preprocessing runs.
- CLI `-maxretry` controls the default `llm_decompile` total attempts for skills that do not override `max_retries`.
- Non-transient LLM errors are not repeatedly retried.
- Exhausted transient errors keep the existing empty-result behavior.
- Existing grouped `LLM_DECOMPILE` caching still works unchanged.

## Self-review

- No unresolved placeholders remain.
- The design explicitly resolves the `max_retries` semantic mismatch by reusing existing total-attempt semantics.
- The change scope is limited to retry configuration propagation and centralized LLM call retry.
- The failure mode remains compatible with the current preprocessor pipeline.
