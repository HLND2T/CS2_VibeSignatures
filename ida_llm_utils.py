#!/usr/bin/env python3

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlparse

import httpx
from openai import OpenAI

CODEX_CLI_USER_AGENT = "codex_cli_rs/0.80.0 (Windows 15.7.2; x86_64) Terminal"
CODEX_CLI_ORIGINATOR = "codex_cli_rs"
_ALLOWED_LLM_EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh"}


def require_nonempty_text(value: Any, name: str) -> str:
    if value is None:
        raise ValueError(f"{name} cannot be empty")
    text = str(value).strip()
    if not text:
        raise ValueError(f"{name} cannot be empty")
    return text


def normalize_optional_temperature(value: Any, name: str = "temperature") -> float | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a number") from exc


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


def create_openai_client(api_key, base_url=None, *, api_key_required_message):
    if api_key is None or not str(api_key).strip():
        raise RuntimeError(api_key_required_message)

    client_kwargs = {
        "api_key": require_nonempty_text(api_key, "api_key"),
    }
    if base_url is not None:
        client_kwargs["base_url"] = require_nonempty_text(base_url, "base_url")

    return OpenAI(**client_kwargs)


def extract_first_message_text(response) -> str:
    choices = getattr(response, "choices", None) or []
    if not choices:
        raise ValueError("OpenAI response missing choices")

    message = getattr(choices[0], "message", None)
    content = getattr(message, "content", "") if message is not None else ""
    if isinstance(content, str):
        return content

    if isinstance(content, Sequence) and not isinstance(content, (str, bytes, bytearray)):
        parts: list[str] = []
        for part in content:
            if isinstance(part, Mapping):
                text = part.get("text")
            else:
                text = getattr(part, "text", None)
            if text:
                parts.append(str(text))
        return "".join(parts)

    text = getattr(content, "text", None)
    if text is not None:
        return str(text)
    return str(content)


def _extract_text_from_message_content(content) -> str:
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, Sequence) and not isinstance(content, (str, bytes, bytearray)):
        parts: list[str] = []
        for part in content:
            if isinstance(part, Mapping):
                text = part.get("text")
                if text is None:
                    text = part.get("content")
            else:
                text = getattr(part, "text", None)
                if text is None:
                    text = getattr(part, "content", None)
            if text is None:
                text = part
            parts.append(str(text))
        return "".join(parts).strip()
    text = getattr(content, "text", None)
    if text is not None:
        stripped_text = str(text).strip()
        if stripped_text:
            return stripped_text
    return str(content or "").strip()


def _build_responses_input(messages) -> list[dict[str, str]]:
    merged_user_parts: list[str] = []
    for message in messages:
        if not isinstance(message, Mapping):
            continue
        role = str(message.get("role", "")).strip().lower()
        if role != "user":
            continue
        text = _extract_text_from_message_content(message.get("content"))
        if text:
            merged_user_parts.append(text)
    if not merged_user_parts:
        raise ValueError("messages must include at least one user message")
    return [{"role": "user", "content": "\n\n".join(merged_user_parts)}]


def _extract_text_from_response_payload(payload) -> str:
    if not isinstance(payload, Mapping):
        return ""
    event_type = payload.get("type")
    if event_type == "response.output_text.delta":
        delta = payload.get("delta")
        return "" if delta is None else str(delta)
    if event_type != "response.completed":
        return ""

    response = payload.get("response")
    if not isinstance(response, Mapping):
        return ""
    output = response.get("output")
    if not isinstance(output, Sequence) or isinstance(output, (str, bytes, bytearray)):
        return ""

    texts: list[str] = []
    for output_item in output:
        if not isinstance(output_item, Mapping):
            continue
        content_items = output_item.get("content")
        if not isinstance(content_items, Sequence) or isinstance(
            content_items, (str, bytes, bytearray)
        ):
            continue
        for content_item in content_items:
            if not isinstance(content_item, Mapping):
                continue
            if content_item.get("type") != "output_text":
                continue
            text = content_item.get("text")
            if text:
                texts.append(str(text))
    return "".join(texts)


def _extract_error_message_from_payload(payload) -> str:
    if isinstance(payload, Mapping):
        error_obj = payload.get("error")
        if isinstance(error_obj, Mapping):
            message = error_obj.get("message")
            if message:
                return str(message)
        message = payload.get("message")
        if message:
            return str(message)
        reason = payload.get("reason")
        if reason:
            return str(reason)
        try:
            return json.dumps(payload, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            return str(payload)
    return str(payload)


def _call_llm_text_via_codex_http(
    *,
    model,
    messages,
    api_key,
    base_url,
    effort=None,
    temperature=None,
):
    normalized_api_key = require_nonempty_text(api_key, "api_key")
    normalized_base_url = require_nonempty_text(base_url, "base_url")
    normalized_model = require_nonempty_text(model, "model")
    parsed_base = urlparse(normalized_base_url)
    host = parsed_base.netloc
    if not host:
        raise ValueError("base_url must include host")

    normalized_effort = normalize_optional_effort(effort)
    body = {
        "input": _build_responses_input(messages),
        "model": normalized_model,
        "reasoning": {"effort": normalized_effort},
        "stream": True,
    }
    normalized_temperature = normalize_optional_temperature(temperature)
    if normalized_temperature is not None:
        body["temperature"] = normalized_temperature

    headers = {
        "Authorization": f"Bearer {normalized_api_key}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "Accept-Encoding": "identity",
        "User-Agent": CODEX_CLI_USER_AGENT,
        "Originator": CODEX_CLI_ORIGINATOR,
        "Host": host,
    }
    endpoint = normalized_base_url.rstrip("/") + "/responses"
    text_parts: list[str] = []
    saw_output_text_delta = False
    failure_event_types = {"error", "response.error", "response.failed", "response.incomplete"}

    with httpx.Client(
        timeout=httpx.Timeout(30.0, read=300.0),
        trust_env=False,
    ) as http_client:
        with http_client.stream("POST", endpoint, headers=headers, json=body) as response:
            response.raise_for_status()
            content_type = response.headers.get("content-type", "")
            if "text/event-stream" not in content_type.lower():
                raise RuntimeError(
                    f"codex transport expected text/event-stream, got {content_type!r}"
                )
            for line in response.iter_lines():
                if line is None:
                    continue
                stripped_line = line.strip()
                if not stripped_line.startswith("data:"):
                    continue
                payload_text = stripped_line[5:].strip()
                if not payload_text:
                    continue
                if payload_text == "[DONE]":
                    break
                payload = json.loads(payload_text)
                event_type = payload.get("type") if isinstance(payload, Mapping) else None
                if event_type in failure_event_types:
                    message = _extract_error_message_from_payload(payload)
                    raise RuntimeError(f"codex transport received {event_type}: {message}")
                if event_type == "response.completed" and saw_output_text_delta:
                    continue
                extracted_text = _extract_text_from_response_payload(payload)
                if extracted_text:
                    if event_type == "response.output_text.delta":
                        saw_output_text_delta = True
                    text_parts.append(extracted_text)

    final_text = "".join(text_parts).strip()
    if not final_text:
        raise RuntimeError("codex transport returned empty response text")
    return final_text


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
            model=model,
            messages=messages,
            api_key=api_key,
            base_url=base_url,
            effort=normalized_effort,
            temperature=temperature,
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
