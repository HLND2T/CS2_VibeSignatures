#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml
from ida_analyze_util import parse_mcp_result
from openai import OpenAI


VCALL_FINDER_DIRNAME = "vcall_finder"

PROMPT_TEMPLATE = """You are a reverse engineering expert. I have disassembly outputs and procedure code of the same function.

**Disassembly**

```c
{disasm_code}
```

**Procedure code**

```c
{procedure}
```

Please collect all virtual function calls for "{object_name}" and output those calls as YAML

Example:

```yaml
found_vcall:
  - insn_va: 0x12345678
    insn_disasm: call    [rax+68h]
    vfunc_offset: 0x68
  - insn_va: 0x12345680
    insn_disasm: call    rax
    vfunc_offset: 0x80
```

If there are no virtual function calls for "{object_name}" found, output an empty YAML.
"""


class LiteralDumper(yaml.SafeDumper):
    pass


def _literal_str_representer(dumper, value):
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


LiteralDumper.add_representer(str, _literal_str_representer)


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a mapping, got {type(value).__name__}")
    return value


def _read_required_text(data: Mapping[str, Any], key: str, context: str) -> str:
    if key not in data:
        raise KeyError(f"{context} missing required key '{key}'")
    text = str(data[key]).strip()
    if not text:
        raise ValueError(f"{context} key '{key}' cannot be empty")
    return text


def _read_optional_text(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key, "")
    if value is None:
        return ""
    return str(value)


def _parse_yaml_mapping(text: str) -> Mapping[str, Any] | None:
    try:
        parsed = yaml.load(text, Loader=yaml.BaseLoader)
    except yaml.YAMLError:
        return None
    if parsed is None:
        return {}
    if isinstance(parsed, Mapping):
        return parsed
    return None


def build_vcall_root(base_dir: str | Path = VCALL_FINDER_DIRNAME) -> Path:
    return Path(base_dir)


def build_vcall_detail_path(
    base_dir: str | Path,
    gamever: str,
    object_name: str,
    module_name: str,
    platform: str,
    func_name: str,
) -> Path:
    gamever_component = _normalize_safe_path_component(gamever, "gamever")
    object_component = _normalize_safe_path_component(object_name, "object_name")
    module_component = _normalize_safe_path_component(module_name, "module_name")
    platform_component = _normalize_safe_path_component(platform, "platform")
    func_component = _normalize_safe_path_component(func_name, "func_name")
    return (
        Path(base_dir)
        / gamever_component
        / object_component
        / module_component
        / platform_component
        / f"{func_component}.yaml"
    )


def build_vcall_summary_path(base_dir: str | Path, gamever: str, object_name: str) -> Path:
    gamever_component = _normalize_safe_path_component(gamever, "gamever")
    object_component = _normalize_safe_path_component(object_name, "object_name")
    return Path(base_dir) / gamever_component / f"{object_component}.yaml"


def write_vcall_detail_yaml(path: str | Path, detail: Mapping[str, Any]) -> None:
    detail_data = _require_mapping(detail, "detail")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "object_name": _read_required_text(detail_data, "object_name", "detail"),
        "module": _read_required_text(detail_data, "module", "detail"),
        "platform": _read_required_text(detail_data, "platform", "detail"),
        "func_name": _read_required_text(detail_data, "func_name", "detail"),
        "func_va": _read_required_text(detail_data, "func_va", "detail"),
        "disasm_code": _read_optional_text(detail_data, "disasm_code"),
        "procedure": _read_optional_text(detail_data, "procedure"),
    }
    with path.open("w", encoding="utf-8") as file_obj:
        yaml.dump(
            payload,
            file_obj,
            Dumper=LiteralDumper,
            sort_keys=False,
            allow_unicode=True,
        )


def load_yaml_file(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as file_obj:
            parsed = yaml.safe_load(file_obj)
    except yaml.YAMLError as exc:
        raise ValueError(f"Failed to parse YAML at '{path}': {exc}") from exc

    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise ValueError(f"YAML root must be mapping at '{path}', got {type(parsed).__name__}")
    return parsed


def render_vcall_prompt(detail: Mapping[str, Any]) -> str:
    detail_data = _require_mapping(detail, "detail")
    return PROMPT_TEMPLATE.format(
        object_name=_read_required_text(detail_data, "object_name", "detail"),
        disasm_code=_read_optional_text(detail_data, "disasm_code"),
        procedure=_read_optional_text(detail_data, "procedure"),
    )


def normalize_found_vcalls(entries: Sequence[Any] | None) -> list[dict[str, str]]:
    if entries is None:
        return []
    if isinstance(entries, (str, bytes, bytearray)) or not isinstance(entries, Sequence):
        return []

    normalized: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        insn_va = str(entry.get("insn_va", "")).strip()
        insn_disasm = str(entry.get("insn_disasm", "")).strip()
        vfunc_offset = str(entry.get("vfunc_offset", "")).strip()
        if not (insn_va and insn_disasm and vfunc_offset):
            continue
        normalized.append(
            {
                "insn_va": insn_va,
                "insn_disasm": insn_disasm,
                "vfunc_offset": vfunc_offset,
            }
        )
    return normalized


def parse_llm_vcall_response(response_text: str | None) -> dict[str, list[dict[str, str]]]:
    response_text = (response_text or "").strip()
    if not response_text:
        return {"found_vcall": []}

    candidates: list[str] = []
    for match in re.finditer(r"```(?:yaml|yml)[ \t]*\n?(.*?)```", response_text, re.IGNORECASE | re.DOTALL):
        candidates.append(match.group(1).strip())
    if not candidates:
        for match in re.finditer(r"```[ \t]*\n(.*?)```", response_text, re.DOTALL):
            candidates.append(match.group(1).strip())

    if candidates:
        for yaml_text in candidates:
            if not yaml_text:
                continue
            parsed = _parse_yaml_mapping(yaml_text)
            if parsed is None:
                continue
            return {"found_vcall": normalize_found_vcalls(parsed.get("found_vcall", []))}
        return {"found_vcall": []}

    parsed = _parse_yaml_mapping(response_text)
    if parsed is None or not parsed:
        return {"found_vcall": []}

    return {"found_vcall": normalize_found_vcalls(parsed.get("found_vcall", []))}


def create_openai_client(api_key=None, api_base=None):
    resolved_api_key = api_key or os.environ.get("OPENAI_API_KEY")
    if not resolved_api_key:
        raise RuntimeError("OPENAI_API_KEY is required when -vcall_finder is enabled")

    client_kwargs = {"api_key": resolved_api_key}
    resolved_api_base = api_base or os.environ.get("OPENAI_API_BASE")
    if resolved_api_base:
        client_kwargs["base_url"] = resolved_api_base

    return OpenAI(**client_kwargs)


def call_openai_for_vcalls(client, detail, model):
    model = _require_nonempty_text(model, "model")
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a reverse engineering expert."},
            {"role": "user", "content": render_vcall_prompt(detail)},
        ],
        temperature=0.1,
    )
    choices = getattr(response, "choices", None) or []
    if not choices:
        raise ValueError("OpenAI response missing choices")

    message = getattr(choices[0], "message", None)
    content = getattr(message, "content", "") if message is not None else ""
    if not isinstance(content, str):
        content = str(content)
    return parse_llm_vcall_response(content)["found_vcall"]


def merge_summary_record(
    summary_data: Mapping[str, Any] | None,
    detail: Mapping[str, Any],
    found_vcall: Sequence[Any] | None,
) -> dict[str, Any]:
    summary = dict(_require_mapping(summary_data or {}, "summary_data"))
    detail_data = _require_mapping(detail, "detail")

    detail_object_name = _read_required_text(detail_data, "object_name", "detail")
    existing_object_name = summary.get("object_name")
    if existing_object_name is not None:
        existing_object_name = str(existing_object_name)
        if existing_object_name != detail_object_name:
            raise ValueError(
                "summary object_name mismatch: "
                f"'{existing_object_name}' != '{detail_object_name}'"
            )
        summary["object_name"] = existing_object_name
    else:
        summary["object_name"] = detail_object_name

    raw_results = summary.get("results", [])
    if not isinstance(raw_results, list):
        raise TypeError(f"summary_data['results'] must be a list, got {type(raw_results).__name__}")
    results = list(raw_results)

    record = {
        "module": _read_required_text(detail_data, "module", "detail"),
        "platform": _read_required_text(detail_data, "platform", "detail"),
        "func_name": _read_required_text(detail_data, "func_name", "detail"),
        "func_va": _read_required_text(detail_data, "func_va", "detail"),
        "found_vcall": normalize_found_vcalls(found_vcall),
    }

    record_key = (
        record["module"],
        record["platform"],
        record["func_name"],
        record["func_va"],
    )

    replaced = False
    for index, existing in enumerate(results):
        if not isinstance(existing, Mapping):
            continue
        existing_key = (
            existing.get("module"),
            existing.get("platform"),
            existing.get("func_name"),
            existing.get("func_va"),
        )
        if existing_key == record_key:
            results[index] = record
            replaced = True
            break

    if not replaced:
        results.append(record)

    summary["results"] = results
    return summary


def aggregate_vcall_results_for_object(
    *,
    base_dir,
    gamever,
    object_name,
    model,
    client=None,
    debug=False,
):
    summary_path = build_vcall_summary_path(base_dir, gamever, object_name)
    detail_root = summary_path.with_suffix("")
    detail_paths = sorted(detail_root.glob("*/*/*.yaml"))
    if not detail_paths:
        return {"status": "skipped", "processed": 0, "failed": 0}

    summary = load_yaml_file(summary_path)
    llm_client = client or create_openai_client()
    processed = 0
    failed = 0

    if debug:
        print(
            "    vcall_finder: OpenAI aggregation "
            f"object='{object_name}', detail_files={len(detail_paths)}"
        )

    for detail_path in detail_paths:
        try:
            detail = load_yaml_file(detail_path)
        except Exception as exc:
            failed += 1
            if debug:
                print(f"    vcall_finder: failed to load detail YAML '{detail_path}': {exc!r}")
            continue

        if not detail:
            failed += 1
            if debug:
                print(f"    vcall_finder: empty detail YAML skipped: '{detail_path}'")
            continue

        try:
            found_vcall = call_openai_for_vcalls(llm_client, detail, model)
            summary = merge_summary_record(summary, detail, found_vcall)
            processed += 1
        except Exception as exc:
            failed += 1
            if debug:
                print(f"    vcall_finder: OpenAI aggregation failed for '{detail_path}': {exc!r}")

    write_vcall_summary_yaml(summary_path, summary)

    if debug:
        print(
            "    vcall_finder: OpenAI aggregation summary "
            f"object='{object_name}', processed={processed}, failed={failed}"
        )

    if failed:
        status = "failed"
    elif processed:
        status = "success"
    else:
        status = "skipped"

    return {"status": status, "processed": processed, "failed": failed}


def write_vcall_summary_yaml(path: str | Path, summary: Mapping[str, Any]) -> None:
    summary_data = _require_mapping(summary, "summary")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file_obj:
        yaml.dump(
            summary_data,
            file_obj,
            Dumper=LiteralDumper,
            sort_keys=False,
            allow_unicode=True,
        )


def _require_nonempty_text(value: Any, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"{name} cannot be empty")
    return text


def _normalize_safe_path_component(value: Any, name: str) -> str:
    text = _require_nonempty_text(value, name)

    normalized = text.replace("::", "_")
    normalized = normalized.replace("/", "_").replace("\\", "_")
    normalized = normalized.replace("..", "_")
    normalized = re.sub(r'[<>:"|?*\x00-\x1f]', "_", normalized)
    normalized = normalized.strip().strip(".")
    normalized = re.sub(r"_+", "_", normalized)

    if not normalized or normalized in {".", ".."}:
        normalized = "_"

    windows_reserved = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    }
    base_name = normalized.split(".", 1)[0].upper()
    if base_name in windows_reserved:
        normalized = f"{normalized}_"

    return normalized


def _parse_int_value(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise TypeError(f"{name} must be an integer-like value, got bool")
    if isinstance(value, int):
        return value
    text = _require_nonempty_text(value, name)
    try:
        return int(text, 0)
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid integer literal, got '{text}'") from exc


def _has_nonempty_error_marker(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (str, bytes, bytearray)):
        return bool(str(value).strip())
    if isinstance(value, Mapping):
        return bool(value)
    if isinstance(value, Sequence):
        return not isinstance(value, (str, bytes, bytearray)) and bool(value)
    return True


def _is_error_payload_mapping(payload: Mapping[str, Any], expected_keys: Sequence[str] | None) -> bool:
    del expected_keys
    error_keys = ("error", "errors", "isError", "message", "stderr", "traceback", "exception")
    return any(
        key in payload and _has_nonempty_error_marker(payload.get(key))
        for key in error_keys
    )


def _format_object_scope(gamever: str, module_name: str, platform: str, object_name: str) -> str:
    return (
        f"gamever='{gamever}', module='{module_name}', "
        f"platform='{platform}', object='{object_name}'"
    )


def _format_function_scope(
    gamever: str,
    module_name: str,
    platform: str,
    object_name: str,
    func_name: str,
    func_va: str,
) -> str:
    return (
        f"{_format_object_scope(gamever, module_name, platform, object_name)}, "
        f"func='{func_name}', func_va='{func_va}'"
    )


def _parse_py_eval_json_payload(
    py_eval_result: Any,
    *,
    debug: bool,
    context: str,
    expected_keys: Sequence[str] | None = None,
) -> Any | None:
    parsed = parse_mcp_result(py_eval_result)

    payload: Any = parsed
    if isinstance(parsed, Mapping):
        stderr = str(parsed.get("stderr", "") or "").strip()
        if stderr and debug:
            print(f"    vcall_finder: {context} stderr:")
            print(stderr)
        if _is_error_payload_mapping(parsed, expected_keys):
            if debug:
                print(f"    vcall_finder: protocol error payload from {context}: {parsed}")
            return None
        if "result" in parsed:
            payload = parsed.get("result")

    if payload is None:
        return None
    if isinstance(payload, Mapping):
        if _is_error_payload_mapping(payload, expected_keys):
            if debug:
                print(f"    vcall_finder: error payload from {context}: {payload}")
            return None
        return payload
    if isinstance(payload, list):
        return payload

    text = str(payload).strip()
    if not text:
        return None
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        if debug:
            print(f"    vcall_finder: invalid JSON payload from {context}")
        return None
    if isinstance(decoded, Mapping):
        if _is_error_payload_mapping(decoded, expected_keys):
            if debug:
                print(f"    vcall_finder: decoded error payload from {context}: {decoded}")
            return None
    return decoded


def build_object_xref_py_eval(object_name: str) -> str:
    object_name = _require_nonempty_text(object_name, "object_name")
    return (
        "import ida_funcs, ida_name, idaapi, idautils, json\n"
        f"object_name = {json.dumps(object_name)}\n"
        "object_ea = ida_name.get_name_ea(idaapi.BADADDR, object_name)\n"
        "if object_ea == idaapi.BADADDR:\n"
        "    result = json.dumps({'object_ea': None, 'functions': []})\n"
        "else:\n"
        "    seen = set()\n"
        "    functions = []\n"
        "    for xref in idautils.XrefsTo(object_ea, 0):\n"
        "        func = ida_funcs.get_func(xref.frm)\n"
        "        if func is None:\n"
        "            continue\n"
        "        func_start = int(func.start_ea)\n"
        "        if func_start in seen:\n"
        "            continue\n"
        "        seen.add(func_start)\n"
        "        func_name = ida_funcs.get_func_name(func_start) or f'sub_{func_start:X}'\n"
        "        functions.append({'func_name': func_name, 'func_va': hex(func_start)})\n"
        "    functions.sort(key=lambda item: int(item['func_va'], 16))\n"
        "    result = json.dumps({'object_ea': hex(object_ea), 'functions': functions})\n"
    )


def build_function_dump_py_eval(func_va: int | str) -> str:
    func_va_int = _parse_int_value(func_va, "func_va")
    return (
        "import ida_funcs, ida_idaapi, ida_lines, ida_segment, idautils, idc, json\n"
        "try:\n"
        "    import ida_hexrays\n"
        "except Exception:\n"
        "    ida_hexrays = None\n"
        f"func_ea = {func_va_int}\n"
        "def get_disasm(start_ea):\n"
        "    func = ida_funcs.get_func(start_ea)\n"
        "    if func is None:\n"
        "        return ''\n"
        "    lines = []\n"
        "    for ea in idautils.FuncItems(func.start_ea):\n"
        "        if ea < func.start_ea or ea >= func.end_ea:\n"
        "            continue\n"
        "        seg = ida_segment.getseg(ea)\n"
        "        seg_name = ida_segment.get_segm_name(seg) if seg else ''\n"
        "        address_text = f'{seg_name}:{ea:016X}' if seg_name else f'{ea:016X}'\n"
        "        disasm_line = idc.generate_disasm_line(ea, 0) or ''\n"
        "        lines.append(f\"{address_text}                 {ida_lines.tag_remove(disasm_line)}\")\n"
        "    return '\\n'.join(lines)\n"
        "def get_pseudocode(start_ea):\n"
        "    if ida_hexrays is None:\n"
        "        return ''\n"
        "    try:\n"
        "        if not ida_hexrays.init_hexrays_plugin():\n"
        "            return ''\n"
        "        cfunc = ida_hexrays.decompile(start_ea)\n"
        "    except Exception:\n"
        "        return ''\n"
        "    if not cfunc:\n"
        "        return ''\n"
        "    return '\\n'.join(ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode())\n"
        "func = ida_funcs.get_func(func_ea)\n"
        "if func is None:\n"
        "    result = json.dumps(None)\n"
        "else:\n"
        "    func_start = int(func.start_ea)\n"
        "    result = json.dumps({\n"
        "        'func_name': ida_funcs.get_func_name(func_start) or f'sub_{func_start:X}',\n"
        "        'func_va': hex(func_start),\n"
        "        'disasm_code': get_disasm(func_start),\n"
        "        'procedure': get_pseudocode(func_start),\n"
        "    })\n"
    )


async def export_object_xref_details_via_mcp(
    session: Any,
    *,
    output_root: str | Path,
    gamever: str,
    module_name: str,
    platform: str,
    object_name: str,
    debug: bool = False,
) -> dict[str, int]:
    gamever = _require_nonempty_text(gamever, "gamever")
    module_name = _require_nonempty_text(module_name, "module_name")
    platform = _require_nonempty_text(platform, "platform")
    object_name = _require_nonempty_text(object_name, "object_name")
    object_scope = _format_object_scope(gamever, module_name, platform, object_name)

    try:
        if debug:
            print(f"    vcall_finder: calling py_eval (object-xref) with {object_scope}")
        object_query_result = await session.call_tool(
            name="py_eval",
            arguments={"code": build_object_xref_py_eval(object_name)},
        )
    except Exception as exc:
        if debug:
            print(f"    vcall_finder: py_eval failed at object-xref step with {object_scope}: {exc!r}")
        return {
            "status": "failed",
            "exported_functions": 0,
            "failed_functions": 1,
            "skipped_functions": 0,
        }

    object_data = _parse_py_eval_json_payload(
        object_query_result,
        debug=debug,
        context=f"object xref query ({object_scope})",
        expected_keys=("object_ea", "functions"),
    )
    if not isinstance(object_data, Mapping):
        if debug:
            print(f"    vcall_finder: invalid object-xref payload with {object_scope}")
        return {
            "status": "failed",
            "exported_functions": 0,
            "failed_functions": 1,
            "skipped_functions": 0,
        }
    if not object_data.get("object_ea"):
        return {
            "status": "skipped",
            "exported_functions": 0,
            "failed_functions": 0,
            "skipped_functions": 1,
        }

    functions = object_data.get("functions", [])
    if isinstance(functions, (str, bytes, bytearray)) or not isinstance(functions, Sequence):
        return {
            "status": "failed",
            "exported_functions": 0,
            "failed_functions": 1,
            "skipped_functions": 0,
        }

    if not functions:
        return {
            "status": "skipped",
            "exported_functions": 0,
            "failed_functions": 0,
            "skipped_functions": 1,
        }

    exported_functions = 0
    failed_functions = 0
    skipped_functions = 0
    output_root_path = Path(output_root)

    for function in functions:
        if not isinstance(function, Mapping):
            if debug:
                print(f"    vcall_finder: invalid function entry for object '{object_name}': {function!r}")
            failed_functions += 1
            continue

        func_name = str(function.get("func_name", "")).strip()
        func_va_text = str(function.get("func_va", "")).strip()
        if not func_name or not func_va_text:
            if debug:
                print(
                    f"    vcall_finder: missing func_name/func_va in xref entry for '{object_name}': {function!r}"
                )
            failed_functions += 1
            continue

        detail_path = build_vcall_detail_path(
            output_root_path,
            gamever,
            object_name,
            module_name,
            platform,
            func_name,
        )
        if detail_path.exists():
            skipped_functions += 1
            continue

        try:
            func_va_int = int(func_va_text, 0)
        except ValueError:
            if debug:
                print(
                    f"    vcall_finder: invalid func_va '{func_va_text}' in object '{object_name}'"
                )
            failed_functions += 1
            continue

        try:
            function_scope = _format_function_scope(
                gamever,
                module_name,
                platform,
                object_name,
                func_name,
                func_va_text,
            )
            if debug:
                print(f"    vcall_finder: calling py_eval (function-dump) with {function_scope}")
            dump_query_result = await session.call_tool(
                name="py_eval",
                arguments={"code": build_function_dump_py_eval(func_va_int)},
            )
        except Exception as exc:
            if debug:
                print(
                    "    vcall_finder: py_eval failed at function-dump step "
                    f"with {function_scope}: {exc!r}"
                )
            failed_functions += 1
            continue

        dump_data = _parse_py_eval_json_payload(
            dump_query_result,
            debug=debug,
            context=f"function dump ({function_scope})",
            expected_keys=("func_name", "func_va", "disasm_code", "procedure"),
        )
        if not isinstance(dump_data, Mapping):
            if debug:
                print(f"    vcall_finder: invalid function-dump payload with {function_scope}")
            failed_functions += 1
            continue

        dump_func_name = str(dump_data.get("func_name", "")).strip() or func_name
        dump_func_va = str(dump_data.get("func_va", "")).strip() or hex(func_va_int)

        try:
            write_vcall_detail_yaml(
                detail_path,
                {
                    "object_name": object_name,
                    "module": module_name,
                    "platform": platform,
                    "func_name": dump_func_name,
                    "func_va": dump_func_va,
                    "disasm_code": str(dump_data.get("disasm_code", "") or ""),
                    "procedure": str(dump_data.get("procedure", "") or ""),
                },
            )
        except Exception as exc:
            if debug:
                print(
                    "    vcall_finder: failed to write detail YAML "
                    f"for object '{object_name}', func '{dump_func_name}' at '{detail_path}': {exc!r}"
                )
            failed_functions += 1
            continue

        exported_functions += 1

    if failed_functions:
        status = "failed"
    elif exported_functions:
        status = "success"
    else:
        status = "skipped"

    return {
        "status": status,
        "exported_functions": exported_functions,
        "failed_functions": failed_functions,
        "skipped_functions": skipped_functions,
    }
