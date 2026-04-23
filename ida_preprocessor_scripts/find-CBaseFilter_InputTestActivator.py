#!/usr/bin/env python3
"""Preprocess script for find-CBaseFilter_InputTestActivator skill.

Windows: LLM_DECOMPILE via CBaseFilter_InputTestActivator_Register
Linux: py_eval to find "TestActivator" string data xref, read func ptr at +0x10
"""

import json
import os

from ida_analyze_util import (
    _build_ida_strings_setup_py_lines,
    parse_mcp_result,
    preprocess_common_skill,
    preprocess_gen_func_sig_via_mcp,
    preprocess_func_sig_via_mcp,
    write_func_yaml,
)

TARGET_FUNCTION_NAMES = [
    "CBaseFilter_InputTestActivator",
]

# Windows only: LLM_DECOMPILE via CBaseFilter_InputTestActivator_Register
LLM_DECOMPILE_WINDOWS = [
    (
        "CBaseFilter_InputTestActivator",
        "prompt/call_llm_decompile.md",
        "references/server/CBaseFilter_InputTestActivator_Register.windows.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CBaseFilter_InputTestActivator",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
]

# Linux: offset from "TestActivator" string data xref to function pointer
STRING_XREF_FUNC_PTR_OFFSET = 0x10


async def _linux_resolve_via_string_xref(
    session, expected_outputs, platform, image_base, debug=False,
):
    """Find CBaseFilter_InputTestActivator on Linux via TestActivator string xref."""
    func_name = "CBaseFilter_InputTestActivator"
    output_filename = f"{func_name}.{platform}.yaml"
    output_path = None
    for p in expected_outputs:
        if os.path.basename(p) == output_filename:
            output_path = p
            break
    if not output_path:
        if debug:
            print(f"    Preprocess: no output path for {output_filename}")
        return False

    # Use py_eval: find exact "TestActivator" string, get data xrefs,
    # read 64-bit pointer at xref_addr + 0x10, verify it's a function start.
    py_lines = [
        "import idautils, idc, ida_nalt, json",
        "search_str = 'TestActivator'",
        "func_va = None",
    ]
    py_lines.extend(_build_ida_strings_setup_py_lines(strings_var_name="strings"))
    py_lines.extend(
        [
            "for s in strings:",
            "    if str(s) == search_str:",
            "        for xref in idautils.XrefsTo(s.ea, 0):",
            f"            ptr_addr = xref.frm + {STRING_XREF_FUNC_PTR_OFFSET}",
            "            candidate = idc.get_qword(ptr_addr)",
            "            if candidate and candidate != 0xFFFFFFFFFFFFFFFF:",
            "                func_start = idc.get_func_attr(candidate, idc.FUNCATTR_START)",
            "                if func_start == candidate:",
            "                    func_va = candidate",
            "                    break",
            "    if func_va is not None:",
            "        break",
            "result = json.dumps(hex(func_va) if func_va else None)",
        ]
    )
    py_code = "\n".join(py_lines) + "\n"

    try:
        eval_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        eval_data = parse_mcp_result(eval_result)
    except Exception as e:
        if debug:
            print(f"    Preprocess: py_eval error: {e}")
        return False

    # Parse the result - py_eval returns a JSON string
    func_va = None
    raw = eval_data
    if isinstance(raw, list) and raw:
        raw = raw[0]
    if isinstance(raw, dict):
        raw = raw.get("value", raw.get("result"))
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if parsed and parsed != "null":
                func_va = int(parsed, 16)
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

    if not func_va:
        if debug:
            print(
                "    Preprocess: could not resolve "
                "CBaseFilter_InputTestActivator via string xref"
            )
        return False

    if debug:
        print(
            f"    Preprocess: {func_name} at {hex(func_va)} "
            "(via TestActivator string xref + 0x10)"
        )

    # Rename function in IDA
    try:
        await session.call_tool(
            name="rename",
            arguments={
                "batch": {"func": {"addr": hex(func_va), "name": func_name}}
            },
        )
    except Exception:
        pass

    # Generate unique signature
    sig_info = await preprocess_gen_func_sig_via_mcp(
        session=session,
        func_va=hex(func_va),
        image_base=image_base,
        debug=debug,
    )
    if not sig_info:
        if debug:
            print(f"    Preprocess: failed to generate func_sig for {func_name}")
        return False

    func_rva = hex(func_va - image_base)
    result_payload = {
        "func_name": func_name,
        "func_va": hex(func_va),
        "func_rva": func_rva,
        "func_size": sig_info.get("func_size", hex(0)),
        "func_sig": sig_info["func_sig"],
    }
    write_func_yaml(output_path, result_payload)
    if debug:
        print(f"    Preprocess: generated {output_filename}")
        print(f"    Preprocess: renamed func {hex(func_va)} -> {func_name}")

    return True


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Windows: LLM_DECOMPILE via _Register. Linux: string xref + data ptr."""
    if platform == "windows":
        return await preprocess_common_skill(
            session=session,
            expected_outputs=expected_outputs,
            old_yaml_map=old_yaml_map,
            new_binary_dir=new_binary_dir,
            platform=platform,
            image_base=image_base,
            func_names=TARGET_FUNCTION_NAMES,
            llm_decompile_specs=LLM_DECOMPILE_WINDOWS,
            llm_config=llm_config,
            generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
            debug=debug,
        )
    else:
        # Linux: try sig reuse first
        func_name = "CBaseFilter_InputTestActivator"
        output_filename = f"{func_name}.{platform}.yaml"
        output_path = None
        for p in expected_outputs:
            if os.path.basename(p) == output_filename:
                output_path = p
                break
        if output_path:
            old_yaml_path = old_yaml_map.get(output_filename)
            if old_yaml_path and os.path.exists(old_yaml_path):
                reuse_result = await preprocess_func_sig_via_mcp(
                    session=session,
                    new_path=output_path,
                    old_path=old_yaml_path,
                    image_base=image_base,
                    new_binary_dir=new_binary_dir,
                    platform=platform,
                    func_name=func_name,
                    debug=debug,
                )
                if reuse_result:
                    write_func_yaml(output_path, reuse_result)
                    if debug:
                        print(
                            f"    Preprocess: {func_name} resolved "
                            "via signature reuse"
                        )
                    return True

        # Fallback: string xref approach
        return await _linux_resolve_via_string_xref(
            session, expected_outputs, platform, image_base, debug=debug,
        )
