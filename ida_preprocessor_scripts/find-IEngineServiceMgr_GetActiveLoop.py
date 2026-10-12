#!/usr/bin/env python3
"""Preprocess script for find-IEngineServiceMgr_GetActiveLoop skill."""

import json
from pathlib import Path

from ida_analyze_util import parse_mcp_result, preprocess_common_skill, preprocess_vtable_via_mcp, write_func_yaml


def recover_linux_active_loop_slot(bodies):
    """Identify the active-loop info writer, excluding the event-dispatcher getter."""
    matches = []
    for index, body in bodies.items():
        # The output record's valid flag is cleared for no active loop and set
        # before copying its name/context. Both paths are required. The separate
        # dispatcher getter merely returns an embedded object's address.
        if (
            bytes.fromhex("C6 46 20 01") in body
            and bytes.fromhex("C6 46 20 00") in body
            and bytes.fromhex("48 8B 57 38") in body
        ):
            matches.append(index)
    return matches[0] if len(matches) == 1 else None


async def _preprocess_linux_active_loop(session, expected_outputs, image_base, debug):
    table = await preprocess_vtable_via_mcp(
        session=session, class_name="CEngineServiceMgr", image_base=image_base, platform="linux", debug=debug
    )
    if not table:
        return False
    entries = {int(index): int(address, 0) for index, address in table["vtable_entries"].items()}
    code = f"""
import idaapi, ida_bytes, json
entries = {entries!r}
bodies = {{}}
MAX_GETTER_SIZE = 1024
for index, address in entries.items():
    function = idaapi.get_func(address)
    if function and function.start_ea == address and 0 < function.end_ea - address <= MAX_GETTER_SIZE:
        raw = ida_bytes.get_bytes(address, function.end_ea - address)
        if raw: bodies[str(index)] = raw.hex()
result = json.dumps(bodies)
"""
    response = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
    bodies = {int(index): bytes.fromhex(raw) for index, raw in json.loads(response["result"]).items()}
    index = recover_linux_active_loop_slot(bodies)
    if index is None or len(expected_outputs) != 1:
        return False
    output = expected_outputs[0]
    if Path(output).name != "IEngineServiceMgr_GetActiveLoop.linux.yaml":
        return False
    write_func_yaml(
        output,
        {
            "func_name": "IEngineServiceMgr_GetActiveLoop",
            "vtable_name": "IEngineServiceMgr",
            "vfunc_offset": hex(index * 8),
            "vfunc_index": index,
        },
    )
    return True


TARGET_FUNCTION_NAMES = [
    "IEngineServiceMgr_GetActiveLoop",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "IEngineServiceMgr_GetActiveLoop",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/MainLoop.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "MainLoop.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # IEngineServiceMgr is an abstract interface; vtable_name is metadata only.
    ("IEngineServiceMgr_GetActiveLoop", "IEngineServiceMgr"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "IEngineServiceMgr_GetActiveLoop",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
]


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    llm_config=None,
    debug=False,
):
    """Recover the IEngineServiceMgr::GetActiveLoop interface slot from MainLoop."""
    if platform == "linux":
        return await _preprocess_linux_active_loop(session, expected_outputs, image_base, debug)
    _ = skill_name
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
