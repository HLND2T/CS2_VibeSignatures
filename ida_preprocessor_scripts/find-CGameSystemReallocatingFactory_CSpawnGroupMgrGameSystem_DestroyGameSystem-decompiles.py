#!/usr/bin/env python3
"""Preprocess script for find-CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_DestroyGameSystem-decompiles skill."""

import json
from pathlib import Path

from ida_analyze_util import parse_mcp_result, preprocess_common_skill, preprocess_vtable_via_mcp, write_func_yaml


def recover_linux_interface_slots(entries, function_bytes):
    """Recognize the IGameSystem name/reallocation tail and its null destructor pair."""
    matches = []
    for index in entries:
        addresses = [entries.get(index + offset) for offset in range(6)]
        if None in addresses or addresses[4:] != [0, 0]:
            continue
        bodies = [function_bytes.get(address, b"") for address in addresses[:4]]
        # GetName / SetGameSystemGlobalPtrs / SetName / DoesGameSystemReallocate.
        # Anchor in this interface's own table, never the factory's primary base.
        if (
            bodies[0].startswith(bytes.fromhex("48 8B 47 08 C3"))
            and bodies[1].startswith(b"\xc3")
            and bodies[2].startswith(bytes.fromhex("48 89 77 08 C3"))
            and bodies[3].startswith(bytes.fromhex("31 C0 C3"))
        ):
            # DestroyGameSystem invokes the complete destructor and then frees
            # the allocation through IMemAlloc; selecting the deleting entry
            # would introduce a second deallocation.
            matches.append({"IGameSystem_SetGameSystemGlobalPtrs": index + 1, "IGameSystem_vdtor": index + 4})
    return matches[0] if len(matches) == 1 else None


async def _preprocess_linux_interface(session, expected_outputs, image_base, debug):
    table = await preprocess_vtable_via_mcp(
        session=session, class_name="IGameSystem", image_base=image_base, platform="linux", debug=debug
    )
    if not table:
        return False
    entries = {int(index): int(address, 0) for index, address in table["vtable_entries"].items()}
    addresses = sorted(set(entries.values()) - {0})
    code = f"""
import ida_bytes, json
addresses = {addresses!r}
bodies = {{}}
for address in addresses:
    raw = ida_bytes.get_bytes(address, 8)
    if raw: bodies[str(address)] = raw.hex()
result = json.dumps(bodies)
"""
    response = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
    bodies = {int(address): bytes.fromhex(raw) for address, raw in json.loads(response["result"]).items()}
    slots = recover_linux_interface_slots(entries, bodies)
    if slots is None:
        return False
    if {Path(output).name.removesuffix(".linux.yaml") for output in expected_outputs} != set(slots):
        return False
    for output in expected_outputs:
        name = Path(output).name.removesuffix(".linux.yaml")
        write_func_yaml(
            output,
            {
                "func_name": name,
                "vtable_name": "IGameSystem",
                "vfunc_offset": hex(slots[name] * 8),
                "vfunc_index": slots[name],
            },
        )
    return True


TARGET_FUNCTION_NAMES = [
    "IGameSystem_SetGameSystemGlobalPtrs",
    "IGameSystem_vdtor",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "IGameSystem_SetGameSystemGlobalPtrs",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/client/CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_DestroyGameSystem.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_DestroyGameSystem.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "IGameSystem_vdtor",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/client/CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_DestroyGameSystem.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_DestroyGameSystem.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("IGameSystem_SetGameSystemGlobalPtrs", "IGameSystem"),
    ("IGameSystem_vdtor", "IGameSystem"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "IGameSystem_SetGameSystemGlobalPtrs",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "IGameSystem_vdtor",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
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
    """Reuse previous gamever vfunc_sig to locate target function(s) and write YAML."""
    if platform == "linux":
        return await _preprocess_linux_interface(session, expected_outputs, image_base, debug)
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
