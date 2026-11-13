#!/usr/bin/env python3
"""Preprocess script for find-CDemoRecorder_ParseMessage-decompiles-14197 skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "INetworkMessages_GetNetMessageInfo",
]

# 14197 dropped SerializeAbstract from INetworkMessages and CDemoRecorder_ParseMessage
# only reaches Serialize and CNetMessage::GetNetMessage, so it can no longer anchor
# this slot. CGameEventSystem::RegisterGameEvent does make the call, and its trailing
# m_bCannotBeNetworked check pins the interface.
LLM_DECOMPILE = [
    {
        "symbol_name": "INetworkMessages_GetNetMessageInfo",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CGameEventSystem_RegisterGameEvent.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CGameEventSystem_RegisterGameEvent.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("INetworkMessages_GetNetMessageInfo", "INetworkMessages"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "INetworkMessages_GetNetMessageInfo",
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
    """Locate the GetNetMessageInfo slot through the RegisterGameEvent call site."""
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
