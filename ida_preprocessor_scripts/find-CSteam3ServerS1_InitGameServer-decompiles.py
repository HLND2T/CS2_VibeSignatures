#!/usr/bin/env python3
"""Extract network interface calls made during Steam game-server initialization."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["INetworkSystem_GetFakeLag", "INetworkServerService_IsActiveInGame"]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/engine/CSteam3ServerS1_InitGameServer.{platform}.yaml"],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {"CSteam3ServerS1_InitGameServer.{platform}.yaml": "required"},
    }
    for name in TARGET_FUNCTION_NAMES
]
FUNC_VTABLE_RELATIONS = [
    ("INetworkSystem_GetFakeLag", "INetworkSystem"),
    ("INetworkServerService_IsActiveInGame", "INetworkServerService"),
]
GENERATE_YAML_DESIRED_FIELDS = [
    (name, ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"])
    for name in TARGET_FUNCTION_NAMES
]

async def preprocess_skill(session, skill_name, expected_outputs, old_yaml_map, new_binary_dir,
                           platform, image_base, llm_config=None, debug=False):
    _ = skill_name
    return await preprocess_common_skill(
        session=session, expected_outputs=expected_outputs, old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir, platform=platform, image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES, func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE, llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS, debug=debug,
    )
