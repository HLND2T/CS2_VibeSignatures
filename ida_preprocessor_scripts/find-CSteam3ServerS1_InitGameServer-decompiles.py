#!/usr/bin/env python3
"""Extract network interface calls made during Steam game-server initialization."""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._init_game_server_anchor import load_anchor, validate_result

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
    (name, ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"]) for name in TARGET_FUNCTION_NAMES
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
    _ = skill_name
    try:
        anchor = await load_anchor(session, new_binary_dir, platform)
    except Exception as exc:
        if debug:
            print(f"    Preprocess: GetFakeLag anchor unavailable: {exc}")
        return False
    if debug:
        print(f"    Preprocess: GetFakeLag verified anchor {hex(anchor['insn_va'])}")
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
        llm_result_validator=lambda result: validate_result(result, anchor),
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
