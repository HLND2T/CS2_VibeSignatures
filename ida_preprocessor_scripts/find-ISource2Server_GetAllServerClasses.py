#!/usr/bin/env python3
"""Preprocess script for find-ISource2Server_GetAllServerClasses skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "ISource2Server_GetAllServerClasses",
]

# ISource2Server::GetAllServerClasses is an abstract-interface vfunc. The engine
# predecessor CNetworkGameServer_Shutdown reaches it through a register-indirect
# vcall on g_pSource2Server: `call qword ptr [rax+0E8h]`. The
# skill runs in the ENGINE module (where the predecessor is renamed/available) and
# produces a caller-anchored vfunc_sig that anchors on that vcall instruction,
# matching the IGameTypes / CEngineServer_UnloadSpawnGroup offset pattern. The same
# predecessor holds the vcall on both platforms.
LLM_DECOMPILE = [
    {
        "symbol_name": "ISource2Server_GetAllServerClasses",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkGameServer_Shutdown.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CNetworkGameServer_Shutdown.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class) -- vtable_name is metadata only; no
    # ISource2Server_vtable YAML is consumed here. The vfunc_sig anchors on the
    # vcall instruction inside the
    # engine predecessor CNetworkGameServer_Shutdown.
    ("ISource2Server_GetAllServerClasses", "ISource2Server"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # Slim Pattern C: not a downstream predecessor, so func_va/rva/size omitted.
    # vfunc_sig is MANDATORY for Pattern C.
    (
        "ISource2Server_GetAllServerClasses",
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
    """Locate the interface vfunc slot from CNetworkGameServer_Shutdown."""
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
