"""Find server reference-count vfuncs from the client/server status helper."""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = [
    "CNetworkGameServerBase_AddRef",
    "CNetworkGameServerBase_Release",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CNetworkGameServerBase_AddRef",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CLoopTypeClientServer_UpdateClientServerStatus.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CLoopTypeClientServer_UpdateClientServerStatus.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkGameServerBase_Release",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CLoopTypeClientServer_UpdateClientServerStatus.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CLoopTypeClientServer_UpdateClientServerStatus.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    ("CNetworkGameServerBase_AddRef", "CNetworkGameServerBase"),
    ("CNetworkGameServerBase_Release", "CNetworkGameServerBase"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CNetworkGameServerBase_AddRef",
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
        "CNetworkGameServerBase_Release",
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
    """Resolve the AddRef and Release vtable calls in the status helper."""
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
