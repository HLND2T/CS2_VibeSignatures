#!/usr/bin/env python3
"""Preprocess ConnectClient's GetFreeClient call and CheckPassword vcall."""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = [
    "CNetworkGameServer_GetFreeClient",
    "CNetworkGameServerBase_CheckPassword",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CNetworkGameServer_GetFreeClient",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkGameServerBase_ConnectClient.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {
            "CNetworkGameServerBase_ConnectClient.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "CNetworkGameServerBase_CheckPassword",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkGameServerBase_ConnectClient.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CNetworkGameServerBase_ConnectClient.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CNetworkGameServerBase_CheckPassword", "CNetworkGameServerBase"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # No func_sig: GetFreeClient's head bytes are not unique in the binary.
    # LLM_DECOMPILE is used to locate it each time.
    (
        "CNetworkGameServer_GetFreeClient",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    # vfunc_sig is MANDATORY for Pattern C (LLM_DECOMPILE vfunc).
    (
        "CNetworkGameServerBase_CheckPassword",
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
    """Locate GetFreeClient and CheckPassword from ConnectClient via LLM decompile."""
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
