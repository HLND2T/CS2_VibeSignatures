#!/usr/bin/env python3
"""Preprocess script for find-INetworkClientService_IsConnected skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "INetworkClientService_IsConnected",
]

LLM_DECOMPILE = [
    (
        "INetworkClientService_IsConnected",
        "prompt/call_llm_decompile.md",
        "references/engine/SetInfo_CommandHandler.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("INetworkClientService_IsConnected", "INetworkClientService"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # Slot-only: INetworkClientService is an abstract interface class with no
    # concrete body in engine binary to sign.
    (
        "INetworkClientService_IsConnected",
        [
            "func_name",
            "vfunc_sig",    # REQUIRED for Pattern C
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Locate INetworkClientService_IsConnected vfunc slot via LLM decompile of SetInfo_CommandHandler."""
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
