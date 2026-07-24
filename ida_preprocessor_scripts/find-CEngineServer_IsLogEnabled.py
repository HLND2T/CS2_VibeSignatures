#!/usr/bin/env python3
"""Preprocess script for find-CEngineServer_IsLogEnabled skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEngineServer_IsLogEnabled",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CEngineServer_IsLogEnabled",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CSource2Server_GameFrame.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CSource2Server_GameFrame.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    # CEngineServer vtable name is metadata only -- the vfunc offset/signature is
    # anchored on the indirect call site inside CSource2Server_GameFrame (server.dll),
    # so no CEngineServer_vtable YAML lookup is required.
    ("CEngineServer_IsLogEnabled", "CEngineServer"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # Slim Pattern C -- not a downstream predecessor, so no func_va/func_rva/func_size.
    # vfunc_sig is MANDATORY for Pattern C.
    (
        "CEngineServer_IsLogEnabled",
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
    """Reuse previous gamever vfunc slot; fallback to LLM_DECOMPILE on CSource2Server_GameFrame."""
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
