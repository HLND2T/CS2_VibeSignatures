#!/usr/bin/env python3
"""Preprocess script for find-ISchemaSystem_FindTypeScopeForModule skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "ISchemaSystem_FindTypeScopeForModule",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "ISchemaSystem_FindTypeScopeForModule",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CreateEntitySubclassVData.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CreateEntitySubclassVData.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("ISchemaSystem_FindTypeScopeForModule", "ISchemaSystem"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "ISchemaSystem_FindTypeScopeForModule",
        [
            "func_name",
            "vfunc_sig",
            # CreateEntitySubclassVData dispatches this slot from two call sites
            "vfunc_sig_max_match:2",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
            "vfunc_sig_allow_across_function_boundary:true",
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
    """Reuse previous gamever vfunc_sig to locate target virtual function and write YAML."""
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
