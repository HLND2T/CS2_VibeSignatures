#!/usr/bin/env python3
"""Preprocess script for find-IGameSystem_SetName skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "IGameSystem_SetName",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "IGameSystem_SetName",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/client/IGameSystem_AddByName.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "IGameSystem_AddByName.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("IGameSystem_SetName", "IGameSystem"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "IGameSystem_SetName",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_sig_max_match:2",  # SetName's vfunc_sig at [reg+0x1E0]-class offset matches multiple call sites
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
    """Reuse previous gamever vfunc_sig to locate IGameSystem_SetName; fallback to LLM_DECOMPILE of IGameSystem_AddByName."""
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
