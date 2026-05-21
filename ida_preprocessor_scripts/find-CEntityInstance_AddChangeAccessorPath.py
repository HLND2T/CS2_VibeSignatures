#!/usr/bin/env python3
"""Preprocess script for find-CEntityInstance_AddChangeAccessorPath skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEntityInstance_AddChangeAccessorPath",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "CEntityInstance_AddChangeAccessorPath",
        "prompt/call_llm_decompile.md",
        "references/server/EntityInstanceAddChangeAccessorPath.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CEntityInstance_AddChangeAccessorPath", "CEntityInstance"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # Slim Pattern C: CEntityInstance_AddChangeAccessorPath is not a downstream predecessor.
    (
        "CEntityInstance_AddChangeAccessorPath",
        [
            "func_name",
            "vfunc_sig",    # REQUIRED for Pattern C
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
            "vfunc_sig_allow_across_function_boundary:true",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Locate CEntityInstance_AddChangeAccessorPath vfunc via LLM decompile of EntityInstanceAddChangeAccessorPath."""
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
