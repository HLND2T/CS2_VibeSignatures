#!/usr/bin/env python3
"""Preprocess script for find-CEntitySaveRestoreBlockHandler_SaveInitEntities-AND-CEntityInstance_OnSave skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEntitySaveRestoreBlockHandler_SaveInitEntities",
    "CEntityInstance_OnSave",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "CEntitySaveRestoreBlockHandler_SaveInitEntities",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySaveRestoreBlockHandler_PreSave.{platform}.yaml",
    ),
    (
        "CEntityInstance_OnSave",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySaveRestoreBlockHandler_PreSave.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CEntityInstance_OnSave", "CEntityInstance_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # Include func_va/func_rva/func_size because this function is a predecessor for downstream LLM_DECOMPILE
    (
        "CEntitySaveRestoreBlockHandler_SaveInitEntities",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    # Slim Pattern C: CEntityInstance_OnSave is not a downstream predecessor
    (
        "CEntityInstance_OnSave",
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
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
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
