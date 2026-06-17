#!/usr/bin/env python3
"""Preprocess script for find-CEntityInstance_PostDataUpdatePreserve-AND-CEntityInstance_PostDataUpdateDelta skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEntityInstance_PostDataUpdatePreserve",
    "CEntityInstance_PostDataUpdateDelta",
]

TARGET_STRUCT_MEMBER_NAMES = [
    "CEntitySystem_m_flChangeCallbackSpewThreshold",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "CEntityInstance_PostDataUpdatePreserve",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_PostDataUpdate.{platform}.yaml",
    ),
    (
        "CEntityInstance_PostDataUpdateDelta",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_PostDataUpdate.{platform}.yaml",
    ),
    (
        "CEntitySystem_m_flChangeCallbackSpewThreshold",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_PostDataUpdate.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CEntityInstance_PostDataUpdatePreserve", "CEntityInstance"),
    ("CEntityInstance_PostDataUpdateDelta", "CEntityInstance"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # IMPORTANT: must be exactly these four fields to trigger slot-only mode
    (
        "CEntityInstance_PostDataUpdatePreserve",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "CEntityInstance_PostDataUpdateDelta",
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
        "CEntitySystem_m_flChangeCallbackSpewThreshold",
        [
            "struct_name",
            "member_name",
            "offset",
            "size",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever vfunc slots; fallback to LLM_DECOMPILE on CEntitySystem_PostDataUpdate."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
