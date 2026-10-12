#!/usr/bin/env python3
"""Preprocess script for find-CBaseModelEntity_RegisteredScriptFuncs skill."""

from ida_preprocessor_scripts._script_desc_internal_common import (
    preprocess_script_desc_internal_skill,
)

SOURCE_YAML_STEM = "CBaseModelEntity_GetScriptDescInternal"
EXPECTED_SCRIPT_FUNC_COUNT = 22

TARGET_SCRIPT_FUNCTIONS = [
    {
        "script_name": "GetModelScale",
        "target_name": "CBaseModelEntity_GetModelScale",
    },
    {
        "script_name": "Script_SetModelScale",
        "target_name": "CBaseModelEntity_Script_SetModelScale",
    },
    {
        "script_name": "ScriptLookupAttachment",
        "target_name": "CBaseModelEntity_ScriptLookupAttachment",
    },
    {
        "script_name": "ScriptGetAttachmentOrigin",
        "target_name": "CBaseModelEntity_ScriptGetAttachmentOrigin",
    },
    {
        "script_name": "ScriptGetAttachmentAngles",
        "target_name": "CBaseModelEntity_ScriptGetAttachmentAngles",
    },
    {
        "script_name": "ScriptGetAttachmentForward",
        "target_name": "CBaseModelEntity_ScriptGetAttachmentForward",
    },
    {
        "script_name": "ScriptSetSize",
        "target_name": "CBaseModelEntity_ScriptSetSize",
    },
    {
        "script_name": "ScriptSetModel",
        "target_name": "CBaseModelEntity_ScriptSetModel",
    },
    {
        "script_name": "ScriptGetRenderAlpha",
        "target_name": "CBaseModelEntity_ScriptGetRenderAlpha",
    },
    {
        "script_name": "ScriptSetRenderAlpha",
        "target_name": "CBaseModelEntity_ScriptSetRenderAlpha",
    },
    {
        "script_name": "ScriptSetRenderMode",
        "target_name": "CBaseModelEntity_ScriptSetRenderMode",
    },
    {
        "script_name": "ScriptSetRenderColor",
        "target_name": "CBaseModelEntity_ScriptSetRenderColor",
    },
    {
        "script_name": "ScriptGetRenderColor",
        "target_name": "CBaseModelEntity_ScriptGetRenderColor",
    },
    {
        "script_name": "ScriptSetMaterialGroup",
        "target_name": "CBaseModelEntity_ScriptSetMaterialGroup",
    },
    {
        "script_name": "ScriptSetMaterialGroupHash",
        "target_name": "CBaseModelEntity_ScriptSetMaterialGroupHash",
    },
    {
        "script_name": "ScriptGetMaterialGroupHash",
        "target_name": "CBaseModelEntity_ScriptGetMaterialGroupHash",
    },
    {
        "script_name": "ScriptSetSingleMeshGroup",
        "target_name": "CBaseModelEntity_ScriptSetSingleMeshGroup",
    },
    {
        "script_name": "ScriptSetMeshGroupMask",
        "target_name": "CBaseModelEntity_ScriptSetMeshGroupMask",
    },
    {
        "script_name": "ScriptGetMeshGroupMask",
        "target_name": "CBaseModelEntity_ScriptGetMeshGroupMask",
    },
    {
        "script_name": "ScriptSetBodygroupByName",
        "target_name": "CBaseModelEntity_ScriptSetBodygroupByName",
    },
    {
        "script_name": "Script_SetBodygroup",
        "target_name": "CBaseModelEntity_Script_SetBodygroup",
    },
    {
        "script_name": "Script_SetSkin",
        "target_name": "CBaseModelEntity_Script_SetSkin",
    },
]

TARGET_FUNCTION_NAMES = [spec["target_name"] for spec in TARGET_SCRIPT_FUNCTIONS]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        name,
        [
            "func_name",
            "func_sig",
            "func_sig_allow_across_function_boundary:true",
            # Some registered script funcs are compiler-emitted jmp thunks; those
            # emit metadata only instead of failing the whole table.
            "func_sig_skip_degenerate:true",
            "func_va",
            "func_rva",
            "func_size",
        ],
    )
    for name in TARGET_FUNCTION_NAMES
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
    """Extract registered script functions from GetScriptDescInternal."""
    return await preprocess_script_desc_internal_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        source_yaml_stem=SOURCE_YAML_STEM,
        target_specs=TARGET_SCRIPT_FUNCTIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        expected_script_func_count=EXPECTED_SCRIPT_FUNC_COUNT,
        debug=debug,
    )
