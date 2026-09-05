#!/usr/bin/env python3
"""Preprocess script for find-CBaseEntity_RegisteredScriptFuncs skill."""

from ida_preprocessor_scripts._script_desc_internal_common import (
    preprocess_script_desc_internal_skill,
)

SOURCE_YAML_STEM = "CBaseEntity_GetScriptDescInternal"
EXPECTED_SCRIPT_FUNC_COUNT = 65

TARGET_SCRIPT_FUNCTIONS = [
    {"script_name": "ScriptInputKill", "target_name": "CBaseEntity_ScriptInputKill"},
    {"script_name": "ScriptGetForward", "target_name": "CBaseEntity_ScriptGetForward"},
    {"script_name": "ScriptGetRight", "target_name": "CBaseEntity_ScriptGetRight"},
    {"script_name": "ScriptGetLeft", "target_name": "CBaseEntity_ScriptGetLeft"},
    {"script_name": "ScriptGetUp", "target_name": "CBaseEntity_ScriptGetUp"},
    {"script_name": "ScriptGetModelName", "target_name": "CBaseEntity_ScriptGetModelName"},
    {"script_name": "ScriptGetMoveParent", "target_name": "CBaseEntity_ScriptGetMoveParent"},
    {"script_name": "ScriptGetRootMoveParent", "target_name": "CBaseEntity_ScriptGetRootMoveParent"},
    {"script_name": "ScriptFirstMoveChild", "target_name": "CBaseEntity_ScriptFirstMoveChild"},
    {"script_name": "ScriptNextMovePeer", "target_name": "CBaseEntity_ScriptNextMovePeer"},
    {"script_name": "ScriptGetOwnerEntity", "target_name": "CBaseEntity_ScriptGetOwnerEntity"},
    {"script_name": "Script_GetChildren", "target_name": "CBaseEntity_Script_GetChildren"},
    {"script_name": "ScriptSetParent", "target_name": "CBaseEntity_ScriptSetParent"},
    {"script_name": "ScriptEyePosition", "target_name": "CBaseEntity_ScriptEyePosition"},
    {"script_name": "ScriptSetAngles", "target_name": "CBaseEntity_ScriptSetAngles"},
    {"script_name": "ScriptSetAbsAngles", "target_name": "CBaseEntity_ScriptSetAbsAngles"},
    {"script_name": "ScriptGetAngles", "target_name": "CBaseEntity_ScriptGetAngles"},
    {"script_name": "ScriptEyeAngles", "target_name": "CBaseEntity_ScriptEyeAngles"},
    {"script_name": "ScriptSetOrigin", "target_name": "CBaseEntity_ScriptSetOrigin"},
    {"script_name": "ScriptSetLocalAngles", "target_name": "CBaseEntity_ScriptSetLocalAngles"},
    {"script_name": "ScriptGetLocalAngles", "target_name": "CBaseEntity_ScriptGetLocalAngles"},
    {"script_name": "ScriptSetLocalOrigin", "target_name": "CBaseEntity_ScriptSetLocalOrigin"},
    {"script_name": "ScriptGetLocalOrigin", "target_name": "CBaseEntity_ScriptGetLocalOrigin"},
    {
        "script_name": "ScriptTransformPointEntityToWorld",
        "target_name": "CBaseEntity_ScriptTransformPointEntityToWorld",
    },
    {
        "script_name": "ScriptTransformPointWorldToEntity",
        "target_name": "CBaseEntity_ScriptTransformPointWorldToEntity",
    },
    {"script_name": "ScriptSetForward", "target_name": "CBaseEntity_ScriptSetForward"},
    {"script_name": "ScriptGetBoundingMins", "target_name": "CBaseEntity_ScriptGetBoundingMins"},
    {"script_name": "ScriptGetBoundingMaxs", "target_name": "CBaseEntity_ScriptGetBoundingMaxs"},
    {"script_name": "ScriptGetBounds", "target_name": "CBaseEntity_ScriptGetBounds"},
    {
        "script_name": "ScriptGetLocalAngularVelocity_OBSOLETE",
        "target_name": "CBaseEntity_ScriptGetLocalAngularVelocity_OBSOLETE",
    },
    {
        "script_name": "ScriptSetLocalAngularVelocity_OBSOLETE",
        "target_name": "CBaseEntity_ScriptSetLocalAngularVelocity_OBSOLETE",
    },
    {"script_name": "ScriptAddEffects", "target_name": "CBaseEntity_ScriptAddEffects"},
    {"script_name": "ScriptRemoveEffects", "target_name": "CBaseEntity_ScriptRemoveEffects"},
    {"script_name": "ScriptSetAttributeFloatValue", "target_name": "CBaseEntity_ScriptSetAttributeFloatValue"},
    {"script_name": "ScriptGetAttributeFloatValue", "target_name": "CBaseEntity_ScriptGetAttributeFloatValue"},
    {"script_name": "ScriptSetAttributeIntValue", "target_name": "CBaseEntity_ScriptSetAttributeIntValue"},
    {"script_name": "ScriptGetAttributeIntValue", "target_name": "CBaseEntity_ScriptGetAttributeIntValue"},
    {"script_name": "ScriptHasAttribute", "target_name": "CBaseEntity_ScriptHasAttribute"},
    {"script_name": "ScriptDeleteAttribute", "target_name": "CBaseEntity_ScriptDeleteAttribute"},
    {"script_name": "GetScriptOwnerEntity", "target_name": "CBaseEntity_GetScriptOwnerEntity"},
    {"script_name": "SetScriptOwnerEntity", "target_name": "CBaseEntity_SetScriptOwnerEntity"},
    {"script_name": "ScriptSetEntityName", "target_name": "CBaseEntity_ScriptSetEntityName"},
    {"script_name": "ScriptGetMass", "target_name": "CBaseEntity_ScriptGetMass"},
    {"script_name": "ScriptSetMass", "target_name": "CBaseEntity_ScriptSetMass"},
    {"script_name": "ScriptGetSpawnGroupHandle", "target_name": "CBaseEntity_ScriptGetSpawnGroupHandle"},
    {"script_name": "GetAbsAngles", "target_name": "CBaseEntity_GetAbsAngles"},
    {"script_name": "Script_GetTeamNumber", "target_name": "CBaseEntity_Script_GetTeamNumber"},
    {"script_name": "Script_FollowEntity", "target_name": "CBaseEntity_Script_FollowEntity"},
    {"script_name": "Script_FollowEntityMerge", "target_name": "CBaseEntity_Script_FollowEntityMerge"},
    {"script_name": "Script_Trigger", "target_name": "CBaseEntity_Script_Trigger"},
    {"script_name": "Script_SetContextThink", "target_name": "CBaseEntity_Script_SetContextThink"},
    {"script_name": "AddContextForScript", "target_name": "CBaseEntity_AddContextForScript"},
    {"script_name": "AddContextForScriptNumeric", "target_name": "CBaseEntity_AddContextForScriptNumeric"},
    {"script_name": "GetContextForScript", "target_name": "CBaseEntity_GetContextForScript"},
    {"script_name": "ScriptGatherCriteria", "target_name": "CBaseEntity_ScriptGatherCriteria"},
    {"script_name": "Script_TakeDamage", "target_name": "CBaseEntity_Script_TakeDamage"},
    {"script_name": "SetGravityScale", "target_name": "CBaseEntity_ScriptSetGravityScale"},
    {"script_name": "SetAbsVelocity", "target_name": "CBaseEntity_SetAbsVelocity"},
    {"script_name": "GetAbsVelocity", "target_name": "CBaseEntity_GetAbsVelocity"},
    {
        "script_name": "Script_ApplyLocalAngularVelocityImpulse",
        "target_name": "CBaseEntity_Script_ApplyLocalAngularVelocityImpulse",
    },
    {"script_name": "GetLocalAngularVelocity_OBSOLETE", "target_name": "CBaseEntity_GetLocalAngularVelocity_OBSOLETE"},
    {"script_name": "ScriptEmitSoundParams", "target_name": "CBaseEntity_ScriptEmitSoundParams"},
    {"script_name": "ScriptStopSound", "target_name": "CBaseEntity_ScriptStopSound"},
    {"script_name": "ScriptSoundDuration", "target_name": "CBaseEntity_ScriptSoundDuration"},
    {"script_name": "ScriptGetAbsOrigin", "target_name": "CBaseEntity_ScriptGetAbsOrigin"},
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
