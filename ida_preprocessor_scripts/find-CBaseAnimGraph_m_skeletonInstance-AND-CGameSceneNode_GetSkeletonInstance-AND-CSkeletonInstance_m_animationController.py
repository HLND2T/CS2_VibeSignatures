#!/usr/bin/env python3
"""Preprocess script for find-CBaseAnimGraph_m_skeletonInstance-AND-CGameSceneNode_GetSkeletonInstance-AND-CSkeletonInstance_m_animationController skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CGameSceneNode_GetSkeletonInstance",
]

TARGET_STRUCT_MEMBER_NAMES = [
    "CBaseAnimGraph_m_skeletonInstance",
    "CSkeletonInstance_m_animationController",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "CBaseAnimGraph_m_skeletonInstance",
        "prompt/call_llm_decompile.md",
        "references/server/CBaseAnimGraph_GetAnimationController.{platform}.yaml",
    ),
    (
        "CGameSceneNode_GetSkeletonInstance",
        "prompt/call_llm_decompile.md",
        "references/server/CBaseAnimGraph_GetAnimationController.{platform}.yaml",
    ),
    (
        "CSkeletonInstance_m_animationController",
        "prompt/call_llm_decompile.md",
        "references/server/CBaseAnimGraph_GetAnimationController.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CGameSceneNode_GetSkeletonInstance", "CGameSceneNode"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CBaseAnimGraph_m_skeletonInstance",
        [
            "struct_name",
            "member_name",
            "offset",
            "size",
            "offset_sig",
            "offset_sig_disp",
            "offset_sig_allow_across_function_boundary:true",  # instruction is at function start
        ],
    ),
    (
        "CGameSceneNode_GetSkeletonInstance",
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
        "CSkeletonInstance_m_animationController",
        [
            "struct_name",
            "member_name",
            "offset",
            "size",
            "offset_sig",
            "offset_sig_disp",
            "offset_sig_allow_across_function_boundary:true",  # instruction is at function start
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever sigs to locate struct members and vfunc, write YAMLs."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
