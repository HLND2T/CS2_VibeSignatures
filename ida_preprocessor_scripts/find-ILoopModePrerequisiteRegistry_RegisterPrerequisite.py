#!/usr/bin/env python3
"""Preprocess script for find-ILoopModePrerequisiteRegistry_RegisterPrerequisite skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "ILoopModePrerequisiteRegistry_RegisterPrerequisite",
]

# ILoopModePrerequisiteRegistry::RegisterPrerequisite is an abstract-interface vfunc.
# The engine predecessor CLoopModeLevelLoad_LoopInit receives an
# ILoopModePrerequisiteRegistry* and reaches the slot through a register-indirect
# vcall: `call qword ptr [rax]`. The skill runs in the ENGINE module (where the
# predecessor is renamed/available) and produces a caller-anchored vfunc_sig that
# anchors on that vcall instruction. The concrete override is resolved separately by
# find-CEngineServiceMgr_RegisterPrerequisite through INHERIT_VFUNCS.
LLM_DECOMPILE = [
    {
        "symbol_name": "ILoopModePrerequisiteRegistry_RegisterPrerequisite",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CLoopModeLevelLoad_LoopInit.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CLoopModeLevelLoad_LoopInit.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class) -- vtable_name is metadata only; no
    # ILoopModePrerequisiteRegistry_vtable YAML is consumed here. The vfunc_sig
    # anchors on the vcall instruction inside the engine predecessor
    # CLoopModeLevelLoad_LoopInit.
    ("ILoopModePrerequisiteRegistry_RegisterPrerequisite", "ILoopModePrerequisiteRegistry"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # Slim Pattern C: not a downstream predecessor, so func_va/rva/size omitted.
    # vfunc_sig is MANDATORY for Pattern C.
    (
        "ILoopModePrerequisiteRegistry_RegisterPrerequisite",
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
    """Locate the interface vfunc slot from CLoopModeLevelLoad_LoopInit."""
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
