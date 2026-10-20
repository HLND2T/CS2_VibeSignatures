#!/usr/bin/env python3
"""Preprocess script for find-CMultiplayRules_ctor-decompiles skill.

Finds the ICvar and IVEngineServer2 interface vfunc call-site offsets that are
invoked inside CMultiplayRules_ctor. Both interfaces are abstract, so the
targets are pure vfunc call-site offsets (no vtable YAML exists for them);
the vtable class name is written purely as metadata via FUNC_VTABLE_RELATIONS.
"""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._convar_filter_chain_common import load_helper_details

TARGET_FUNCTION_NAMES = [
    "IVEngineServer2_ServerCommand",
    "IVEngineServer2_IsDedicatedServer",
    "ICvar_ResetConVarsToDefaultValuesByFlag",
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class) -- vtable_name is metadata only; no IVEngineServer2_vtable/ICvar_vtable YAML exists
    ("IVEngineServer2_ServerCommand", "IVEngineServer2"),
    ("IVEngineServer2_IsDedicatedServer", "IVEngineServer2"),
    ("ICvar_ResetConVarsToDefaultValuesByFlag", "ICvar"),
]

LLM_DECOMPILE = [
    {
        "symbol_name": "IVEngineServer2_ServerCommand",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CMultiplayRules_ctor.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CMultiplayRules_ctor.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "IVEngineServer2_IsDedicatedServer",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CMultiplayRules_ctor.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CMultiplayRules_ctor.{platform}.yaml": "required",
        },
    },
    {
        "symbol_name": "ICvar_ResetConVarsToDefaultValuesByFlag",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/server/CMultiplayRules_ctor.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CMultiplayRules_ctor.{platform}.yaml": "required",
        },
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # Slim Pattern C: abstract interface vfuncs are inherited downstream via INHERIT_VFUNCS
    # (which reads vfunc_index), not decompiled, so func_va/func_rva/func_size are omitted.
    # vfunc_sig is MANDATORY for Pattern C.
    (
        "IVEngineServer2_ServerCommand",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "IVEngineServer2_IsDedicatedServer",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "ICvar_ResetConVarsToDefaultValuesByFlag",
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
    """Reuse previous gamever vfunc_sig to locate targets; fall back to LLM decompilation.

    The inline body is tried first; only the targets still missing after it are
    re-attempted with the bounded direct-call/tail-jump helper chain, so a build
    that de-inlines one of the vcalls into a helper still resolves.
    """
    kwargs = dict(
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
    if await preprocess_common_skill(**kwargs):
        return True
    return await preprocess_common_skill(**kwargs, llm_target_details_loader=load_helper_details)
