#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_PrecacheEntity-decompiles skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEntitySystem_DestroyEntity",
    "CConcreteEntityList_AllocEntity",
    "CEntitySystem_ConstructEntity",
    "CEntitySystem_GetSpawnGroupWorldId",
    "CEntitySystem_FindClassByDesignName",
    "CEntityIdentity_FreeAttributes",
    "CConcreteEntityList_FreeEntity",
]

TARGET_STRUCT_MEMBER_NAMES = [
    "CEntitySystem_m_EntityList",
    "CEntitySystem_m_hActiveSpawnGroup",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "CEntitySystem_DestroyEntity",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_PrecacheEntity.{platform}.yaml",
    ),
    (
        "CConcreteEntityList_AllocEntity",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_PrecacheEntity.{platform}.yaml",
    ),
    (
        "CEntitySystem_ConstructEntity",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_PrecacheEntity.{platform}.yaml",
    ),
    (
        "CEntitySystem_GetSpawnGroupWorldId",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_PrecacheEntity.{platform}.yaml",
    ),
    (
        "CEntitySystem_FindClassByDesignName",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_PrecacheEntity.{platform}.yaml",
    ),
    (
        "CEntitySystem_m_EntityList",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_PrecacheEntity.{platform}.yaml",
    ),
    (
        "CEntitySystem_m_hActiveSpawnGroup",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_PrecacheEntity.{platform}.yaml",
    ),
    (
        "CEntityIdentity_FreeAttributes",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_PrecacheEntity.{platform}.yaml",
    ),
    (
        "CConcreteEntityList_FreeEntity",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_PrecacheEntity.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CEntitySystem_GetSpawnGroupWorldId", "CEntitySystem"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CEntitySystem_DestroyEntity",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CConcreteEntityList_AllocEntity",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CEntitySystem_ConstructEntity",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CEntitySystem_GetSpawnGroupWorldId",
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
        "CEntitySystem_FindClassByDesignName",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CEntitySystem_m_EntityList",
        [
            "struct_name",
            "member_name",
            "offset",
            "size?",  # lea-based access has no natural operand size
            "offset_sig",
            "offset_sig_disp",
            "offset_sig_allow_across_function_boundary:true",
        ],
    ),
    (
        "CEntitySystem_m_hActiveSpawnGroup",
        [
            "struct_name",
            "member_name",
            "offset",
            "size",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
    (
        "CEntityIdentity_FreeAttributes",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CConcreteEntityList_FreeEntity",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever func_sig/vfunc_sig/offset_sig to locate targets and write YAMLs."""
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
