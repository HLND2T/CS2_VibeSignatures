#!/usr/bin/env python3
"""Preprocess script for find-CSource2EntitySystem_StaticInit-decompiles skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "IGameResourceService_SetEntityResourceManifestHandler",
    "CEntitySystem_EnableAutoDeletionExecution",
    "CEntitySystem_InstallPostSpawnCallback",
    "CEntitySystem_InstallCreationWrapperCallbacks",
    "CGameEntitySystem_RegisterSpawnGroupEntityFilter",
]

TARGET_GLOBALVAR_NAMES = [
    "g_pGameResourceService",
    "g_pGameEntitySystem",
]

TARGET_STRUCT_MEMBER_NAMES = [
    "CEntitySystem_m_entityIONotifiers",
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("IGameResourceService_SetEntityResourceManifestHandler", "IGameResourceService"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "IGameResourceService_SetEntityResourceManifestHandler",
        [
            "func_name",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
            "vfunc_sig",
        ],
    ),
    (
        "g_pGameResourceService",
        [
            "gv_name",
            "gv_va",
            "gv_rva",
            "gv_sig",
            "gv_sig_va",
            "gv_inst_offset",
            "gv_inst_length",
            "gv_inst_disp",
        ],
    ),
    (
        "g_pGameEntitySystem",
        [
            "gv_name",
            "gv_va",
            "gv_rva",
            "gv_sig",
            "gv_sig_va",
            "gv_inst_offset",
            "gv_inst_length",
            "gv_inst_disp",
        ],
    ),
    (
        "CEntitySystem_m_entityIONotifiers",
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
        "CEntitySystem_EnableAutoDeletionExecution",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CEntitySystem_InstallPostSpawnCallback",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CEntitySystem_InstallCreationWrapperCallbacks",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
    (
        "CGameEntitySystem_RegisterSpawnGroupEntityFilter",
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
    """Reuse previous gamever vfunc_sig/gv_sig/offset_sig to locate targets and write YAML."""
    llm_decompile = [
        (
            "IGameResourceService_SetEntityResourceManifestHandler",
            "prompt/call_llm_decompile.md",
            "references/{module_name}/CSource2EntitySystem_StaticInit.{platform}.yaml",
        ),
        (
            "g_pGameResourceService",
            "prompt/call_llm_decompile.md",
            "references/{module_name}/CSource2EntitySystem_StaticInit.{platform}.yaml",
        ),
        (
            "g_pGameEntitySystem",
            "prompt/call_llm_decompile.md",
            "references/{module_name}/CSource2EntitySystem_StaticInit.{platform}.yaml",
        ),
        (
            "CEntitySystem_m_entityIONotifiers",
            "prompt/call_llm_decompile.md",
            "references/{module_name}/CSource2EntitySystem_StaticInit.{platform}.yaml",
        ),
        (
            "CEntitySystem_EnableAutoDeletionExecution",
            "prompt/call_llm_decompile.md",
            "references/{module_name}/CSource2EntitySystem_StaticInit.{platform}.yaml",
        ),
        (
            "CEntitySystem_InstallPostSpawnCallback",
            "prompt/call_llm_decompile.md",
            "references/{module_name}/CSource2EntitySystem_StaticInit.{platform}.yaml",
        ),
        (
            "CEntitySystem_InstallCreationWrapperCallbacks",
            "prompt/call_llm_decompile.md",
            "references/{module_name}/CSource2EntitySystem_StaticInit.{platform}.yaml",
        ),
        (
            "CGameEntitySystem_RegisterSpawnGroupEntityFilter",
            "prompt/call_llm_decompile.md",
            "references/{module_name}/CSource2EntitySystem_StaticInit.{platform}.yaml",
        ),
    ]

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        gv_names=TARGET_GLOBALVAR_NAMES,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=llm_decompile,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
