#!/usr/bin/env python3
"""Preprocess script for find-CEngineServiceMgr_GetAddonCount.

The interface slot is recovered by find-IEngineServiceMgr_GetAddonCount
(LLM_DECOMPILE on the client disconnect-game flow); this skill inherits
that slot index and resolves the concrete override in the CEngineServiceMgr vtable.
"""

from ida_analyze_util import preprocess_common_skill

INHERIT_VFUNCS = [
    # (target_func_name, inherit_vtable_class, base_vfunc_name, generate_func_sig)
    (
        "CEngineServiceMgr_GetAddonCount",
        "CEngineServiceMgr",
        "IEngineServiceMgr_GetAddonCount",
        True,
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CEngineServiceMgr_GetAddonCount",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
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
    debug=False,
):
    """Inherit the GetAddonCount slot from IEngineServiceMgr."""
    _ = skill_name
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=INHERIT_VFUNCS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
