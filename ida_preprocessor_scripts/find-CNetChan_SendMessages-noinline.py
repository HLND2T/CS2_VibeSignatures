#!/usr/bin/env python3
"""Preprocess script for find-CNetChan_SendMessages-noinline skill.

Resolves ``CNetChan_SendMessages`` as the caller of the standalone
``CNetChan_SendMessages_Internal`` helper. This path only applies when the helper is
NOT inlined into the vfunc. ``CNetChan_Transmit`` calls the same helper, so it is
excluded by name — a symbol reference resolved from the current binary — rather than
by a fixed game-layout offset, which shifts between builds. The ``CNetChan`` vtable
relation then collapses the caller set to the single vtable member. Its output is
optional: when the caller cannot be resolved, the
``find-CNetChan_SendMessages-inlined`` fallback runs instead.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CNetChan_SendMessages"]
FUNC_XREFS = [
    {
        "func_name": "CNetChan_SendMessages",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["CNetChan_SendMessages_Internal"],
        "exclude_funcs": ["CNetChan_Transmit"],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    }
]
FUNC_VTABLE_RELATIONS = [("CNetChan_SendMessages", "CNetChan")]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CNetChan_SendMessages",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "vtable_name", "vfunc_offset", "vfunc_index"],
    )
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
