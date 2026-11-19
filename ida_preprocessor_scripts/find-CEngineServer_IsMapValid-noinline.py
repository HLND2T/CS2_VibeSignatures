#!/usr/bin/env python3
"""Preprocess script for find-CEngineServer_IsMapValid-noinline skill (deinline-fix chain, link 2/3).

Resolves ``CEngineServer_IsMapValid`` (a vfunc of ``CEngineServer_vtable``) as
the single caller of the standalone ``CNetworkGameServer_IsMapValid`` helper.
This path only applies when the helper is NOT inlined into the vfunc (e.g. Linux
14168, where ``CEngineServer_IsMapValid`` merely calls
``CNetworkGameServer_IsMapValid`` after resolving the game server).  When the
helper is inlined (Windows both versions, Linux 14167) the ``xref_funcs`` callee
YAML is absent and this skill legitimately produces nothing (its output is
optional), so the ``find-CEngineServer_IsMapValid-inlined`` fallback runs instead.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEngineServer_IsMapValid",
]

FUNC_XREFS = [
    {
        "func_name": "CEngineServer_IsMapValid",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["CNetworkGameServer_IsMapValid"],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CEngineServer_IsMapValid", "CEngineServer_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CEngineServer_IsMapValid",
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
    """Resolve the wrapper from its current helper call and vtable membership."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        # Short wrapper signatures can uniquely match a sibling after relocation.
        # Require the current-version helper call to establish function identity.
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
