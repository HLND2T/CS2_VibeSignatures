#!/usr/bin/env python3
"""Preprocess script for find-CEngineServer_IsMapValid-inlined skill (deinline-fix chain, link 3/3).

Resolves ``CEngineServer_IsMapValid`` (a vfunc of ``CEngineServer_vtable``)
directly, for the builds where the ``CNetworkGameServer_IsMapValid`` guard is
inlined into the vfunc (Windows both versions, Linux 14167).  It is the fallback
for the ``find-CEngineServer_IsMapValid-noinline`` path (which handles the Linux
14168 de-inlined case) and is skipped whenever
``CEngineServer_IsMapValid.{platform}.yaml`` already exists.

This is the merge of the former platform-split ``-windows`` / ``-linux`` finders
into one cross-platform script.  The immediate callee that ``CEngineServer_IsMapValid``
reaches differs per platform because the string-owning body has a different name:

- Windows: ``CEngineServer_IsMapValid`` calls ``CMapListService_IsMapValid`` (the
  vtable-25 body that owns the map-validation strings).
- Linux 14167: the guard is inlined, so ``CEngineServer_IsMapValid`` calls the
  standalone ``IsMapValid`` body directly.  ``CEngineServer_ChangeLevel`` is also a
  ``CEngineServer_vtable`` member that calls ``IsMapValid``, so the
  ``"Changelevel %s %s"`` string is excluded to collapse the intersection to the
  single ``IsMapValid`` vfunc.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEngineServer_IsMapValid",
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


def _build_func_xrefs(platform):
    """The string-owning callee differs per platform (see module docstring)."""
    if platform == "windows":
        return [
            {
                "func_name": "CEngineServer_IsMapValid",
                "xref_strings": [],
                "xref_gvs": [],
                "xref_signatures": [],
                "xref_funcs": ["CMapListService_IsMapValid"],
                "exclude_funcs": [],
                "exclude_strings": [],
                "exclude_gvs": [],
                "exclude_signatures": [],
            },
        ]
    return [
        {
            "func_name": "CEngineServer_IsMapValid",
            "xref_strings": ["FULLMATCH:<empty>"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": ["IsMapValid"],
            "exclude_funcs": [],
            "exclude_strings": ["Changelevel %s %s"],
            "exclude_gvs": [],
            "exclude_signatures": [],
        },
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
        # The fallback must also validate the current callee when an old wrapper
        # signature uniquely matches a different member of the same vtable.
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=_build_func_xrefs(platform),
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
