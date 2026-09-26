#!/usr/bin/env python3
"""Preprocess script for find-CCSPlayerPawn_CreatePlayerPawnServices skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CCSPlayerPawn_CreatePlayerPawnServices"]
# The pawn-services vfunc no longer references schema field-name strings (e.g.
# m_pBulletServices) since 14182: those strings moved to datamap registration
# code, so the old "field-name xref ∩ pawn vtable" anchor stays empty. Anchor on
# the BulletServices allocation inside the vfunc body instead: CreatePlayerPawnServices
# is the only pawn vfunc that allocates a 0x70-byte CCSPlayer_BulletServices and
# then zeroes it with interleaved xorps/movups before calling the ctor.
FUNC_XREFS_WINDOWS = [
    {
        "func_name": "CCSPlayerPawn_CreatePlayerPawnServices",
        "xref_strings": [],
        "xref_gvs": [],
        # mov edx, 0x70; mov rcx,[rax]; mov rax,[rcx]; call [rax+8]; xorps xmm0,xmm0; xor ebx,ebx
        "xref_signatures": ["BA 70 00 00 00 48 8B 08 48 8B 01 FF 50 08 0F 57 C0 33 DB"],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    }
]
FUNC_XREFS_LINUX = [
    {
        "func_name": "CCSPlayerPawn_CreatePlayerPawnServices",
        "xref_strings": [],
        "xref_gvs": [],
        # mov esi, 0x70; mov rdi,[r14]; mov rax,[rdi]; call [rax+0x10]
        "xref_signatures": ["BE 70 00 00 00 49 8B 3E 48 8B 07 FF 50 10"],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    }
]
FUNC_VTABLE_RELATIONS = [("CCSPlayerPawn_CreatePlayerPawnServices", "CCSPlayerPawn_vtable")]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CCSPlayerPawn_CreatePlayerPawnServices",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "vtable_name", "vfunc_offset", "vfunc_index"],
    )
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    """Resolve the pawn-services vfunc via its BulletServices allocation body signature."""
    _ = skill_name
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS_WINDOWS if platform == "windows" else FUNC_XREFS_LINUX,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
