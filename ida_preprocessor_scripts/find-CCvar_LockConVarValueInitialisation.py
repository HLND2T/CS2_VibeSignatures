"""Find CCvar_LockConVarValueInitialisation through the inline initialisation path."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CCvar_LockConVarValueInitialisation"]

FUNC_XREFS = [
    {
        "func_name": "CCvar_LockConVarValueInitialisation",
        "xref_strings": ["FULLMATCH:Failed to parse initial ConVar '%s'[%d] from string '%s'\n"],
        "xref_funcs": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    }
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CCvar_LockConVarValueInitialisation",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "vtable_name", "vfunc_offset", "vfunc_index"],
    )
]

FUNC_VTABLE_RELATIONS = [("CCvar_LockConVarValueInitialisation", "CCvar_vtable")]


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
    func_xrefs = [dict(FUNC_XREFS[0])]
    func_xrefs[0]["xref_signatures"] = ["84 DB 0F 85 ?? ?? ?? ??"] if platform == "windows" else ["45 84 F6 75 ??"]
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=func_xrefs,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
