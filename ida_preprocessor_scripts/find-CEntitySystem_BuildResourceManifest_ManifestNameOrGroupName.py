from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CEntitySystem_BuildResourceManifest_ManifestNameOrGroupName"]
FUNC_XREFS = [
    {
        "func_name": "CEntitySystem_BuildResourceManifest_ManifestNameOrGroupName",
        "xref_strings": ["classname"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["CEntitySystem_PrecacheEntity", "CEntitySystem_DestroyEntity"],
        "exclude_funcs": [],
        "exclude_strings": ["kv 0x%p AddRef refcount == %d\n"],
        "exclude_gvs": [],
        "exclude_signatures": [],
    }
]
FUNC_VTABLE_RELATIONS = [("CEntitySystem_BuildResourceManifest_ManifestNameOrGroupName", "CEntitySystem_vtable")]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CEntitySystem_BuildResourceManifest_ManifestNameOrGroupName",
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
