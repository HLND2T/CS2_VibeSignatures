#!/usr/bin/env python3
"""Preprocess script for find-CEngineClient_ExecuteClientCmd skill.

Resolves the engine's ``ServerCmd( CSplitScreenSlot, const char * )`` override,
which the artifact key still spells ``ExecuteClientCmd``.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CEngineClient_ExecuteClientCmd",
]

# The artifact key is historical: the slot clamps the split-screen slot and
# forwards to the network client's SendStringCmd, which the SDK declares as
# ServerCmd.
OUTPUT_NAME_MAP = {
    "CEngineClient_ExecuteClientCmd": "CEngineClient_ServerCmd",
}

INHERIT_VFUNCS = [
    # (target_func_name, inherit_vtable_class, base_vfunc_name, generate_func_sig)
    (
        "CEngineClient_ExecuteClientCmd",
        "CEngineClient",
        "../client/IVEngineClient2_ExecuteClientCmd",
        True,
    ),
]

FUNC_VTABLE_RELATIONS = [
    ("CEngineClient_ExecuteClientCmd", "CEngineClient"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CEngineClient_ExecuteClientCmd",
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
    """Resolve CEngineClient's ServerCmd implementation on each ABI.

    Both ABIs keep this IVEngineClient2 override at the inherited slot, so the
    same inherit path serves them. The former Linux-only byte signature matched
    a sibling forwarder and recorded slot 101 instead of 50.
    """
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
        output_name_map=OUTPUT_NAME_MAP,
    )
