#!/usr/bin/env python3
"""Find BeamUpdateVars from its invalid endpoint warning."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CEnvBeam_BeamUpdateVars"]
FUNC_XREFS = [
    {
        "func_name": "CEnvBeam_BeamUpdateVars",
        "xref_strings": [
            "FULLMATCH:env_beams cannot have the end entity be the beam itself\n"
            "unless the start entity is also the beam itself!\n",
        ],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CEnvBeam_BeamUpdateVars", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
