#!/usr/bin/env python3
"""Resolve the 14197 serializer vfuncs across inlined and registry-wrapper forms."""

from ida_preprocessor_scripts._network_registry_vfunc_common import VFUNC_FIELDS, preprocess_registry_vfuncs

TARGETS = (
    ("CNetworkMessages_RegisterNetworkFieldSerializer", "NetSerializers_RegisterNetworkFieldSerializer"),
    ("CNetworkMessages_RegisterNetworkArrayFieldSerializer", "NetSerializers_RegisterNetworkArrayFieldSerializer"),
)
GENERATE_YAML_DESIRED_FIELDS = [(name, list(VFUNC_FIELDS)) for name, _anchor in TARGETS]


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
    """Resolve both current implementations before generating fresh vfunc signatures."""
    _ = skill_name, old_yaml_map
    return await preprocess_registry_vfuncs(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        targets=TARGETS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
