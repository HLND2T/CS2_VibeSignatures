#!/usr/bin/env python3
"""Find the 14197 field-change registry virtual entry points."""

from ida_preprocessor_scripts._network_registry_vfunc_common import VFUNC_FIELDS, preprocess_registry_vfuncs

TARGETS = (
    ("CNetworkMessages_RegisterNetworkFieldChangeCallbackInternal", "NetSerializers_RegisterNetworkFieldChangeCallback"),
    ("CNetworkMessages_RegisterFieldChangeCallbackPriority", "NetSerializers_RegisterFieldChangeCallbackPriority"),
    ("CNetworkMessages_ComputeOrderForPriority", "NetSerializers_ComputeOrderForPriority"),
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
    """Locate the current registry bodies and their unique virtual entries."""
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
