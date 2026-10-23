#!/usr/bin/env python3
"""Preprocess script for find-GetCSWeaponDataFromKey-noinline skill (deinline-fix chain, link 2/3)."""

from ida_preprocessor_scripts._weapon_data_from_key_common import preprocess_weapon_data_lookup


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    llm_config=None,
    debug=False,
):
    """Accept a verified string lookup anchor or find it inside a genuine wrapper."""
    if platform != "linux":
        return False
    return await preprocess_weapon_data_lookup(
        session,
        expected_outputs,
        new_binary_dir,
        image_base,
        source_stem="CSmokeGrenadeProjectile_GetCSWeaponData",
        artifact_stem="GetCSWeaponDataFromKey",
        include_source=True,
        debug=debug,
    )
