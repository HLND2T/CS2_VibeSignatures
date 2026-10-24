#!/usr/bin/env python3
"""Preprocess script for find-GetCSWeaponDataFromKey-inlined skill (deinline-fix chain, link 3/3)."""

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
    """Find the string lookup directly when the old wrapper is inlined."""
    return await preprocess_weapon_data_lookup(
        session,
        expected_outputs,
        new_binary_dir,
        image_base,
        source_stem="CSmokeGrenadeProjectile_Create",
        artifact_stem="GetCSWeaponDataFromKey",
        platform=platform,
        debug=debug,
    )
