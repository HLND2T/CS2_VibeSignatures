#!/usr/bin/env python3
"""Preprocess script for find-IGameSystem_OnServerBeginAsyncPostTickWork skill."""

from ida_preprocessor_scripts._igamesystem_dispatch_common import (
    preprocess_igamesystem_dispatch_skill,
)

SOURCE_YAML_STEM = "CLoopModeGame_OnServerBeginAsyncPostTickWork"
# The dispatcher invokes OnServerBeginAsyncPostTickWork followed by
# OnServerGameBeginAsyncPostTickWork. Legacy artifact keys retain the earlier
# Pre/Begin labels; MULTI_ORDER="index" and OUTPUT_NAME_MAP preserve both
# identities without colliding when the lower slot's canonical name is Begin.
# Artifact keys stay stable; emitted names reflect the verified SDK semantics.
OUTPUT_NAME_MAP = {
    "IGameSystem_OnServerPreBeginAsyncPostTickWork": "IGameSystem_OnServerBeginAsyncPostTickWork",
    "IGameSystem_OnServerBeginAsyncPostTickWork": "IGameSystem_OnServerGameBeginAsyncPostTickWork",
}

TARGET_SPECS = [
    {
        "target_name": "IGameSystem_OnServerPreBeginAsyncPostTickWork",
        "rename_to": "GameSystem_OnServerBeginAsyncPostTickWork",
    },
    {
        "target_name": "IGameSystem_OnServerBeginAsyncPostTickWork",
        "rename_to": "GameSystem_OnServerGameBeginAsyncPostTickWork",
    },
]
VIA_INTERNAL_WRAPPER = False
INTERNAL_RENAME_TO = None
MULTI_ORDER = "index"


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
    """Resolve target function(s) via IGameSystem dispatch and write YAML."""
    _ = skill_name, old_yaml_map
    return await preprocess_igamesystem_dispatch_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        source_yaml_stem=SOURCE_YAML_STEM,
        target_specs=TARGET_SPECS,
        via_internal_wrapper=VIA_INTERNAL_WRAPPER,
        internal_rename_to=INTERNAL_RENAME_TO,
        multi_order=MULTI_ORDER,
        debug=debug,
        output_name_map=OUTPUT_NAME_MAP,
    )
