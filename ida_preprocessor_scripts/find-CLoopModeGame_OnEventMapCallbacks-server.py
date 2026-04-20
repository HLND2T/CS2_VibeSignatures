#!/usr/bin/env python3
"""Preprocess script for find-CLoopModeGame_OnEventMapCallbacks-server skill."""

from ida_preprocessor_scripts._register_event_listener_abstract import (
    preprocess_register_event_listener_abstract_skill,
)


SOURCE_YAML_STEM = "CLoopModeGame_RegisterEventMapInternal"
REGISTER_FUNC_TARGET_NAME = "RegisterEventListener_Abstract"
ANCHOR_EVENT_NAME = "CLoopModeGame::OnServerAdvanceTick"
SEARCH_WINDOW_AFTER_ANCHOR = 64
SEARCH_WINDOW_BEFORE_CALL = 64

TARGET_SPECS = [
    {
        "target_name": "CLoopModeGame_OnServerAdvanceTick",
        "event_name": "CLoopModeGame::OnServerAdvanceTick",
        "rename_to": "CLoopModeGame_OnServerAdvanceTick",
    },
    {
        "target_name": "CLoopModeGame_OnServerBeginSimulate",
        "event_name": "CLoopModeGame::OnServerBeginSimulate",
        "rename_to": "CLoopModeGame_OnServerBeginSimulate",
    },
    {
        "target_name": "CLoopModeGame_OnServerPostSimulate",
        "event_name": "CLoopModeGame::OnServerPostSimulate",
        "rename_to": "CLoopModeGame_OnServerPostSimulate",
    },
    {
        "target_name": "CLoopModeGame_OnServerPostAdvanceTick",
        "event_name": "CLoopModeGame::OnServerPostAdvanceTick",
        "rename_to": "CLoopModeGame_OnServerPostAdvanceTick",
    },
    {
        "target_name": "CLoopModeGame_OnServerBeginAsyncPostTickWork",
        "event_name": "CLoopModeGame::OnServerBeginAsyncPostTickWork",
        "rename_to": "CLoopModeGame_OnServerBeginAsyncPostTickWork",
    },
    {
        "target_name": "CLoopModeGame_OnServerEndAsyncPostTickWork",
        "event_name": "CLoopModeGame::OnServerEndAsyncPostTickWork",
        "rename_to": "CLoopModeGame_OnServerEndAsyncPostTickWork",
    },
    {
        "target_name": "CLoopModeGame_OnFrameBoundary",
        "event_name": "CLoopModeGame::OnFrameBoundary",
        "rename_to": "CLoopModeGame_OnFrameBoundary",
    },
]

_COMMON_GENERATE_FIELDS = [
    "func_name",
    "func_sig",
    "func_va",
    "func_rva",
    "func_size",
]

GENERATE_YAML_DESIRED_FIELDS = [
    (REGISTER_FUNC_TARGET_NAME, _COMMON_GENERATE_FIELDS),
    *[(target_spec["target_name"], _COMMON_GENERATE_FIELDS) for target_spec in TARGET_SPECS],
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
    """Resolve RegisterEventListener_Abstract callbacks and write YAML outputs."""
    _ = skill_name, old_yaml_map
    return await preprocess_register_event_listener_abstract_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        source_yaml_stem=SOURCE_YAML_STEM,
        register_func_target_name=REGISTER_FUNC_TARGET_NAME,
        anchor_event_name=ANCHOR_EVENT_NAME,
        target_specs=TARGET_SPECS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        search_window_after_anchor=SEARCH_WINDOW_AFTER_ANCHOR,
        search_window_before_call=SEARCH_WINDOW_BEFORE_CALL,
        debug=debug,
    )
