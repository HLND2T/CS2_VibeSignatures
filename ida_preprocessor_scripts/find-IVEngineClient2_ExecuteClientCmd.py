#!/usr/bin/env python3
"""Preprocess script for find-IVEngineClient2_ExecuteClientCmd skill.

Resolves the interface's ``ServerCmd( CSplitScreenSlot, const char * )`` slot,
which the artifact key still spells ``ExecuteClientCmd``.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "IVEngineClient2_ExecuteClientCmd",
]

# The artifact key is historical; the slot sends the command to the server.
OUTPUT_NAME_MAP = {
    "IVEngineClient2_ExecuteClientCmd": "IVEngineClient2_ServerCmd",
}

LLM_DECOMPILE = [
    {
        "symbol_name": "IVEngineClient2_ExecuteClientCmd",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/client/CMapAnNodeManager_FireGameEvent.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CMapAnNodeManager_FireGameEvent.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # IVEngineClient2 is abstract; this relation supplies vtable metadata only.
    ("IVEngineClient2_ExecuteClientCmd", "IVEngineClient2"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "IVEngineClient2_ExecuteClientCmd",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
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
    llm_config=None,
    debug=False,
):
    """Resolve the IVEngineClient2 ServerCmd slot from FireGameEvent."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
        output_name_map=OUTPUT_NAME_MAP,
    )
