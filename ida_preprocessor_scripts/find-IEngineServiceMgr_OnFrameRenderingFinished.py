#!/usr/bin/env python3
"""Preprocess script for find-IEngineServiceMgr_OnFrameRenderingFinished skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "IEngineServiceMgr_OnFrameRenderingFinished",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "IEngineServiceMgr_OnFrameRenderingFinished",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CRenderService_OnClientOutput.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CRenderService_OnClientOutput.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # IEngineServiceMgr is an abstract interface; vtable_name is metadata only.
    ("IEngineServiceMgr_OnFrameRenderingFinished", "IEngineServiceMgr"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "IEngineServiceMgr_OnFrameRenderingFinished",
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
    """Find the IEngineServiceMgr::OnFrameRenderingFinished slot from render output."""
    _ = skill_name
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
    )
