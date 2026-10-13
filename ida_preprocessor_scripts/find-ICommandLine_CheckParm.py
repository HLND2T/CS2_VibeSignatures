#!/usr/bin/env python3
"""Identify the ICommandLine::CheckParm virtual dispatch in CCSBotManager::StartFrame."""

from pathlib import Path

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["ICommandLine_CheckParm"]
LLM_DECOMPILE = [
    {
        "symbol_name": "ICommandLine_CheckParm",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/server/CCSBotManager_StartFrame.windows.yaml"],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {"CCSBotManager_StartFrame.{platform}.yaml": "required"},
    },
]
FUNC_VTABLE_RELATIONS = [("ICommandLine_CheckParm", "ICommandLine")]
GENERATE_YAML_DESIRED_FIELDS = [
    ("ICommandLine_CheckParm", ["func_name", "vtable_name", "vfunc_offset", "vfunc_index", "vfunc_sig"]),
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
    # The command-line gate is inlined on Windows 14190 and separate on Linux.
    # Select by the current artifact closure, rather than fixing a platform/slot.
    helper = Path(new_binary_dir) / f"CCSBotManager_StartFrame_ShouldUpdate.{platform}.yaml"
    llm_specs = LLM_DECOMPILE
    if helper.is_file():
        llm_specs = [
            {
                "symbol_name": "ICommandLine_CheckParm",
                "prompt_path": "prompt/call_llm_decompile.md",
                "reference_yaml_paths": ["references/server/CCSBotManager_StartFrame_ShouldUpdate.linux.yaml"],
                "expected_result_sections": ["found_vcall"],
                "dependency_policy": {"CCSBotManager_StartFrame_ShouldUpdate.{platform}.yaml": "optional"},
            },
        ]
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=llm_specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
