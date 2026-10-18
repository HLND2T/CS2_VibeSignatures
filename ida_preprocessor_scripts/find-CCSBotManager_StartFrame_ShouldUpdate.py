#!/usr/bin/env python3
"""Resolve the optional standalone command-line gate used by StartFrame.

On inlined builds no helper is required; the CheckParm finder reads StartFrame
itself. This optional producer supplies the predecessor on de-inlined builds.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CCSBotManager_StartFrame_ShouldUpdate"]
LLM_DECOMPILE = [
    {
        "symbol_name": "CCSBotManager_StartFrame_ShouldUpdate",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/server/CCSBotManager_StartFrame.linux.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"CCSBotManager_StartFrame.{platform}.yaml": "required"},
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CCSBotManager_StartFrame_ShouldUpdate", ["func_name", "func_va", "func_rva", "func_size", "func_sig"]),
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
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
