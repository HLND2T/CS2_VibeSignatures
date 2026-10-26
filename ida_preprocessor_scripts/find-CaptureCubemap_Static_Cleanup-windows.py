#!/usr/bin/env python3
"""Find CaptureCubemap_Static_Cleanup by decompiling CaptureCubemap_Static_Init."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CaptureCubemap_Static_Cleanup"]

LLM_DECOMPILE = [
    {
        "symbol_name": "CaptureCubemap_Static_Cleanup",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/client/CaptureCubemap_Static_Init.windows.yaml"],
        "expected_result_sections": ["found_funcptr"],
        "dependency_policy": {"CaptureCubemap_Static_Init.windows.yaml": "required"},
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # Include func_va/func_rva/func_size: this function is a predecessor for downstream LLM_DECOMPILE
    (
        "CaptureCubemap_Static_Cleanup",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
    ),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, llm_config=None, debug=False
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
