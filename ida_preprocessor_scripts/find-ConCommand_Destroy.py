#!/usr/bin/env python3
"""Find ConCommand_Destroy via the Capture Cubemap static cleanup chain."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["ConCommand_Destroy"]

# The cleanup gate is a separate function on Windows and inlined into the
# static initializer on Linux. Select the reference by platform.
_WINDOWS_REFERENCE = "references/client/CaptureCubemap_Static_Cleanup.windows.yaml"
_LINUX_REFERENCE = "references/client/Global_Static_Init.linux.yaml"


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
    if platform == "windows":
        reference = _WINDOWS_REFERENCE
        dependency = "CaptureCubemap_Static_Cleanup.{platform}.yaml"
        # Windows: the cleanup gate tail-jumps to ConCommand_Destroy.
        expected_sections = ["found_call"]
    else:
        reference = _LINUX_REFERENCE
        dependency = "Global_Static_Init.{platform}.yaml"
        # Linux: ConCommand_Destroy is passed as a function pointer to __cxa_atexit.
        expected_sections = ["found_funcptr"]

    llm_decompile_specs = [
        {
            "symbol_name": "ConCommand_Destroy",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": [reference],
            "expected_result_sections": expected_sections,
            "dependency_policy": {dependency: "required"},
        },
    ]
    generate_yaml_desired_fields = [
        # (symbol_name, generate_yaml_fields)
        # Include func_va/func_rva/func_size: this function is a predecessor for downstream LLM_DECOMPILE
        (
            "ConCommand_Destroy",
            ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
        ),
    ]
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        llm_decompile_specs=llm_decompile_specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=generate_yaml_desired_fields,
        debug=debug,
    )
