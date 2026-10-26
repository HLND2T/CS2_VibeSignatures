#!/usr/bin/env python3
"""Find ICvar_UnregisterConCommandCallbacks by decompiling ConCommand_Destroy."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["ICvar_UnregisterConCommandCallbacks"]

LLM_DECOMPILE = [
    {
        "symbol_name": "ICvar_UnregisterConCommandCallbacks",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/client/ConCommand_Destroy.{platform}.yaml"],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {"ConCommand_Destroy.{platform}.yaml": "required"},
    },
]

FUNC_VTABLE_RELATIONS = [("ICvar_UnregisterConCommandCallbacks", "ICvar")]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "ICvar_UnregisterConCommandCallbacks",
        [
            "func_name",
            "vfunc_sig",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
            # Linux ConCommand_Destroy tail-dispatches the vfunc (mov rdx,[rdx+158h]; jmp rdx),
            # so anchor the signature on the mov instead of a call instruction.
            "vfunc_sig_allow_across_function_boundary:true",
        ],
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
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
