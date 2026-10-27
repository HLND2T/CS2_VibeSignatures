#!/usr/bin/env python3
"""Find ICvar_GetConCommandData by decompiling its predecessor CCvar_FindConCommand."""

from ida_preprocessor_scripts._llm_helper_chain_common import make_helper_loader, preprocess_call_chain

load_helper_details = make_helper_loader("CCvar_FindConCommand_helper")

TARGET_FUNCTION_NAMES = ["ICvar_GetConCommandData"]
# Follow the predecessor across inline/de-inline builds.
LLM_DECOMPILE = [
    {
        "symbol_name": "ICvar_GetConCommandData",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/tier0/CCvar_FindConCommand.{platform}.yaml"],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {"CCvar_FindConCommand.{platform}.yaml": "required"},
    }
]
FUNC_VTABLE_RELATIONS = [("ICvar_GetConCommandData", "ICvar")]
GENERATE_YAML_DESIRED_FIELDS = [
    ("ICvar_GetConCommandData", ["func_name", "vfunc_sig", "vtable_name", "vfunc_offset", "vfunc_index"])
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
    return await preprocess_call_chain(
        helper_loader=load_helper_details,
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
