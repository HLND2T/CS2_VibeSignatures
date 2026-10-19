#!/usr/bin/env python3
"""Find the integer ParmValue slot used by VScript CommandLineInt."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["ICommandLine_ParmValue_Int"]
LLM_DECOMPILE = [
    {
        "symbol_name": "ICommandLine_ParmValue_Int",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/server/Script_CommandLineInt.{platform}.yaml"],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {"Script_CommandLineInt.{platform}.yaml": "required"},
    },
]
FUNC_VTABLE_RELATIONS = [("ICommandLine_ParmValue_Int", "ICommandLine")]
GENERATE_YAML_DESIRED_FIELDS = [
    ("ICommandLine_ParmValue_Int", ["func_name", "vtable_name", "vfunc_offset", "vfunc_index", "vfunc_sig"]),
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
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
