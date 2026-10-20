"""Find the filter callback wrapper called by the integer ConVar setter."""

from ida_preprocessor_scripts._convar_filter_chain_common import preprocess_call_chain

TARGET_FUNCTION_NAMES = ["ConVarRefAbstract_CallFilterCallback"]
LLM_DECOMPILE = [
    {
        "symbol_name": "ConVarRefAbstract_CallFilterCallback",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/engine/CConVarRef_Int_Set.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"CConVarRef_Int_Set.{platform}.yaml": "required"},
    }
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("ConVarRefAbstract_CallFilterCallback", ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
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
