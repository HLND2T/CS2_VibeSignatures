"""Find the ICvar filter virtual dispatch in its ordinary engine wrapper."""

from ida_preprocessor_scripts._convar_filter_chain_common import preprocess_call_chain

TARGET_FUNCTION_NAMES = ["ICvar_CallFilterCallback"]
LLM_DECOMPILE = [
    {
        "symbol_name": "ICvar_CallFilterCallback",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/engine/ConVarRefAbstract_CallFilterCallback.{platform}.yaml"],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {"ConVarRefAbstract_CallFilterCallback.{platform}.yaml": "required"},
    }
]
FUNC_VTABLE_RELATIONS = [("ICvar_CallFilterCallback", "ICvar")]
GENERATE_YAML_DESIRED_FIELDS = [
    ("ICvar_CallFilterCallback", ["func_name", "vtable_name", "vfunc_offset", "vfunc_index", "vfunc_sig"])
]


def validate_dispatch(result):
    entries = [entry for entry in result.get("found_vcall", []) if entry.get("func_name") == TARGET_FUNCTION_NAMES[0]]
    slots = {str(entry.get("vfunc_offset")) for entry in entries}
    return ["Ambiguous ICvar filter callback slots"] if len(slots) > 1 else []


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
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        llm_result_validator=validate_dispatch,
        debug=debug,
    )
