#!/usr/bin/env python3
"""Find ICvar_RemoveGlobalChangeCallback by decompiling its predecessor chain."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["ICvar_RemoveGlobalChangeCallback"]
# Follow the predecessor across inline/de-inline builds.
LLM_DECOMPILE = [
    {
        "symbol_name": "ICvar_RemoveGlobalChangeCallback",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/server/CCommentarySystem_Shutdown_Impl.{platform}.yaml"],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {"CCommentarySystem_Shutdown_Impl.{platform}.yaml": "required"},
    }
]
FUNC_VTABLE_RELATIONS = [("ICvar_RemoveGlobalChangeCallback", "ICvar")]
GENERATE_YAML_DESIRED_FIELDS = [
    ("ICvar_RemoveGlobalChangeCallback", ["func_name", "vfunc_sig", "vtable_name", "vfunc_offset", "vfunc_index"])
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
