#!/usr/bin/env python3
"""Find IGameEventSystem::PostEventAbstract_Local from its concrete caller."""

from ida_preprocessor_scripts._llm_helper_chain_common import preprocess_call_chain

TARGET_FUNCTION_NAMES = ["IGameEventSystem_PostEventAbstract_Local"]

LLM_DECOMPILE = [
    {
        "symbol_name": "IGameEventSystem_PostEventAbstract_Local",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CGameEventSystem_PostEventAbstract2.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CGameEventSystem_PostEventAbstract2.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    ("IGameEventSystem_PostEventAbstract_Local", "IGameEventSystem"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "IGameEventSystem_PostEventAbstract_Local",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
]


def validate_dispatch(result):
    entries = [entry for entry in result.get("found_vcall", []) if entry.get("func_name") == TARGET_FUNCTION_NAMES[0]]
    offsets = {int(str(entry["vfunc_offset"]), 0) for entry in entries}
    return ["Ambiguous PostEventAbstract_Local virtual dispatch slots"] if len(offsets) > 1 else []


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
    """Resolve the interface slot, including inline and de-inlined caller paths."""
    _ = skill_name
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
