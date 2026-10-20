"""Find the FreeEvent virtual dispatch in FireEvent or its de-inlined helpers."""

from ida_preprocessor_scripts._llm_helper_chain_common import make_helper_loader, preprocess_call_chain

load_helper_details = make_helper_loader("GameEvent_helper")

TARGET_FUNCTION_NAMES = ["IGameEventManager2_FreeEvent"]
LLM_DECOMPILE = [
    {
        "symbol_name": "IGameEventManager2_FreeEvent",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/server/CGameEventManager_FireEvent.{platform}.yaml"],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {"CGameEventManager_FireEvent.{platform}.yaml": "required"},
    }
]
FUNC_VTABLE_RELATIONS = [("IGameEventManager2_FreeEvent", "IGameEventManager2")]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "IGameEventManager2_FreeEvent",
        [
            "func_name",
            "vtable_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            # The FreeEvent vcall sits at the end of FireEvent's inline body and
            # only stays unique when the signature may bridge into padding.
            "vfunc_sig_allow_across_function_boundary:true",
        ],
    )
]


def validate_dispatch(result):
    entries = [entry for entry in result.get("found_vcall", []) if entry.get("func_name") == TARGET_FUNCTION_NAMES[0]]
    offsets = {int(str(entry["vfunc_offset"]), 0) for entry in entries}
    return ["Ambiguous FreeEvent virtual dispatch slots"] if len(offsets) > 1 else []


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
        llm_result_validator=validate_dispatch,
        debug=debug,
    )
