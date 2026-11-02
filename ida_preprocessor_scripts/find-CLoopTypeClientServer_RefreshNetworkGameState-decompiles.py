#!/usr/bin/env python3
"""Identify INetworkGameServer Release/AddRef vcalls in RefreshNetworkGameState.

Release is always called directly from RefreshNetworkGameState. AddRef is inlined
into it on some builds (Windows) and de-inlined into a helper on others (Linux);
select the AddRef predecessor by whether the optional helper artifact exists.
"""

from pathlib import Path

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["INetworkGameServer_Release", "INetworkGameServer_AddRef"]
REFRESH_REFERENCE = "references/engine/CLoopTypeClientServer_RefreshNetworkGameState.{platform}.yaml"
ACQUIRE_REFERENCE = "references/engine/CLoopTypeClientServer_RefreshNetworkGameState_Acquire.linux.yaml"


def _spec(symbol_name, reference, dependency, policy):
    return {
        "symbol_name": symbol_name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [reference],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {dependency: policy},
    }


FUNC_VTABLE_RELATIONS = [
    # INetworkGameServer is an abstract interface; vtable_name is metadata only.
    ("INetworkGameServer_Release", "INetworkGameServer"),
    ("INetworkGameServer_AddRef", "INetworkGameServer"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "INetworkGameServer_Release",
        ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"],
    ),
    (
        "INetworkGameServer_AddRef",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
            # De-inlined AddRef is a tail-dispatched `mov rax,[rax+disp8]` / `jmp rax`
            # whose signature can only be made unique across the function boundary.
            "vfunc_sig_allow_across_function_boundary:true",
        ],
    ),
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
    helper = Path(new_binary_dir) / f"CLoopTypeClientServer_RefreshNetworkGameState_Acquire.{platform}.yaml"
    refresh_dep = "CLoopTypeClientServer_RefreshNetworkGameState.{platform}.yaml"
    llm_specs = [_spec("INetworkGameServer_Release", REFRESH_REFERENCE, refresh_dep, "required")]
    if helper.is_file():
        llm_specs.append(
            _spec(
                "INetworkGameServer_AddRef",
                ACQUIRE_REFERENCE,
                "CLoopTypeClientServer_RefreshNetworkGameState_Acquire.{platform}.yaml",
                "optional",
            )
        )
    else:
        llm_specs.append(_spec("INetworkGameServer_AddRef", REFRESH_REFERENCE, refresh_dep, "required"))
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=llm_specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
