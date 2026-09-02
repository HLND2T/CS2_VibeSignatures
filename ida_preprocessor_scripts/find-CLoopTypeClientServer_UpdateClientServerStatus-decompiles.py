"""Find INetworkGameServer reference-count vfunc slots from the status helper.

The refcount calls in CLoopTypeClientServer::UpdateClientServerStatus are
indirect vcalls through an INetworkGameServer*, so the slots belong to the
abstract interface; the concrete CNetworkGameServerBase overrides are resolved
downstream by find-CNetworkGameServerBase_AddRef / _Release via INHERIT_VFUNCS
(mirrors find-INetworkGameServer_ServerAdvanceTick).

Release is reachable from UpdateClientServerStatus on both platforms. AddRef is
not: on Windows the acquire block is inlined into UpdateClientServerStatus, while
on Linux the compiler split it into a separate helper that UpdateClientServerStatus
merely calls, so the AddRef vcall is absent from the parent there. The reference
func_name drives which function is decompiled in the new binary, so each platform
points AddRef at its own predecessor (mirrors find-CLoopModeGame_LoopInit-decompiles).

Output is slot-only: the Linux AddRef callsite is a tail-dispatched
``mov rax, [rax+28h]`` / ``jmp rax`` pair that yields no unique vfunc_sig.
"""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = [
    "INetworkGameServer_AddRef",
    "INetworkGameServer_Release",
]


def _release_spec():
    return {
        "symbol_name": "INetworkGameServer_Release",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CLoopTypeClientServer_UpdateClientServerStatus.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CLoopTypeClientServer_UpdateClientServerStatus.{platform}.yaml": "required",
        },
    }


LLM_DECOMPILE_WINDOWS = [
    {
        "symbol_name": "INetworkGameServer_AddRef",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CLoopTypeClientServer_UpdateClientServerStatus.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CLoopTypeClientServer_UpdateClientServerStatus.{platform}.yaml": "required",
        },
    },
    _release_spec(),
]

LLM_DECOMPILE_LINUX = [
    {
        "symbol_name": "INetworkGameServer_AddRef",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CLoopTypeClientServer_AcquireClientServer.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CLoopTypeClientServer_AcquireClientServer.{platform}.yaml": "required",
        },
    },
    _release_spec(),
]

FUNC_VTABLE_RELATIONS = [
    # INetworkGameServer is an abstract interface -- no vtable YAML is needed;
    # the vtable name is metadata only.
    ("INetworkGameServer_AddRef", "INetworkGameServer"),
    ("INetworkGameServer_Release", "INetworkGameServer"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields) -- slot-only output for an abstract interface vfunc
    (
        "INetworkGameServer_AddRef",
        [
            "func_name",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
        ],
    ),
    (
        "INetworkGameServer_Release",
        [
            "func_name",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
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
    """Resolve the AddRef and Release interface slots from the platform's predecessor."""
    _ = skill_name
    llm_decompile_specs = LLM_DECOMPILE_LINUX if platform == "linux" else LLM_DECOMPILE_WINDOWS
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=llm_decompile_specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
