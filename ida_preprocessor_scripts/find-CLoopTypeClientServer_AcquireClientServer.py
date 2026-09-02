"""Find the Linux-only client/server acquire helper split out of the status update.

On Windows the client and server pointers are acquired inline inside
CLoopTypeClientServer::UpdateClientServerStatus, so INetworkGameServer::AddRef is
reachable directly from that function. On Linux the compiler moved the whole
acquire block into a separate function that UpdateClientServerStatus calls, so the
AddRef vcall is not present in the parent at all. Naming that helper here gives
find-CLoopTypeClientServer_UpdateClientServerStatus-decompiles a Linux predecessor
to anchor AddRef on (mirrors find-CLoopModeGame_LoopInitInternal).
"""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = [
    "CLoopTypeClientServer_AcquireClientServer",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CLoopTypeClientServer_AcquireClientServer",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CLoopTypeClientServer_UpdateClientServerStatus.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {
            "CLoopTypeClientServer_UpdateClientServerStatus.{platform}.yaml": "required",
        },
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CLoopTypeClientServer_AcquireClientServer",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
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
    """Resolve the direct acquire-helper call in the status update helper."""
    _ = skill_name
    return await preprocess_common_skill(
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
