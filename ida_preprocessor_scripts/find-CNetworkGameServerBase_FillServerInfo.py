#!/usr/bin/env python3
"""Preprocess script for find-CNetworkGameServerBase_FillServerInfo skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkGameServerBase_FillServerInfo",
]

# CServerSideClientBase::SendServerInfo populates its CSVCMsg_ServerInfo_t via a
# single virtual call on its CNetworkGameServer (m_pServer at this+80):
#   (*(server->vtable + 0x250))(server, &serverInfoMsg)  // FillServerInfo
# right before serializing CSVCMsg_ServerInfo_t. Decompile that predecessor and
# take the vcall whose argument is the CSVCMsg_ServerInfo_t being filled.
LLM_DECOMPILE = [
    {
        "symbol_name": "CNetworkGameServerBase_FillServerInfo",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CServerSideClientBase_SendServerInfo.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CServerSideClientBase_SendServerInfo.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CNetworkGameServerBase_FillServerInfo", "CNetworkGameServer"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # Standard Pattern C: FillServerInfo has a real body worth signing.
    # vfunc_sig is MANDATORY for Pattern C.
    (
        "CNetworkGameServerBase_FillServerInfo",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
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
    """Resolve the CNetworkGameServerBase FillServerInfo slot from the SendServerInfo predecessor."""
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
