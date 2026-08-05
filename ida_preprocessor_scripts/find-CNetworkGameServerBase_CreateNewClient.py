#!/usr/bin/env python3
"""Preprocess script for find-CNetworkGameServerBase_CreateNewClient skill.

CNetworkGameServerBase::CreateNewClient is a virtual function with no
identifying debug string of its own. It is located as the virtual call made on
`this` inside CNetworkGameServer::GetFreeClient's create path
(CNetworkGameServer_GetFreeClientCreatePath): the call whose result is
initialized with the client-slot netadr fields (offsets +204/+220/+236/+252).
Windows resolves to CNetworkGameServer vtable offset 0x278 (index 79); Linux to
offset 0x2A0 (index 84).
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "CNetworkGameServerBase_CreateNewClient",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CNetworkGameServerBase_CreateNewClient",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CNetworkGameServer_GetFreeClientCreatePath.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CNetworkGameServer_GetFreeClientCreatePath.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("CNetworkGameServerBase_CreateNewClient", "CNetworkGameServer"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "CNetworkGameServerBase_CreateNewClient",
        [
            "func_name",
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
    """Locate the CreateNewClient virtual call inside the GetFreeClient create path."""
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
