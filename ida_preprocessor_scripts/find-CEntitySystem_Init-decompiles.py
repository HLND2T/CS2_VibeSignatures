#!/usr/bin/env python3
"""Preprocess script for find-CEntitySystem_Init-decompiles skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "INetworkMessages_SetNetworkSerializationContextData",
    "IFlattenedSerializers_CreateFieldChangedEventQueue",
]

TARGET_STRUCT_MEMBER_NAMES = [
    "CEntitySystem_m_sEntSystemName",
    "CEntitySystem_m_eNetworkSerializationMode",
    "CEntitySystem_m_Symbols",
    "CEntitySystem_m_pNetworkFieldChangedEventQueue",
    "CEntitySystem_m_pNetworkFieldScratchData",
    "CEntitySystem_m_pFieldChangeLimitSpew",
    "CEntitySystem_m_ComponentUnserializerInfoAllocator",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "INetworkMessages_SetNetworkSerializationContextData",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_Init.{platform}.yaml",
    ),
    (
        "IFlattenedSerializers_CreateFieldChangedEventQueue",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_Init.{platform}.yaml",
    ),
    (
        "CEntitySystem_m_sEntSystemName",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_Init.{platform}.yaml",
    ),
    (
        "CEntitySystem_m_eNetworkSerializationMode",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_Init.{platform}.yaml",
    ),
    (
        "CEntitySystem_m_Symbols",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_Init.{platform}.yaml",
    ),
    (
        "CEntitySystem_m_pNetworkFieldChangedEventQueue",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_Init.{platform}.yaml",
    ),
    (
        "CEntitySystem_m_pNetworkFieldScratchData",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_Init.{platform}.yaml",
    ),
    (
        "CEntitySystem_m_pNetworkFieldScratchData",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_Init.{platform}.yaml",
    ),
    (
        "CEntitySystem_m_ComponentUnserializerInfoAllocator",
        "prompt/call_llm_decompile.md",
        "references/server/CEntitySystem_Init.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("INetworkMessages_SetNetworkSerializationContextData", "INetworkMessages"),
    ("IFlattenedSerializers_CreateFieldChangedEventQueue", "IFlattenedSerializers"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "INetworkMessages_SetNetworkSerializationContextData",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "IFlattenedSerializers_CreateFieldChangedEventQueue",
        [
            "func_name",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
    (
        "CEntitySystem_m_sEntSystemName",
        [
            "struct_name",
            "member_name",
            "offset",
            #"size",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
    (
        "CEntitySystem_m_eNetworkSerializationMode",
        [
            "struct_name",
            "member_name",
            "offset",
            #"size",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
    (
        "CEntitySystem_m_Symbols",
        [
            "struct_name",
            "member_name",
            "offset",
            #"size",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
    (
        "CEntitySystem_m_pNetworkFieldChangedEventQueue",
        [
            "struct_name",
            "member_name",
            "offset",
            #"size",
            "offset_sig",
            "offset_sig_disp",
            #"offset_sig_max_match:2",
            "offset_sig_allow_across_function_boundary:true",
        ],
    ),
    (
        "CEntitySystem_m_pNetworkFieldScratchData",
        [
            "struct_name",
            "member_name",
            "offset",
            #"size",
            "offset_sig",
            "offset_sig_disp",
            #"offset_sig_max_match:2",
            "offset_sig_allow_across_function_boundary:true",
        ],
    ),
    (
        "CEntitySystem_m_pFieldChangeLimitSpew",
        [
            "struct_name",
            "member_name",
            "offset",
            #"size",
            "offset_sig",
            "offset_sig_disp",
            #"offset_sig_max_match:2",
            "offset_sig_allow_across_function_boundary:true",
        ],
    ),
    (
        "CEntitySystem_m_ComponentUnserializerInfoAllocator",
        [
            "struct_name",
            "member_name",
            "offset",
            #"size",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Locate vfuncs and struct member offsets from CEntitySystem_Init via LLM decompile."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
