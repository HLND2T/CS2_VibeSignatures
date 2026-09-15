#!/usr/bin/env python3
"""Recover ReplyChallenge's server and network-system virtual calls."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CNetworkGameServerBase_GetChallengeType", "INetworkSystem_GetSteamNetworkingSockets"]
LLM_DECOMPILE = [
    {"symbol_name": "CNetworkGameServerBase_GetChallengeType", "prompt_path": "prompt/call_llm_decompile.md", "reference_yaml_paths": ["references/engine/CNetworkGameServerBase_ReplyChallenge.{platform}.yaml"], "expected_result_sections": ["found_vcall"], "dependency_policy": {"CNetworkGameServerBase_ReplyChallenge.{platform}.yaml": "required"}},
    {"symbol_name": "INetworkSystem_GetSteamNetworkingSockets", "prompt_path": "prompt/call_llm_decompile.md", "reference_yaml_paths": ["references/engine/CNetworkGameServerBase_ReplyChallenge.{platform}.yaml"], "expected_result_sections": ["found_vcall"], "dependency_policy": {"CNetworkGameServerBase_ReplyChallenge.{platform}.yaml": "required"}},
]
FUNC_VTABLE_RELATIONS = [("CNetworkGameServerBase_GetChallengeType", "CNetworkGameServerBase"), ("INetworkSystem_GetSteamNetworkingSockets", "INetworkSystem")]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CNetworkGameServerBase_GetChallengeType", ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"]),
    ("INetworkSystem_GetSteamNetworkingSockets", ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"]),
]

async def preprocess_skill(session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, llm_config=None, debug=False):
    _ = skill_name
    return await preprocess_common_skill(session=session, expected_outputs=expected_outputs, old_yaml_map=old_yaml_map, new_binary_dir=new_binary_dir, platform=platform, image_base=image_base, func_names=TARGET_FUNCTION_NAMES, func_vtable_relations=FUNC_VTABLE_RELATIONS, llm_decompile_specs=LLM_DECOMPILE, llm_config=llm_config, generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS, debug=debug)
