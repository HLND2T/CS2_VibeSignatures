#!/usr/bin/env python3
"""Preprocess script for find-CServerSideClientBase_dtor-decompiles skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "ISource2GameClients_ClientSetConVarUserInfoSet",
    "ICvar_CopyUserInfoCvarDefaults",
]

# Windows: the SetConVarUserInfo body (and with it the
# ISource2GameClients::ClientSetConVarUserInfoSet vcall) is inlined directly
# into CServerSideClientBase::~CServerSideClientBase, so the vcall lives in the
# destructor's own body -- decompile the destructor.
LLM_DECOMPILE_WINDOWS = [
    {
        "symbol_name": "ISource2GameClients_ClientSetConVarUserInfoSet",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CServerSideClientBase_dtor.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CServerSideClientBase_dtor.{platform}.yaml": "required",
        },
    },
]

# Linux: that same body is emitted as a shared out-of-line helper
# (CServerSideClientBase_SetConVarUserInfo), so the vcall is NOT present in the
# destructor's own body -- decompile the helper instead.
LLM_DECOMPILE_LINUX = [
    {
        "symbol_name": "ISource2GameClients_ClientSetConVarUserInfoSet",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CServerSideClientBase_SetConVarUserInfo.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CServerSideClientBase_SetConVarUserInfo.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [
    ("ICvar_CopyUserInfoCvarDefaults", "ICvar"),
    # ISource2GameClients is abstract; this relation supplies vtable metadata only.
    ("ISource2GameClients_ClientSetConVarUserInfoSet", "ISource2GameClients"),
]

# Slim Pattern C: ISource2GameClients is an abstract interface class with no
# concrete body in engine to sign, and it is not a downstream predecessor.
#
# Windows: the ClientSetConVarUserInfoSet dispatch inlined into the destructor
# is a normal `call qword ptr [rax+90h]` (FF 90 90 00 00 00); the 6-byte vcall
# plus a couple of trailing instructions is uniquely signable on its own.
GENERATE_YAML_DESIRED_FIELDS_WINDOWS = [
    (
        "ISource2GameClients_ClientSetConVarUserInfoSet",
        [
            "func_name",
            "vfunc_sig",  # REQUIRED for Pattern C
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
]

# Linux: the dispatch is TAIL-CALL OPTIMIZED -- `mov rax, [rax+90h]`
# (48 8B 80 90 00 00 00) followed by the epilogue and `jmp rax`. The load
# instruction that encodes the 0x90 slot displacement sits just before the
# function's internal `align` gap, so linear signature collection stops at that
# gap and the ~19-byte prefix (mov + standard epilogue + jmp rax) is not unique.
# Allow the vfunc_sig to bridge the internal CC/NOP align gap and continue into
# the tail block (loc: `call qword ptr [rax+20h]` ...) to reach uniqueness.
GENERATE_YAML_DESIRED_FIELDS_LINUX = [
    (
        "ISource2GameClients_ClientSetConVarUserInfoSet",
        [
            "func_name",
            "vfunc_sig",  # REQUIRED for Pattern C
            "vfunc_sig_allow_across_function_boundary:True",
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
    """Resolve the client user-info and ICvar defaults dispatches from the platform predecessor."""
    llm_decompile = LLM_DECOMPILE_WINDOWS if platform == "windows" else LLM_DECOMPILE_LINUX
    llm_decompile = list(llm_decompile)
    predecessor = "CServerSideClientBase_dtor" if platform == "windows" else "CServerSideClientBase_SetConVarUserInfo"
    llm_decompile.append(
        {
            "symbol_name": "ICvar_CopyUserInfoCvarDefaults",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": [f"references/engine/{predecessor}.{{platform}}.yaml"],
            "expected_result_sections": ["found_vcall"],
            "dependency_policy": {f"{predecessor}.{{platform}}.yaml": "required"},
        }
    )
    generate_yaml_desired_fields = (
        GENERATE_YAML_DESIRED_FIELDS_WINDOWS if platform == "windows" else GENERATE_YAML_DESIRED_FIELDS_LINUX
    )
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=llm_decompile,
        llm_config=llm_config,
        generate_yaml_desired_fields=list(generate_yaml_desired_fields)
        + [
            (
                "ICvar_CopyUserInfoCvarDefaults",
                ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"],
            ),
        ],
        debug=debug,
    )
