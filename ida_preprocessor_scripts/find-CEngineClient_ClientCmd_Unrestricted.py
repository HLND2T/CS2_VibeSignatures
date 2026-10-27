#!/usr/bin/env python3
"""Preprocess script for find-CEngineClient_ClientCmd_Unrestricted skill.

Resolves the engine's ``ClientCommand`` override, which the artifact key still
spells ``ClientCmd_Unrestricted``. It wraps a non-NAN input time in
``__beginseq``/``__endseq`` and sends the ``"%s\\n"`` text, matching the SDK's
ClientCommand rather than an unrestricted command path.
"""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = [
    "CEngineClient_ClientCmd_Unrestricted",
]

# The artifact key is historical; the body matches the SDK's ClientCommand.
OUTPUT_NAME_MAP = {
    "CEngineClient_ClientCmd_Unrestricted": "CEngineClient_ClientCommand",
}

FUNC_XREFS = [
    {
        "func_name": "CEngineClient_ClientCmd_Unrestricted",
        "xref_strings": [
            "FULLMATCH:__beginseq",
            "FULLMATCH:__endseq",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [
            "CInputService_ProcessCommandBuffer",
            "CInputService_ProcessCommandBuffers",
            "CInputService_HandleAnalogValueChange",
            "CInputService_HandleInputEvent",
        ],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [
    ("CEngineClient_ClientCmd_Unrestricted", "CEngineClient_vtable"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CEngineClient_ClientCmd_Unrestricted",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
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
    debug=False,
):
    """Reuse previous gamever func_sig to locate CEngineClient::ClientCommand."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
        output_name_map=OUTPUT_NAME_MAP,
    )
