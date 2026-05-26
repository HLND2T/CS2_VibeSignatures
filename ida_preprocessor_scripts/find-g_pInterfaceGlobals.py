#!/usr/bin/env python3
"""Preprocess script for find-g_pInterfaceGlobals skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_GLOBALVAR_NAMES = [
    "g_pInterfaceGlobals",
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "g_pInterfaceGlobals",
        [
            "gv_name",
            "gv_va",
            "gv_rva",
            "gv_sig",
            "gv_sig_va",
            "gv_inst_offset",
            "gv_inst_length",
            "gv_inst_disp",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever gv_sig; fallback to LLM_DECOMPILE of ConnectInterfaces."""
    llm_decompile = [
        (
            "g_pInterfaceGlobals",
            "prompt/call_llm_decompile.md",
            "references/{module_name}/ConnectInterfaces.{platform}.yaml",
        ),
    ]

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=TARGET_GLOBALVAR_NAMES,
        llm_decompile_specs=llm_decompile,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
