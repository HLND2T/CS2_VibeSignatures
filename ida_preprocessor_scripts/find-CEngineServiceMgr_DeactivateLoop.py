#!/usr/bin/env python3
"""Preprocess script for find-CEngineServiceMgr_DeactivateLoop skill."""

from ida_analyze_util import (
    _load_llm_decompile_target_detail_via_mcp,
    preprocess_common_skill,
)

TARGET_FUNCTION_NAMES = [
    "CEngineServiceMgr_DeactivateLoop",
]

LLM_DECOMPILE = [
    (
        "CEngineServiceMgr_DeactivateLoop",
        "prompt/call_llm_decompile.md",
        "references/engine/CEngineServiceMgr__MainLoop.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CEngineServiceMgr_DeactivateLoop",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
]

INLINE_SEQUENCE_MARKERS = (
    "LoopDeactivate",
    "DeallocateLoopMode",
)


def _looks_like_inlined_deactivate_loop(detail):
    if not isinstance(detail, dict):
        return False

    joined = "\n".join(
        [
            str(detail.get("disasm_code", "") or ""),
            str(detail.get("procedure", "") or ""),
        ]
    )
    return (
        "CEngineServiceMgr_DeactivateLoop" not in joined
        and all(marker in joined for marker in INLINE_SEQUENCE_MARKERS)
    )

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
    success = await preprocess_common_skill(
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
    if success:
        return True

    mainloop_detail = await _load_llm_decompile_target_detail_via_mcp(
        session,
        "CEngineServiceMgr__MainLoop",
        new_binary_dir=new_binary_dir,
        platform=platform,
        debug=debug,
    )
    if _looks_like_inlined_deactivate_loop(mainloop_detail):
        return "absent_ok"
    return False
