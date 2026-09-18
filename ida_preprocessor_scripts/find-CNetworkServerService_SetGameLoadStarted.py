#!/usr/bin/env python3
"""Preprocess the concrete CNetworkServerService SetGameLoadStarted slot.

CLoopTypeSimpleService calls INetworkServerService::SetGameLoadStarted through
the secondary interface vtable at slot 2. The source-owned symbol describes the
concrete CNetworkServerService primary-vtable ABI slot verified by cpp_tests,
which is slot 37. The generic LLM vcall path creates the call-site signature but
reports the interface slot, so this preprocessor normalizes the generated slot
before publishing the artifact.
"""

from pathlib import Path

from ida_analyze_util import preprocess_common_skill, write_func_yaml
from trusted_yaml import load_yaml_file

TARGET_FUNCTION_NAMES = ["CNetworkServerService_SetGameLoadStarted"]
VTABLE_CLASS = "CNetworkServerService"

CONCRETE_VFUNC_INDEX = 37

LLM_DECOMPILE = [
    {
        "symbol_name": "CNetworkServerService_SetGameLoadStarted",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/engine/CLoopTypeSimpleService_OnLoopActivate.{platform}.yaml",
        ],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {
            "CLoopTypeSimpleService_OnLoopActivate.{platform}.yaml": "required",
        },
    },
]

FUNC_VTABLE_RELATIONS = [("CNetworkServerService_SetGameLoadStarted", "CNetworkServerService")]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CNetworkServerService_SetGameLoadStarted",
        ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"],
    ),
]


def _resolve_target_output(expected_outputs, new_binary_dir, platform):
    expected_basename = f"{TARGET_FUNCTION_NAMES[0]}.{platform}.yaml"
    module_root = Path(new_binary_dir).resolve()
    matches = [
        Path(output_path)
        for output_path in expected_outputs
        if Path(output_path).name == expected_basename and Path(output_path).resolve().parent == module_root
    ]
    return matches[0] if len(matches) == 1 else None


def _normalize_concrete_vtable_slot(expected_outputs, new_binary_dir, platform, debug=False):
    target_output = _resolve_target_output(expected_outputs, new_binary_dir, platform)
    if target_output is None:
        if debug:
            print("    Preprocess: expected exactly one in-module SetGameLoadStarted output")
        return False

    vtable_path = Path(new_binary_dir) / f"{VTABLE_CLASS}_vtable.{platform}.yaml"
    try:
        payload = load_yaml_file(target_output)
        vtable_payload = load_yaml_file(vtable_path)
        entries = vtable_payload["vtable_entries"]
        concrete_entry = entries.get(CONCRETE_VFUNC_INDEX, entries.get(str(CONCRETE_VFUNC_INDEX)))
    except Exception:
        if debug:
            print("    Preprocess: failed to load generated function or concrete vtable artifact")
        return False

    if (
        not isinstance(payload, dict)
        or payload.get("func_name") != TARGET_FUNCTION_NAMES[0]
        or payload.get("vtable_name") != VTABLE_CLASS
        or not payload.get("vfunc_sig")
        or concrete_entry is None
    ):
        if debug:
            print("    Preprocess: generated SetGameLoadStarted payload or concrete ABI slot is invalid")
        return False

    payload["vfunc_offset"] = hex(CONCRETE_VFUNC_INDEX * 8)
    payload["vfunc_index"] = CONCRETE_VFUNC_INDEX
    write_func_yaml(target_output, payload)
    if debug:
        print(
            "    Preprocess: mapped INetworkServerService slot 2 call-site evidence "
            f"to {VTABLE_CLASS} slot {CONCRETE_VFUNC_INDEX}"
        )
    return True


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
    """Locate SetGameLoadStarted from the simple-service loop activation body."""
    _ = skill_name
    generated = await preprocess_common_skill(
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
    if not generated:
        return False
    return _normalize_concrete_vtable_slot(
        expected_outputs,
        new_binary_dir,
        platform,
        debug=debug,
    )
