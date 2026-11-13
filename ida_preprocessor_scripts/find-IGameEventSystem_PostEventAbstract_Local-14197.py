#!/usr/bin/env python3
"""Find the local event slot from proven receiver dispatches, including devirtualized loads."""

import inspect
import json
from pathlib import Path

from ida_analyze_util import parse_mcp_result, preprocess_gen_vfunc_sig_via_mcp, write_func_yaml
from ida_preprocessor_scripts._vtable_slot_anchor_common import (
    SLOT_SIZE,
    _load_vfunc_anchor_slot,
    _load_vtable_entries,
    _probe_receiver_vcall_offsets,
)

VTABLE_CLASS = "CGameEventSystem"
CALLER_NAME = "CGameEventSystem_PostEventAbstract2"
TARGET_FUNCTION_NAMES = ["IGameEventSystem_PostEventAbstract_Local"]
GENERATE_YAML_DESIRED_FIELDS = [
    (TARGET_FUNCTION_NAMES[0], ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"]),
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
    """Derive the unique this-dispatch slot and sign one proven memory-access instruction."""
    _ = skill_name, old_yaml_map, image_base
    if platform not in {"windows", "linux"}:
        return False
    root = Path(new_binary_dir).resolve()
    filename = f"{TARGET_FUNCTION_NAMES[0]}.{platform}.yaml"
    outputs = [path for path in expected_outputs if Path(path).name == filename and Path(path).resolve().parent == root]
    if len(outputs) != 1:
        return False
    entries = _load_vtable_entries(new_binary_dir, VTABLE_CLASS, platform, debug=debug)
    if entries is None:
        return False
    caller_index = _load_vfunc_anchor_slot(new_binary_dir, platform, CALLER_NAME, VTABLE_CLASS, entries, debug=debug)
    if caller_index is None:
        return False
    code = (
        inspect.getsource(_probe_receiver_vcall_offsets)
        + f"\nimport json\nresult = json.dumps(_probe_receiver_vcall_offsets({entries[caller_index]}, include_sites=True))\n"
    )
    try:
        parsed = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
        dispatches = json.loads(parsed.get("result") or "null")
        if not isinstance(dispatches, list) or len(dispatches) != 1 or not isinstance(dispatches[0], dict):
            return False
        offset = dispatches[0].get("offset")
        sites = dispatches[0].get("inst_vas")
        if type(offset) is not int or offset < 0 or offset % SLOT_SIZE or offset // SLOT_SIZE not in entries:
            return False
        if not isinstance(sites, list) or not sites or any(type(site) is not int or site <= 0 for site in sites):
            return False
    except Exception as exc:
        if debug:
            print(f"    Preprocess: local event dispatch probe failed: {exc}")
        return False

    for site in sorted(set(sites)):
        generated = await preprocess_gen_vfunc_sig_via_mcp(
            session=session, inst_va=site, vfunc_offset=offset, debug=debug
        )
        if not isinstance(generated, dict) or not generated.get("vfunc_sig"):
            continue
        write_func_yaml(
            outputs[0],
            {
                "func_name": TARGET_FUNCTION_NAMES[0],
                "vfunc_sig": generated["vfunc_sig"],
                "vfunc_offset": hex(offset),
                "vfunc_index": offset // SLOT_SIZE,
                "vtable_name": "IGameEventSystem",
            },
        )
        if debug:
            print(f"    Preprocess: local event dispatch uses slot {offset // SLOT_SIZE}, anchor {hex(site)}")
        return True
    return False
