#!/usr/bin/env python3
"""Locate the 14197 stats sender across fused and extracted group serialization."""

from ida_analyze_util import (
    _collect_single_call_or_jump_xref_func_starts_for_ea,
    _collect_xref_func_starts_for_string,
    preprocess_gen_func_sig_via_mcp,
    write_func_yaml,
)
from ida_preprocessor_scripts._network_stats_common import (
    load_group_slots,
    probe_stats_group_calls,
    resolve_output_path,
)

TARGET_FUNCTION_NAMES = ["CNetworkSystem_SendNetworkStats"]
GENERATE_YAML_DESIRED_FIELDS = [
    (TARGET_FUNCTION_NAMES[0], ["func_name", "func_va", "func_rva", "func_size", "func_sig"]),
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
    """Find the unique serialization owner/caller containing the current group getter triplet."""
    _ = skill_name, old_yaml_map
    slots = load_group_slots(new_binary_dir, platform, debug=debug)
    output = resolve_output_path(expected_outputs, new_binary_dir, TARGET_FUNCTION_NAMES[0], platform)
    if slots is None or output is None:
        return False
    owners = await _collect_xref_func_starts_for_string(session, "FULLMATCH:groupnames", debug=debug)
    errors = await _collect_xref_func_starts_for_string(session, "FULLMATCH:Stack depth limit hit (%d)", debug=debug)
    if owners is None or len(owners) != 1 or not errors:
        return False
    owner = next(iter(owners))
    try:
        sender = None
        if owner in errors and await probe_stats_group_calls(
            session=session, func_va=owner, slots=slots, platform=platform, debug=debug
        ):
            sender = owner
        if sender is None:
            callers = await _collect_single_call_or_jump_xref_func_starts_for_ea(session, owner, debug=debug)
            if callers is None:
                return False
            matches = []
            for caller in sorted(callers & errors):
                if await probe_stats_group_calls(
                    session=session, func_va=caller, slots=slots, platform=platform, debug=debug
                ):
                    matches.append(caller)
            if len(matches) != 1:
                return False
            sender = matches[0]
    except Exception as exc:
        if debug:
            print(f"    Preprocess: network stats sender validation failed: {exc}")
        return False

    generated = await preprocess_gen_func_sig_via_mcp(
        session=session, func_va=sender, image_base=image_base, debug=debug
    )
    required = ("func_va", "func_rva", "func_size", "func_sig")
    if not isinstance(generated, dict) or not set(required) <= generated.keys() or not generated.get("func_sig"):
        return False
    try:
        if int(str(generated["func_va"]), 0) != sender:
            return False
    except (TypeError, ValueError):
        return False
    write_func_yaml(output, {"func_name": TARGET_FUNCTION_NAMES[0], **{field: generated[field] for field in required}})
    try:
        await session.call_tool(
            name="rename", arguments={"batch": {"func": {"addr": hex(sender), "name": TARGET_FUNCTION_NAMES[0]}}}
        )
    except Exception:
        if debug:
            print("    Preprocess: stats sender rename failed (non-fatal)")
    if debug:
        print(f"    Preprocess: {TARGET_FUNCTION_NAMES[0]} resolved to {hex(sender)}")
    return True
