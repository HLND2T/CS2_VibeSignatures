#!/usr/bin/env python3
"""Locate the retained 14197 string-table parser through its current diagnostics."""

from ida_analyze_util import _collect_xref_func_starts_for_string, preprocess_gen_func_sig_via_mcp, write_func_yaml
from ida_preprocessor_scripts._network_stats_common import resolve_output_path

TARGET = "CNetworkStringTableClient_ParseUpdate"
TARGET_FUNCTION_NAMES = [TARGET]
ANCHORS = (
    "CNetworkStringTableClient::ParseUpdate: bogus user data size (%d bytes, max %d).",
    "CNetworkStringTableClient::ParseUpdate: failed to decompress user data for table %s",
)
FIELDS = ("func_name", "func_sig", "func_va", "func_rva", "func_size")
GENERATE_YAML_DESIRED_FIELDS = [(TARGET, list(FIELDS))]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False,
):
    _ = skill_name, old_yaml_map
    output = resolve_output_path(expected_outputs, new_binary_dir, TARGET, platform)
    if output is None:
        return False
    candidates = None
    for anchor in ANCHORS:
        owners = await _collect_xref_func_starts_for_string(
            session=session, xref_string=f"FULLMATCH:{anchor}", debug=debug
        )
        if not owners:
            return False
        candidates = set(owners) if candidates is None else candidates.intersection(owners)
    if len(candidates) != 1:
        return False
    generated = await preprocess_gen_func_sig_via_mcp(
        session=session, func_va=next(iter(candidates)), image_base=image_base, debug=debug
    )
    if not isinstance(generated, dict) or not all(generated.get(field) for field in FIELDS if field != "func_name"):
        return False
    write_func_yaml(output, {field: TARGET if field == "func_name" else generated[field] for field in FIELDS})
    return True
