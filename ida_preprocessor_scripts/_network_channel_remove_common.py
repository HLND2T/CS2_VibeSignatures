#!/usr/bin/env python3
"""Prove the current network-channel removal pair from direct calls and receiver flow."""

import inspect
import json

from ida_analyze_util import (
    _collect_single_call_or_jump_xref_func_starts_for_ea,
    _collect_xref_func_starts_for_string,
    parse_mcp_result,
)
from ida_preprocessor_scripts._vtable_slot_anchor_common import _load_vtable_entries

VTABLE_CLASS = "CNetworkSystem"
REMOVE = "CNetworkSystem_RemoveNetChannel"
BY_ADDRESS = "CNetworkSystem_RemoveNetChannelByAddress"
# The address-based overload immediately follows removal in INetworkSystem.
BY_ADDRESS_SLOT_DELTA = 1


def _probe_channel_calls(func_va, mode, target_va=0, root_fields=()):
    """Run inside IDA: identify the close helper, removal body, or its address-based caller."""
    import ida_hexrays as hx

    cfunc = hx.decompile(func_va)
    if cfunc is None or not len(cfunc.argidx):
        return None
    if mode != "close_helper" and len(cfunc.argidx) != 3:
        return None
    receiver = cfunc.argidx[0]

    def uncast(expr):
        while expr.op == hx.cot_cast:
            expr = expr.x
        return expr

    def is_arg(expr, index):
        expr = uncast(expr)
        return expr.op == hx.cot_var and expr.v.idx == index

    def direct_target(expr):
        expr = uncast(expr)
        return int(expr.obj_ea) if expr.op == hx.cot_obj else None

    def receiver_field(expr):
        expr = uncast(expr)
        if expr.op == hx.cot_memptr and is_arg(expr.x, receiver):
            return int(expr.m)
        if expr.op != hx.cot_ptr:
            return None
        address = uncast(expr.x)
        if address.op != hx.cot_add or not is_arg(address.x, receiver):
            return None
        step = uncast(address.y)
        if step.op != hx.cot_num:
            return None
        scale = address.x.type.get_ptrarr_objsize() if address.x.type.is_ptr() else 1
        return int(step.numval() * scale) if scale > 0 else None

    assignments, fields, calls = {}, set(), []
    other_writes = {
        getattr(hx, name, None)
        for name in (
            "cot_asgbor",
            "cot_asgxor",
            "cot_asgband",
            "cot_asgadd",
            "cot_asgsub",
            "cot_asgmul",
            "cot_asgsshr",
            "cot_asgushr",
            "cot_asgshl",
            "cot_asgsdiv",
            "cot_asgudiv",
            "cot_asgsmod",
            "cot_asgumod",
            "cot_preinc",
            "cot_predec",
            "cot_postinc",
            "cot_postdec",
            "cot_ref",
        )
    } - {None}

    class Expressions(hx.ctree_visitor_t):
        def __init__(self):
            super().__init__(hx.CV_FAST)

        def visit_expr(self, expr):
            offset = receiver_field(expr)
            if offset is not None and offset >= 0:
                fields.add(offset)
            if expr.op == hx.cot_asg and uncast(expr.x).op == hx.cot_var:
                assignments.setdefault(uncast(expr.x).v.idx, []).append(uncast(expr.y))
            elif expr.op in other_writes and uncast(expr.x).op == hx.cot_var:
                assignments.setdefault(uncast(expr.x).v.idx, []).append(None)
            if expr.op == hx.cot_call:
                calls.append(expr)
            return 0

    Expressions().apply_to(cfunc.body, None)
    if receiver in assignments:
        return None
    if mode == "close_helper":
        import ida_bytes
        import idc

        helpers = set()
        for call in calls:
            target = direct_target(call.x)
            if target is None or call.a.size() != 5 or not is_arg(call.a[0], receiver):
                continue
            literal = uncast(call.a[3])
            if (
                literal.op == hx.cot_obj
                and ida_bytes.get_strlit_contents(literal.obj_ea, -1, idc.STRTYPE_C) == b"CloseSocket"
            ):
                helpers.add(target)
        return {"helper_vas": sorted(helpers)} if helpers else None

    matched = [call for call in calls if direct_target(call.x) == target_va]
    if mode == "remove":
        sites = {int(call.ea) for call in matched if call.a.size() == 5 and is_arg(call.a[0], receiver)}
        return {"receiver_fields": sorted(fields), "call_vas": sorted(sites)} if sites else None
    if mode != "by_address":
        return None

    def collection_source(expr):
        expr = uncast(expr)
        if expr.op == hx.cot_idx:
            return receiver_field(expr.x) in root_fields
        if expr.op != hx.cot_ptr:
            return False
        address = uncast(expr.x)
        return address.op == hx.cot_add and receiver_field(address.x) in root_fields

    def local_address(expr):
        expr = uncast(expr)
        if expr.op == hx.cot_ref:
            return uncast(expr.x).op == hx.cot_var and uncast(expr.x).v.idx not in cfunc.argidx
        if expr.op == hx.cot_var and expr.v.idx not in cfunc.argidx:
            # A stack array decays to a pointer at the call site; its lvar
            # retains the array type even when the argument expression does not.
            locals_ = cfunc.get_lvars()
            return 0 <= expr.v.idx < len(locals_) and locals_[expr.v.idx].type().is_array()
        return False

    def channel_source(expr, seen):
        if expr is None:
            return None
        expr = uncast(expr)
        if expr.op == hx.cot_num and expr.numval() == 0:
            return False
        if collection_source(expr):
            return True
        if expr.op == hx.cot_call:
            # GCC keeps the (this, socket, address*) lookup out of line.
            return (
                True
                if (
                    direct_target(expr.x) not in (None, target_va)
                    and expr.a.size() == 3
                    and is_arg(expr.a[0], receiver)
                    and is_arg(expr.a[1], cfunc.argidx[1])
                    and local_address(expr.a[2])
                )
                else None
            )
        if expr.op != hx.cot_var or expr.v.idx in seen or expr.v.idx in cfunc.argidx:
            return None
        definitions = assignments.get(expr.v.idx, [])
        if not definitions:
            return None
        sources = [channel_source(source, seen | {expr.v.idx}) for source in definitions]
        # Inlined searches may assign null on failure and a collection element on success.
        return any(sources) if all(source is not None for source in sources) else None

    if len(matched) != 1:
        return None
    call = matched[0]
    if call.a.size() != 3 or not is_arg(call.a[0], receiver):
        return None
    flag = uncast(call.a[2])
    if flag.op != hx.cot_num or flag.numval() != 0 or channel_source(call.a[1], set()) is not True:
        return None
    return {"call_vas": [int(call.ea)]}


async def probe_channel_calls(session, func_va, mode, target_va=0, root_fields=()):
    code = (
        inspect.getsource(_probe_channel_calls)
        + f"\nimport json\nresult = json.dumps(_probe_channel_calls({func_va}, {mode!r}, {target_va}, {list(root_fields)!r}))\n"
    )
    parsed = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
    if parsed.get("stderr"):
        raise ValueError(f"channel-removal probe execution failed: {parsed['stderr']}")
    payload = json.loads(parsed.get("result") or "null")
    if payload is None:
        return None
    keys = (
        ("helper_vas",)
        if mode == "close_helper"
        else (("call_vas", "receiver_fields") if mode == "remove" else ("call_vas",))
    )
    if not isinstance(payload, dict):
        raise ValueError("invalid channel-removal probe result")
    for key in keys:
        values = payload.get(key)
        minimum = 0 if key == "receiver_fields" else 1
        if not isinstance(values, list) or any(type(value) is not int or value < minimum for value in values):
            raise ValueError(f"invalid {key} in channel-removal probe")
        if len(values) != len(set(values)) or (key != "receiver_fields" and not values):
            raise ValueError(f"empty or duplicate {key} in channel-removal probe")
    return payload


async def resolve_remove_pair(session, new_binary_dir, platform, debug=False):
    entries = _load_vtable_entries(new_binary_dir, VTABLE_CLASS, platform, debug=debug)
    if entries is None:
        return None
    try:
        owners = await _collect_xref_func_starts_for_string(
            session=session, xref_string="FULLMATCH:CloseSocket", debug=debug
        )
        helpers = set()
        for owner in sorted(owners or ()):
            result = await probe_channel_calls(session, owner, "close_helper")
            if result is not None:
                helpers.update(result["helper_vas"])
        if len(helpers) != 1:
            if debug:
                print(
                    f"    Preprocess: expected one close helper from {len(owners or ())} owners, found {len(helpers)}"
                )
            return None
        helper = next(iter(helpers))
        callers = await _collect_single_call_or_jump_xref_func_starts_for_ea(
            session=session, target_ea=helper, debug=debug
        )
        candidates = []
        for slot, address in sorted(entries.items()):
            sibling = entries.get(slot + BY_ADDRESS_SLOT_DELTA)
            if address not in (callers or ()) or sibling is None or sibling == address:
                continue
            root = await probe_channel_calls(session, address, "remove", target_va=helper)
            if root is None:
                continue
            pair = await probe_channel_calls(
                session, sibling, "by_address", target_va=address, root_fields=root["receiver_fields"]
            )
            if pair is not None:
                candidates.append(slot)
        if len(candidates) != 1:
            if debug:
                print(f"    Preprocess: expected one channel removal pair, found {len(candidates)}")
            return None
    except Exception as exc:
        if debug:
            print(f"    Preprocess: channel removal proof failed: {exc}")
        return None
    if debug:
        print(
            f"    Preprocess: close helper {hex(helper)} proves removal pair at slots {candidates[0]}, {candidates[0] + BY_ADDRESS_SLOT_DELTA}"
        )
    return entries, candidates[0]
