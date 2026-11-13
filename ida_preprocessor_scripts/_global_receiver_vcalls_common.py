#!/usr/bin/env python3
"""Validate virtual calls on a shared global receiver and optional result flow."""

import inspect
import json

from ida_analyze_util import parse_mcp_result


def _probe_global_receiver_calls(func_va, expected_offsets, expected_arities, result_flow=None):
    """Run inside IDA; result_flow is (producer role, consumer role, argument index)."""
    import ida_hexrays as hx

    cfunc = hx.decompile(func_va)
    if cfunc is None or not expected_offsets or len(expected_offsets) != len(expected_arities):
        return None

    def uncast(expr):
        while expr.op == hx.cot_cast:
            expr = expr.x
        return expr

    def global_receiver(expr):
        expr = uncast(expr)
        if expr.op == hx.cot_obj:
            return int(expr.obj_ea)
        # IDA may merge neighboring globals into an array. Only a true static
        # array plus a constant index denotes a fixed global slot; pointer
        # indexing would depend on a loaded runtime value.
        if expr.op == hx.cot_idx:
            base, index = uncast(expr.x), uncast(expr.y)
            if base.op == hx.cot_obj and base.type.is_array() and index.op == hx.cot_num:
                size = expr.type.get_size()
                if size > 0 and index.numval() >= 0:
                    return int(base.obj_ea + index.numval() * size)
        return None

    def virtual_target(expr):
        expr = uncast(expr)
        if expr.op == hx.cot_idx:
            step = uncast(expr.y)
            if step.op != hx.cot_num:
                return None
            offset, base = step.numval() * expr.type.get_size(), uncast(expr.x)
        elif expr.op == hx.cot_ptr:
            address = uncast(expr.x)
            if address.op != hx.cot_add:
                return None
            step = uncast(address.y)
            if step.op != hx.cot_num:
                return None
            scale = address.x.type.get_ptrarr_objsize() if address.x.type.is_ptr() else 1
            if scale <= 0:
                return None
            offset, base = step.numval() * scale, uncast(address.x)
        else:
            return None
        if base.op != hx.cot_ptr:
            return None
        receiver = global_receiver(base.x)
        return (int(offset), receiver) if receiver is not None else None

    assignments = {}
    if result_flow is not None:
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

        class Assignments(hx.ctree_visitor_t):
            def __init__(self):
                super().__init__(hx.CV_FAST)

            def visit_expr(self, expr):
                if expr.op == hx.cot_asg and uncast(expr.x).op == hx.cot_var:
                    assignments.setdefault(uncast(expr.x).v.idx, []).append(uncast(expr.y))
                elif expr.op in other_writes and uncast(expr.x).op == hx.cot_var:
                    # A mutation or escaped address defeats single-definition proof.
                    assignments.setdefault(uncast(expr.x).v.idx, []).append(None)
                return 0

        Assignments().apply_to(cfunc.body, None)

    def result_source(expr, seen):
        expr = uncast(expr)
        if expr.op == hx.cot_call:
            return int(expr.ea)
        if expr.op != hx.cot_var or expr.v.idx in seen:
            return None
        sources = assignments.get(expr.v.idx, [])
        if len(sources) != 1 or sources[0] is None:
            return None
        return result_source(sources[0], seen | {expr.v.idx})

    groups, call_nodes = {}, {}

    class Calls(hx.ctree_visitor_t):
        def __init__(self):
            super().__init__(hx.CV_FAST)

        def visit_expr(self, expr):
            if expr.op != hx.cot_call or not expr.a.size():
                return 0
            target = virtual_target(expr.x)
            if target is None:
                return 0
            offset, receiver = target
            if offset not in expected_offsets or global_receiver(expr.a[0]) != receiver:
                return 0
            site = int(expr.ea)
            groups.setdefault(receiver, {}).setdefault(offset, set()).add((site, expr.a.size()))
            call_nodes[site] = expr
            return 0

    Calls().apply_to(cfunc.body, None)
    matches = []
    for receiver, calls in groups.items():
        resolved = []
        for offset, arity in zip(expected_offsets, expected_arities):
            sites = calls.get(offset, set())
            if len(sites) != 1:
                break
            inst_va, actual_arity = next(iter(sites))
            if inst_va <= 0 or actual_arity != arity:
                break
            resolved.append({"offset": offset, "inst_va": inst_va})
        if len(resolved) != len(expected_offsets):
            continue
        if result_flow is not None:
            producer, consumer, argument = result_flow
            consumer_call = call_nodes[resolved[consumer]["inst_va"]]
            if argument >= consumer_call.a.size():
                continue
            if result_source(consumer_call.a[argument], set()) != resolved[producer]["inst_va"]:
                continue
        matches.append({"receiver": receiver, "calls": resolved})
    return matches[0] if len(matches) == 1 else None


async def probe_global_receiver_calls(session, func_va, offsets, arities, result_flow=None, debug=False):
    code = (
        inspect.getsource(_probe_global_receiver_calls)
        + f"\nimport json\nresult = json.dumps(_probe_global_receiver_calls({func_va}, {list(offsets)!r}, "
        + f"{list(arities)!r}, {result_flow!r}))\n"
    )
    parsed = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
    payload = json.loads(parsed.get("result") or "null")
    if payload is None:
        return None
    if not isinstance(payload, dict) or type(payload.get("receiver")) is not int or payload["receiver"] <= 0:
        raise ValueError("invalid global receiver in virtual-call probe")
    calls = payload.get("calls")
    if not isinstance(calls, list) or len(calls) != len(offsets):
        raise ValueError("incomplete virtual-call group")
    sites = []
    for call, offset in zip(calls, offsets):
        if (
            not isinstance(call, dict)
            or type(call.get("offset")) is not int
            or call["offset"] != offset
            or type(call.get("inst_va")) is not int
            or call["inst_va"] <= 0
        ):
            raise ValueError("invalid virtual-call site")
        sites.append(call["inst_va"])
    if len(set(sites)) != len(sites):
        raise ValueError("virtual-call roles share a call site")
    if debug:
        print(f"    Preprocess: {hex(func_va)} has verified calls on receiver {hex(payload['receiver'])}")
    return payload
