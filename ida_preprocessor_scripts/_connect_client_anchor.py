"""Verify the first client acquisition call on ConnectClient's server-full path."""

import inspect
import json
import os

import yaml

from ida_analyze_util import parse_mcp_result


SYMBOL = "CNetworkGameServer_GetFreeClient"
SOURCE_SYMBOL = "CNetworkGameServerBase_ConnectClient"


def _probe_anchor(func_va):
    """Run inside IDA; use ctree data flow instead of names or version addresses."""
    import ida_bytes
    import ida_funcs
    import ida_hexrays as hx
    import ida_lines
    import idautils
    import idc

    def uncast(expr):
        while expr.op == hx.cot_cast:
            expr = expr.x
        return expr

    def is_var(expr, index):
        expr = uncast(expr)
        return expr.op == hx.cot_var and expr.v.idx == index

    def null_branch(condition, index):
        condition = uncast(condition)
        if condition.op == hx.cot_lnot and is_var(condition.x, index):
            return "then"
        if is_var(condition, index):
            return "else"
        if condition.op in (hx.cot_eq, hx.cot_ne):
            right = uncast(condition.y)
            if is_var(condition.x, index) and right.op == hx.cot_num and right.numval() == 0:
                return "then" if condition.op == hx.cot_eq else "else"
        # A fallback allocator can be folded into the non-null condition.
        if condition.op == hx.cot_lor and is_var(condition.x, index):
            right = uncast(condition.y)
            if right.op == hx.cot_ne and uncast(right.y).op == hx.cot_num and uncast(right.y).numval() == 0:
                right = uncast(right.x)
            if right.op == hx.cot_asg and is_var(right.x, index) and uncast(right.y).op == hx.cot_call:
                return "else"
        return None

    class FailurePath(hx.ctree_visitor_t):
        def __init__(self):
            super().__init__(hx.CV_FAST)
            self.has_server_full = False
            self.calls = []

        def visit_expr(self, expr):
            if expr.op == hx.cot_call:
                self.calls.append(int(expr.ea))
            if expr.op == hx.cot_obj:
                value = ida_bytes.get_strlit_contents(expr.obj_ea, -1, idc.STRTYPE_C) or b""
                if b"NETWORK_DISCONNECT_REJECT_SERVERFULL" in value and b"Cannot get free client" in value:
                    self.has_server_full = True
            return 0

    candidates = []
    acquisitions = []

    class FindPairs(hx.ctree_visitor_t):
        def __init__(self):
            super().__init__(hx.CV_FAST)

        def visit_expr(self, expr):
            if expr.op == hx.cot_asg and uncast(expr.x).op == hx.cot_var:
                value = uncast(expr.y)
                if value.op == hx.cot_call:
                    acquisitions.append((uncast(expr.x).v.idx, int(value.ea)))
            return 0

        def visit_insn(self, insn):
            if insn.op != hx.cit_block:
                return 0
            statements = list(insn.cblock)
            for previous, following in zip(statements, statements[1:]):
                if previous.op != hx.cit_expr or following.op != hx.cit_if:
                    continue
                assignment = previous.cexpr
                if assignment.op != hx.cot_asg or uncast(assignment.x).op != hx.cot_var:
                    continue
                index = uncast(assignment.x).v.idx
                call = uncast(assignment.y)
                branch = null_branch(following.cif.expr, index)
                if call.op != hx.cot_call and branch is None:
                    continue
                failure = following.cif.ithen if branch == "then" else following.cif.ielse
                visitor = FailurePath()
                if branch is None:
                    # Keep unsupported outer candidates so a later fallback can
                    # never be promoted merely because the first call failed validation.
                    visitor.apply_to(following, None)
                elif failure is not None:
                    visitor.apply_to(failure, None)
                if not visitor.has_server_full:
                    continue
                if call.op != hx.cot_call:
                    # Copies and conditional expressions do not prove the first
                    # allocator. Retain an outer blocker instead of promoting a fallback.
                    candidates.append(
                        {
                            "insn_va": int(previous.ea),
                            "verified": False,
                            "client_var": int(index),
                            "failure_calls": visitor.calls,
                            "chain_calls": [],
                        }
                    )
                    continue
                call_va = int(call.ea)
                owner = ida_funcs.get_func(call_va)
                refs = list(idautils.CodeRefsFrom(call_va, False))
                target = ida_funcs.get_func(refs[0]) if len(refs) == 1 else None
                verified = (
                    branch is not None
                    and owner is not None
                    and owner.start_ea == func_va
                    and idc.print_insn_mnem(call_va) == "call"
                    and target is not None
                    and target.start_ea == refs[0]
                    and uncast(call.x).op == hx.cot_obj
                    and uncast(call.x).obj_ea == target.start_ea
                )
                chain = FailurePath()
                chain.apply_to(following, None)
                candidates.append(
                    {
                        "insn_va": call_va,
                        "target_va": int(target.start_ea) if target is not None else None,
                        "verified": verified,
                        "client_var": int(index),
                        "failure_calls": visitor.calls,
                        "chain_calls": chain.calls,
                        "insn_disasm": ida_lines.tag_remove(idc.generate_disasm_line(call_va, 0)),
                    }
                )
            return 0

    function = hx.decompile(func_va)
    if function is None:
        raise ValueError("ConnectClient decompilation unavailable")
    FindPairs().apply_to(function.body, None)
    for candidate in candidates:
        allowed = {candidate["insn_va"], *candidate["chain_calls"]}
        # If an earlier acquisition is folded into an unsupported condition or
        # separated from its test, never promote a recognizable inner fallback.
        if any(index == candidate["client_var"] and ea not in allowed for index, ea in acquisitions):
            candidate["verified"] = False
    return candidates


def select_anchor(candidates):
    # The final fallback also has a null check and server-full log. Its call lies
    # inside the first acquisition's failure subtree; it is not GetFreeClient.
    roots = [
        candidate
        for candidate in candidates
        if not any(
            candidate["client_var"] == parent["client_var"] and candidate["insn_va"] in parent["failure_calls"]
            for parent in candidates
            if parent is not candidate
        )
    ]
    if len(roots) != 1:
        raise ValueError(f"expected one first client acquisition anchor, found {len(roots)}")
    if not roots[0]["verified"]:
        raise ValueError("first client acquisition has unsupported data flow or an ambiguous call target")
    return roots[0]


async def load_anchor(session, artifact_dir, platform):
    path = os.path.join(artifact_dir, f"{SOURCE_SYMBOL}.{platform}.yaml")
    with open(path, encoding="utf-8") as stream:
        payload = yaml.safe_load(stream)
    func_va = int(str(payload["func_va"]), 0)
    code = inspect.getsource(_probe_anchor) + f"\nimport json\nprint(json.dumps(_probe_anchor({func_va})))"
    result = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
    # py_eval prints are in stdout; expression results may also carry JSON.
    if not isinstance(result, dict):
        raise ValueError("missing ConnectClient anchor probe result")
    candidates = json.loads(result.get("stdout") or result.get("result") or "null")
    if not isinstance(candidates, list):
        raise ValueError("invalid ConnectClient anchor probe result")
    return select_anchor(candidates)


def validate_result(parsed_result, anchor):
    from ida_llm_decompile import _parse_llm_int_value

    issues = []
    entries = [entry for entry in parsed_result.get("found_call", []) if entry.get("func_name") == SYMBOL]
    if len(entries) != 1:
        return [f"{SYMBOL}: return exactly one found_call entry for the verified first client acquisition."]
    for entry in entries:
        if _parse_llm_int_value(entry.get("insn_va")) != anchor["insn_va"]:
            issues.append(
                f"{SYMBOL}: choose the FIRST client acquisition in the null-result fallback chain, "
                f"at {hex(anchor['insn_va'])} ({anchor['insn_disasm']}). "
                "Later fallback allocators also precede the server-full log and must not be selected."
            )
    return issues
