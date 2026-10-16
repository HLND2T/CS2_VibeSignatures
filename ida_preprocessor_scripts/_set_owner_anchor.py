"""Check SetOwner against live EquipWeapon sites and the entity-handle setter body."""

import inspect
import json
from pathlib import Path

import yaml

from ida_analyze_util import parse_mcp_result, preprocess_vtable_via_mcp
from ida_llm_decompile import _parse_llm_int_value

SYMBOL = "CBaseEntity_SetOwner"
SOURCE_SYMBOL = "CCSPlayer_WeaponServices_EquipWeapon"
SLOT_SIZE = 8


def _probe_sites(func_va, entries):
    """Run inside IDA. Do not trust inferred argument counts at indirect callers."""
    import ida_funcs
    import ida_hexrays as hx
    import idautils
    import idc

    def uncast(expr):
        while expr.op == hx.cot_cast:
            expr = expr.x
        return expr

    def number(expr, expected):
        expr = uncast(expr)
        return expr.op == hx.cot_num and expr.numval() == expected

    def describe_target(address):
        function = ida_funcs.get_func(address)
        if function is None or function.start_ea != address:
            return {}
        cfunc = hx.decompile(address)
        if cfunc is None:
            return {}
        arguments = [index for index, var in enumerate(cfunc.get_lvars()) if var.is_arg_var]
        facts = dict(argument_count=len(arguments), compares_owner=False, handle_mask=False, handle_shift=False)
        if len(arguments) != 2:
            return facts

        class Inspect(hx.ctree_visitor_t):
            def __init__(self):
                super().__init__(hx.CV_FAST)

            def visit_expr(self, expr):
                if expr.op == hx.cot_band and (number(expr.x, 0x1FF) or number(expr.y, 0x1FF)):
                    facts["handle_mask"] = True
                if expr.op in (hx.cot_ushr, hx.cot_sshr) and number(expr.y, 9):
                    facts["handle_shift"] = True
                return 0

            def visit_insn(self, insn):
                if insn.op == hx.cit_if:
                    condition = uncast(insn.cif.expr)
                    if condition.op == hx.cot_ne:
                        left, right = uncast(condition.x), uncast(condition.y)
                        # SetOwner compares the incoming owner to the resolved
                        # handle before notifying/writing. Null checks alone do
                        # not distinguish a setter from unrelated two-arg calls.
                        if (left.op == hx.cot_var and left.v.idx == arguments[1] and right.op == hx.cot_var) or (
                            right.op == hx.cot_var and right.v.idx == arguments[1] and left.op == hx.cot_var
                        ):
                            facts["compares_owner"] = True
                return 0

        Inspect().apply_to(cfunc.body, None)
        return facts

    function = ida_funcs.get_func(func_va)
    if function is None or function.start_ea != func_va:
        raise ValueError("EquipWeapon does not resolve to a function entry")
    targets = {}
    sites = []
    for ea in idautils.FuncItems(func_va):
        mnemonic = idc.print_insn_mnem(ea).lower()
        operand = 1 if mnemonic == "mov" else 0
        if mnemonic not in ("mov", "call", "jmp") or idc.get_operand_type(ea, operand) != idc.o_displ:
            continue
        offset = idc.get_operand_value(ea, operand)
        if offset < 0 or offset % 8 or offset // 8 not in entries:
            continue
        target = entries[offset // 8]
        if target not in targets:
            targets[target] = describe_target(target)
        sites.append(dict(insn_va=int(ea), vfunc_offset=int(offset), target_va=target, facts=targets[target]))
    return sites


def is_owner_setter(facts):
    return facts.get("argument_count") == 2 and all(
        facts.get(field) is True for field in ("compares_owner", "handle_mask", "handle_shift")
    )


def select_anchors(sites):
    if not sites or len({site["vfunc_offset"] for site in sites}) != 1:
        raise ValueError("expected one verified SetOwner slot in EquipWeapon")
    return sites


async def load_anchors(session, artifact_dir, platform, image_base):
    source = yaml.safe_load((Path(artifact_dir) / f"{SOURCE_SYMBOL}.{platform}.yaml").read_text(encoding="utf-8"))
    table = await preprocess_vtable_via_mcp(
        session=session, class_name="CBaseEntity", image_base=image_base, platform=platform
    )
    if not table:
        raise ValueError("CBaseEntity vtable unavailable")
    entries = {int(index): int(str(address), 0) for index, address in table["vtable_entries"].items()}
    code = inspect.getsource(_probe_sites) + (
        f"\nimport json\nprint(json.dumps(_probe_sites({int(str(source['func_va']), 0)}, {entries!r})))"
    )
    result = parse_mcp_result(await session.call_tool(name="py_eval", arguments={"code": code}))
    sites = json.loads(result.get("stdout") or result.get("result") or "null")
    if not isinstance(sites, list):
        raise ValueError("SetOwner probe unavailable")
    return select_anchors([site for site in sites if is_owner_setter(site["facts"])])


def validate_result(result, sites):
    entries = [entry for entry in result.get("found_vcall", []) if entry.get("func_name") == SYMBOL]
    allowed = {(site["insn_va"], site["vfunc_offset"]) for site in sites}
    if (
        len(entries) == 1
        and (_parse_llm_int_value(entries[0].get("insn_va")), _parse_llm_int_value(entries[0].get("vfunc_offset")))
        in allowed
    ):
        return []
    choices = ", ".join(f"{hex(va)} (slot offset {hex(offset)})" for va, offset in sorted(allowed))
    return [f"{SYMBOL}: use exactly one verified owner-handle setter site in current EquipWeapon: {choices}."]


async def find_signature_matches(session, signature):
    response = parse_mcp_result(
        await session.call_tool(name="find_bytes", arguments={"patterns": [signature], "limit": 2})
    )
    if not isinstance(response, list) or not response or response[0].get("n") != 1:
        return []
    return [int(str(address), 0) for address in response[0].get("matches", [])]


async def can_reuse(session, payload, sites):
    """A globally unique old signature can migrate to an unrelated sibling call."""
    offset = _parse_llm_int_value(payload.get("vfunc_offset"))
    if (
        not payload.get("vfunc_sig")
        or payload.get("func_sig")
        or offset != sites[0]["vfunc_offset"]
        or _parse_llm_int_value(payload.get("vfunc_index")) != offset // SLOT_SIZE
        or _parse_llm_int_value(str(payload.get("vfunc_sig_disp", 0))) != 0
    ):
        return False
    matches = await find_signature_matches(session, payload["vfunc_sig"])
    return len(matches) == 1 and matches[0] in {site["insn_va"] for site in sites}
