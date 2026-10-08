"""Resolve a ConVar's unique runtime reader through its registration."""

import json
from pathlib import Path

import yaml

from ida_analyze_util import parse_mcp_result, preprocess_gen_func_sig_via_mcp, write_func_yaml
from ida_preprocessor_scripts._define_inputfunc import _resolve_output_path


CONVAR_READER_QUERY = r"""
import json, ida_hexrays as h, ida_funcs, ida_bytes, ida_nalt, ida_segment, idautils, idc

def address(expr):
    while expr.op in (h.cot_cast, h.cot_ref):
        expr = expr.x
    if expr.op == h.cot_obj:
        return int(expr.obj_ea)
    if expr.op == h.cot_num:
        value = int(expr.numval())
        if not ida_bytes.is_loaded(value):
            value = (ida_nalt.get_imagebase() & ~0xffffffff) | (value & 0xffffffff)
        return value
    return None

class Registrations(h.ctree_visitor_t):
    def __init__(self, strings):
        super().__init__(h.CV_FAST)
        self.strings = strings
        self.globals = set()
        self.destructors = set()
    def visit_expr(self, expr):
        if expr.op == h.cot_call and expr.a.size() == 1:
            target = address(expr.a[0])
            if target is not None and ida_funcs.get_func(target):
                self.destructors.add(target)
        if expr.op == h.cot_call and expr.a.size() >= 2:
            name_expr = expr.a[1]
            while name_expr.op in (h.cot_cast, h.cot_ref):
                name_expr = name_expr.x
            matches_name = name_expr.op == h.cot_str and name_expr.string == convar_name
            if matches_name or address(expr.a[1]) in self.strings:
                target = address(expr.a[0])
                if target is not None and ida_segment.getseg(target):
                    self.globals.add(target)
        return 0

strings = {int(s.ea) for s in idautils.Strings() if str(s) == convar_name}
registrations = set()
for ea in strings:
    for ref in idautils.XrefsTo(ea):
        func = ida_funcs.get_func(ref.frm)
        if func:
            registrations.add(func.start_ea)
objects = set()
destructors = set()
for ea in registrations:
    visitor = Registrations(strings)
    visitor.apply_to(h.decompile(ea).body, None)
    objects.update(visitor.globals)
    destructors.update(visitor.destructors)
readers = set()
for obj in objects:
    # The ConVar wrapper owns a handle and its backing value pointer.
    for location in (obj, obj + 8):
        for ref in idautils.XrefsTo(location):
            func = ida_funcs.get_func(ref.frm)
            if not func or func.start_ea in registrations or func.start_ea in destructors:
                continue
            # Older builds call the accessor with the wrapper address; newer
            # builds directly load its backing pointer.
            if idc.print_insn_mnem(ref.frm) in ('mov', 'lea') and idc.get_operand_value(ref.frm, 1) == location:
                readers.add(func.start_ea)
result = {'objects': sorted(objects), 'readers': sorted(readers)}
"""


async def preprocess_convar_function(
    session,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    *,
    convar_name,
    target_name,
    desired_fields,
    vtable_name=None,
    debug=False,
):
    namespace = "namespace = {}\nexec(" + repr("convar_name = " + repr(convar_name) + "\n" + CONVAR_READER_QUERY)
    code = namespace + ", namespace)\nresult = json.dumps(namespace['result'])"
    response = parse_mcp_result(await session.call_tool("py_eval", {"code": "import json\n" + code}))
    if response.get("stderr"):
        raise RuntimeError(response["stderr"])
    found = json.loads(response.get("result", "null"))
    if not found or len(found["objects"]) != 1 or len(found["readers"]) != 1:
        if debug:
            print(f"    Preprocess: ambiguous ConVar reader for {convar_name}: {found}")
        return False
    target = found["readers"][0]
    payload = await preprocess_gen_func_sig_via_mcp(session, hex(target), image_base, debug=debug)
    if not payload or not payload.get("func_sig"):
        return False
    payload["func_name"] = target_name
    if vtable_name:
        path = Path(new_binary_dir) / f"{vtable_name}_vtable.{platform}.yaml"
        table = yaml.safe_load(path.read_text(encoding="utf-8"))
        slots = [int(slot) for slot, ea in table["vtable_entries"].items() if int(ea, 0) == target]
        if len(slots) != 1:
            return False
        payload.update(vtable_name=vtable_name, vfunc_index=slots[0], vfunc_offset=hex(slots[0] * 8))
    output = _resolve_output_path(expected_outputs, target_name, platform, debug)
    if not output:
        return False
    write_func_yaml(output, {field: payload[field] for field in dict(desired_fields)[target_name]})
    return True
