#!/usr/bin/env python3
"""Shared preprocess helpers for indirect virtual-call (vcall) target skills.

Locate a virtual-function vtable slot by scanning a known source function
(typically a thin thunk/wrapper) for an indirect branch of the form
``jmp/call qword ptr [reg+disp]`` and reading the displacement as the vfunc
offset. This is a deterministic alternative to LLM_DECOMPILE + vfunc_sig
generation for interface vfuncs whose only stable anchor is a single indirect
vtable call inside a caller/thunk (e.g. ``INetworkGameServer`` methods
dispatched by ``CNetworkServerService`` thunks). Signing such a call site is
unreliable because the ``jmp qword ptr [reg+disp8]`` encoding (e.g. offset
``0x68`` -> ``FF 60 68``) is only 3 bytes and rarely unique.

The scan mirrors ``_direct_branch_target_common`` but resolves a vtable *slot*
(offset/index) instead of a concrete branch target, so the output is slot-only:
``func_name, vtable_name, vfunc_offset, vfunc_index``. The source function is
re-scanned every run, so a vtable layout shift is picked up automatically.

Some compilers split the dispatch so the slot displacement lives in a load
rather than the branch itself (e.g. Linux/GCC emits ``mov rax, [rax+78h]`` then
``jmp rax`` where Windows/MSVC emits ``jmp qword ptr [rax+78h]``). Passing
``resolve_load_then_branch=True`` makes the scan resolve a register-indirect
branch to the vtable slot via a control-flow-aware backward walk: from the
branch's basic block it climbs the predecessor chain to the reaching
``mov reg, [base+disp]`` load. Walking real control-flow edges (rather than
linear address order) lets it see past an early-out guard whose *not-taken*
path clobbers the register -- e.g. ``mov rax,[rax+128h]; cmp rax,rdx; jnz L;
mov eax,-1; retn; L: jmp rax`` -- which a linear scan would mis-resolve. It is
opt-in and off by default, leaving the strict memory-indirect-only scan
unchanged for existing callers.

``preprocess_vcall_on_global_skill`` covers the other shape: a large function
that dispatches on a *global singleton* rather than a thin thunk. There the
"exactly one indirect branch in the body" rule cannot select the right slot, so
that resolver anchors on a reference to the global instead of on the branch and
walks the dereference chain forward. See its docstring for details.
"""

import json
import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import parse_mcp_result, write_func_yaml


_SUPPORTED_FIELDS = {
    "func_name",
    "vtable_name",
    "vfunc_offset",
    "vfunc_index",
}


_INDIRECT_VCALL_TARGET_PY_EVAL = """import idaapi, idautils, idc, json
func_addr = __FUNC_ADDR__
allowed_mnemonics = set(__ALLOWED_MNEMONICS__)
resolve_load_then_branch = __RESOLVE_LOAD_THEN_BRANCH__
result_obj = None
if not idaapi.get_func(func_addr):
    idaapi.add_func(func_addr)
func = idaapi.get_func(func_addr)

NON_DEF_MNEMONICS = {"cmp", "test", "push", "jmp"}


def _reg_def_kind(ea, reg):
    # Classify how the instruction at `ea` defines register `reg`:
    #   ("load", disp) -- `mov reg, [base+disp]` (a vtable-slot load)
    #   ("other", )    -- any other write to reg (clobbers a tracked slot)
    #   None           -- does not write reg
    insn = idaapi.insn_t()
    if not idaapi.decode_insn(insn, ea):
        return None
    mnem = idc.print_insn_mnem(ea).lower()
    if mnem == "mov":
        dst = insn.ops[0]
        src = insn.ops[1]
        if dst.type == idaapi.o_reg and dst.reg == reg:
            if src.type in (idaapi.o_displ, idaapi.o_phrase):
                return ("load", int(src.addr) & 0xFFFFFFFF)
            return ("other", )
        return None
    # A call clobbers its return register; treat it as an opaque redefinition.
    if mnem == "call":
        return ("other", )
    op0 = insn.ops[0]
    if op0.type == idaapi.o_reg and op0.reg == reg and mnem not in NON_DEF_MNEMONICS:
        return ("other", )
    return None


def _resolve_reg_branch(fc, branch_ea, reg):
    # Control-flow-aware backward search: resolve a register-indirect branch
    # (`jmp/call reg`) to the vtable slot it dispatches through by walking back
    # over the dominating basic-block chain to the reaching `mov reg,[base+disp]`
    # load. This sees past an early-out guard whose *not-taken* path clobbers reg
    # (e.g. the Linux/GCC form `mov rax,[rax+128h]; cmp rax,rdx; jnz L;
    # mov eax,-1; retn; L: jmp rax`), which a purely linear scan cannot. Returns
    # the single offset when all explored paths agree, else None.
    start = None
    for b in fc:
        if b.start_ea <= branch_ea < b.end_ea:
            start = b
            break
    if start is None:
        return None
    found = set()
    visited = set()
    stack = [(start, branch_ea)]
    steps = 0
    while stack and steps < 256:
        steps += 1
        block, upper = stack.pop()
        kind = None
        for h in reversed([x for x in idautils.Heads(block.start_ea, block.end_ea) if x < upper]):
            kind = _reg_def_kind(h, reg)
            if kind is not None:
                break
        if kind is not None:
            # A load contributes its offset; a non-load clobber contributes
            # nothing -- either way this path is resolved, so stop climbing it.
            if kind[0] == "load":
                found.add(kind[1])
            continue
        for p in block.preds():
            if p.id not in visited:
                visited.add(p.id)
                stack.append((p, p.end_ea))
    if len(found) == 1:
        return next(iter(found))
    return None


# py_eval runs this template via `exec(code, globals, locals)` with distinct
# dicts, so the top-level constants/imports/helpers above land in `locals` and
# are invisible to each other's function bodies (which resolve names via
# `globals`). Bridge them into globals before the main logic -- the repo-wide
# py_eval idiom that avoids NameError at runtime.
globals().update(locals())

if func:
    fc = None
    targets = []
    seen = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        insn = idaapi.insn_t()
        if not idaapi.decode_insn(insn, head):
            continue
        mnem = idc.print_insn_mnem(head).lower()
        if mnem not in allowed_mnemonics:
            continue
        op = insn.ops[0]
        # o_displ = [reg+disp]; o_phrase = [reg] (disp 0): register-based
        # memory-indirect branches (vtable calls). o_mem (rip-relative / absolute
        # global pointer) is intentionally excluded. o_reg (branch through a bare
        # register) is resolved from its reaching vtable-slot load when enabled.
        offset = None
        if op.type in (idaapi.o_displ, idaapi.o_phrase):
            offset = int(op.addr) & 0xFFFFFFFF
        elif resolve_load_then_branch and op.type == idaapi.o_reg:
            if fc is None:
                fc = idaapi.FlowChart(func, flags=idaapi.FC_PREDS)
            offset = _resolve_reg_branch(fc, head, op.reg)
        if offset is None:
            continue
        # vtable slots are non-negative and pointer-aligned; drop anything else.
        if offset % 8 != 0:
            continue
        if offset in seen:
            continue
        seen.add(offset)
        targets.append({
            "source_ea": hex(head),
            "source_mnemonic": mnem,
            "vfunc_offset": hex(offset),
            "vfunc_index": offset // 8,
        })
    result_obj = {
        "source_func_va": hex(func.start_ea),
        "source_func_size": hex(func.end_ea - func.start_ea),
        "targets": targets,
    }
result = json.dumps(result_obj)
"""


def _debug(debug, message):
    if debug:
        print(f"    Preprocess: {message}")


def _read_yaml(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception:
        return None


def _parse_int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ValueError("empty integer string")
        return int(raw, 0)
    return int(value)


def _normalize_requested_fields(generate_yaml_desired_fields, target_name, debug=False):
    if not generate_yaml_desired_fields:
        _debug(debug, "missing generate_yaml_desired_fields")
        return None

    desired_map = {}
    try:
        for symbol_name, fields in generate_yaml_desired_fields:
            desired_map[str(symbol_name)] = list(fields)
    except Exception:
        _debug(debug, "invalid generate_yaml_desired_fields")
        return None

    fields = desired_map.get(target_name)
    if not fields:
        _debug(debug, f"missing desired fields for {target_name}")
        return None

    normalized = []
    seen = set()
    for field in fields:
        field_name = str(field)
        if field_name not in _SUPPORTED_FIELDS:
            _debug(debug, f"unsupported requested field for {target_name}: {field_name}")
            return None
        if field_name in seen:
            _debug(debug, f"duplicate requested field for {target_name}: {field_name}")
            return None
        seen.add(field_name)
        normalized.append(field_name)

    return normalized


def _resolve_output_path(expected_outputs, target_name, platform, debug=False):
    filename = f"{target_name}.{platform}.yaml"
    matches = [path for path in expected_outputs if os.path.basename(path) == filename]
    if len(matches) != 1:
        _debug(debug, f"expected exactly one output for {filename}")
        return None
    return matches[0]


async def _call_py_eval_json(session, code, debug=False, error_label="py_eval"):
    try:
        result = await session.call_tool(name="py_eval", arguments={"code": code})
        result_data = parse_mcp_result(result)
    except Exception:
        _debug(debug, f"{error_label} error")
        return None

    raw = None
    if isinstance(result_data, dict):
        stderr_text = result_data.get("stderr", "")
        if stderr_text and debug:
            print("    Preprocess: py_eval stderr:")
            print(str(stderr_text).strip())
        raw = result_data.get("result", "")
    elif result_data is not None:
        raw = str(result_data)

    if not raw:
        return None

    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        _debug(debug, f"invalid JSON result from {error_label}")
        return None


def _build_indirect_vcall_target_py_eval(func_va, allowed_mnemonics, resolve_load_then_branch=False):
    normalized = [str(item).lower() for item in allowed_mnemonics]
    return (
        _INDIRECT_VCALL_TARGET_PY_EVAL.replace("__FUNC_ADDR__", str(func_va))
        .replace("__ALLOWED_MNEMONICS__", json.dumps(normalized))
        .replace("__RESOLVE_LOAD_THEN_BRANCH__", "True" if resolve_load_then_branch else "False")
    )


class IndirectVcallTargetLocator:
    """Locate register-based indirect vcall slots inside a known source function."""

    def __init__(self, session, debug=False):
        self.session = session
        self.debug = debug

    async def collect_targets(
        self,
        source_func_va,
        allowed_mnemonics=("call", "jmp"),
        resolve_load_then_branch=False,
    ):
        code = _build_indirect_vcall_target_py_eval(
            func_va=source_func_va,
            allowed_mnemonics=allowed_mnemonics,
            resolve_load_then_branch=resolve_load_then_branch,
        )
        parsed = await _call_py_eval_json(
            session=self.session,
            code=code,
            debug=self.debug,
            error_label="py_eval collecting indirect vcall targets",
        )
        if not isinstance(parsed, dict):
            _debug(self.debug, "failed to collect indirect vcall targets")
            return None

        raw_targets = parsed.get("targets")
        if not isinstance(raw_targets, list):
            _debug(self.debug, "indirect vcall target result missing targets list")
            return None

        targets = []
        seen = set()
        for item in raw_targets:
            if not isinstance(item, dict):
                _debug(self.debug, "invalid indirect vcall target entry")
                return None
            try:
                offset = _parse_int(item.get("vfunc_offset"))
            except Exception:
                _debug(self.debug, f"invalid vfunc_offset: {item.get('vfunc_offset')}")
                return None
            if offset < 0 or offset % 8 != 0:
                _debug(self.debug, f"vfunc_offset must be non-negative and 8-byte aligned: {offset}")
                return None
            if offset in seen:
                continue
            seen.add(offset)
            targets.append(
                {
                    "source_ea": str(item.get("source_ea", "")),
                    "source_mnemonic": str(item.get("source_mnemonic", "")),
                    "vfunc_offset": hex(offset),
                    "vfunc_index": offset // 8,
                }
            )

        return targets


async def preprocess_indirect_vcall_target_skill(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    source_yaml_stem,
    target_name,
    vtable_name,
    generate_yaml_desired_fields,
    allowed_mnemonics=("call", "jmp"),
    resolve_load_then_branch=False,
    expected_target_count=1,
    debug=False,
):
    """Scan ``source_yaml_stem`` for its unique indirect vcall and write a slot-only vfunc YAML.

    The source function is located via its previously written output YAML
    (``{source_yaml_stem}.{platform}.yaml`` in ``new_binary_dir``); its body is
    scanned for register-based indirect branches. Exactly ``expected_target_count``
    (default 1) unique vtable-slot offset must be found, otherwise the skill fails.

    When ``resolve_load_then_branch`` is set, a register-indirect branch
    (``jmp/call reg``) is also resolved by a control-flow-aware backward walk
    from the branch's basic block up the predecessor chain to the reaching
    ``mov reg, [base+disp]`` load, so the split dispatch form
    ``mov rax, [rax+78h]`` / ``jmp rax`` (common on Linux/GCC) yields the same
    slot as the direct ``jmp qword ptr [rax+78h]`` form emitted on Windows --
    even when an early-out guard clobbers the register on its not-taken path.
    """
    if yaml is None:
        _debug(debug, "PyYAML is required")
        return False

    if expected_target_count != 1:
        _debug(debug, "expected_target_count must be 1")
        return False

    requested_fields = _normalize_requested_fields(
        generate_yaml_desired_fields,
        target_name,
        debug=debug,
    )
    if requested_fields is None:
        return False

    output_path = _resolve_output_path(
        expected_outputs,
        target_name,
        platform,
        debug=debug,
    )
    if output_path is None:
        return False

    source_path = os.path.join(
        new_binary_dir,
        f"{source_yaml_stem}.{platform}.yaml",
    )
    source_yaml = _read_yaml(source_path)
    if not isinstance(source_yaml, dict) or not source_yaml.get("func_va"):
        _debug(debug, f"failed to read source function YAML: {source_path}")
        return False

    source_func_va = str(source_yaml["func_va"])
    locator = IndirectVcallTargetLocator(session=session, debug=debug)
    targets = await locator.collect_targets(
        source_func_va=source_func_va,
        allowed_mnemonics=allowed_mnemonics,
        resolve_load_then_branch=resolve_load_then_branch,
    )
    if not isinstance(targets, list) or len(targets) != expected_target_count:
        count = len(targets) if isinstance(targets, list) else "N/A"
        _debug(
            debug,
            f"expected {expected_target_count} indirect vcall target, got {count}",
        )
        return False

    target = targets[0]
    available = {
        "func_name": target_name,
        "vtable_name": vtable_name,
        "vfunc_offset": target["vfunc_offset"],
        "vfunc_index": target["vfunc_index"],
    }

    payload = {}
    for field in requested_fields:
        if field not in available:
            _debug(debug, f"requested field is not available for {target_name}: {field}")
            return False
        payload[field] = available[field]

    write_func_yaml(output_path, payload)

    if debug:
        print(
            f"    Preprocess: written {os.path.basename(output_path)} from indirect vcall target "
            f"{target['source_mnemonic']} @ {target['source_ea']} -> vfunc_offset {target['vfunc_offset']}"
        )

    return True


_VCALL_ON_GLOBAL_PY_EVAL = """import idaapi, idautils, idc, json
func_addr = __FUNC_ADDR__
global_va = __GLOBAL_VA__
max_levels = __MAX_LEVELS__

# Mnemonics that read (or only partially touch) their first operand, so they do
# not end a dereference chain that is currently held in that register.
BREAK_EXEMPT = {"cmp", "test", "push", "nop"}


def _decode(ea):
    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, ea):
        return insn
    return None


def _mem_base_disp(op):
    # Return (base_reg, displacement) for a plain [base] / [base+disp] operand.
    # SIB forms are rejected: an indexed access is an array read, not the
    # single-pointer dereference this walk models.
    if op.type not in (idaapi.o_displ, idaapi.o_phrase):
        return None
    if op.specflag1:
        return None
    disp = int(op.addr) if op.type == idaapi.o_displ else 0
    return (op.phrase, disp & 0xFFFFFFFFFFFFFFFF)


globals().update(locals())

func = idaapi.get_func(func_addr)
result_obj = None
if func:
    heads = list(idautils.Heads(func.start_ea, func.end_ea))
    order = {ea: i for i, ea in enumerate(heads)}

    # Index every indirect branch through a bare register by that register, so a
    # resolved slot can be confirmed as actually dispatched rather than merely
    # loaded. Compilers freely spill and reload the slot between the load and
    # the call, so this deliberately does not require the definition to reach
    # the branch -- only that the register is branched through later.
    reg_branches = {}
    for ea in heads:
        insn = _decode(ea)
        if insn is None:
            continue
        if (idc.print_insn_mnem(ea) or "").lower() not in ("call", "jmp"):
            continue
        op = insn.ops[0]
        if op.type == idaapi.o_reg:
            reg_branches.setdefault(op.reg, []).append(ea)

    chains = []
    for ref in idautils.DataRefsTo(global_va):
        if not (func.start_ea <= ref < func.end_ea) or ref not in order:
            continue
        ref_insn = _decode(ref)
        if ref_insn is None or ref_insn.ops[0].type != idaapi.o_reg:
            continue

        # `mov reg, cs:g` loads the global's value; `lea reg, g` loads its
        # address. The extra indirection the PIC/`lea` form introduces is just
        # one more zero-displacement dereference, so both are walked uniformly.
        cur = ref_insn.ops[0].reg
        levels = 0
        found = None
        trace = [hex(ref) + " " + (idc.GetDisasm(ref) or "")]

        for j in range(order[ref] + 1, len(heads)):
            ea = heads[j]
            insn = _decode(ea)
            if insn is None:
                break
            mnem = (idc.print_insn_mnem(ea) or "").lower()
            op0 = insn.ops[0]

            # A vtable dispatch that never materializes the slot in a register:
            # `call qword ptr [vptr+disp]`.
            if mnem in ("call", "jmp"):
                branch = _mem_base_disp(op0)
                if branch is not None and branch[0] == cur and branch[1]:
                    trace.append(hex(ea) + " " + (idc.GetDisasm(ea) or ""))
                    found = {"offset": branch[1], "load_ea": ea, "branch_ea": ea}
                    break

            if mnem == "mov" and op0.type == idaapi.o_reg:
                src = _mem_base_disp(insn.ops[1])
                if src is not None and src[0] == cur:
                    trace.append(hex(ea) + " " + (idc.GetDisasm(ea) or ""))
                    if src[1] == 0:
                        # Another level of pointer chasing (global -> object ->
                        # vtable pointer); keep walking.
                        cur = op0.reg
                        levels += 1
                        if levels > max_levels:
                            break
                        continue
                    # First non-zero displacement off the dereference chain is
                    # the vtable slot.
                    found = {"offset": src[1], "load_ea": ea, "slot_reg": op0.reg}
                    break

            # An unconditional branch or a call ends the linear walk: the former
            # leaves this instruction stream, the latter clobbers the volatile
            # registers the chain may live in.
            if mnem in ("call", "jmp"):
                break
            if op0.type == idaapi.o_reg and op0.reg == cur and mnem not in BREAK_EXEMPT:
                break

        if found is None:
            chains.append({"ref": hex(ref), "status": "unresolved", "trace": trace})
            continue

        offset = found["offset"]
        branch_ea = found.get("branch_ea")
        if branch_ea is None:
            for candidate in reg_branches.get(found.get("slot_reg"), []):
                if candidate > found["load_ea"]:
                    branch_ea = candidate
                    break
        if branch_ea is None:
            chains.append({"ref": hex(ref), "status": "not-dispatched", "trace": trace})
            continue
        if offset <= 0 or offset % 8 or offset > 0x4000:
            chains.append({"ref": hex(ref), "status": "bad-offset", "offset": hex(offset), "trace": trace})
            continue

        chains.append({
            "ref": hex(ref),
            "status": "resolved",
            "vfunc_offset": hex(offset),
            "vfunc_index": offset // 8,
            "load_ea": hex(found["load_ea"]),
            "branch_ea": hex(branch_ea),
            "trace": trace,
        })

    result_obj = {"source_func_va": hex(func.start_ea), "chains": chains}

result = json.dumps(result_obj)
"""


def _build_vcall_on_global_py_eval(func_va, global_va, max_deref_levels):
    return (
        _VCALL_ON_GLOBAL_PY_EVAL.replace("__FUNC_ADDR__", str(func_va))
        .replace("__GLOBAL_VA__", str(global_va))
        .replace("__MAX_LEVELS__", str(int(max_deref_levels)))
    )


async def preprocess_vcall_on_global_skill(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    source_yaml_stem,
    global_yaml_stem,
    target_name,
    vtable_name,
    generate_yaml_desired_fields,
    max_deref_levels=4,
    debug=False,
):
    """Resolve the vtable slot dispatched on a *global object* and write a slot-only YAML.

    ``preprocess_indirect_vcall_target_skill`` fits a thin thunk whose whole body
    is one indirect branch. It does not fit a large function that dispatches on a
    global singleton: such a body holds several unrelated vtable calls (so the
    "exactly one slot" rule cannot select the right one), and its backward walk
    from the branch mis-resolves a slot the compiler spilled to the stack and
    reloaded across an intervening call.

    This resolver anchors on the *data* instead of the branch. Starting at each
    reference to ``global_yaml_stem``'s address inside ``source_yaml_stem``, it
    walks forward through zero-displacement dereferences (global -> object ->
    vtable pointer) and takes the first non-zero displacement off that chain as
    the vtable slot. Anchoring this way makes the two platforms' dispatch forms
    converge without a per-platform branch: MSVC's ``mov reg, cs:g`` loads the
    global's value while GCC/PIC's ``lea reg, g`` loads its address, and the
    extra indirection that costs is simply one more zero-displacement step.

    Unrelated vtable calls in the same function are excluded because they are not
    reachable from a ``global_va`` reference, and the spill/reload problem does
    not arise because the walk moves forward from the load rather than backward
    from the branch. Every candidate must still be confirmed as dispatched (its
    register is branched through later, or the slot load *is* the branch), and
    all resolved chains must agree on a single offset.
    """
    if yaml is None:
        _debug(debug, "PyYAML is required")
        return False

    requested_fields = _normalize_requested_fields(
        generate_yaml_desired_fields,
        target_name,
        debug=debug,
    )
    if requested_fields is None:
        return False

    output_path = _resolve_output_path(expected_outputs, target_name, platform, debug=debug)
    if output_path is None:
        return False

    source_path = os.path.join(new_binary_dir, f"{source_yaml_stem}.{platform}.yaml")
    source_yaml = _read_yaml(source_path)
    if not isinstance(source_yaml, dict) or not source_yaml.get("func_va"):
        _debug(debug, f"failed to read source function YAML: {source_path}")
        return False

    global_path = os.path.join(new_binary_dir, f"{global_yaml_stem}.{platform}.yaml")
    global_yaml = _read_yaml(global_path)
    if not isinstance(global_yaml, dict) or not global_yaml.get("gv_va"):
        _debug(debug, f"failed to read global variable YAML: {global_path}")
        return False

    try:
        source_func_va = _parse_int(source_yaml["func_va"])
        global_va = _parse_int(global_yaml["gv_va"])
    except Exception:
        _debug(debug, "invalid func_va/gv_va in input YAML")
        return False

    parsed = await _call_py_eval_json(
        session=session,
        code=_build_vcall_on_global_py_eval(source_func_va, global_va, max_deref_levels),
        debug=debug,
        error_label="py_eval resolving vcall on global",
    )
    if not isinstance(parsed, dict) or not isinstance(parsed.get("chains"), list):
        _debug(debug, f"failed to resolve vcall on global for {target_name}")
        return False

    chains = parsed["chains"]
    if debug:
        for chain in chains:
            print(f"    Preprocess: chain {chain.get('ref')} -> {chain.get('status')}")
            for line in chain.get("trace", []):
                print(f"      {line}")

    resolved = [chain for chain in chains if chain.get("status") == "resolved"]
    if not resolved:
        _debug(debug, f"no dispatched vtable slot reachable from {global_yaml_stem} in {source_yaml_stem}")
        return False

    offsets = {str(chain.get("vfunc_offset")) for chain in resolved}
    if len(offsets) != 1:
        _debug(debug, f"ambiguous vtable slot for {target_name}: {sorted(offsets)}")
        return False

    target = resolved[0]
    available = {
        "func_name": target_name,
        "vtable_name": vtable_name,
        "vfunc_offset": target["vfunc_offset"],
        "vfunc_index": target["vfunc_index"],
    }

    payload = {}
    for field in requested_fields:
        if field not in available:
            _debug(debug, f"requested field is not available for {target_name}: {field}")
            return False
        payload[field] = available[field]

    write_func_yaml(output_path, payload)

    if debug:
        print(
            f"    Preprocess: written {os.path.basename(output_path)} from vcall on "
            f"{global_yaml_stem} @ {target['branch_ea']} -> vfunc_offset {target['vfunc_offset']}"
        )

    return True
