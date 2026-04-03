#!/usr/bin/env python3
"""Shared utility helpers for IDA analyze scripts."""

import json
import os

try:
    import yaml
except ImportError:
    yaml = None


# Combined vtable lookup + entry reading script for IDA py_eval.
# Merges logic from get-vtable-address/SKILL.md and write-vtable-as-yaml/SKILL.md.
# Uses CLASS_NAME_PLACEHOLDER for substitution (avoids brace-escaping issues).
# Returns JSON via the 'result' variable.
_VTABLE_PY_EVAL_TEMPLATE = r'''
import ida_bytes, ida_name, idaapi, idautils, ida_segment, json

class_name = "CLASS_NAME_PLACEHOLDER"
ptr_size = 8 if idaapi.inf_is_64bit() else 4

vtable_start = None
vtable_symbol = ""
is_linux = False

# Direct symbol: Windows ??_7ClassName@@6B@
win_name = "??_7" + class_name + "@@6B@"
addr = ida_name.get_name_ea(idaapi.BADADDR, win_name)
if addr != idaapi.BADADDR:
    vtable_start = addr
    vtable_symbol = win_name
    is_linux = False

# Direct symbol: Linux _ZTV<len>ClassName
if vtable_start is None:
    linux_name = "_ZTV" + str(len(class_name)) + class_name
    addr = ida_name.get_name_ea(idaapi.BADADDR, linux_name)
    if addr != idaapi.BADADDR:
        vtable_start = addr + 0x10
        vtable_symbol = linux_name + " + 0x10"
        is_linux = True

# RTTI fallback: Windows ??_R4ClassName@@6B@
if vtable_start is None:
    col_name = "??_R4" + class_name + "@@6B@"
    col_addr = ida_name.get_name_ea(idaapi.BADADDR, col_name)
    if col_addr != idaapi.BADADDR:
        is_linux = False
        rdata_seg = ida_segment.get_segm_by_name(".rdata")
        for ref in idautils.DataRefsTo(col_addr):
            if rdata_seg and not (rdata_seg.start_ea <= ref < rdata_seg.end_ea):
                continue
            vtable_start = ref + ptr_size
            sym = ida_name.get_name(vtable_start) or ("??_7" + class_name + "@@6B@")
            vtable_symbol = sym
            break

# RTTI fallback: Linux _ZTI<len>ClassName
if vtable_start is None:
    ti_name = "_ZTI" + str(len(class_name)) + class_name
    ti_addr = ida_name.get_name_ea(idaapi.BADADDR, ti_name)
    if ti_addr != idaapi.BADADDR:
        is_linux = True
        for ref in idautils.DataRefsTo(ti_addr):
            ott = ida_bytes.get_qword(ref - ptr_size) if ptr_size == 8 else ida_bytes.get_dword(ref - ptr_size)
            if ott == 0:
                vtable_start = ref + ptr_size
                ztv_addr = ref - ptr_size
                ztv_name = ida_name.get_name(ztv_addr) or ("_ZTV" + str(len(class_name)) + class_name)
                vtable_symbol = ztv_name + " + 0x10"
                break

if vtable_start is None:
    result = json.dumps(None)
else:
    vtable_seg = ida_segment.getseg(vtable_start)
    entries = {}
    count = 0
    for i in range(1000):
        ea = vtable_start + i * ptr_size
        if is_linux and i > 0:
            name = ida_name.get_name(ea)
            if name and (name.startswith("_ZTV") or name.startswith("_ZTI")):
                break
        ptr_value = ida_bytes.get_qword(ea) if ptr_size == 8 else ida_bytes.get_dword(ea)
        if ptr_value == 0:
            if is_linux:
                entries[count] = hex(ptr_value)
                count += 1
                continue
            else:
                break
        if ptr_value == 0xFFFFFFFFFFFFFFFF:
            break
        target_seg = ida_segment.getseg(ptr_value)
        if not target_seg:
            break
        # If an entry points back into the vtable's own segment (.rdata/.rodata),
        # it is metadata or unrelated data, not a virtual function.
        if vtable_seg and (vtable_seg.start_ea <= ptr_value < vtable_seg.end_ea):
            break
        if not (target_seg.perm & ida_segment.SEGPERM_EXEC):
            break
        func = idaapi.get_func(ptr_value)
        if func is not None:
            entries[count] = hex(ptr_value)
            count += 1
            continue
        flags = ida_bytes.get_full_flags(ptr_value)
        if ida_bytes.is_code(flags):
            entries[count] = hex(ptr_value)
            count += 1
            continue
        break

    size_in_bytes = count * ptr_size
    result = json.dumps({
        "vtable_class": class_name,
        "vtable_symbol": vtable_symbol,
        "vtable_va": hex(vtable_start),
        "vtable_size": hex(size_in_bytes),
        "vtable_numvfunc": count,
        "vtable_entries": entries
    })
'''


def parse_mcp_result(result):
    """Parse CallToolResult content to a Python object."""
    if result.content:
        text = result.content[0].text
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text
    return None


def _build_vtable_py_eval(class_name):
    """Build the vtable py_eval script for the given class name."""
    return _VTABLE_PY_EVAL_TEMPLATE.replace("CLASS_NAME_PLACEHOLDER", class_name)


def write_vtable_yaml(path, data):
    """Write vtable YAML matching the format produced by write-vtable-as-yaml skill."""
    if yaml is None:
        raise RuntimeError("PyYAML is required to write vtable YAML")

    raw_entries = data.get("vtable_entries", {})
    normalized_entries = {int(k): str(v) for k, v in raw_entries.items()}
    payload = {
        "vtable_class": data["vtable_class"],
        "vtable_symbol": data["vtable_symbol"],
        "vtable_va": str(data["vtable_va"]),
        "vtable_rva": str(data["vtable_rva"]),
        "vtable_size": str(data["vtable_size"]),
        "vtable_numvfunc": data["vtable_numvfunc"],
        "vtable_entries": dict(sorted(normalized_entries.items())),
    }

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            payload,
            f,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=False,
        )

def write_func_yaml(path, data):
    """Write function/vfunc YAML with the same key set and key order as write-func-as-yaml; scalar quoting/styling is handled by PyYAML."""
    if yaml is None:
        raise RuntimeError("PyYAML is required to write function YAML")

    ordered_keys = [
        "func_name", "func_va", "func_rva", "func_size", "func_sig",
        "vtable_name", "vfunc_offset", "vfunc_index", "vfunc_sig",
    ]
    payload = {key: data[key] for key in ordered_keys if key in data}

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            payload,
            f,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=False,
        )

def write_gv_yaml(path, data):
    """Write global-variable YAML with the same key set and key order as write-globalvar-as-yaml; scalar quoting/styling is handled by PyYAML."""
    if yaml is None:
        raise RuntimeError("PyYAML is required to write global-variable YAML")

    ordered_keys = [
        "gv_name",
        "gv_va", "gv_rva", "gv_sig", "gv_sig_va",
        "gv_inst_offset", "gv_inst_length", "gv_inst_disp",
    ]
    payload = {key: data[key] for key in ordered_keys if key in data}

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            payload,
            f,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=False,
        )




def write_patch_yaml(path, data):
    """Write patch YAML with stable key order."""
    if yaml is None:
        raise RuntimeError("PyYAML is required to write patch YAML")

    ordered_keys = [
        "patch_name",
        "patch_sig",
        "patch_bytes",
    ]
    payload = {key: data[key] for key in ordered_keys if key in data}

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            payload,
            f,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=False,
        )

def write_struct_offset_yaml(path, data):
    """Write struct-member offset YAML matching write-structoffset-as-yaml key order."""
    if yaml is None:
        raise RuntimeError("PyYAML is required to write struct offset YAML")

    ordered_keys = [
        "struct_name",
        "member_name",
        "offset",
        "size",
        "offset_sig",
        "offset_sig_disp",
    ]
    payload = {key: data[key] for key in ordered_keys if key in data}

    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            payload,
            f,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=False,
        )

async def preprocess_vtable_via_mcp(session, class_name, image_base, platform, debug=False):
    """
    Preprocess a vtable output by looking up the class vtable via py_eval.

    No old YAML is needed - vtable lookup is purely class-name-based.

    Args:
        session: Active MCP ClientSession
        class_name: Class name (e.g., "CSource2Server")
        image_base: Binary image base address (int)
        platform: "windows" or "linux"
        debug: Enable debug output

    Returns:
        Dict with vtable YAML data, or None on failure
    """
    _ = platform  # Reserved for future platform-specific behavior.
    py_code = _build_vtable_py_eval(class_name)

    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code}
        )
        result_data = parse_mcp_result(result)
    except Exception as e:
        if debug:
            print(f"    Preprocess vtable: py_eval error for {class_name}: {e}")
        return None

    # Parse py_eval result
    vtable_info = None
    if isinstance(result_data, dict):
        result_str = result_data.get("result", "")
        if result_str:
            try:
                vtable_info = json.loads(result_str)
            except (json.JSONDecodeError, TypeError):
                pass

    if not vtable_info or not isinstance(vtable_info, dict):
        if debug:
            print(f"    Preprocess vtable: no result for {class_name}")
        return None

    # Compute vtable_rva (py_eval doesn't know image_base)
    vtable_va_int = int(vtable_info["vtable_va"], 16)
    vtable_rva = hex(vtable_va_int - image_base)

    # Convert vtable_entries keys from string to int (JSON serialization side-effect)
    raw_entries = vtable_info.get("vtable_entries", {})
    entries = {int(k): v for k, v in raw_entries.items()}

    return {
        "vtable_class": vtable_info["vtable_class"],
        "vtable_symbol": vtable_info["vtable_symbol"],
        "vtable_va": vtable_info["vtable_va"],
        "vtable_rva": vtable_rva,
        "vtable_size": vtable_info["vtable_size"],
        "vtable_numvfunc": vtable_info["vtable_numvfunc"],
        "vtable_entries": entries,
    }


async def preprocess_func_sig_via_mcp(
    session, new_path, old_path, image_base, new_binary_dir, platform, func_name=None, debug=False
):
    """
    Preprocess a function output by reusing old-version signature metadata.

    Primary path:
    - Reuse old `func_sig`, locate unique match in the new binary, and resolve
      function metadata from the matched function head.

    Fallback path (for old YAML without `func_sig`):
    - Reuse old `vfunc_sig` (must uniquely match in the new binary), then reuse
      old vfunc index/offset and resolve function metadata from the
      corresponding entry in the new vtable YAML.
    - After resolving function VA/size from vtable, try to generate a new
      function-head `func_sig` automatically.

    Args:
        session: Active MCP ClientSession
        new_path: Full path to expected output YAML
        old_path: Full path to old version YAML (may be None)
        image_base: Binary image base address (int)
        new_binary_dir: Directory for new version outputs
        platform: "windows" or "linux"
        debug: Enable debug output

    Returns:
        Dict with function YAML data, or None on failure
    """
    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required for func_sig preprocessing")
        return None

    # Check if old YAML exists
    if not old_path or not os.path.exists(old_path):
        if debug:
            print(f"    Preprocess: no old YAML for {os.path.basename(new_path)}")
        return None

    # Read old YAML
    try:
        with open(old_path, "r", encoding="utf-8") as f:
            old_data = yaml.safe_load(f)
    except Exception:
        return None

    if not old_data or not isinstance(old_data, dict):
        return None

    def _parse_int_field(value, field_name):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                raise ValueError(f"empty {field_name}")
            return int(raw, 0)
        return int(value)

    async def _find_unique_match(signature, label):
        try:
            fb_result = await session.call_tool(
                name="find_bytes",
                arguments={"patterns": [signature], "limit": 2}
            )
            fb_data = parse_mcp_result(fb_result)
        except Exception as e:
            if debug:
                print(f"    Preprocess: find_bytes error: {e}")
            return None

        if not isinstance(fb_data, list) or len(fb_data) == 0:
            return None

        entry = fb_data[0]
        if not isinstance(entry, dict):
            return None

        matches = entry.get("matches", [])
        match_count = entry.get("n", len(matches))
        if match_count != 1:
            if debug:
                print(f"    Preprocess: {label} matched {match_count} (need 1)")
            return None

        return matches[0]

    async def _get_func_info(addr_expr):
        py_code = (
            f"import idaapi, json\n"
            f"addr = {addr_expr}\n"
            f"f = idaapi.get_func(addr)\n"
            f"if f and f.start_ea == addr:\n"
            f"    result = json.dumps({{'func_va': hex(f.start_ea), 'func_size': hex(f.end_ea - f.start_ea)}})\n"
            f"else:\n"
            f"    result = json.dumps(None)\n"
        )
        try:
            fi_result = await session.call_tool(
                name="py_eval",
                arguments={"code": py_code}
            )
            fi_data = parse_mcp_result(fi_result)
        except Exception as e:
            if debug:
                print(f"    Preprocess: py_eval error: {e}")
            return None

        func_info = None
        if isinstance(fi_data, dict):
            stderr_text = fi_data.get("stderr", "")
            if stderr_text and debug:
                print("    Preprocess: py_eval stderr:")
                print(stderr_text.strip())
            result_str = fi_data.get("result", "")
            if result_str:
                try:
                    func_info = json.loads(result_str)
                except (json.JSONDecodeError, TypeError):
                    pass

        if not isinstance(func_info, dict):
            return None
        if "func_va" not in func_info or "func_size" not in func_info:
            return None
        return func_info

    async def _load_vtable_data(vtable_name):
        vtable_yaml_path = os.path.join(
            new_binary_dir,
            f"{vtable_name}_vtable.{platform}.yaml"
        )

        if not os.path.exists(vtable_yaml_path):
            # Generate vtable YAML on-the-fly via py_eval
            vtable_gen_data = await preprocess_vtable_via_mcp(
                session, vtable_name, image_base, platform, debug
            )
            if vtable_gen_data is None:
                if debug:
                    print(
                        "    Preprocess: vtable YAML not found and generation failed: "
                        f"{os.path.basename(vtable_yaml_path)}"
                    )
                return None
            write_vtable_yaml(vtable_yaml_path, vtable_gen_data)
            if debug:
                print(f"    Preprocess: generated vtable YAML: {os.path.basename(vtable_yaml_path)}")

        try:
            with open(vtable_yaml_path, "r", encoding="utf-8") as vf:
                vtable_data = yaml.safe_load(vf)
        except Exception:
            return None

        if not isinstance(vtable_data, dict):
            return None
        return vtable_data

    func_sig = old_data.get("func_sig")
    vfunc_sig = old_data.get("vfunc_sig")
    vtable_name = old_data.get("vtable_name")

    used_vfunc_fallback = False
    vfunc_index = None
    vfunc_offset = None
    vfunc_match_addr = None

    if func_sig:
        match_addr = await _find_unique_match(
            func_sig, f"{os.path.basename(old_path)} func_sig"
        )
        if match_addr is None:
            return None

        func_info = await _get_func_info(match_addr)
        if not func_info:
            if debug:
                print(f"    Preprocess: could not get func info at {match_addr}")
            return None
    else:
        used_vfunc_fallback = True
        if not vfunc_sig:
            if debug:
                print(f"    Preprocess: no func_sig/vfunc_sig in {os.path.basename(old_path)}")
            return None
        if not vtable_name:
            if debug:
                print(
                    "    Preprocess: no vtable_name for vfunc fallback in "
                    f"{os.path.basename(old_path)}"
                )
            return None

        has_index = old_data.get("vfunc_index") is not None
        has_offset = old_data.get("vfunc_offset") is not None
        if not has_index and not has_offset:
            if debug:
                print(
                    "    Preprocess: missing vfunc_index/vfunc_offset in "
                    f"{os.path.basename(old_path)}"
                )
            return None

        try:
            if has_index:
                vfunc_index = _parse_int_field(old_data.get("vfunc_index"), "vfunc_index")
            if has_offset:
                vfunc_offset = _parse_int_field(old_data.get("vfunc_offset"), "vfunc_offset")
        except Exception:
            if debug:
                print(f"    Preprocess: invalid vfunc metadata in {os.path.basename(old_path)}")
            return None

        if vfunc_index is None:
            if vfunc_offset % 8 != 0:
                if debug:
                    print(
                        "    Preprocess: vfunc_offset is not 8-byte aligned in "
                        f"{os.path.basename(old_path)}"
                    )
                return None
            vfunc_index = vfunc_offset // 8
        if vfunc_offset is None:
            vfunc_offset = vfunc_index * 8

        if vfunc_index < 0 or vfunc_offset < 0 or vfunc_offset != vfunc_index * 8:
            if debug:
                print(
                    "    Preprocess: inconsistent vfunc_index/vfunc_offset in "
                    f"{os.path.basename(old_path)}"
                )
            return None

        vfunc_match_addr = await _find_unique_match(
            vfunc_sig, f"{os.path.basename(old_path)} vfunc_sig"
        )
        if vfunc_match_addr is None:
            return None

        # If the old YAML never had func_va, the vtable is only used as
        # metadata (e.g. pure-interface classes like IGameTypes whose vtable
        # symbol cannot be resolved).  Carry forward vfunc metadata as-is.
        old_has_func_va = old_data.get("func_va") is not None
        if not old_has_func_va:
            if func_name is None:
                func_name = old_data.get("func_name")
            if func_name is None:
                func_name = os.path.basename(new_path).rsplit(".", 2)[0]

            new_data = {
                "func_name": func_name,
                "vfunc_sig": vfunc_sig,
                "vtable_name": vtable_name,
                "vfunc_offset": hex(vfunc_offset),
                "vfunc_index": vfunc_index,
            }
            if debug:
                print(
                    "    Preprocess: reused vfunc_sig metadata (no vtable resolution) at "
                    f"{vfunc_match_addr} for {os.path.basename(new_path)}"
                )
            return new_data

        vtable_data = await _load_vtable_data(vtable_name)
        if not isinstance(vtable_data, dict):
            return None

        vtable_entries = vtable_data.get("vtable_entries", {})
        func_va_from_vtable = None
        for idx, entry_addr in vtable_entries.items():
            try:
                idx_int = int(idx)
            except Exception:
                continue
            if idx_int != vfunc_index:
                continue
            try:
                func_va_from_vtable = int(str(entry_addr), 16)
            except Exception:
                func_va_from_vtable = None
            break

        if func_va_from_vtable is None:
            if debug:
                print(
                    "    Preprocess: vfunc_index not found in vtable entries: "
                    f"{vtable_name}[{vfunc_index}]"
                )
            return None

        func_info = await _get_func_info(hex(func_va_from_vtable))
        if not func_info:
            if debug:
                print(
                    "    Preprocess: could not get func info from vtable entry: "
                    f"{vtable_name}[{vfunc_index}] -> {hex(func_va_from_vtable)}"
                )
            return None

    func_va_hex = func_info["func_va"]
    func_va_int = int(func_va_hex, 16)
    func_size_hex = func_info["func_size"]

    # Resolve func_name: explicit parameter > old YAML > derive from filename
    if func_name is None:
        func_name = old_data.get("func_name")
    if func_name is None:
        func_name = os.path.basename(new_path).rsplit(".", 2)[0]

    # Build new YAML data
    new_data = {
        "func_name": func_name,
        "func_va": func_va_hex,
        "func_rva": hex(func_va_int - image_base),
        "func_size": func_size_hex,
    }
    if func_sig:
        new_data["func_sig"] = func_sig

    # vfunc fallback path: reuse old index/offset and regenerate func_sig from vtable-resolved function.
    if used_vfunc_fallback:
        new_data["vfunc_sig"] = vfunc_sig
        new_data["vtable_name"] = vtable_name
        new_data["vfunc_offset"] = hex(vfunc_offset)
        new_data["vfunc_index"] = vfunc_index

        if debug:
            print(
                "    Preprocess: reused vfunc_sig + vtable metadata at "
                f"{vfunc_match_addr} for {os.path.basename(new_path)}"
            )
        return new_data

    # For vfunc with func_sig input: cross-reference with new vtable YAML for vfunc_offset/index.
    if vtable_name:
        vtable_data = await _load_vtable_data(vtable_name)
        if not isinstance(vtable_data, dict):
            return None

        vtable_entries = vtable_data.get("vtable_entries", {})
        found_index = None
        for idx, entry_addr in vtable_entries.items():
            try:
                idx_int = int(idx)
                entry_int = int(str(entry_addr), 16)
            except Exception:
                continue
            if entry_int == func_va_int:
                found_index = idx_int
                break

        if found_index is None:
            if debug:
                print(f"    Preprocess: {func_va_hex} not in {vtable_name} vtable entries")
            return None

        new_data["vtable_name"] = vtable_name
        new_data["vfunc_offset"] = hex(found_index * 8)
        new_data["vfunc_index"] = found_index

    return new_data


async def preprocess_gen_func_sig_via_mcp(
    session,
    func_va,
    image_base,
    min_sig_bytes=6,
    max_sig_bytes=96,
    max_instructions=64,
    extra_wildcard_offsets=None,
    debug=False,
):
    """
    Generate a shortest unique function-head signature for a known function address.

    The generated signature always starts at the function entry (func start address),
    never from the middle of a function. The routine progressively searches for the
    shortest prefix that still uniquely resolves to the target function.

    Wildcards:
    - Auto wildcard: volatile operand bytes (imm/near/far/mem/displ) and branch/call
      relative offsets are wildcarded programmatically.
    - Extra wildcard: caller may provide additional byte offsets (relative to func head)
      via extra_wildcard_offsets.

    Args:
        session: Active MCP ClientSession.
        func_va: Function virtual address (int or hex string) and must be function head.
        image_base: Binary image base address (int).
        min_sig_bytes: Minimum signature prefix length to try.
        max_sig_bytes: Maximum bytes collected from function head.
        max_instructions: Max instructions collected from function head.
        extra_wildcard_offsets: Optional iterable of extra wildcard offsets.
        debug: Enable debug output.

    Returns:
        Dict with function YAML data (func_va, func_rva, func_size, func_sig),
        or None on failure.
    """

    def _parse_int(value):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                raise ValueError("empty integer string")
            return int(raw, 0)
        return int(value)

    def _parse_addr(value):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            return int(value.strip(), 0)
        return int(value)

    try:
        func_va_int = _parse_int(func_va)
    except Exception:
        if debug:
            print(f"    Preprocess: invalid func_va: {func_va}")
        return None

    try:
        min_sig_bytes = max(1, int(min_sig_bytes))
        max_sig_bytes = max(1, int(max_sig_bytes))
        max_instructions = max(1, int(max_instructions))
    except Exception:
        if debug:
            print("    Preprocess: invalid signature generation limits")
        return None

    extra_wildcard_set = set()
    if extra_wildcard_offsets:
        try:
            for offset in extra_wildcard_offsets:
                parsed = _parse_int(offset)
                if parsed >= 0:
                    extra_wildcard_set.add(parsed)
        except Exception:
            if debug:
                print("    Preprocess: invalid extra_wildcard_offsets")
            return None

    py_code = (
        "import idaapi, ida_bytes, idautils, ida_ua, json\n"
        f"target_ea = {func_va_int}\n"
        f"max_sig_bytes = {max_sig_bytes}\n"
        f"max_instructions = {max_instructions}\n"
        "f = idaapi.get_func(target_ea)\n"
        "if not f or f.start_ea != target_ea:\n"
        "    result = json.dumps(None)\n"
        "else:\n"
        "    limit_end = min(f.end_ea, target_ea + max_sig_bytes)\n"
        "    insts = []\n"
        "    cursor = target_ea\n"
        "    total = 0\n"
        "    while cursor < f.end_ea and cursor < limit_end and len(insts) < max_instructions:\n"
        "        insn = idautils.DecodeInstruction(cursor)\n"
        "        if not insn or insn.size <= 0:\n"
        "            break\n"
        "        raw = ida_bytes.get_bytes(cursor, insn.size)\n"
        "        if not raw:\n"
        "            break\n"
        "        wild = set()\n"
        "        for op in insn.ops:\n"
        "            op_type = int(op.type)\n"
        "            if op_type == int(idaapi.o_void):\n"
        "                continue\n"
        "            if op_type in (int(idaapi.o_imm), int(idaapi.o_near), int(idaapi.o_far), int(idaapi.o_mem), int(idaapi.o_displ)):\n"
        "                offb = int(op.offb)\n"
        "                if offb > 0 and offb < insn.size:\n"
        "                    dsz = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))\n"
        "                    if dsz <= 0:\n"
        "                        dsz = insn.size - offb\n"
        "                    end = min(insn.size, offb + dsz)\n"
        "                    for i in range(offb, end):\n"
        "                        wild.add(i)\n"
        "                offo = int(op.offo)\n"
        "                if offo > 0 and offo < insn.size:\n"
        "                    dsz2 = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))\n"
        "                    if dsz2 <= 0:\n"
        "                        dsz2 = insn.size - offo\n"
        "                    end2 = min(insn.size, offo + dsz2)\n"
        "                    for i in range(offo, end2):\n"
        "                        wild.add(i)\n"
        "        b0 = raw[0]\n"
        "        if b0 in (0xE8, 0xE9, 0xEB):\n"
        "            for i in range(1, insn.size):\n"
        "                wild.add(i)\n"
        "        elif b0 == 0x0F and insn.size >= 2 and (raw[1] & 0xF0) == 0x80:\n"
        "            for i in range(2, insn.size):\n"
        "                wild.add(i)\n"
        "        elif 0x70 <= b0 <= 0x7F:\n"
        "            for i in range(1, insn.size):\n"
        "                wild.add(i)\n"
        "        insts.append({'ea': hex(cursor), 'size': insn.size, 'bytes': raw.hex(), 'wild': sorted(wild)})\n"
        "        cursor += insn.size\n"
        "        total += insn.size\n"
        "        if total >= max_sig_bytes:\n"
        "            break\n"
        "    result = json.dumps({'func_va': hex(f.start_ea), 'func_size': hex(f.end_ea - f.start_ea), 'insts': insts})\n"
    )

    try:
        fi_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        fi_data = parse_mcp_result(fi_result)
    except Exception as e:
        if debug:
            print(f"    Preprocess: py_eval error while generating func_sig: {e}")
        return None

    func_info = None
    if isinstance(fi_data, dict):
        stderr_text = fi_data.get("stderr", "")
        if stderr_text and debug:
            print("    Preprocess: py_eval stderr:")
            print(stderr_text.strip())
        result_str = fi_data.get("result", "")
        if result_str:
            try:
                func_info = json.loads(result_str)
            except (json.JSONDecodeError, TypeError):
                pass

    if not isinstance(func_info, dict):
        if debug:
            print(f"    Preprocess: could not resolve function head at {hex(func_va_int)}")
        return None

    insts = func_info.get("insts", [])
    if not isinstance(insts, list) or len(insts) == 0:
        if debug:
            print(f"    Preprocess: no instruction bytes available at {hex(func_va_int)}")
        return None

    sig_tokens = []
    inst_boundaries = []
    for inst in insts:
        try:
            inst_size = int(inst.get("size", 0))
            inst_hex = str(inst.get("bytes", ""))
            if inst_size <= 0 or len(inst_hex) != inst_size * 2:
                if debug:
                    print("    Preprocess: malformed instruction bytes from py_eval")
                return None

            inst_bytes = [int(inst_hex[i:i + 2], 16) for i in range(0, len(inst_hex), 2)]
            inst_wild = set()
            for item in inst.get("wild", []):
                pos = int(item)
                if 0 <= pos < inst_size:
                    inst_wild.add(pos)
        except Exception:
            if debug:
                print("    Preprocess: failed to decode instruction bytes for func_sig")
            return None

        base_offset = len(sig_tokens)
        for rel_idx, value in enumerate(inst_bytes):
            abs_off = base_offset + rel_idx
            use_wild = (rel_idx in inst_wild) or (abs_off in extra_wildcard_set)
            sig_tokens.append("??" if use_wild else f"{value:02X}")

        # Growth step must align to the next full instruction boundary.
        inst_boundaries.append(len(sig_tokens))

    if len(sig_tokens) == 0 or len(inst_boundaries) == 0:
        if debug:
            print(f"    Preprocess: empty signature token stream at {hex(func_va_int)}")
        return None

    search_start = min_sig_bytes

    best_sig = None
    for prefix_len in inst_boundaries:
        if prefix_len < search_start:
            continue
        prefix_tokens = sig_tokens[:prefix_len]

        # Skip signatures that are all wildcards.
        if all(token == "??" for token in prefix_tokens):
            continue

        candidate_sig = " ".join(prefix_tokens)
        try:
            fb_result = await session.call_tool(
                name="find_bytes",
                arguments={"patterns": [candidate_sig], "limit": 2},
            )
            fb_data = parse_mcp_result(fb_result)
        except Exception as e:
            if debug:
                print(f"    Preprocess: find_bytes error while testing generated sig: {e}")
            return None

        if not isinstance(fb_data, list) or len(fb_data) == 0:
            continue

        entry = fb_data[0]
        matches = entry.get("matches", [])
        match_count = entry.get("n", len(matches))

        if match_count != 1 or not matches:
            continue

        try:
            match_addr = _parse_addr(matches[0])
        except Exception:
            continue

        # Signature must resolve to the target function head, not middle/function body.
        if match_addr != func_va_int:
            continue

        best_sig = candidate_sig
        break

    if not best_sig:
        if debug:
            print(
                "    Preprocess: failed to generate a unique function-head signature "
                f"for {hex(func_va_int)}"
            )
        return None

    try:
        resolved_func_va = str(func_info["func_va"])
        resolved_func_va_int = int(resolved_func_va, 16)
        resolved_func_size = str(func_info["func_size"])
    except Exception:
        if debug:
            print("    Preprocess: invalid func info returned from py_eval")
        return None

    if resolved_func_va_int != func_va_int:
        if debug:
            print(
                "    Preprocess: function head mismatch while generating func_sig "
                f"({hex(resolved_func_va_int)} != {hex(func_va_int)})"
            )
        return None

    if debug:
        print(
            "    Preprocess: generated shortest unique func_sig "
            f"({len(best_sig.split())} bytes) for {hex(func_va_int)}"
        )

    return {
        "func_va": resolved_func_va,
        "func_rva": hex(resolved_func_va_int - image_base),
        "func_size": resolved_func_size,
        "func_sig": best_sig,
    }

async def preprocess_gen_gv_sig_via_mcp(
    session,
    gv_va,
    image_base,
    gv_access_inst_va=None,
    gv_access_func_va=None,
    min_sig_bytes=8,
    max_sig_bytes=96,
    max_instructions=64,
    max_candidates=32,
    extra_wildcard_offsets=None,
    debug=False,
):
    """
    Generate a shortest unique signature for a known global variable address.

    The generated signature MUST resolve to an instruction that accesses the global
    variable (GV-accessing instruction). The signature start address equals that
    instruction address (gv_inst_offset = 0).

    Args:
        session: Active MCP ClientSession.
        gv_va: Global variable virtual address (int or hex string).
        image_base: Binary image base address (int).
        gv_access_inst_va: Optional instruction address known to access gv_va.
        gv_access_func_va: Optional function address to constrain candidate search.
        min_sig_bytes: Minimum signature prefix length to try.
        max_sig_bytes: Maximum bytes collected from signature start.
        max_instructions: Max instructions collected from signature start.
        max_candidates: Maximum GV-access instruction candidates to evaluate.
        extra_wildcard_offsets: Optional iterable of extra wildcard offsets relative
            to signature start.
        debug: Enable debug output.

    Returns:
        Dict with global-variable YAML data, or None on failure.
    """

    def _parse_int(value):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                raise ValueError("empty integer string")
            return int(raw, 0)
        return int(value)

    def _parse_addr(value):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            return int(value.strip(), 0)
        return int(value)

    try:
        gv_va_int = _parse_int(gv_va)
    except Exception:
        if debug:
            print(f"    Preprocess: invalid gv_va: {gv_va}")
        return None

    try:
        min_sig_bytes = max(1, int(min_sig_bytes))
        max_sig_bytes = max(1, int(max_sig_bytes))
        max_instructions = max(1, int(max_instructions))
        max_candidates = max(1, int(max_candidates))
    except Exception:
        if debug:
            print("    Preprocess: invalid gv signature generation limits")
        return None

    inst_va_int = None
    if gv_access_inst_va is not None:
        try:
            inst_va_int = _parse_int(gv_access_inst_va)
        except Exception:
            if debug:
                print(f"    Preprocess: invalid gv_access_inst_va: {gv_access_inst_va}")
            return None

    func_va_int = None
    if gv_access_func_va is not None:
        try:
            func_va_int = _parse_int(gv_access_func_va)
        except Exception:
            if debug:
                print(f"    Preprocess: invalid gv_access_func_va: {gv_access_func_va}")
            return None

    extra_wildcard_set = set()
    if extra_wildcard_offsets:
        try:
            for offset in extra_wildcard_offsets:
                parsed = _parse_int(offset)
                if parsed >= 0:
                    extra_wildcard_set.add(parsed)
        except Exception:
            if debug:
                print("    Preprocess: invalid extra_wildcard_offsets")
            return None

    py_code = (
        "import idaapi, ida_bytes, idautils, ida_ua, json\n"
        f"target_gv = {gv_va_int}\n"
        f"target_inst = {inst_va_int if inst_va_int is not None else 'None'}\n"
        f"target_func = {func_va_int if func_va_int is not None else 'None'}\n"
        f"max_sig_bytes = {max_sig_bytes}\n"
        f"max_instructions = {max_instructions}\n"
        f"max_candidates = {max_candidates}\n"
        "\n"
        "def _resolve_disp_off(insn_ea, insn, raw):\n"
        "    cand_offsets = set()\n"
        "    for op in insn.ops:\n"
        "        op_type = int(op.type)\n"
        "        if op_type == int(idaapi.o_void):\n"
        "            continue\n"
        "        offb = int(getattr(op, 'offb', 0))\n"
        "        offo = int(getattr(op, 'offo', 0))\n"
        "        if offb > 0 and offb + 4 <= insn.size:\n"
        "            cand_offsets.add(offb)\n"
        "        if offo > 0 and offo + 4 <= insn.size:\n"
        "            cand_offsets.add(offo)\n"
        "\n"
        "    for off in sorted(cand_offsets):\n"
        "        disp_i32 = int.from_bytes(raw[off:off + 4], 'little', signed=True)\n"
        "        resolved = (insn_ea + insn.size + disp_i32) & 0xFFFFFFFFFFFFFFFF\n"
        "        if resolved == target_gv:\n"
        "            return off\n"
        "\n"
        "    return None\n"
        "\n"
        "def _collect_sig_stream(inst_ea, disp_off):\n"
        "    f = idaapi.get_func(inst_ea)\n"
        "    if not f:\n"
        "        return None\n"
        "\n"
        "    limit_end = min(f.end_ea, inst_ea + max_sig_bytes)\n"
        "    cursor = inst_ea\n"
        "    total = 0\n"
        "    insts = []\n"
        "    first_len = None\n"
        "\n"
        "    while cursor < f.end_ea and cursor < limit_end and len(insts) < max_instructions:\n"
        "        insn = idautils.DecodeInstruction(cursor)\n"
        "        if not insn or insn.size <= 0:\n"
        "            break\n"
        "\n"
        "        raw = ida_bytes.get_bytes(cursor, insn.size)\n"
        "        if not raw:\n"
        "            break\n"
        "\n"
        "        wild = set()\n"
        "        for op in insn.ops:\n"
        "            op_type = int(op.type)\n"
        "            if op_type == int(idaapi.o_void):\n"
        "                continue\n"
        "\n"
        "            if op_type in (int(idaapi.o_imm), int(idaapi.o_near), int(idaapi.o_far), int(idaapi.o_mem), int(idaapi.o_displ)):\n"
        "                offb = int(getattr(op, 'offb', 0))\n"
        "                if offb > 0 and offb < insn.size:\n"
        "                    dsz = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))\n"
        "                    if dsz <= 0:\n"
        "                        dsz = insn.size - offb\n"
        "                    end = min(insn.size, offb + dsz)\n"
        "                    for i in range(offb, end):\n"
        "                        wild.add(i)\n"
        "\n"
        "                offo = int(getattr(op, 'offo', 0))\n"
        "                if offo > 0 and offo < insn.size:\n"
        "                    dsz2 = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))\n"
        "                    if dsz2 <= 0:\n"
        "                        dsz2 = insn.size - offo\n"
        "                    end2 = min(insn.size, offo + dsz2)\n"
        "                    for i in range(offo, end2):\n"
        "                        wild.add(i)\n"
        "\n"
        "        b0 = raw[0]\n"
        "        if b0 in (0xE8, 0xE9, 0xEB):\n"
        "            for i in range(1, insn.size):\n"
        "                wild.add(i)\n"
        "        elif b0 == 0x0F and insn.size >= 2 and (raw[1] & 0xF0) == 0x80:\n"
        "            for i in range(2, insn.size):\n"
        "                wild.add(i)\n"
        "        elif 0x70 <= b0 <= 0x7F:\n"
        "            for i in range(1, insn.size):\n"
        "                wild.add(i)\n"
        "\n"
        "        if cursor == inst_ea:\n"
        "            first_len = insn.size\n"
        "            for i in range(disp_off, min(insn.size, disp_off + 4)):\n"
        "                wild.add(i)\n"
        "\n"
        "        insts.append({'ea': hex(cursor), 'size': insn.size, 'bytes': raw.hex(), 'wild': sorted(wild)})\n"
        "\n"
        "        cursor += insn.size\n"
        "        total += insn.size\n"
        "        if total >= max_sig_bytes:\n"
        "            break\n"
        "\n"
        "    if not insts or first_len is None:\n"
        "        return None\n"
        "\n"
        "    return {\n"
        "        'gv_inst_va': hex(inst_ea),\n"
        "        'gv_inst_length': first_len,\n"
        "        'gv_inst_disp': disp_off,\n"
        "        'insts': insts,\n"
        "    }\n"
        "\n"
        "candidates = []\n"
        "seen = set()\n"
        "\n"
        "def _try_add(inst_ea):\n"
        "    if inst_ea in seen:\n"
        "        return\n"
        "    seen.add(inst_ea)\n"
        "\n"
        "    insn = idautils.DecodeInstruction(inst_ea)\n"
        "    if not insn or insn.size <= 0:\n"
        "        return\n"
        "\n"
        "    raw = ida_bytes.get_bytes(inst_ea, insn.size)\n"
        "    if not raw:\n"
        "        return\n"
        "\n"
        "    disp_off = _resolve_disp_off(inst_ea, insn, raw)\n"
        "    if disp_off is None:\n"
        "        return\n"
        "\n"
        "    packed = _collect_sig_stream(inst_ea, disp_off)\n"
        "    if packed is None:\n"
        "        return\n"
        "\n"
        "    candidates.append(packed)\n"
        "\n"
        "if target_inst is not None:\n"
        "    _try_add(target_inst)\n"
        "elif target_func is not None:\n"
        "    f = idaapi.get_func(target_func)\n"
        "    if f:\n"
        "        ea = f.start_ea\n"
        "        while ea < f.end_ea and len(candidates) < max_candidates:\n"
        "            flags = ida_bytes.get_full_flags(ea)\n"
        "            if ida_bytes.is_code(flags):\n"
        "                _try_add(ea)\n"
        "\n"
        "            next_ea = ida_bytes.next_head(ea, f.end_ea)\n"
        "            if next_ea == idaapi.BADADDR or next_ea <= ea:\n"
        "                break\n"
        "            ea = next_ea\n"
        "else:\n"
        "    for ref in idautils.DataRefsTo(target_gv):\n"
        "        if len(candidates) >= max_candidates:\n"
        "            break\n"
        "\n"
        "        flags = ida_bytes.get_full_flags(ref)\n"
        "        if not ida_bytes.is_code(flags):\n"
        "            continue\n"
        "\n"
        "        _try_add(ref)\n"
        "\n"
        "result = json.dumps(candidates)\n"
    )

    try:
        gv_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        gv_data = parse_mcp_result(gv_result)
    except Exception as e:
        if debug:
            print(f"    Preprocess: py_eval error while generating gv_sig: {e}")
        return None

    candidate_infos = None
    if isinstance(gv_data, dict):
        stderr_text = gv_data.get("stderr", "")
        if stderr_text and debug:
            print("    Preprocess: py_eval stderr:")
            print(stderr_text.strip())

        result_str = gv_data.get("result", "")
        if result_str:
            try:
                candidate_infos = json.loads(result_str)
            except (json.JSONDecodeError, TypeError):
                pass

    if not isinstance(candidate_infos, list) or len(candidate_infos) == 0:
        if debug:
            print(f"    Preprocess: no gv-access instruction candidates for {hex(gv_va_int)}")
        return None

    best = None

    for cand in candidate_infos:
        try:
            gv_inst_va = _parse_addr(cand.get("gv_inst_va"))
            gv_inst_length = int(cand.get("gv_inst_length"))
            gv_inst_disp = int(cand.get("gv_inst_disp"))
            insts = cand.get("insts", [])
        except Exception:
            continue

        if not isinstance(insts, list) or len(insts) == 0 or gv_inst_length <= 0 or gv_inst_disp < 0:
            continue

        sig_tokens = []
        inst_boundaries = []
        malformed = False
        for inst in insts:
            try:
                inst_size = int(inst.get("size", 0))
                inst_hex = str(inst.get("bytes", ""))
                if inst_size <= 0 or len(inst_hex) != inst_size * 2:
                    malformed = True
                    break

                inst_bytes = [int(inst_hex[i:i + 2], 16) for i in range(0, len(inst_hex), 2)]
                inst_wild = set()
                for item in inst.get("wild", []):
                    pos = int(item)
                    if 0 <= pos < inst_size:
                        inst_wild.add(pos)
            except Exception:
                malformed = True
                break

            base_offset = len(sig_tokens)
            for rel_idx, value in enumerate(inst_bytes):
                abs_off = base_offset + rel_idx
                use_wild = (rel_idx in inst_wild) or (abs_off in extra_wildcard_set)
                sig_tokens.append("??" if use_wild else f"{value:02X}")

            # Growth step must align to the next full instruction boundary.
            inst_boundaries.append(len(sig_tokens))

        if malformed or len(sig_tokens) == 0 or len(inst_boundaries) == 0:
            continue

        search_start = min_sig_bytes

        for prefix_len in inst_boundaries:
            if prefix_len < search_start:
                continue
            prefix_tokens = sig_tokens[:prefix_len]

            if all(token == "??" for token in prefix_tokens):
                continue

            candidate_sig = " ".join(prefix_tokens)
            try:
                fb_result = await session.call_tool(
                    name="find_bytes",
                    arguments={"patterns": [candidate_sig], "limit": 2},
                )
                fb_data = parse_mcp_result(fb_result)
            except Exception as e:
                if debug:
                    print(f"    Preprocess: find_bytes error while testing generated gv_sig: {e}")
                return None

            if not isinstance(fb_data, list) or len(fb_data) == 0:
                continue

            entry = fb_data[0]
            matches = entry.get("matches", [])
            match_count = entry.get("n", len(matches))

            if match_count != 1 or not matches:
                continue

            try:
                match_addr = _parse_addr(matches[0])
            except Exception:
                continue

            # Signature must resolve to this GV-accessing instruction address.
            if match_addr != gv_inst_va:
                continue

            if best is None or prefix_len < best["sig_len"]:
                best = {
                    "sig": candidate_sig,
                    "sig_len": prefix_len,
                    "gv_sig_va": gv_inst_va,
                    "gv_inst_length": gv_inst_length,
                    "gv_inst_disp": gv_inst_disp,
                }
            break

    if best is None:
        if debug:
            print(
                "    Preprocess: failed to generate a unique gv-access signature "
                f"for {hex(gv_va_int)}"
            )
        return None

    if debug:
        print(
            "    Preprocess: generated shortest unique gv_sig "
            f"({best['sig_len']} bytes) for {hex(gv_va_int)} at {hex(best['gv_sig_va'])}"
        )

    return {
        "gv_va": hex(gv_va_int),
        "gv_rva": hex(gv_va_int - image_base),
        "gv_sig": best["sig"],
        "gv_sig_va": hex(best["gv_sig_va"]),
        "gv_inst_offset": 0,
        "gv_inst_length": best["gv_inst_length"],
        "gv_inst_disp": best["gv_inst_disp"],
    }

async def preprocess_gv_sig_via_mcp(
    session, new_path, old_path, image_base, new_binary_dir, platform, debug=False
):
    """
    Preprocess a global-variable output by reusing old-version gv_sig signature.

    Searches the old signature in the new binary via find_bytes.
    For unique matches, resolves gv_va from RIP-relative instruction metadata
    (gv_inst_offset, gv_inst_length, gv_inst_disp) and builds new YAML data.

    Args:
        session: Active MCP ClientSession
        new_path: Full path to expected output YAML
        old_path: Full path to old version YAML (may be None)
        image_base: Binary image base address (int)
        new_binary_dir: Directory for new version outputs (reserved)
        platform: "windows" or "linux" (reserved)
        debug: Enable debug output

    Returns:
        Dict with global-variable YAML data, or None on failure
    """
    _ = new_binary_dir, platform  # Reserved for future platform-specific behavior.

    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required for gv_sig preprocessing")
        return None

    # Check if old YAML exists
    if not old_path or not os.path.exists(old_path):
        if debug:
            print(f"    Preprocess: no old YAML for {os.path.basename(new_path)}")
        return None

    # Read old YAML
    try:
        with open(old_path, "r", encoding="utf-8") as f:
            old_data = yaml.safe_load(f)
    except Exception:
        return None

    if not old_data or not isinstance(old_data, dict):
        return None

    gv_sig = old_data.get("gv_sig")
    if not gv_sig:
        if debug:
            print(f"    Preprocess: no gv_sig in {os.path.basename(old_path)}")
        return None

    def _parse_int_field(value, field_name):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                raise ValueError(f"empty {field_name}")
            return int(raw, 0)
        return int(value)

    try:
        gv_inst_offset = _parse_int_field(old_data.get("gv_inst_offset"), "gv_inst_offset")
        gv_inst_length = _parse_int_field(old_data.get("gv_inst_length"), "gv_inst_length")
        gv_inst_disp = _parse_int_field(old_data.get("gv_inst_disp"), "gv_inst_disp")
    except Exception:
        if debug:
            print(f"    Preprocess: invalid gv instruction metadata in {os.path.basename(old_path)}")
        return None

    if gv_inst_offset < 0 or gv_inst_length <= 0 or gv_inst_disp < 0:
        if debug:
            print(f"    Preprocess: invalid gv instruction values in {os.path.basename(old_path)}")
        return None

    # Search signature in new binary via MCP find_bytes
    try:
        fb_result = await session.call_tool(
            name="find_bytes",
            arguments={"patterns": [gv_sig], "limit": 2}
        )
        fb_data = parse_mcp_result(fb_result)
    except Exception as e:
        if debug:
            print(f"    Preprocess: find_bytes error: {e}")
        return None

    # Parse find_bytes result: list of {pattern, matches, n, ...}
    if not isinstance(fb_data, list) or len(fb_data) == 0:
        return None

    entry = fb_data[0]
    matches = entry.get("matches", [])
    match_count = entry.get("n", len(matches))

    if match_count != 1:
        if debug:
            print(f"    Preprocess: {os.path.basename(old_path)} gv sig matched {match_count} (need 1)")
        return None

    match_addr = matches[0]  # hex string like "0x1804f3df3"

    # Resolve gv_va from instruction metadata via py_eval
    py_code = (
        f"import ida_bytes, json\n"
        f"sig_addr = {match_addr}\n"
        f"inst_addr = sig_addr + {gv_inst_offset}\n"
        f"inst_length = {gv_inst_length}\n"
        f"inst_disp = {gv_inst_disp}\n"
        f"inst_bytes = ida_bytes.get_bytes(inst_addr, inst_length)\n"
        f"if not inst_bytes or len(inst_bytes) < inst_disp + 4:\n"
        f"    result = json.dumps(None)\n"
        f"else:\n"
        f"    disp_bytes = inst_bytes[inst_disp:inst_disp + 4]\n"
        f"    disp_i32 = int.from_bytes(disp_bytes, 'little', signed=True)\n"
        f"    gv_addr = (inst_addr + inst_length + disp_i32) & 0xFFFFFFFFFFFFFFFF\n"
        f"    result = json.dumps({{'gv_va': hex(gv_addr), 'gv_sig_va': hex(sig_addr)}})\n"
    )

    try:
        gv_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code}
        )
        gv_data = parse_mcp_result(gv_result)
    except Exception as e:
        if debug:
            print(f"    Preprocess: py_eval error: {e}")
        return None

    # Parse py_eval result
    gv_info = None
    if isinstance(gv_data, dict):
        stderr_text = gv_data.get("stderr", "")
        if stderr_text and debug:
            print("    Preprocess: py_eval stderr:")
            print(stderr_text.strip())
        result_str = gv_data.get("result", "")
        if result_str:
            try:
                gv_info = json.loads(result_str)
            except (json.JSONDecodeError, TypeError):
                pass

    if not gv_info:
        if debug:
            print(f"    Preprocess: could not resolve global variable at {match_addr}")
        return None

    try:
        gv_va_hex = str(gv_info["gv_va"])
        gv_va_int = int(gv_va_hex, 16)
    except Exception:
        if debug:
            print(f"    Preprocess: invalid gv_va parsed from {match_addr}")
        return None

    gv_sig_va_hex = str(gv_info.get("gv_sig_va", match_addr))

    return {
        "gv_name": old_data.get("gv_name") or os.path.basename(new_path).split(".")[0],
        "gv_va": gv_va_hex,
        "gv_rva": hex(gv_va_int - image_base),
        "gv_sig": gv_sig,
        "gv_sig_va": gv_sig_va_hex,
        "gv_inst_offset": gv_inst_offset,
        "gv_inst_length": gv_inst_length,
        "gv_inst_disp": gv_inst_disp,
    }




async def preprocess_patch_via_mcp(
    session, new_path, old_path, image_base, new_binary_dir, platform, debug=False
):
    """
    Preprocess a patch output by reusing old-version patch metadata.

    Verifies that old ``patch_sig`` can be uniquely found in the new binary via
    ``find_bytes``. On success, reuses ``patch_name``, ``patch_sig``, and
    ``patch_bytes`` from old YAML.

    Args:
        session: Active MCP ClientSession
        new_path: Full path to expected output YAML
        old_path: Full path to old version YAML (may be None)
        image_base: Binary image base address (reserved)
        new_binary_dir: Directory for new version outputs (reserved)
        platform: "windows" or "linux" (reserved)
        debug: Enable debug output

    Returns:
        Dict with patch YAML data, or None on failure
    """
    _ = image_base, new_binary_dir, platform  # Reserved for future behavior.

    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required for patch preprocessing")
        return None

    # Check if old YAML exists
    if not old_path or not os.path.exists(old_path):
        if debug:
            print(f"    Preprocess: no old YAML for {os.path.basename(new_path)}")
        return None

    # Read old YAML
    try:
        with open(old_path, "r", encoding="utf-8") as f:
            old_data = yaml.safe_load(f)
    except Exception:
        return None

    if not old_data or not isinstance(old_data, dict):
        return None

    patch_sig = old_data.get("patch_sig")
    patch_bytes = old_data.get("patch_bytes")

    if not patch_sig:
        if debug:
            print(f"    Preprocess: no patch_sig in {os.path.basename(old_path)}")
        return None

    if not patch_bytes:
        if debug:
            print(f"    Preprocess: no patch_bytes in {os.path.basename(old_path)}")
        return None

    # Verify patch_sig uniquely matches in new binary via MCP find_bytes.
    try:
        fb_result = await session.call_tool(
            name="find_bytes",
            arguments={"patterns": [patch_sig], "limit": 2}
        )
        fb_data = parse_mcp_result(fb_result)
    except Exception as e:
        if debug:
            print(f"    Preprocess: find_bytes error: {e}")
        return None

    if not isinstance(fb_data, list) or len(fb_data) == 0:
        return None

    entry = fb_data[0]
    if not isinstance(entry, dict):
        return None

    matches = entry.get("matches", [])
    match_count = entry.get("n", len(matches))
    try:
        match_count_int = int(match_count)
    except Exception:
        match_count_int = len(matches)

    if match_count_int != 1:
        if debug:
            print(
                "    Preprocess: patch_sig matched "
                f"{match_count_int} (need 1) in {os.path.basename(old_path)}"
            )
        return None

    return {
        "patch_name": old_data.get("patch_name") or os.path.basename(new_path).rsplit(".", 2)[0],
        "patch_sig": patch_sig,
        "patch_bytes": patch_bytes,
    }

async def preprocess_struct_offset_sig_via_mcp(
    session, new_path, old_path, image_base, new_binary_dir, platform, debug=False
):
    """
    Preprocess a struct-member offset output by reusing old-version offset_sig signature.

    Searches the old signature in the new binary via find_bytes.
    For unique matches, decodes the target instruction (match + offset_sig_disp)
    and extracts the struct offset displacement/immediate.

    Args:
        session: Active MCP ClientSession
        new_path: Full path to expected output YAML
        old_path: Full path to old version YAML (may be None)
        image_base: Binary image base address (reserved)
        new_binary_dir: Directory for new version outputs (reserved)
        platform: "windows" or "linux" (reserved)
        debug: Enable debug output

    Returns:
        Dict with struct-member YAML data, or None on failure
    """
    _ = image_base, new_binary_dir, platform  # Reserved for future platform-specific behavior.

    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required for struct offset preprocessing")
        return None

    if not old_path or not os.path.exists(old_path):
        if debug:
            print(f"    Preprocess: no old YAML for {os.path.basename(new_path)}")
        return None

    try:
        with open(old_path, "r", encoding="utf-8") as f:
            old_data = yaml.safe_load(f)
    except Exception:
        return None

    if not old_data or not isinstance(old_data, dict):
        return None

    struct_name = old_data.get("struct_name")
    member_name = old_data.get("member_name")
    offset_sig = old_data.get("offset_sig")
    if not struct_name or not member_name:
        if debug:
            print(f"    Preprocess: missing struct_name/member_name in {os.path.basename(old_path)}")
        return None
    if not offset_sig:
        if debug:
            print(f"    Preprocess: no offset_sig in {os.path.basename(old_path)}")
        return None

    def _parse_int_field(value, field_name):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                raise ValueError(f"empty {field_name}")
            return int(raw, 0)
        return int(value)

    offset_sig_disp = 0
    try:
        raw_disp = old_data.get("offset_sig_disp")
        if raw_disp is not None:
            offset_sig_disp = _parse_int_field(raw_disp, "offset_sig_disp")
    except Exception:
        if debug:
            print(f"    Preprocess: invalid offset_sig_disp in {os.path.basename(old_path)}")
        return None

    if offset_sig_disp < 0:
        if debug:
            print(f"    Preprocess: offset_sig_disp must be >= 0 in {os.path.basename(old_path)}")
        return None

    old_offset = None
    try:
        if old_data.get("offset") is not None:
            old_offset = _parse_int_field(old_data.get("offset"), "offset")
    except Exception:
        if debug:
            print(f"    Preprocess: invalid offset in {os.path.basename(old_path)}")

    # Search signature in new binary via MCP find_bytes
    try:
        fb_result = await session.call_tool(
            name="find_bytes",
            arguments={"patterns": [offset_sig], "limit": 2}
        )
        fb_data = parse_mcp_result(fb_result)
    except Exception as e:
        if debug:
            print(f"    Preprocess: find_bytes error: {e}")
        return None

    if not isinstance(fb_data, list) or len(fb_data) == 0:
        return None

    entry = fb_data[0]
    matches = entry.get("matches", [])
    match_count = entry.get("n", len(matches))

    if match_count != 1:
        if debug:
            print(f"    Preprocess: {os.path.basename(old_path)} offset sig matched {match_count} (need 1)")
        return None

    match_addr = matches[0]
    expected_offset_expr = "None" if old_offset is None else str(old_offset)

    py_code = (
        "import idaapi, ida_bytes, idautils, ida_ua, json\n"
        f"sig_addr = {match_addr}\n"
        f"inst_addr = sig_addr + {offset_sig_disp}\n"
        f"expected_offset = {expected_offset_expr}\n"
        "insn = idautils.DecodeInstruction(inst_addr)\n"
        "raw = ida_bytes.get_bytes(inst_addr, insn.size) if insn and insn.size > 0 else None\n"
        "if not insn or insn.size <= 0 or not raw:\n"
        "    result = json.dumps(None)\n"
        "else:\n"
        "    candidates = []\n"
        "    for op in insn.ops:\n"
        "        ot = int(op.type)\n"
        "        if ot == int(idaapi.o_void):\n"
        "            continue\n"
        "        if ot not in (int(idaapi.o_displ), int(idaapi.o_mem), int(idaapi.o_imm)):\n"
        "            continue\n"
        "        for attr in ('offb', 'offo'):\n"
        "            off = int(getattr(op, attr, 0))\n"
        "            if off <= 0 or off >= insn.size:\n"
        "                continue\n"
        "            sizes = []\n"
        "            dsz = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))\n"
        "            if dsz > 0:\n"
        "                sizes.append(dsz)\n"
        "            for s in (1, 2, 4, 8):\n"
        "                if s not in sizes:\n"
        "                    sizes.append(s)\n"
        "            for sz in sizes:\n"
        "                if off + sz > insn.size:\n"
        "                    continue\n"
        "                chunk = raw[off:off + sz]\n"
        "                unsigned_val = int.from_bytes(chunk, 'little', signed=False)\n"
        "                signed_val = int.from_bytes(chunk, 'little', signed=True)\n"
        "                expected_match = False\n"
        "                if expected_offset is not None:\n"
        "                    expected_mod = expected_offset & ((1 << (8 * sz)) - 1)\n"
        "                    expected_match = unsigned_val == expected_mod or signed_val == expected_offset\n"
        "                candidates.append({\n"
        "                    'off': off,\n"
        "                    'size': sz,\n"
        "                    'unsigned': unsigned_val,\n"
        "                    'signed': signed_val,\n"
        "                    'expected': expected_match,\n"
        "                })\n"
        "    uniq = []\n"
        "    seen = set()\n"
        "    for c in candidates:\n"
        "        key = (c['off'], c['size'])\n"
        "        if key in seen:\n"
        "            continue\n"
        "        seen.add(key)\n"
        "        uniq.append(c)\n"
        "    if not uniq:\n"
        "        result = json.dumps(None)\n"
        "    else:\n"
        "        preferred = [c for c in uniq if c['expected']]\n"
        "        pool = preferred if preferred else uniq\n"
        "        pool.sort(key=lambda c: (c['size'], -c['off']), reverse=True)\n"
        "        best = pool[0]\n"
        "        final_offset = best['signed'] if best['signed'] < 0 else best['unsigned']\n"
        "        result = json.dumps({\n"
        "            'offset': final_offset,\n"
        "            'sig_va': hex(sig_addr),\n"
        "            'inst_va': hex(inst_addr),\n"
        "            'offset_size': best['size'],\n"
        "            'matched_expected': bool(preferred),\n"
        "        })\n"
    )

    try:
        offset_result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code}
        )
        offset_data = parse_mcp_result(offset_result)
    except Exception as e:
        if debug:
            print(f"    Preprocess: py_eval error: {e}")
        return None

    offset_info = None
    if isinstance(offset_data, dict):
        stderr_text = offset_data.get("stderr", "")
        if stderr_text and debug:
            print("    Preprocess: py_eval stderr:")
            print(stderr_text.strip())
        result_str = offset_data.get("result", "")
        if result_str:
            try:
                offset_info = json.loads(result_str)
            except (json.JSONDecodeError, TypeError):
                pass

    if not isinstance(offset_info, dict) or "offset" not in offset_info:
        if debug:
            print(f"    Preprocess: could not resolve struct offset at {match_addr}")
        return None

    try:
        offset_int = _parse_int_field(offset_info["offset"], "offset")
    except Exception:
        if debug:
            print(f"    Preprocess: invalid parsed offset at {match_addr}")
        return None

    new_data = {
        "struct_name": struct_name,
        "member_name": member_name,
        "offset": hex(offset_int),
        "offset_sig": offset_sig,
    }

    raw_size = old_data.get("size")
    if raw_size is not None:
        try:
            size_value = _parse_int_field(raw_size, "size")
            if size_value > 0:
                new_data["size"] = size_value
        except Exception:
            if debug:
                print(f"    Preprocess: invalid size in {os.path.basename(old_path)}")

    if offset_sig_disp > 0:
        new_data["offset_sig_disp"] = offset_sig_disp

    if debug:
        print(
            "    Preprocess: reused offset_sig at "
            f"{match_addr} for {os.path.basename(new_path)}"
        )

    return new_data


async def preprocess_index_based_vfunc_via_mcp(
    session,
    target_func_name,
    target_output,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    base_vfunc_name,
    inherit_vtable_class,
    generate_func_sig=True,
    debug=False,
):
    """Resolve an inherited virtual function by base-class vfunc_index + vtable lookup.

    Reads ``{base_vfunc_name}.{platform}.yaml`` to obtain the base vfunc_index,
    then reads ``{inherit_vtable_class}_vtable.{platform}.yaml`` to look up the
    function address at that exact index.

    Each target function should specify its own *base_vfunc_name* that maps
    directly to the correct vtable slot.  This avoids fragile relative-offset
    calculations that break when the engine inserts new virtual functions
    between existing ones.

    If an old YAML exists for the target, its ``func_sig`` is reused.  Otherwise
    (or when no old YAML is available), a new ``func_sig`` is generated via
    ``preprocess_gen_func_sig_via_mcp`` when *generate_func_sig* is True.

    Args:
        session: Active MCP ClientSession.
        target_func_name: Human-readable name for debug messages.
        target_output: Full path to the expected output YAML.
        old_yaml_map: Mapping from new output path to old version path (may be None).
        new_binary_dir: Directory containing per-binary YAML files.
        platform: ``"windows"`` or ``"linux"``.
        image_base: Binary image base address (int).
        base_vfunc_name: YAML stem of the base-class vfunc whose ``vfunc_index``
            is used directly (e.g. ``"CBaseEntity_Touch"``).
        inherit_vtable_class: Class name whose vtable is looked up
            (e.g. ``"CTriggerPush"``).
        generate_func_sig: Whether to generate a new func_sig when none can be
            reused from old YAML (default True).
        debug: Enable debug output.

    Returns:
        Dict with function YAML data ready for ``write_func_yaml``, or None on
        failure.
    """
    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required for index-based vfunc preprocessing")
        return None

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

    # 1. Read base vfunc YAML to get vfunc_index
    base_vfunc_path = os.path.join(
        new_binary_dir,
        f"{base_vfunc_name}.{platform}.yaml",
    )
    base_vfunc_data = _read_yaml(base_vfunc_path)
    if not isinstance(base_vfunc_data, dict):
        if debug:
            print(
                "    Preprocess: failed to read base vfunc YAML: "
                f"{os.path.basename(base_vfunc_path)}"
            )
        return None

    try:
        base_index = _parse_int(base_vfunc_data.get("vfunc_index"))
    except Exception:
        if debug:
            print(
                "    Preprocess: invalid vfunc_index in "
                f"{os.path.basename(base_vfunc_path)}"
            )
        return None

    # 2. Read inherit-class vtable YAML
    vtable_path = os.path.join(
        new_binary_dir,
        f"{inherit_vtable_class}_vtable.{platform}.yaml",
    )
    vtable_data = _read_yaml(vtable_path)
    if not isinstance(vtable_data, dict):
        if debug:
            print(
                "    Preprocess: failed to read vtable YAML: "
                f"{os.path.basename(vtable_path)}"
            )
        return None

    raw_entries = vtable_data.get("vtable_entries", {})
    if not isinstance(raw_entries, dict):
        if debug:
            print(
                "    Preprocess: invalid vtable_entries in "
                f"{inherit_vtable_class}_vtable YAML"
            )
        return None

    vtable_entries = {}
    for idx, addr in raw_entries.items():
        try:
            vtable_entries[int(idx)] = str(addr)
        except (TypeError, ValueError):
            if debug:
                print(f"    Preprocess: invalid vtable entry index: {idx}")
            return None

    # 3. Look up target function address
    target_index = base_index
    target_addr_hex = vtable_entries.get(target_index)
    if not target_addr_hex:
        if debug:
            print(
                f"    Preprocess: {inherit_vtable_class} vtable missing index "
                f"{target_index} for {target_func_name}"
            )
        return None

    # 4. Query function info via py_eval
    py_code = (
        "import idaapi, json\n"
        f"addr = {target_addr_hex}\n"
        "f = idaapi.get_func(addr)\n"
        "if f and f.start_ea == addr:\n"
        "    result = json.dumps({'func_va': hex(f.start_ea), "
        "'func_size': hex(f.end_ea - f.start_ea)})\n"
        "else:\n"
        "    result = json.dumps(None)\n"
    )

    try:
        result = await session.call_tool(
            name="py_eval",
            arguments={"code": py_code},
        )
        result_data = parse_mcp_result(result)
    except Exception:
        if debug:
            print(f"    Preprocess: py_eval error for {target_func_name}")
        return None

    func_info = None
    if isinstance(result_data, dict):
        result_str = result_data.get("result", "")
        if result_str:
            try:
                func_info = json.loads(result_str)
            except (json.JSONDecodeError, TypeError):
                pass

    if not isinstance(func_info, dict):
        if debug:
            print(f"    Preprocess: failed to query function info for {target_func_name}")
        return None

    func_va_hex = func_info.get("func_va")
    func_size_hex = func_info.get("func_size")
    if not func_va_hex or not func_size_hex:
        if debug:
            print(f"    Preprocess: incomplete function info for {target_func_name}")
        return None

    try:
        func_va_int = int(str(func_va_hex), 16)
    except (TypeError, ValueError):
        if debug:
            print(f"    Preprocess: invalid func_va for {target_func_name}: {func_va_hex}")
        return None

    # 5. Build func_name from base_vfunc_name + inherit_vtable_class
    func_name = target_func_name  # fallback
    base_vtable_name = base_vfunc_data.get("vtable_name")
    if base_vtable_name and base_vfunc_name.startswith(base_vtable_name + "_"):
        method_suffix = base_vfunc_name[len(base_vtable_name) + 1:]
        func_name = f"{inherit_vtable_class}_{method_suffix}"

    # 6. Build payload
    payload = {
        "func_name": func_name,
        "func_va": str(func_va_hex),
        "func_rva": hex(func_va_int - image_base),
        "func_size": str(func_size_hex),
        "vtable_name": inherit_vtable_class,
        "vfunc_offset": hex(target_index * 8),
        "vfunc_index": target_index,
    }

    # 7. Try to reuse old func_sig
    old_path = (old_yaml_map or {}).get(target_output)
    old_func_sig = None
    if old_path and os.path.exists(old_path):
        old_data = _read_yaml(old_path)
        if isinstance(old_data, dict):
            sig = old_data.get("func_sig")
            if sig:
                old_func_sig = str(sig)

    if old_func_sig:
        payload["func_sig"] = old_func_sig
    elif generate_func_sig:
        gen_data = await preprocess_gen_func_sig_via_mcp(
            session=session,
            func_va=func_va_int,
            image_base=image_base,
            debug=debug,
        )
        if gen_data and gen_data.get("func_sig"):
            payload["func_sig"] = gen_data["func_sig"]
        elif debug:
            print(
                f"    Preprocess: func_sig generation failed for "
                f"{target_func_name} at {func_va_hex}"
            )

    return payload


async def preprocess_func_xref_strings_via_mcp(
    session, func_name, xref_strings, image_base, debug=False
):
    """
    Locate a function by finding unique cross-references to known string literals.

    For each string in *xref_strings*, the routine searches IDA's string list,
    collects all code cross-references to the matched string address, resolves
    the owning function of each xref, and intersects the function sets across
    all strings.  If exactly **one** function references every listed string,
    that function is accepted as the target.

    After identification the routine generates a shortest-unique ``func_sig``
    via ``preprocess_gen_func_sig_via_mcp``.

    Args:
        session: Active MCP ClientSession.
        func_name: Desired function name (used in output YAML and IDA rename).
        xref_strings: List of string literals the target function must reference.
        image_base: Binary image base address (int).
        debug: Enable debug output.

    Returns:
        Dict with function YAML data (func_name, func_va, func_rva, func_size,
        func_sig), or None on failure.
    """
    if not xref_strings:
        if debug:
            print(f"    Preprocess: no xref_strings provided for {func_name}")
        return None

    # IDA py_eval script that, given a string literal, searches the binary's
    # string list for an exact match, then collects all code xrefs and resolves
    # their owning functions.  Returns a JSON list of unique function start
    # addresses (as hex strings).
    _XREF_PY_TEMPLATE = r'''
import idautils, idaapi, ida_bytes, ida_nalt, json

search_str = SEARCH_STR_PLACEHOLDER
func_starts = set()

for s in idautils.Strings():
    if str(s) == search_str:
        str_ea = s.ea
        for xref in idautils.XrefsTo(str_ea, 0):
            f = idaapi.get_func(xref.frm)
            if f:
                func_starts.add(f.start_ea)

result = json.dumps([hex(ea) for ea in sorted(func_starts)])
'''

    # Collect the set of candidate function addresses for each xref string,
    # then intersect them.
    candidate_sets = []

    for xref_str in xref_strings:
        # Build py_eval code with the search string injected safely.
        escaped = xref_str.replace("\\", "\\\\").replace('"', '\\"')
        py_code = _XREF_PY_TEMPLATE.replace(
            "SEARCH_STR_PLACEHOLDER", f'"{escaped}"'
        )

        try:
            eval_result = await session.call_tool(
                name="py_eval",
                arguments={"code": py_code},
            )
            eval_data = parse_mcp_result(eval_result)
        except Exception as e:
            if debug:
                print(f"    Preprocess: py_eval error for xref string search: {e}")
            return None

        func_addrs = None
        if isinstance(eval_data, dict):
            stderr_text = eval_data.get("stderr", "")
            if stderr_text and debug:
                print("    Preprocess: py_eval stderr:")
                print(stderr_text.strip())
            result_str = eval_data.get("result", "")
            if result_str:
                try:
                    func_addrs = json.loads(result_str)
                except (json.JSONDecodeError, TypeError):
                    pass

        if not isinstance(func_addrs, list) or len(func_addrs) == 0:
            if debug:
                short = xref_str[:80] + ("..." if len(xref_str) > 80 else "")
                print(
                    f"    Preprocess: no functions reference string "
                    f"\"{short}\" for {func_name}"
                )
            return None

        addr_set = set()
        for addr_hex in func_addrs:
            try:
                addr_set.add(int(addr_hex, 16))
            except Exception:
                continue

        if not addr_set:
            return None

        if debug:
            short = xref_str[:60] + ("..." if len(xref_str) > 60 else "")
            print(
                f"    Preprocess: string \"{short}\" referenced by "
                f"{len(addr_set)} function(s)"
            )

        candidate_sets.append(addr_set)

    # Intersect all candidate sets.
    common_funcs = candidate_sets[0]
    for s in candidate_sets[1:]:
        common_funcs = common_funcs & s

    if len(common_funcs) != 1:
        if debug:
            print(
                f"    Preprocess: xref string intersection yielded "
                f"{len(common_funcs)} function(s) for {func_name} (need exactly 1)"
            )
        return None

    target_va = next(iter(common_funcs))

    if debug:
        print(
            f"    Preprocess: xref string intersection resolved {func_name} "
            f"at {hex(target_va)}"
        )

    # Generate func_sig via the existing helper.
    sig_data = await preprocess_gen_func_sig_via_mcp(
        session=session,
        func_va=target_va,
        image_base=image_base,
        debug=debug,
    )

    if sig_data is None:
        if debug:
            print(
                f"    Preprocess: failed to generate func_sig for "
                f"{func_name} at {hex(target_va)}"
            )
        # Even without a signature, return basic function info.
        func_rva = target_va - image_base
        # Try to get func size via py_eval.
        py_size_code = (
            f"import idaapi, json\n"
            f"f = idaapi.get_func({target_va})\n"
            f"if f and f.start_ea == {target_va}:\n"
            f"    result = json.dumps(hex(f.end_ea - f.start_ea))\n"
            f"else:\n"
            f"    result = json.dumps(None)\n"
        )
        func_size_hex = None
        try:
            sz_result = await session.call_tool(
                name="py_eval", arguments={"code": py_size_code}
            )
            sz_data = parse_mcp_result(sz_result)
            if isinstance(sz_data, dict):
                rs = sz_data.get("result", "")
                if rs:
                    parsed = json.loads(rs)
                    if parsed is not None:
                        func_size_hex = str(parsed)
        except Exception:
            pass

        if func_size_hex is None:
            return None

        return {
            "func_name": func_name,
            "func_va": hex(target_va),
            "func_rva": hex(func_rva),
            "func_size": func_size_hex,
        }

    sig_data["func_name"] = func_name
    return sig_data


# ---------------------------------------------------------------------------
# Common preprocess_skill template
# ---------------------------------------------------------------------------


async def _rename_func_in_ida(session, func_va_hex, func_name, debug=False):
    """Best-effort rename of a function address in IDA via MCP rename tool."""
    if not func_va_hex or not func_name:
        return
    try:
        await session.call_tool(
            name="rename",
            arguments={"batch": {"func": {"addr": str(func_va_hex), "name": func_name}}},
        )
        if debug:
            print(f"    Preprocess: renamed func {func_va_hex} -> {func_name}")
    except Exception as e:
        if debug:
            print(f"    Preprocess: failed to rename func {func_va_hex} -> {func_name}: {e}")


async def _rename_gv_in_ida(session, gv_va_hex, gv_name, debug=False):
    """Best-effort rename of a global variable address in IDA via py_eval."""
    if not gv_va_hex or not gv_name:
        return
    try:
        gv_va_int = int(gv_va_hex, 16)
        await session.call_tool(
            name="py_eval",
            arguments={"code": f"import idc; idc.set_name({gv_va_int}, \"{gv_name}\", idc.SN_NOWARN)"},
        )
        if debug:
            print(f"    Preprocess: renamed gv {gv_va_hex} -> {gv_name}")
    except Exception as e:
        if debug:
            print(f"    Preprocess: failed to rename gv {gv_va_hex} -> {gv_name}: {e}")


async def preprocess_common_skill(
    session,
    expected_outputs,
    old_yaml_map=None,
    new_binary_dir=None,
    platform="windows",
    image_base=0,
    func_names=None,
    gv_names=None,
    patch_names=None,
    struct_member_names=None,
    vtable_class_names=None,
    inherit_vfuncs=None,
    func_xref_strings=None,
    debug=False,
):
    """Reusable preprocess_skill implementation for func/vfunc, gv, patch, struct-member, vtable, inherit-vfunc, and xref-string targets.

    Handles any combination of the seven target types in a single call:
    - ``func_names``: func/vfunc targets via ``preprocess_func_sig_via_mcp``
      (which already supports vfunc_sig fallback internally).
    - ``gv_names``: global-variable targets via ``preprocess_gv_sig_via_mcp``.
    - ``patch_names``: patch targets via ``preprocess_patch_via_mcp``.
    - ``struct_member_names``: struct-member offset targets via
      ``preprocess_struct_offset_sig_via_mcp``.
    - ``vtable_class_names``: vtable targets via ``preprocess_vtable_via_mcp``.
    - ``inherit_vfuncs``: inherited virtual function targets resolved by
      base-class vfunc_index + vtable lookup via
      ``preprocess_index_based_vfunc_via_mcp``.  Each element is a tuple of
      ``(target_func_name, inherit_vtable_class, base_vfunc_name)`` or
      ``(target_func_name, inherit_vtable_class, base_vfunc_name, generate_func_sig)``.
      When *generate_func_sig* is omitted it defaults to ``True``.
      For each target, ``preprocess_func_sig_via_mcp`` is attempted first
      (reusing an existing ``func_sig`` from old YAML); the index-based
      fallback is used only when that fails.
    - ``func_xref_strings``: locate functions by string cross-reference via
      ``preprocess_func_xref_strings_via_mcp``.  Each element is a tuple of
      ``(func_name, xref_strings_list)``.  Used as a fallback when
      ``preprocess_func_sig_via_mcp`` fails for a func target that has a
      matching xref-string entry, or as the sole resolution method for
      func targets that only appear in this list.

    Args:
        session: Active MCP ClientSession.
        expected_outputs: List of expected output YAML paths.
        old_yaml_map: Mapping from new output path to old version path.
        new_binary_dir: Directory for new version outputs.
        platform: "windows" or "linux".
        image_base: Binary image base address (int).
        func_names: List of function/vfunc target names (may be empty/None).
        gv_names: List of global-variable target names (may be empty/None).
        patch_names: List of patch target names (may be empty/None).
        struct_member_names: List of struct-member target names (may be empty/None).
        vtable_class_names: List of class names for vtable lookup, or None.
        inherit_vfuncs: List of inherited vfunc specs (may be empty/None).
        func_xref_strings: List of (func_name, xref_strings_list) tuples for
            string-xref-based function lookup (may be empty/None).
        debug: Enable debug output.

    Returns:
        True if all targets were successfully preprocessed, False otherwise.
    """
    func_names = func_names or []
    gv_names = gv_names or []
    patch_names = patch_names or []
    struct_member_names = struct_member_names or []
    vtable_class_names = vtable_class_names or []
    inherit_vfuncs = inherit_vfuncs or []
    func_xref_strings = func_xref_strings or []

    # Build xref-string lookup: func_name -> list of xref strings
    xref_strings_map = {}
    for spec in func_xref_strings:
        xref_strings_map[spec[0]] = spec[1]

    # --- vtable targets ---
    for vtable_class in vtable_class_names:
        target_filename = f"{vtable_class}_vtable.{platform}.yaml"
        target_outputs = [
            path for path in expected_outputs
            if os.path.basename(path) == target_filename
        ]

        if len(target_outputs) != 1:
            if debug:
                print(
                    f"    Preprocess: expected exactly one output named {target_filename}, "
                    f"got {len(target_outputs)}"
                )
            return False

        vtable_data = await preprocess_vtable_via_mcp(
            session=session,
            class_name=vtable_class,
            image_base=image_base,
            platform=platform,
            debug=debug,
        )
        if vtable_data is None:
            return False

        write_vtable_yaml(target_outputs[0], vtable_data)
        if debug:
            print(f"    Preprocess: generated {target_filename}")

    # --- inherit-vfunc targets ---
    if inherit_vfuncs:
        iv_expected_by_filename = {}
        for spec in inherit_vfuncs:
            func_name = spec[0]
            iv_expected_by_filename[f"{func_name}.{platform}.yaml"] = spec

        iv_matched = {}
        for path in expected_outputs:
            basename = os.path.basename(path)
            matched_spec = iv_expected_by_filename.get(basename)
            if matched_spec is not None:
                iv_matched[matched_spec[0]] = path

        missing_iv = [s[0] for s in inherit_vfuncs if s[0] not in iv_matched]
        if missing_iv:
            if debug:
                print(
                    "    Preprocess: expected outputs missing for "
                    f"{', '.join(missing_iv)}"
                )
            return False

        for spec in inherit_vfuncs:
            func_name = spec[0]
            vtable_class = spec[1]
            base_vfunc_name = spec[2]
            gen_func_sig = spec[3] if len(spec) > 3 else True

            target_output = iv_matched[func_name]
            old_path = (old_yaml_map or {}).get(target_output)

            # Try reusing old func_sig first (fast path).
            func_data = None
            if old_path:
                func_data = await preprocess_func_sig_via_mcp(
                    session=session,
                    new_path=target_output,
                    old_path=old_path,
                    image_base=image_base,
                    new_binary_dir=new_binary_dir,
                    platform=platform,
                    func_name=func_name,
                    debug=debug,
                )

            # Fallback: resolve via base-class vfunc_index + vtable lookup.
            if func_data is None:
                func_data = await preprocess_index_based_vfunc_via_mcp(
                    session=session,
                    target_func_name=func_name,
                    target_output=target_output,
                    old_yaml_map=old_yaml_map,
                    new_binary_dir=new_binary_dir,
                    platform=platform,
                    image_base=image_base,
                    base_vfunc_name=base_vfunc_name,
                    inherit_vtable_class=vtable_class,
                    generate_func_sig=gen_func_sig,
                    debug=debug,
                )
                if func_data is None:
                    if debug:
                        print(f"    Preprocess: failed to locate {func_name}")
                    return False

            await _rename_func_in_ida(session, func_data.get("func_va"), func_name, debug)
            write_func_yaml(target_output, func_data)
            if debug:
                print(f"    Preprocess: generated {func_name}.{platform}.yaml")

    # --- func/vfunc + gv + patch + struct-member targets ---
    # Merge func_names with xref-string-only targets so that functions that
    # appear exclusively in func_xref_strings (and not in func_names) are also
    # processed through the func pipeline.
    xref_only_names = [
        name for name in xref_strings_map if name not in func_names
    ]
    all_func_names = list(func_names) + xref_only_names

    if not all_func_names and not gv_names and not patch_names and not struct_member_names:
        return True

    # Build expected filename -> (kind, name) mapping
    expected_by_filename = {
        f"{func_name}.{platform}.yaml": ("func", func_name)
        for func_name in all_func_names
    }
    for gv_name in gv_names:
        expected_by_filename[f"{gv_name}.{platform}.yaml"] = ("gv", gv_name)
    for patch_name in patch_names:
        expected_by_filename[f"{patch_name}.{platform}.yaml"] = ("patch", patch_name)
    for struct_member_name in struct_member_names:
        expected_by_filename[f"{struct_member_name}.{platform}.yaml"] = ("struct", struct_member_name)

    # Match expected outputs
    matched_func_outputs = {}
    matched_gv_outputs = {}
    matched_patch_outputs = {}
    matched_struct_outputs = {}
    for path in expected_outputs:
        basename = os.path.basename(path)
        item = expected_by_filename.get(basename)
        if item is None:
            continue
        kind, name = item
        if kind == "func":
            matched_func_outputs[name] = path
        elif kind == "gv":
            matched_gv_outputs[name] = path
        elif kind == "patch":
            matched_patch_outputs[name] = path
        else:
            matched_struct_outputs[name] = path

    # Validate all expected outputs are present
    missing_func = [n for n in all_func_names if n not in matched_func_outputs]
    missing_gv = [n for n in gv_names if n not in matched_gv_outputs]
    missing_patch = [n for n in patch_names if n not in matched_patch_outputs]
    missing_struct = [n for n in struct_member_names if n not in matched_struct_outputs]
    if missing_func or missing_gv or missing_patch or missing_struct:
        if debug:
            missing = missing_func + missing_gv + missing_patch + missing_struct
            print(
                "    Preprocess: expected outputs missing for "
                f"{', '.join(missing)}"
            )
        return False

    # Process func/vfunc targets
    for func_name in all_func_names:
        target_output = matched_func_outputs[func_name]
        old_path = (old_yaml_map or {}).get(target_output)

        func_data = await preprocess_func_sig_via_mcp(
            session=session,
            new_path=target_output,
            old_path=old_path,
            image_base=image_base,
            new_binary_dir=new_binary_dir,
            platform=platform,
            func_name=func_name,
            debug=debug,
        )

        # Fallback: try xref-string-based lookup if func_sig failed and
        # the function has an entry in func_xref_strings.
        if func_data is None and func_name in xref_strings_map:
            if debug:
                print(f"    Preprocess: trying xref-string fallback for {func_name}")
            func_data = await preprocess_func_xref_strings_via_mcp(
                session=session,
                func_name=func_name,
                xref_strings=xref_strings_map[func_name],
                image_base=image_base,
                debug=debug,
            )

        if func_data is None:
            if debug:
                print(f"    Preprocess: failed to locate {func_name}")
            return False

        await _rename_func_in_ida(session, func_data.get("func_va"), func_name, debug)
        write_func_yaml(target_output, func_data)
        if debug:
            print(f"    Preprocess: generated {func_name}.{platform}.yaml")

    # Process gv targets
    for gv_name in gv_names:
        target_output = matched_gv_outputs[gv_name]
        gv_old_path = (old_yaml_map or {}).get(target_output)

        gv_data = await preprocess_gv_sig_via_mcp(
            session=session,
            new_path=target_output,
            old_path=gv_old_path,
            image_base=image_base,
            new_binary_dir=new_binary_dir,
            platform=platform,
            debug=debug,
        )

        if gv_data is None:
            if debug:
                print(f"    Preprocess: failed to locate {gv_name}")
            return False

        await _rename_gv_in_ida(session, gv_data.get("gv_va"), gv_name, debug)
        write_gv_yaml(target_output, gv_data)
        if debug:
            print(f"    Preprocess: generated {gv_name}.{platform}.yaml")

    # Process patch targets
    for patch_name in patch_names:
        target_output = matched_patch_outputs[patch_name]
        patch_old_path = (old_yaml_map or {}).get(target_output)

        patch_data = await preprocess_patch_via_mcp(
            session=session,
            new_path=target_output,
            old_path=patch_old_path,
            image_base=image_base,
            new_binary_dir=new_binary_dir,
            platform=platform,
            debug=debug,
        )

        if patch_data is None:
            if debug:
                print(f"    Preprocess: failed to locate {patch_name}")
            return False

        write_patch_yaml(target_output, patch_data)
        if debug:
            print(f"    Preprocess: generated {patch_name}.{platform}.yaml")

    # Process struct-member targets
    for struct_member_name in struct_member_names:
        target_output = matched_struct_outputs[struct_member_name]
        struct_old_path = (old_yaml_map or {}).get(target_output)

        struct_data = await preprocess_struct_offset_sig_via_mcp(
            session=session,
            new_path=target_output,
            old_path=struct_old_path,
            image_base=image_base,
            new_binary_dir=new_binary_dir,
            platform=platform,
            debug=debug,
        )

        if struct_data is None:
            if debug:
                print(f"    Preprocess: failed to locate {struct_member_name}")
            return False

        write_struct_offset_yaml(target_output, struct_data)
        if debug:
            print(f"    Preprocess: generated {struct_member_name}.{platform}.yaml")

    return True
