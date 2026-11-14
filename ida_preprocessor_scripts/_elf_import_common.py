"""Verified ELF import identities shared by native Linux ctree probes."""


def _read_elf_import_bindings(input_paths, image_base, expected_md5):
    """Read loader bindings from the verified CS2 AMD64 shared object, independently of IDB annotations."""
    import hashlib
    import struct
    from pathlib import Path

    data = None
    for path in dict.fromkeys(input_paths):
        if not path or not Path(path).is_file():
            continue
        candidate = Path(path).read_bytes()
        if not candidate.startswith(b"\x7fELF"):
            return {}
        if hashlib.md5(candidate).digest() == expected_md5:
            data = candidate
            break
    if data is None:
        raise ValueError("ELF input matching the IDB MD5 is unavailable")

    header_format = struct.Struct("<16sHHIQQQIHHHHHH")
    section_format = struct.Struct("<IIQQQQIIQQ")
    rela_format = struct.Struct("<QQq")
    symbol_format = struct.Struct("<IBBHQQ")
    sht_strtab, sht_rela, sht_dynsym = 3, 4, 11
    shn_undef = 0
    stt_notype, stt_func = 0, 2
    r_x86_64_glob_dat, r_x86_64_jump_slot = 6, 7
    symbol_type_mask, relocation_type_mask, symbol_index_shift = 0xF, 0xFFFFFFFF, 32

    def region(offset, size):
        if offset < 0 or size < 0 or offset + size > len(data):
            raise ValueError("ELF table extends beyond the input file")
        return data[offset : offset + size]

    def string(table, offset):
        end = table.find(b"\0", offset)
        if offset < 0 or offset >= len(table) or end < 0:
            raise ValueError("invalid ELF string offset")
        return table[offset:end].decode("utf-8")

    header = header_format.unpack(region(0, header_format.size))
    elf64_little_endian = b"\x7fELF\x02\x01\x01"
    et_dyn, em_x86_64 = 3, 62
    if not header[0].startswith(elf64_little_endian) or header[1:3] != (et_dyn, em_x86_64):
        raise ValueError("expected an ELF64 little-endian AMD64 shared object")
    section_offset, section_size, section_count, names_index = header[6], header[11], header[12], header[13]
    if section_size != section_format.size or not section_count or names_index >= section_count:
        raise ValueError("unsupported ELF section table")
    table = region(section_offset, section_size * section_count)
    sections = list(section_format.iter_unpack(table))
    names_section = sections[names_index]
    if names_section[1] != sht_strtab:
        raise ValueError("ELF section names do not reference a string table")
    names = region(names_section[4], names_section[5])
    plt_ranges, relocations = [], {}
    for section in sections:
        if string(names, section[0]) in {".plt", ".plt.sec", ".plt.got"}:
            region(section[4], section[5])
            plt_ranges.append((image_base + section[3], image_base + section[3] + section[5]))
        if section[1] != sht_rela:
            continue
        if section[9] != rela_format.size or section[5] % rela_format.size or section[6] >= section_count:
            raise ValueError("invalid ELF relocation table")
        symbols = sections[section[6]]
        if symbols[1] != sht_dynsym:
            continue
        if symbols[9] != symbol_format.size or symbols[5] % symbol_format.size or symbols[6] >= section_count:
            raise ValueError("invalid ELF dynamic symbol table")
        symbol_data = region(symbols[4], symbols[5])
        strings_section = sections[symbols[6]]
        if strings_section[1] != sht_strtab:
            raise ValueError("ELF symbols do not reference a string table")
        strings = region(strings_section[4], strings_section[5])
        for address, info, addend in rela_format.iter_unpack(region(section[4], section[5])):
            if info & relocation_type_mask not in (r_x86_64_glob_dat, r_x86_64_jump_slot):
                continue
            index = info >> symbol_index_shift
            if index >= len(symbol_data) // symbol_format.size:
                raise ValueError("ELF relocation symbol index is out of range")
            symbol = symbol_format.unpack_from(symbol_data, index * symbol_format.size)
            if symbol[3] != shn_undef or symbol[1] & symbol_type_mask not in (stt_notype, stt_func) or addend:
                continue
            name = string(strings, symbol[0])
            if not name:
                continue
            got_va = image_base + address
            if got_va in relocations and relocations[got_va] != name:
                raise ValueError(f"ambiguous ELF import binding at {hex(got_va)}")
            relocations[got_va] = name
    return {"plt_ranges": plt_ranges, "relocations": relocations}


def _resolve_imported_comparison_names(target_va, import_names, elf_bindings=None):
    """Run inside IDA: resolve a direct import, native thunk, or bounded ELF PLT stub."""
    import ida_bytes
    import ida_funcs
    import ida_idp
    import ida_segment
    import ida_ua
    import idautils
    from ida_idaapi import BADADDR

    targets = {target_va} if target_va in import_names else set()
    func = None if targets else ida_funcs.get_func(target_va)
    elf_bindings = elf_bindings or {}
    plt_end = next((end for start, end in elf_bindings.get("plt_ranges", []) if start <= target_va < end), None)
    terminal = None
    if func is not None and func.start_ea == target_va:
        if func.flags & ida_funcs.FUNC_THUNK:
            thunk = ida_funcs.calc_thunk_func_target(func)
            destination = thunk[0] if isinstance(thunk, (tuple, list)) and thunk else thunk
            if type(destination) is int and destination not in (0, BADADDR) and destination in import_names:
                targets.add(destination)
        segment = ida_segment.getseg(target_va)
        if (
            plt_end is None
            and segment is not None
            and ida_segment.get_segm_name(segment) in {".plt", ".plt.sec", ".plt.got"}
        ):
            plt_end = func.end_ea
    if plt_end is not None:
        # Source2's tagged PLT stubs are not always recognized as thunks. Decode
        # their short straight-line body without relying on function/xref labels.
        max_plt_instructions = 4
        site = target_va
        for _ in range(max_plt_instructions):
            insn = ida_ua.insn_t()
            size = ida_ua.decode_insn(insn, site)
            if size <= 0 or site + size > plt_end:
                return []
            features = insn.get_canon_feature()
            if features & ida_idp.CF_CALL:
                return []
            if features & (ida_idp.CF_JUMP | ida_idp.CF_STOP):
                if features & (ida_idp.CF_JUMP | ida_idp.CF_STOP) == (ida_idp.CF_JUMP | ida_idp.CF_STOP):
                    terminal = (site, insn)
                break
            site += size
        if terminal is None:
            return []
        site, insn = terminal
        destinations = set(idautils.CodeRefsFrom(site, False))
        pointers = set(idautils.DataRefsFrom(site))
        if insn.ops[0].type == ida_ua.o_mem:
            pointers.add(insn.ops[0].addr)
        for pointer in pointers:
            destinations.add(pointer)
            destinations.add(ida_bytes.get_qword(pointer))
        targets.update(destination for destination in destinations if destination in import_names)
    if len(targets) > 1:
        raise ValueError(f"ambiguous import bindings for {hex(target_va)}: {sorted(targets)}")
    bindings = [{"target_va": hex(target), "name": import_names[target]} for target in sorted(targets)]
    if terminal is not None and insn.ops[0].type == ida_ua.o_mem:
        pointer = insn.ops[0].addr
        name = elf_bindings.get("relocations", {}).get(pointer)
        if name:
            if bindings and bindings[0]["name"] != name:
                raise ValueError(f"conflicting IDB and ELF import bindings for {hex(target_va)}")
            if not bindings:
                bindings.append({"target_va": hex(pointer), "name": name, "binding_kind": "elf_relocation"})
    return bindings
