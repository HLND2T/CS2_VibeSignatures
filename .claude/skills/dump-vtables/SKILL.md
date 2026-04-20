---
name: dump-vtables
description: |
  Batch-dump vtables from IDA Pro MCP by searching mangled symbol patterns, then write a merged YAML file beside the binary.
  Use this skill when you need to find and export all vtables matching a name pattern (e.g., all GameSystem vtables) in one shot.
  Triggers: dump vtables, batch vtable dump, export vtables, dump all vtables matching pattern
---

# Dump VTables by Symbol Pattern

Search for vtable symbols matching a mangled name glob pattern via IDA Pro MCP, read all their entries, and write a merged YAML file beside the binary.

## Prerequisites

- An IDA Pro MCP instance with the target binary loaded

## Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `symbol_pattern` | Mangled symbol glob pattern for vtables | `??_7C*System@@6B@` |
| `output_name` | Base name for the output YAML file (without extension) | `IGameSystem_vtables` |

## Method

### Step 1: Search for matching vtable symbols

Use `mcp__ida-pro-mcp__entity_query` with kind `names` and a glob filter to find all matching mangled vtable symbols:

```
mcp__ida-pro-mcp__entity_query queries={"kind": "names", "filter": "<symbol_pattern>", "count": 0}
```

This returns all matching symbol names, addresses, and segments.

### Step 2: Read vtable entries and write merged YAML

Run a single `mcp__ida-pro-mcp__py_eval` script that:
1. Iterates each discovered vtable address
2. Reads consecutive qword pointers until hitting a non-code address or 0
3. Gets `func.size()` for each entry
4. Writes a merged YAML list to disk

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi
import ida_bytes
import ida_name
import os
import yaml

# === REQUIRED: Replace these values ===
output_name = "<output_name>"  # e.g., "IGameSystem_vtables"

# Populate from Step 1 results: list of (address, class_name, mangled_symbol)
vtables = [
    # (0x181538bb8, "CCSGCServerSystem", "??_7CCSGCServerSystem@@6B@"),
    # ...add all matches from entity_query results...
]
# ======================================

image_base = idaapi.get_imagebase()
ptr_size = 8 if idaapi.inf_is_64bit() else 4

input_file = idaapi.get_input_file_path()
dir_path = os.path.dirname(input_file)
platform = 'windows' if input_file.endswith('.dll') else 'linux'

all_vtables = []
for vt_addr, vt_name, vt_symbol in vtables:
    entries = []
    for i in range(1000):
        if ptr_size == 8:
            ptr_value = ida_bytes.get_qword(vt_addr + i * ptr_size)
        else:
            ptr_value = ida_bytes.get_dword(vt_addr + i * ptr_size)

        if ptr_value == 0 or ptr_value == 0xFFFFFFFFFFFFFFFF:
            break

        func = idaapi.get_func(ptr_value)
        if func is None:
            flags = ida_bytes.get_full_flags(ptr_value)
            if not ida_bytes.is_code(flags):
                break

        entries.append((ptr_value, func))

    count = len(entries)
    vtable_size = count * ptr_size
    vt_rva = vt_addr - image_base

    entries_dict = {}
    for i, (ptr_value, func) in enumerate(entries):
        func_size = func.size() if func else 0
        entries_dict[i] = f"{hex(ptr_value)} size={hex(func_size)}"

    yaml_data = {
        'vtable_class': vt_name,
        'vtable_symbol': vt_symbol,
        'vtable_va': hex(vt_addr),
        'vtable_rva': hex(vt_rva),
        'vtable_size': hex(vtable_size),
        'vtable_numvfunc': count,
        'vtable_entries': entries_dict
    }
    all_vtables.append(yaml_data)

yaml_path = os.path.join(dir_path, f"{output_name}.{platform}.yaml")
with open(yaml_path, 'w', encoding='utf-8') as f:
    yaml.dump(all_vtables, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

print(f"Written {len(all_vtables)} vtables to {yaml_path}")
"""
```

## Deriving `vtable_class` from the Mangled Symbol

For MSVC mangled vtable symbols (`??_7<ClassName>@@6B@`), extract the class name by stripping the `??_7` prefix and `@@6B@` suffix.

For nested classes like `??_7CServerSideClient_GameEventLegacyProxy@CSource1LegacyGameEventGameSystem@@6B@`, use the outermost class or a descriptive name (e.g., `CSource1LegacyGameEventGameSystem_Proxy`).

## Output File Naming Convention

- `<output_name>.<platform>.yaml`
- Written to the same directory as the input binary

Examples:
- `IGameSystem_vtables.windows.yaml`
- `IGameSystem_vtables.linux.yaml`

## Output YAML Format

The file is a YAML list. Each entry follows the `write-vtable-as-yaml` convention with an added `size=` annotation per vfunc:

```yaml
- vtable_class: CCSGCServerSystem
  vtable_symbol: ??_7CCSGCServerSystem@@6B@
  vtable_va: '0x181538bb8'
  vtable_rva: '0x1538bb8'
  vtable_size: '0x238'
  vtable_numvfunc: 71
  vtable_entries:
    0: 0x180ea9370 size=0x21
    1: 0x1801b7cd0 size=0x5
    2: 0x1801b88d0 size=0xb0

- vtable_class: CBotGameSystem
  vtable_symbol: ??_7CBotGameSystem@@6B@
  vtable_va: '0x18156c280'
  vtable_rva: '0x156c280'
  vtable_size: '0x1f8'
  vtable_numvfunc: 63
  vtable_entries:
    0: 0x180166080 size=0x14
    1: 0x18016b6f0 size=0x3
    ...
```

### Entry format

Each `vtable_entries` value is a string: `<hex_address> size=<hex_func_size>`
- `size=0x0` means IDA has no function defined at that address (code but no `func_t`)
- Small sizes like `size=0x3` typically indicate stubs/thunks (`ret` or similar)

## Notes

- All addresses are version-specific and must be regenerated for each binary update
- The script stops reading a vtable when it encounters a NULL pointer, BADADDR, or a non-code address
- Maximum 1000 entries per vtable (safety limit)
- Uses `yaml.dump` for consistent formatting with other skill outputs
