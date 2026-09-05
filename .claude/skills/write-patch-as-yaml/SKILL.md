---
name: write-patch-as-yaml
description: Write patch analysis results, including patch_sig match VA/RVA, as a YAML file beside the binary using IDA Pro MCP. Use this skill after identifying a patch target and generating a unique signature to persist patch_name, patch_va, patch_rva, patch_sig, optional patch_sig_disp, and patch_bytes in a standardized format.
---

# Write Patch as YAML

Persist a single patch analysis result to a YAML file beside the binary using IDA Pro MCP. Resolve the unique
`patch_sig` match in the current IDB and record its VA and RVA in the output.

## Prerequisites

Before using this skill, you should have:
1. Identified the patch name and determined `patch_bytes`
2. Generated a unique signature using `/generate-signature-for-patch`

## Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `patch_name` | Descriptive name of the patch | `ServerMovementUnlock` |
| `patch_sig` | Unique byte signature locating the instruction to patch | `0F 86 AF 00 00 00 0F 57 C0 0F 2E C2` |
| `patch_bytes` | Replacement bytes to write at the patch location | `E9 B0 00 00 00 90` |

The skill computes these required output fields automatically; callers do not provide them:

| Output field | Description | Example |
|--------------|-------------|---------|
| `patch_va` | VA where `patch_sig` uniquely matches | `0x180A00E2F` |
| `patch_rva` | RVA of the same signature match (`patch_va - image_base`) | `0xA00E2F` |

## Optional Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `patch_sig_disp` | Byte displacement from signature start to the target instruction. `0` or `None` means signature starts at the target instruction. Non-zero values support legacy or externally generated displaced signatures. (use `None` to omit) | `5` |

## Method

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi
import ida_bytes
import ida_segment
import os
import yaml

# === REQUIRED: Replace these values ===
patch_name = "<patch_name>"             # e.g., "ServerMovementUnlock"
patch_sig = "<patch_sig>"               # e.g., "0F 86 AF 00 00 00 0F 57 C0 0F 2E C2"
patch_bytes = "<patch_bytes>"           # e.g., "E9 B0 00 00 00 90"
# ======================================

# === OPTIONAL: Set to None to omit from output ===
patch_sig_disp = <patch_sig_disp>       # e.g., 5 or None (0 also omitted)
# =================================================

# Find the unique patch_sig match in .text. patch_va/patch_rva always point to
# the signature start; when patch_sig_disp is non-zero, the target instruction
# is at patch_va + patch_sig_disp.
tokens = patch_sig.split()
if not tokens or any(token != '??' and (len(token) != 2 or any(c not in '0123456789abcdefABCDEF' for c in token)) for token in tokens):
    raise ValueError(f"Invalid patch_sig: {patch_sig!r}")

pattern = bytes(0 if token == '??' else int(token, 16) for token in tokens)
mask = bytes(0x00 if token == '??' else 0xFF for token in tokens)

def raw_bin_search(ea, max_ea, data, data_mask, flags=0):
    if hasattr(ida_bytes, 'find_bytes'):
        return ida_bytes.find_bytes(data, ea, range_end=max_ea, mask=data_mask, flags=flags)
    return ida_bytes.bin_search(ea, max_ea, data, data_mask, len(data), flags)

text_seg = ida_segment.get_segm_by_name('.text')
if text_seg:
    search_start, search_end = text_seg.start_ea, text_seg.end_ea
else:
    search_start, search_end = idaapi.cvar.inf.min_ea, idaapi.cvar.inf.max_ea

flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK
matches = []
ea = raw_bin_search(search_start, search_end, pattern, mask, flags)
while ea != idaapi.BADADDR and len(matches) < 2:
    matches.append(ea)
    ea = raw_bin_search(ea + 1, search_end, pattern, mask, flags)

if len(matches) != 1:
    raise RuntimeError(f"patch_sig must match exactly once in .text, found {len(matches)} matches")

patch_va = matches[0]
patch_rva = patch_va - idaapi.get_imagebase()

# Get binary path and determine platform
input_file = idaapi.get_input_file_path()
dir_path = os.environ.get('CS2VIBE_ARTIFACT_DIR') or os.path.dirname(input_file)

if input_file.endswith('.dll'):
    platform = 'windows'
else:
    platform = 'linux'

# Build data dictionary conditionally
data = {}

data['patch_name'] = patch_name
data['patch_va'] = hex(patch_va)
data['patch_rva'] = hex(patch_rva)
data['patch_sig'] = patch_sig

if patch_sig_disp is not None and patch_sig_disp > 0:
    data['patch_sig_disp'] = patch_sig_disp

data['patch_bytes'] = patch_bytes

yaml_path = os.path.join(dir_path, f"{patch_name}.{platform}.yaml")
with open(yaml_path, 'w', encoding='utf-8') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
print(f"Written to: {yaml_path}")
print(f"patch_va={hex(patch_va)}, patch_rva={hex(patch_rva)}")
"""
```

## Output File Naming Convention

The output YAML filename follows this pattern:
- `<patch_name>.<platform>.yaml`

Examples:
- `server.dll` → `ServerMovementUnlock.windows.yaml`
- `libserver.so` / `libserver.so` → `ServerMovementUnlock.linux.yaml`

## Output YAML Format

Full output (with a displaced signature):
```yaml
patch_name: ServerMovementUnlock
patch_va: '0x180a00e2f'
patch_rva: '0xa00e2f'
patch_sig: 48 85 C0 74 ?? E8 ?? ?? ?? ?? 0F 86 AF 00 00 00
patch_sig_disp: 5
patch_bytes: E9 B0 00 00 00 90
```

Standard output (without backward expansion, `patch_sig_disp` is 0 or omitted):
```yaml
patch_name: ServerMovementUnlock
patch_va: '0x180a00e2f'
patch_rva: '0xa00e2f'
patch_sig: 0F 86 AF 00 00 00 0F 57 C0 0F 2E C2
patch_bytes: E9 B0 00 00 00 90
```

Each field:
- `patch_name` - Descriptive name of the patch
- `patch_va` - VA where `patch_sig` uniquely matches in the current binary
- `patch_rva` - RVA of the same signature match (`patch_va - image_base`)
- `patch_sig` - Unique byte signature locating the instruction to patch
- `patch_sig_disp` (optional) - Byte displacement from `patch_va` to the target instruction. Only present when non-zero. Runtime: scan for `patch_sig`, then add `patch_sig_disp` to get the target instruction address.
- `patch_bytes` - Replacement bytes to write at the patch location

## Platform Detection

The skill automatically detects the platform based on file extension:
- `.dll` → Windows
- `.so` → Linux

## Example Usage

### Standard patch (forward-only signature)

```python
patch_name = "ServerMovementUnlock"
patch_sig = "0F 86 AF 00 00 00 0F 57 C0 0F 2E C2"
patch_bytes = "E9 B0 00 00 00 90"
patch_sig_disp = None
```

### Legacy or externally generated displaced signature

```python
patch_name = "DisableSteamBanCheck"
patch_sig = "48 85 C0 74 ?? E8 ?? ?? ?? ?? 0F 84 AA 00 00 00"
patch_bytes = "90 90 90 90 90 90"
patch_sig_disp = 5
```

### NOP a call instruction

```python
patch_name = "SkipPrecacheCall"
patch_sig = "E8 AA BB CC DD 48 8B 5C 24 30"
patch_bytes = "90 90 90 90 90"
patch_sig_disp = None
```

## Trusted finalization

This writer produces a semantic YAML payload at the caller-provided expected artifact path. It does not own final field ordering, scalar spelling, encoding, or line endings. After runtime validation, the trusted analyzer rewrites every successful preprocessor or Agent output through the Source2 central canonicalizer; that canonical rewrite is the only byte-level trust boundary.

## Notes

- The YAML file is written to the same directory as the input binary
- `patch_sig` must match exactly once in the current IDB `.text` segment; otherwise the skill stops without writing YAML
- `patch_va` and `patch_rva` always identify the `patch_sig` match start, not the displaced target instruction
- When `patch_sig_disp` is `None` or `0`, the `patch_sig_disp` field is omitted from the output entirely (signature starts at the target instruction)
- `patch_sig` should be a signature generated by `/generate-signature-for-patch`
- `patch_bytes` must have the same byte count as the original instruction being patched
- `patch_sig_disp` is the byte displacement from signature start to the target instruction; the current `/generate-signature-for-patch` normally returns `0`
