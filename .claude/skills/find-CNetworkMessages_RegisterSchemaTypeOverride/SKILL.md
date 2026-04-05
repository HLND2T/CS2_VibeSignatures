---
name: find-CNetworkMessages_RegisterSchemaTypeOverride
description: |
  Find and identify the CNetworkMessages_RegisterSchemaTypeOverride virtual function call in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 server.dll or libserver.so to locate the RegisterSchemaTypeOverride vfunc call
  by searching for the unique hash constant 963099A8h byte pattern.
  Trigger: CNetworkMessages_RegisterSchemaTypeOverride
disable-model-invocation: true
---

# Find CNetworkMessages_RegisterSchemaTypeOverride

Locate `CNetworkMessages_RegisterSchemaTypeOverride` vfunc call in CS2 server.dll or libserver.so using IDA Pro MCP tools.

## Method

### 1. Search for the Hash Constant Byte Pattern

The hash constant `963099A8h` appears as bytes `A8 99 30 96` in the binary. Search with the platform-specific instruction prefix:

**Windows (server.dll):**
```
mcp__ida-pro-mcp__find_bytes pattern="41 B8 A8 99 30 96"
```
This matches `mov r8d, 963099A8h`.

**Linux (libserver.so):**
```
mcp__ida-pro-mcp__find_bytes pattern="BA A8 99 30 96"
```
This matches `mov edx, 963099A8h`.

### 2. Identify the Containing Function

Get the function that contains the matched address. Decompile it to confirm the pattern:

```
mcp__ida-pro-mcp__decompile addr="<matched_addr>"
```

The function should look like this:

**Windows:**
```asm
mov     rcx, cs:g_pNetworkMessages
lea     r9, aEhandle            ; "ehandle"
mov     r8d, 963099A8h
lea     rdx, aCentityhandle     ; "CEntityHandle"
mov     rax, [rcx]
jmp     qword ptr [rax+<VFUNC_OFFSET>]
```

**Linux:**
```asm
lea     rax, g_pNetworkMessages
lea     rcx, aEhandle           ; "ehandle"
mov     edx, 963099A8h
lea     rsi, aCentityhandle     ; "CEntityHandle"
mov     rdi, [rax]
mov     rax, [rdi]
mov     rax, [rax+<VFUNC_OFFSET>]
jmp     rax
```

Extract `<VFUNC_OFFSET>` from the virtual call (e.g., `110h`).

Calculate the vtable index: `index = <VFUNC_OFFSET> / 8`.

### 3. Generate VFunc Offset Signature

Identify the instruction address (`inst_addr`) of the virtual call at the call site:
- **Windows:** the `jmp qword ptr [rax+<VFUNC_OFFSET>]` instruction
- **Linux:** the `mov rax, [rax+<VFUNC_OFFSET>]` instruction

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_RegisterSchemaTypeOverride`, with `inst_addr` and `vfunc_offset` from this step.

### 4. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_RegisterSchemaTypeOverride`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 3

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<VFUNC_OFFSET>` in hex (e.g. `0x110`)
- `vfunc_index`: The calculated index (e.g. `34`)

## Function Characteristics

- **Purpose**: Registers a schema type override for network serialization, mapping a schema type name to a network-compatible type alias
- **Called from**: A small wrapper function in server.dll that passes `"CEntityHandle"` and `"ehandle"` to the virtual call
- **Call context**: Called through `g_pNetworkMessages` vtable pointer with schema type name, hash, and override name
- **Parameters**: `(this, "CEntityHandle", hash, "ehandle")` where `this` is the `g_pNetworkMessages` global pointer

## VTable Information

- **VTable Name**: `CNetworkMessages`
- **VTable Offset**: Changes with game updates. Extract from the decompiled function.
- **VTable Index**: Changes with game updates. Resolve via `<VFUNC_OFFSET> / 8`.

## Identification Pattern

The function is identified by searching for the unique hash constant `963099A8h` (`A8 99 30 96` in little-endian bytes):
1. Search for `41 B8 A8 99 30 96` (Windows) or `BA A8 99 30 96` (Linux)
2. The match is inside the wrapper function that calls `RegisterSchemaTypeOverride` through `g_pNetworkMessages`
3. Extract `<VFUNC_OFFSET>` from the virtual call instruction in that function

This is robust because:
- The hash `963099A8h` is a unique constant specific to this registration call
- A single byte search directly locates the function with no cross-referencing needed
- The virtual call pattern through `g_pNetworkMessages` is distinctive

## Output YAML Format

The output YAML filename depends on the platform:
- `server.dll` -> `CNetworkMessages_RegisterSchemaTypeOverride.windows.yaml`
- `libserver.so` -> `CNetworkMessages_RegisterSchemaTypeOverride.linux.yaml`
