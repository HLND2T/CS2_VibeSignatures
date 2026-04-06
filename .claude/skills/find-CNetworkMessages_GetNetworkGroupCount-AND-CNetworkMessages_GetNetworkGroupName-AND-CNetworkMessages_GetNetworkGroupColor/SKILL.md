---
name: find-CNetworkMessages_GetNetworkGroupCount-AND-CNetworkMessages_GetNetworkGroupName-AND-CNetworkMessages_GetNetworkGroupColor
description: |
  Find and identify CNetworkMessages_GetNetworkGroupCount, CNetworkMessages_GetNetworkGroupName, and CNetworkMessages_GetNetworkGroupColor
  virtual function calls in CS2 binary using IDA Pro MCP. Use this skill when reverse engineering CS2 engine2.dll or libengine2.so to locate
  these vfunc calls by decompiling CNetworkSystem_SendNetworkStats and identifying virtual calls through g_pNetworkMessages.
  Trigger: CNetworkMessages_GetNetworkGroupCount, CNetworkMessages_GetNetworkGroupName, CNetworkMessages_GetNetworkGroupColor
disable-model-invocation: true
---

# Find CNetworkMessages_GetNetworkGroupCount, CNetworkMessages_GetNetworkGroupName, and CNetworkMessages_GetNetworkGroupColor

Locate `CNetworkMessages_GetNetworkGroupCount`, `CNetworkMessages_GetNetworkGroupName`, and `CNetworkMessages_GetNetworkGroupColor` vfunc calls in CS2 engine2.dll or libengine2.so using IDA Pro MCP tools.

## Method

### 1. Get CNetworkSystem_SendNetworkStats Function Info

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CNetworkSystem_SendNetworkStats`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract `func_va` for subsequent steps.

### 2. Decompile CNetworkSystem_SendNetworkStats

```
mcp__ida-pro-mcp__decompile addr="<func_va>"
```

### 3. Identify All Three VFunc Offsets from Code Pattern

In the decompiled output, look for a sequence of three **virtual function calls through `g_pNetworkMessages`** that appear together in a loop. The pattern on Windows:

```c
          if ( v12 )
          {
            v13 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)g_pNetworkMessages + <OFFSET_COUNT>))(g_pNetworkMessages);
            // ...
            if ( v13 > 0 )
            {
              // ... loop starts ...
              do
              {
                v54[0] = (*(__int64 (__fastcall **)(__int64, _QWORD))(*(_QWORD *)g_pNetworkMessages + <OFFSET_NAME>))(
                           g_pNetworkMessages,
                           v6);
                (*(void (__fastcall **)(__int64, int *, _QWORD))(*(_QWORD *)g_pNetworkMessages + <OFFSET_COLOR>))(
                  g_pNetworkMessages,
                  &v45,
                  v6);
```

Where:
- `<OFFSET_COUNT>` (e.g. `128LL` = `0x80`) is the vfunc offset of `CNetworkMessages_GetNetworkGroupCount` — called **first**, before the loop, to get the total number of groups
- `<OFFSET_NAME>` (e.g. `136LL` = `0x88`) is the vfunc offset of `CNetworkMessages_GetNetworkGroupName` — called **inside the loop**, returns a string (group name)
- `<OFFSET_COLOR>` (e.g. `144LL` = `0x90`) is the vfunc offset of `CNetworkMessages_GetNetworkGroupColor` — called **inside the loop** right after GetNetworkGroupName, takes an output `int*` parameter (color)

On Linux (`libnetworksystem.so`), the pattern is more complex due to compiler optimizations but follows the same logical structure: `GetNetworkGroupCount` is called first to determine iteration count, then `GetNetworkGroupName` and `GetNetworkGroupColor` are called in a loop.

**Cross-validation**: These three offsets are consecutive (each 8 bytes apart), appearing as adjacent vtable entries. The sequence Count → Name → Color is always in this order.

Extract all three `<OFFSET_*>` values. Calculate vtable indices: `index = offset / 8`.

### 4. Generate VFunc Offset Signature for GetNetworkGroupCount

Identify the instruction address (`inst_addr`) of the virtual call `call qword ptr [rax+<OFFSET_COUNT>]` or similar for the `GetNetworkGroupCount` call site (the one before the loop).

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_GetNetworkGroupCount`, with `inst_addr` and `vfunc_offset` from this step.

### 5. Write YAML for GetNetworkGroupCount

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_GetNetworkGroupCount`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 4

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<OFFSET_COUNT>` in hex (e.g. `0x80`)
- `vfunc_index`: The calculated index (e.g. `16`)

### 6. Generate VFunc Offset Signature for GetNetworkGroupName

Identify the instruction address (`inst_addr`) of the virtual call for `GetNetworkGroupName` (the first call inside the loop, returning a string).

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_GetNetworkGroupName`, with `inst_addr` and `vfunc_offset` from this step.

### 7. Write YAML for GetNetworkGroupName

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_GetNetworkGroupName`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 6

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<OFFSET_NAME>` in hex (e.g. `0x88`)
- `vfunc_index`: The calculated index (e.g. `17`)

### 8. Generate VFunc Offset Signature for GetNetworkGroupColor

Identify the instruction address (`inst_addr`) of the virtual call for `GetNetworkGroupColor` (the call inside the loop right after GetNetworkGroupName, with an `int*` output parameter).

**ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` to generate a robust and unique signature for `CNetworkMessages_GetNetworkGroupColor`, with `inst_addr` and `vfunc_offset` from this step.

### 9. Write YAML for GetNetworkGroupColor

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_GetNetworkGroupColor`
- `func_addr`: `None` (virtual call, actual address resolved at runtime)
- `func_sig`: `None`
- `vfunc_sig`: The validated signature from step 8

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<OFFSET_COLOR>` in hex (e.g. `0x90`)
- `vfunc_index`: The calculated index (e.g. `18`)

## Function Characteristics

### CNetworkMessages_GetNetworkGroupCount

- **Type**: Virtual function of `CNetworkMessages`
- **Purpose**: Returns the total number of registered network message groups
- **Called from**: `CNetworkSystem_SendNetworkStats` — called before the group iteration loop
- **Call context**: Called through `g_pNetworkMessages` vtable pointer
- **Parameters**: `(this)` where `this` is `g_pNetworkMessages`
- **Return**: Integer count of network groups

### CNetworkMessages_GetNetworkGroupName

- **Type**: Virtual function of `CNetworkMessages`
- **Purpose**: Returns the name string for a network message group by index
- **Called from**: `CNetworkSystem_SendNetworkStats` — called inside the loop, first of two calls per iteration
- **Call context**: Called through `g_pNetworkMessages` vtable pointer
- **Parameters**: `(this, group_index)` where `this` is `g_pNetworkMessages`
- **Return**: `const char*` group name string

### CNetworkMessages_GetNetworkGroupColor

- **Type**: Virtual function of `CNetworkMessages`
- **Purpose**: Gets the display color for a network message group by index
- **Called from**: `CNetworkSystem_SendNetworkStats` — called inside the loop, immediately after GetNetworkGroupName
- **Call context**: Called through `g_pNetworkMessages` vtable pointer
- **Parameters**: `(this, int* out_color, group_index)` where `this` is `g_pNetworkMessages`

## VTable Information

- **VTable Name**: `CNetworkMessages`
- **VTable Offsets**: Change with game updates. Extract from the `CNetworkSystem_SendNetworkStats` decompiled code.
- **VTable Indices**: Change with game updates. Resolve via `offset / 8`.
- **Note**: The three offsets are consecutive (8 bytes apart) in the vtable.

## Identification Pattern

The three functions are identified by the characteristic pattern in `CNetworkSystem_SendNetworkStats`:
1. `GetNetworkGroupCount` is called first to get the loop bound
2. Inside the loop, `GetNetworkGroupName` returns the group name string
3. Immediately after, `GetNetworkGroupColor` retrieves the group color via output pointer
4. All three use the `g_pNetworkMessages` global pointer for vtable dispatch

This is robust because:
- `CNetworkSystem_SendNetworkStats` is reliably found via its own signature
- The three virtual calls appear in a distinctive Count → Name → Color sequence
- The consecutive vtable offsets (8 bytes apart) provide cross-validation

## Output YAML Format

The output YAML filenames depend on the platform:
- `engine2.dll` -> `CNetworkMessages_GetNetworkGroupCount.windows.yaml`, `CNetworkMessages_GetNetworkGroupName.windows.yaml`, `CNetworkMessages_GetNetworkGroupColor.windows.yaml`
- `libengine2.so` -> `CNetworkMessages_GetNetworkGroupCount.linux.yaml`, `CNetworkMessages_GetNetworkGroupName.linux.yaml`, `CNetworkMessages_GetNetworkGroupColor.linux.yaml`
