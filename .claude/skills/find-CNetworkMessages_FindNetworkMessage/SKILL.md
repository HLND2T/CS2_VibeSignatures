---
name: find-CNetworkMessages_FindNetworkMessage
description: |
  Find and identify the CNetworkMessages_FindNetworkMessage virtual function in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 networksystem.dll or libnetworksystem.so to locate the FindNetworkMessage vfunc
  by checking vtable entries adjacent to the known CNetworkMessages_FindNetworkMessagePartial slot.
  Trigger: CNetworkMessages_FindNetworkMessage
disable-model-invocation: true
---

# Find CNetworkMessages_FindNetworkMessage

Locate `CNetworkMessages_FindNetworkMessage` vfunc in CS2 `networksystem.dll` or `libnetworksystem.so` using IDA Pro MCP tools.

## Method

### 1. Load CNetworkMessages_FindNetworkMessagePartial from YAML

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CNetworkMessages_FindNetworkMessagePartial`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract:
- `func_va` of `CNetworkMessages_FindNetworkMessagePartial`
- `vfunc_index`
- `vfunc_offset`

### 2. Load CNetworkMessages VTable from YAML

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name=CNetworkMessages`.

If the skill returns an error, **STOP** and report to user.

Otherwise, extract:
- `vtable_numvfunc`
- `vtable_entries`

### 3. Resolve Candidate Slots

Compute the candidate slots for `CNetworkMessages_FindNetworkMessage`:

- `candidate_index_1 = CNetworkMessages_FindNetworkMessagePartial.vfunc_index - 2`
- `candidate_index_2 = CNetworkMessages_FindNetworkMessagePartial.vfunc_index - 1`

Validate that both indices are >= 0, then read:

- `candidate_addr_1 = CNetworkMessages_vtable[candidate_index_1]`
- `candidate_addr_2 = CNetworkMessages_vtable[candidate_index_2]`

### 4. Decompile and Identify the Correct Candidate

Decompile both candidate functions:

```text
mcp__ida-pro-mcp__decompile addr="<candidate_addr_1>"
mcp__ida-pro-mcp__decompile addr="<candidate_addr_2>"
```

#### Windows (`networksystem.dll`)

`CNetworkMessages_FindNetworkMessage` has these characteristic patterns:

```c
__int64 __thiscall CNetworkMessages_FindNetworkMessage(__int64 this, __int64 a2)
{
  // ...
  v12 = *(__int64 (__fastcall ****)(_QWORD))((*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v10 + 16LL))(v10) + 8);
  v13 = v12 ? (char *)(**v12)(v12) : "unknown";
  if ( !(unsigned int)V_stricmp_fast(v13) )
    return v10;
  // ...
}
```

Key identification rules for Windows:
1. Takes two parameters: `(__int64 this, __int64 a2)` — this pointer + message name
2. Contains a reference to the literal string `"unknown"` as a fallback when a pointer is null
3. Calls `V_stricmp_fast` to compare a retrieved name string against the search argument
4. Contains a loop with `0xFFFF` sentinel checks — `while ( v2 != 0xFFFF )` and `if ( v5 == 0xFFFF ) return 0`
5. Uses a lock mechanism with `GetCurrentThreadId` and `_InterlockedCompareExchange`
6. Returns a pointer to the found network message, or 0 if not found

#### Linux (`libnetworksystem.so`)

`CNetworkMessages_FindNetworkMessage` has these characteristic patterns:

```c
__int64 __fastcall CNetworkMessages_FindNetworkMessage(__int64 a1, __int64 a2)
{
  // ...
  v14 = "unknown";
  if ( v13 )
    v14 = (const char *)(**v13)(v13);
  // ...
}
```

Key identification rules for Linux:
1. Takes two parameters: `(__int64 a1, __int64 a2)` — this pointer + message name
2. Contains a reference to the literal string `"unknown"` as a fallback when a pointer is null
3. Contains `if ( v2 == 0xFFFF ) return 0` sentinel checks
4. Uses `_InterlockedCompareExchange` for lock acquisition
5. Returns a pointer to the found network message, or 0 if not found

### 5. Confirm the Correct Candidate

The correct function among the two candidates is the one that:
- References the literal string `"unknown"`
- Calls `V_stricmp_fast` (Windows) or a string comparison function (Linux)
- Contains `0xFFFF` sentinel value checks with `return 0` on not-found
- Uses thread locking (`GetCurrentThreadId` / `_InterlockedCompareExchange`)

If neither candidate matches, **STOP** and report to user.

### 6. Generate Function Signature

**ALWAYS** Use SKILL `/generate-signature-for-function` with `addr=<confirmed_func_addr>` to generate a robust and unique `func_sig` for `CNetworkMessages_FindNetworkMessage`.

Use the returned validated `func_sig` in the next step.

### 7. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_FindNetworkMessage`
- `func_addr`: `<confirmed_func_addr>`
- `func_sig`: The validated signature from step 6
- `vfunc_sig`: `None`

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: `<target_vfunc_offset>` in hex (computed as `confirmed_vfunc_index * 8`)
- `vfunc_index`: `<confirmed_vfunc_index>`

## Function Characteristics

- **Purpose**: Finds a registered network message by name, iterating through a hash-table structure and comparing message names using case-insensitive string comparison
- **Binary**: `networksystem.dll` / `libnetworksystem.so`
- **Parameters**: `(this, const char* messageName)` — the CNetworkMessages instance and the name to search for
- **Return value**: Pointer to the found network message object, or 0 (null) if not found

## Discovery Strategy

1. Load the existing `CNetworkMessages_FindNetworkMessagePartial` YAML to obtain its vtable index
2. Load the existing `CNetworkMessages_vtable` YAML to resolve adjacent vtable entries
3. Check the two entries at `vfunc_index - 2` and `vfunc_index - 1`
4. Decompile both candidates and match against the `"unknown"` string literal + `V_stricmp_fast` pattern
5. Generate a stable `func_sig` from the confirmed function body

This is robust because:
- The vtable adjacency to `FindNetworkMessagePartial` is stable
- The `"unknown"` string literal and `V_stricmp_fast` call are highly distinctive identifiers
- The `0xFFFF` sentinel pattern and thread locking are additional confirmation signals

## Output YAML Format

The output YAML filename depends on the platform:
- `networksystem.dll` -> `CNetworkMessages_FindNetworkMessage.windows.yaml`
- `libnetworksystem.so` -> `CNetworkMessages_FindNetworkMessage.linux.yaml`
