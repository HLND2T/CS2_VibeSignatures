---
name: find-CNetworkMessages_GetLoggingChannel
description: |
  Find and identify the CNetworkMessages_GetLoggingChannel virtual function in CS2 binary using IDA Pro MCP.
  Use this skill when reverse engineering CS2 networksystem.dll or libnetworksystem.so to locate the GetLoggingChannel vfunc
  by cross-referencing the "Networking" logging channel registration with the CNetworkMessages vtable.
  Trigger: CNetworkMessages_GetLoggingChannel
disable-model-invocation: true
---

# Find CNetworkMessages_GetLoggingChannel

Locate `CNetworkMessages_GetLoggingChannel` vfunc in CS2 networksystem.dll or libnetworksystem.so using IDA Pro MCP tools.

## Method

### 1. Search for the "Networking" String

```
mcp__ida-pro-mcp__find_regex pattern="Networking"
```

Find the exact string `"Networking"` and get its address.

### 2. Find Cross-References to the String

```
mcp__ida-pro-mcp__xrefs_to addrs="<string_addr>"
```

Collect all functions that reference this string.

### 3. Find Cross-References to LoggingSystem_RegisterLoggingChannel

```
mcp__ida-pro-mcp__xrefs_to addrs="<LoggingSystem_RegisterLoggingChannel_addr>"
```

Collect all functions that call `LoggingSystem_RegisterLoggingChannel`.

### 4. Find the Intersection

Find the function that appears in **both** xref sets. This is the logging channel registration function, which looks like:

```c
__int64 sub_XXXXXXXX()
{
  __int64 result;
  result = LoggingSystem_RegisterLoggingChannel("Networking", 0LL, 0LL, 2LL, -156);
  g_pLoggingChannel = result;
  return result;
}
```

Rename the global variable to `g_pLoggingChannel`.

### 5. Load CNetworkMessages VTable from YAML

**ALWAYS** Use SKILL `/get-vtable-from-yaml` to load the CNetworkMessages vtable information, including its address and size (vfunc_count).

### 6. Decompile the Last 4 VTable Entries

Decompile the virtual functions at indices `vfunc_count - 4` through `vfunc_count - 1` from the CNetworkMessages vtable.

```
mcp__ida-pro-mcp__decompile addr="<vtable_entry_addr>"
```

Look for a vfunc that simply returns `g_pLoggingChannel`:

```c
__int64 CNetworkMessages_GetLoggingChannel()
{
  return (unsigned int)g_pLoggingChannel;
}
```

This is `CNetworkMessages_GetLoggingChannel`.

### 7. Write IDA Analysis Output as YAML

**ALWAYS** Use SKILL `/write-vfunc-as-yaml` to write the analysis results.

Required parameters:
- `func_name`: `CNetworkMessages_GetLoggingChannel`
- `func_addr`: The resolved vfunc address
- `func_sig`: `None`
- `vfunc_sig`: `None`

VTable parameters:
- `vtable_name`: `CNetworkMessages`
- `vfunc_offset`: The calculated offset in hex (e.g. `0x120`)
- `vfunc_index`: The calculated index

## Function Characteristics

- **Purpose**: Returns a logging channel handle used for network-related log messages
- **Binary**: networksystem.dll / libnetworksystem.so
- **Parameters**: `(this)` — takes only the vtable `this` pointer
- **Return value**: A logging channel handle (the `g_pLoggingChannel` global, cast to `unsigned int`)

## VTable Information

- **VTable Name**: `CNetworkMessages`
- **VTable Offset / Index**: Changes with game updates. Always near the end of the vtable (last 4 entries).

## Discovery Strategy

1. **String + API intersection**: Find the function that both references `"Networking"` and calls `LoggingSystem_RegisterLoggingChannel` — this gives `g_pLoggingChannel`
2. **VTable tail scan**: The getter is always near the end of the CNetworkMessages vtable — decompile the last 4 entries and match the one returning `g_pLoggingChannel`

This approach is robust because:
- The `"Networking"` string combined with `LoggingSystem_RegisterLoggingChannel` uniquely identifies the channel registration
- The getter is a trivial function (just returns a global), easy to identify by structure
- No byte-pattern signatures needed — the discovery is entirely semantic

## Output YAML Format

The output YAML filename depends on the platform:
- `networksystem.dll` -> `CNetworkMessages_GetLoggingChannel.windows.yaml`
- `libnetworksystem.so` -> `CNetworkMessages_GetLoggingChannel.linux.yaml`
