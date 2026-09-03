---
name: find-CNetworkGameServer_GetFreeClient
description: |
  Final-guarantee fallback for CNetworkGameServer_GetFreeClient. Locate the concrete free-client allocator
  in CS2 engine2.dll / libengine2.so when the ConnectClient decompile preprocessor cannot resolve it.
  Use only after the deterministic preprocessor returns failure.
  Trigger: CNetworkGameServer_GetFreeClient
disable-model-invocation: true
---

# Find CNetworkGameServer_GetFreeClient (Agent fallback)

Locate `CNetworkGameServer_GetFreeClient` in the current CS2 `engine2.dll` or `libengine2.so` using IDA Pro
MCP tools. The fallback must recover the concrete function called by `CNetworkGameServerBase_ConnectClient`
on its server object; do not infer an address from an old build.

## Step 0. Skip an existing output

If `CNetworkGameServer_GetFreeClient.<platform>.yaml` already exists as a non-empty mapping in the active
artifact module directory, skip that platform. The artifact directory is separate from `bin`; never derive
the output path from the binary root.

## Step 1. Load the ConnectClient predecessor

Use `/get-func-from-yaml` with `func_name=CNetworkGameServerBase_ConnectClient` to obtain the current
`func_va`. If it is unavailable, stop and report that the predecessor is missing.

Decompile that function with IDA Pro MCP. Confirm the first argument is the `CNetworkGameServerBase`/
`CNetworkGameServer` server object (`rcx` on Windows, normally `rdi` on Linux).

## Step 2. Identify the GetFreeClient call

Find the call on the server object's connection path that returns a client pointer immediately before the
server-full rejection. The semantic anchors are the error string or equivalent message containing
`NETWORK_DISCONNECT_REJECT_SERVERFULL` and `Cannot get free client`, and the null check on the call result.
The target has the shape:

```c
client = sub_<current>(server, address, 0, steam_id, 0, out_buffer);
if (!client) {
    // disconnect with NETWORK_DISCONNECT_REJECT_SERVERFULL
    // log: "Cannot get free client"
}
```

Search the exact error text (including format-string variants), enumerate xrefs, and decompile each
referencing function if necessary. Follow one caller/callee level when the allocator is outlined. Reject
helpers that only log, register a command, or perform unrelated client setup. Confirm that the selected
function allocates/selects a free client slot and returns a pointer or null.

Reference values from build 14167 are orientation only and must not be copied without verification:

| Platform | Reference `func_va` | Reference size |
|---|---:|---:|
| Windows | `0x1800af840` | `0x24d` |
| Linux | `0x6968d0` | `0x2b8` |

## Step 3. Generate and write the artifact

Rename the verified function with IDA MCP, then use `/generate-signature-for-function` when it can produce a
unique signature. Use `/write-func-as-yaml` to write the semantic payload to the active artifact module
directory with:

- `func_name=CNetworkGameServer_GetFreeClient`
- the verified current `func_addr`
- `func_rva` relative to the image base
- the current `func_size`
- `func_sig` only when the generated signature passes uniqueness validation

The output is `CNetworkGameServer_GetFreeClient.windows.yaml` beside `engine2.dll` or
`CNetworkGameServer_GetFreeClient.linux.yaml` beside `libengine2.so` in the artifact root. The trusted
analyzer performs final canonical serialization; this skill supplies semantic fields only.

## Failure handling

- Do not guess from the reference addresses.
- Do not emit a Windows result while analyzing Linux, or vice versa.
- If the error anchor or allocator semantics cannot be confirmed, stop and report the ambiguity.
