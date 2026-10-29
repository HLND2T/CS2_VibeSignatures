---
name: find-INetworkGameServer_GetGameServerSteamID
description: |
  Final-guarantee fallback for the find-INetworkGameServer_GetGameServerSteamID preprocessor.
  Recovers INetworkGameServer::GetGameServerSteamID (a virtual function of the INetworkGameServer
  interface) in CS2 client.dll / libclient.so by decompiling its known predecessor
  GetRichPresenceStatusString and identifying the vtable-slot fetch made on the network game server.
  Use this skill only when the deterministic/LLM preprocessor
  (ida_preprocessor_scripts/find-INetworkGameServer_GetGameServerSteamID.py) could not resolve the target.
  Trigger: INetworkGameServer_GetGameServerSteamID
disable-model-invocation: true
---

# Find INetworkGameServer_GetGameServerSteamID (final-guarantee fallback)

Recover the virtual function `INetworkGameServer::GetGameServerSteamID` in CS2 `client.dll` /
`libclient.so` using IDA Pro MCP tools. This is the **Agent fallback** for the
`find-INetworkGameServer_GetGameServerSteamID` skill: it runs only when the preprocessor script
returned failure (almost always a transient LLM error, or the predecessor's call structure moved).

## Realworld Function References

Read the platform-relevant reference YAMLs before searching in IDA. Treat their addresses as
reference-build values only; verify against the current binary.

- Windows baseline: `ida_preprocessor_scripts/references/client/GetRichPresenceStatusString.windows.yaml`
- Linux baseline: `ida_preprocessor_scripts/references/client/GetRichPresenceStatusString.linux.yaml`

## Step 1. Load and decompile the predecessor

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=GetRichPresenceStatusString` to obtain its
`func_va`. If it returns an error, **STOP** and report to user (this fallback cannot run without the
predecessor).

Decompile it:

```
mcp__ida-pro-mcp__decompile addr="<GetRichPresenceStatusString.func_va>"
```

## Step 2. Locate the vtable-slot reference to the target

The predecessor resolves the **network game server** through a second interface hop and then fetches
the steam id from *that* object's vtable. Anchor by the **semantic fingerprint**, not a fixed offset:

- Windows: `mov rax, [rcx]` -> `call qword ptr [rax+0B8h]` -> `test rax, rax` -> `mov rcx, [rax]`
  -> `mov r8, [rcx+1E8h]` -> `mov rcx, rax` -> `call r8`
- Linux: `mov rax, [rdi]` -> `call qword ptr [rax+0C0h]` -> `test rax, rax` -> `mov rax, [rax]`
  -> `call qword ptr [rax+1E8h]`

**Important:** on Windows the compiler *hoists the slot into a register* instead of calling it in
place, so the reference is a `mov`, not a `call`. Searching only for `call qword ptr [reg+...]` will
find nothing there.

Reference build vtable offset (verify, do not hardcode): `vfunc_offset = 0x1E8` (488),
`vfunc_index = 61` on both platforms.

### Do not confuse this slot with IVEngineServer2

`0x1E8` is **INetworkGameServer** index 61. `IVEngineServer2::GetGameServerSteamID` is a *different*
symbol at index **85** (`0x2A8`); `IVEngineServer2` index 61 is `SetSpawnGroupDescription` (a tiny
forwarder into the spawn-group manager global, next to `MakeSpawnGroupActive` at index 64 / `0x200`).
Claiming `IVEngineServer2_GetGameServerSteamID` at `0x1E8` makes `cpp_tests/ivengineserver2.cpp`
fail with an index-61 name mismatch.

## Step 3. Resolve the vfunc slot and write the YAML

1. From the resolved `vfunc_offset`, rename the reference to
   `INetworkGameServer_GetGameServerSteamID` with `mcp__ida-pro-mcp__rename`.
2. **ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` for the vfunc at the resolved
   offset to obtain a validated `vfunc_sig`.
3. **ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:
   - `func_name`: `INetworkGameServer_GetGameServerSteamID`
   - `vtable_name`: `INetworkGameServer`
   - `vfunc_sig`: the validated signature from step 2
   - `vfunc_offset` / `vfunc_index`: the resolved values

`INetworkGameServer` is an abstract interface with no vtable in the client module, so this YAML is
slot-only: do **not** attempt to emit `func_va`. The concrete implementation address is resolved
separately in the engine module by `find-CNetworkGameServerBase_GetGameServerSteamID`, which inherits
this slot.

## Output YAML filenames

Written beside the binary by the writer skill, one file per platform:

- Windows (`client.dll`): `INetworkGameServer_GetGameServerSteamID.windows.yaml`
- Linux (`libclient.so`): `INetworkGameServer_GetGameServerSteamID.linux.yaml`

## Failure handling

- If the predecessor `GetRichPresenceStatusString` YAML is missing -> **STOP** and report to user.
- If the target slot fetch cannot be located even after inspecting the predecessor -> **STOP** and
  report so the user can extend the references.
