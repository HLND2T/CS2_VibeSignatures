---
name: find-IVEngineServer2_GetGameServerSteamID
description: |
  Final-guarantee fallback for the find-IVEngineServer2_GetGameServerSteamID preprocessor.
  Recovers IVEngineServer2::GetGameServerSteamID (a virtual function of the IVEngineServer2 interface)
  in CS2 client.dll / libclient.so by decompiling its known predecessor
  GetRichPresenceStatusString and identifying the vtable-slot fetch made on the connected game server.
  Use this skill only when the deterministic/LLM preprocessor
  (ida_preprocessor_scripts/find-IVEngineServer2_GetGameServerSteamID.py) could not resolve the target.
  Trigger: IVEngineServer2_GetGameServerSteamID
disable-model-invocation: true
---

# Find IVEngineServer2_GetGameServerSteamID (final-guarantee fallback)

Recover the virtual function `IVEngineServer2::GetGameServerSteamID` in CS2 `client.dll` /
`libclient.so` using IDA Pro MCP tools. This is the **Agent fallback** for the
`find-IVEngineServer2_GetGameServerSteamID` skill: it runs only when the preprocessor script returned
failure (almost always a transient LLM error, or the predecessor's call structure moved).

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

The predecessor resolves the game server through a **second interface hop**: it calls a slot on some
interface, then fetches the target slot from the *returned* object's vtable. Anchor by the
**semantic fingerprint**, not a fixed offset:

- Windows: `mov rax, [rcx]` -> `call qword ptr [rax+0B8h]` -> `test rax, rax` -> `mov rcx, [rax]`
  -> `mov r8, [rcx+1E8h]` -> `mov rcx, rax` -> `call r8`
- Linux: `mov rax, [rdi]` -> `call qword ptr [rax+0C0h]` -> `test rax, rax` -> `mov rax, [rax]`
  -> `call qword ptr [rax+1E8h]`

**Important:** on Windows the compiler *hoists the slot into a register* instead of calling it in
place, so the reference is a `mov`, not a `call`. Searching only for `call qword ptr [reg+...]` will
find nothing there.

Reference build vtable offset (verify, do not hardcode): `vfunc_offset = 0x1E8` (488),
`vfunc_index = 61` on both platforms.

## Step 3. Resolve the vfunc slot and write the YAML

1. From the resolved `vfunc_offset`, rename the reference to
   `IVEngineServer2_GetGameServerSteamID` with `mcp__ida-pro-mcp__rename`.
2. **ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` for the vfunc at the resolved
   offset to obtain a validated `vfunc_sig`.
3. **ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:
   - `func_name`: `IVEngineServer2_GetGameServerSteamID`
   - `vtable_name`: `IVEngineServer2`
   - `vfunc_sig`: the validated signature from step 2
   - `vfunc_offset` / `vfunc_index`: the resolved values

`IVEngineServer2` is an abstract interface with no vtable in the client module, so this YAML is
slot-only: do **not** attempt to emit `func_va`. The concrete implementation address is resolved
separately in the engine module by `find-CEngineServer_GetGameServerSteamID`, which inherits this slot.

## Output YAML filenames

Written beside the binary by the writer skill, one file per platform:

- Windows (`client.dll`): `IVEngineServer2_GetGameServerSteamID.windows.yaml`
- Linux (`libclient.so`): `IVEngineServer2_GetGameServerSteamID.linux.yaml`

## Failure handling

- If the predecessor `GetRichPresenceStatusString` YAML is missing -> **STOP** and report to user.
- If the target slot fetch cannot be located even after inspecting the predecessor -> **STOP** and
  report so the user can extend the references.
