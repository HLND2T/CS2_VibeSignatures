---
name: find-IVEngineServer2_GetClientSteamID
description: |
  Final-guarantee fallback for the find-IVEngineServer2_GetClientSteamID preprocessor.
  Recovers IVEngineServer2::GetClientSteamID (a virtual function of the IVEngineServer2 interface)
  in CS2 server.dll / libserver.so by decompiling its known predecessor
  CBasePlayerController_HandleCommand_JoinTeam and identifying the vtable-slot fetch on g_engine.
  Use this skill only when the deterministic/LLM preprocessor
  (ida_preprocessor_scripts/find-IVEngineServer2_GetClientSteamID.py) could not resolve the target.
  Trigger: IVEngineServer2_GetClientSteamID
disable-model-invocation: true
---

# Find IVEngineServer2_GetClientSteamID (final-guarantee fallback)

Recover the virtual function `IVEngineServer2::GetClientSteamID` in CS2 `server.dll` /
`libserver.so` using IDA Pro MCP tools. This is the **Agent fallback** for the
`find-IVEngineServer2_GetClientSteamID` skill: it runs only when the preprocessor script returned
failure (almost always a transient LLM error, or the predecessor's call structure moved).

## Realworld Function References

Read the platform-relevant reference YAMLs before searching in IDA. Treat their addresses as
reference-build values only; verify against the current binary.

- Windows baseline: `ida_preprocessor_scripts/references/server/CBasePlayerController_HandleCommand_JoinTeam.windows.yaml`
- Linux baseline: `ida_preprocessor_scripts/references/server/CBasePlayerController_HandleCommand_JoinTeam.linux.yaml`

## Step 1. Load and decompile the predecessor

**ALWAYS** Use SKILL `/get-func-from-yaml` with
`func_name=CBasePlayerController_HandleCommand_JoinTeam` to obtain its `func_va`. If it returns an
error, **STOP** and report to user (this fallback cannot run without the predecessor).

Decompile it:

```
mcp__ida-pro-mcp__decompile addr="<CBasePlayerController_HandleCommand_JoinTeam.func_va>"
```

## Step 2. Locate the vtable-slot reference to the target

`IVEngineServer2::GetClientSteamID` is reached through the global `g_engine`. **Important:** in this
predecessor the compiler *hoists the slot into a register* instead of calling it in place, so the
reference is a `mov`, not a `call`. Searching only for `call qword ptr [reg+...]` will find nothing.

Anchor by the **semantic fingerprint**, not a fixed offset — load the interface pointer from
`g_engine`, load its vtable, then fetch the slot:

- Linux: `lea rax, g_engine` -> `mov r12, [rax]` -> `mov rax, [r12]` -> `mov r13, [rax+228h]`
- Windows: `mov rax, cs:g_engine` -> `mov rcx, [rax]` -> `mov rbx, [rcx+228h]`

Reference build vtable offset (verify, do not hardcode): `vfunc_offset = 0x228` (552),
`vfunc_index = 69` on both platforms. The predecessor contains more than one such fetch; any of them
resolves the same slot.

## Step 3. Resolve the vfunc slot and write the YAML

1. From the resolved `vfunc_offset`, rename the reference to `IVEngineServer2_GetClientSteamID`
   with `mcp__ida-pro-mcp__rename`.
2. **ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` for the vfunc at the resolved
   offset to obtain a validated `vfunc_sig`.
3. **ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:
   - `func_name`: `IVEngineServer2_GetClientSteamID`
   - `vtable_name`: `IVEngineServer2`
   - `vfunc_sig`: the validated signature from step 2
   - `vfunc_offset` / `vfunc_index`: the resolved values

`IVEngineServer2` is an abstract interface with no vtable in the server module, so this YAML is
slot-only: do **not** attempt to emit `func_va`. The concrete implementation address is resolved
separately in the engine module by `find-CEngineServer_GetClientSteamID`, which inherits this slot.

## Output YAML filenames

Written beside the binary by the writer skill, one file per platform:

- Windows (`server.dll`): `IVEngineServer2_GetClientSteamID.windows.yaml`
- Linux (`libserver.so`): `IVEngineServer2_GetClientSteamID.linux.yaml`

## Failure handling

- If the predecessor `CBasePlayerController_HandleCommand_JoinTeam` YAML is missing -> **STOP** and
  report to user.
- If the target slot fetch cannot be located even after inspecting the predecessor -> **STOP** and
  report so the user can extend the references.
