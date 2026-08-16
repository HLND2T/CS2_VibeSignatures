---
name: find-INetworkServerService_IsActiveInGame
description: |
  Final-guarantee fallback for the find-INetworkServerService_IsActiveInGame preprocessor.
  Recovers INetworkServerService::IsActiveInGame (a virtual function of the CNetworkServerService vtable)
  in CS2 engine2.dll / libengine2.so by decompiling its known predecessor CSteam3ServerS1_InitGameServer
  and identifying the virtual call on g_pNetworkServerService. Use this skill only when the
  deterministic/LLM preprocessor
  (ida_preprocessor_scripts/find-INetworkServerService_IsActiveInGame.py) could not resolve the target.
  Trigger: INetworkServerService_IsActiveInGame
disable-model-invocation: true
---

# Find INetworkServerService_IsActiveInGame (final-guarantee fallback)

Recover the virtual function `INetworkServerService::IsActiveInGame` in CS2 `engine2.dll` /
`libengine2.so` using IDA Pro MCP tools. This is the **Agent fallback** for the
`find-INetworkServerService_IsActiveInGame` skill: it runs only when the preprocessor script returned
failure (almost always a transient LLM error, or the predecessor's call structure moved).

## Realworld Function References

Read the platform-relevant reference YAMLs before searching in IDA. They contain the annotated virtual
call site (`; 0x0C0/0x0C8 = ... = INetworkServerService_IsActiveInGame`). Treat their addresses as
reference-build values only; verify against the current binary.

- Windows baseline: `ida_preprocessor_scripts/references/engine/CSteam3ServerS1_InitGameServer.windows.yaml`
- Linux baseline: `ida_preprocessor_scripts/references/engine/CSteam3ServerS1_InitGameServer.linux.yaml`

## Step 1. Load and decompile the predecessor

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CSteam3ServerS1_InitGameServer` to obtain its
`func_va`. If it returns an error, **STOP** and report to user (this fallback cannot run without the
predecessor).

Decompile it:

```
mcp__ida-pro-mcp__decompile addr="<CSteam3ServerS1_InitGameServer.func_va>"
```

## Step 2. Locate the virtual call to the target

`INetworkServerService::IsActiveInGame(this)` is an indirect virtual call on the global
`g_pNetworkServerService`. Anchor by its **semantic fingerprint**, not a fixed offset:

- It is the `call qword ptr [reg + <off>]` where `reg = *g_pNetworkServerService` (load the vtable from
  the global, then call through it).
- It returns a boolean (`al`) that **selects between two 16-bit values** which are then stored to a member
  of the `CSteam3Server` `this` (`*(this + 0x114/*win*/ or + 0x13C/*linux*/) = ...`).
- It sits **immediately after** two `g_pNetworkSystem` virtual calls (`+0x118` and `+0x110` on Windows;
  `+0x118` and `+0x110` on Linux) whose results are the two 16-bit candidates.
- It sits **immediately before** the `LoggingSystem_IsChannelEnabled` / `"SteamGameServer_Init()\n"`
  logging block.

Reference build vtable offsets (verify, do not hardcode):

- Windows: `call qword ptr [rdx+0C0h]` -> `vfunc_offset = 0xC0` (192), `vfunc_index = 24`
- Linux: `call qword ptr [rax+0C8h]` -> `vfunc_offset = 0xC8` (200), `vfunc_index = 25`

The vtable offset differs per platform; derive it from the located call instruction on the current binary.

## Step 3. Resolve the vfunc body, generate the signature, and write the YAML

1. From the resolved `vfunc_offset`, read the vtable slot of `CNetworkServerService_vtable` to obtain the
   concrete function address, and rename it to `INetworkServerService_IsActiveInGame` with
   `mcp__ida-pro-mcp__rename`.
2. **ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` for the vfunc at the resolved address/offset
   to obtain a validated `vfunc_sig`.
3. **ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:
   - `func_name`: `INetworkServerService_IsActiveInGame`
   - `vtable_name`: `CNetworkServerService_vtable`
   - `vfunc_sig`: the validated signature from step 2
   - `vfunc_offset` / `vfunc_index`: the resolved values

## Output YAML filenames

Written beside the binary by the writer skill, one file per platform:

- Windows (`engine2.dll`): `INetworkServerService_IsActiveInGame.windows.yaml`
- Linux (`libengine2.so`): `INetworkServerService_IsActiveInGame.linux.yaml`

## Failure handling

- If the predecessor `CSteam3ServerS1_InitGameServer` YAML is missing → **STOP** and report to user.
- If the target virtual call cannot be located even after inspecting the predecessor → **STOP** and report
  so the user can extend the references.
