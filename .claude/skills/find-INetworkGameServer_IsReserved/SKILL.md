---
name: find-INetworkGameServer_IsReserved
description: |
  Final-guarantee fallback for the find-INetworkGameServer_IsReserved preprocessor.
  Recovers INetworkGameServer::IsReserved (a virtual function of the INetworkGameServer
  interface) in CS2 engine2.dll / libengine2.so by decompiling its known predecessor
  CNetworkGameServerBase_RecalculateTags and identifying the vtable-slot call made on the server object.
  Use this skill only when the deterministic/LLM preprocessor
  (ida_preprocessor_scripts/find-INetworkGameServer_IsReserved.py) could not resolve the target.
  Trigger: INetworkGameServer_IsReserved
disable-model-invocation: true
---

# Find INetworkGameServer_IsReserved (final-guarantee fallback)

Recover the virtual function `INetworkGameServer::IsReserved` in CS2 `engine2.dll` /
`libengine2.so` using IDA Pro MCP tools. This is the **Agent fallback** for the
`find-INetworkGameServer_IsReserved` skill: it runs only when the preprocessor script returned
failure (almost always a transient LLM error, or the predecessor's call structure moved).

## Realworld Function References

Read the platform-relevant reference YAMLs before searching in IDA. Treat their addresses as
reference-build values only; verify against the current binary.

- Windows baseline: `ida_preprocessor_scripts/references/engine/CNetworkGameServerBase_RecalculateTags.windows.yaml`
- Linux baseline: `ida_preprocessor_scripts/references/engine/CNetworkGameServerBase_RecalculateTags.linux.yaml`

## Step 1. Load and decompile the predecessor

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=CNetworkGameServerBase_RecalculateTags` to
obtain its `func_va`. If it returns an error, **STOP** and report to user (this fallback cannot run
without the predecessor).

Decompile it:

```
mcp__ida-pro-mcp__decompile addr="<CNetworkGameServerBase_RecalculateTags.func_va>"
```

## Step 2. Locate the vtable-slot call to the target

`CNetworkGameServerBase::RecalculateTags` builds the server tag string (it logs
`"Tags string is too long: %s\n"` on overflow). Look for the virtual call on the server object
(`this` or the interface pointer derived from it) whose boolean result reports whether the server is
reserved and feeds the tag-building logic. Anchor on the **semantic fingerprint** -- a
`call qword ptr [reg+disp]` (Windows may hoist the slot into a register with `mov`) on the server
object, with a boolean result gating tag text -- not on a fixed offset. Use the reference YAML
annotations (`INetworkGameServer_IsReserved` comment tags) to confirm which call.

Do **not** pick sibling slots on the same object (for example `GetServerState`).

## Step 3. Resolve the vfunc slot and write the YAML

1. From the resolved `vfunc_offset`, rename the reference to `INetworkGameServer_IsReserved` with
   `mcp__ida-pro-mcp__rename`.
2. **ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` for the vfunc at the resolved
   offset to obtain a validated `vfunc_sig`.
3. **ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:
   - `func_name`: `INetworkGameServer_IsReserved`
   - `vtable_name`: `INetworkGameServer`
   - `vfunc_sig`: the validated signature from step 2
   - `vfunc_offset` / `vfunc_index`: the resolved values

`INetworkGameServer` is an abstract interface; this YAML is slot-only: do **not** emit `func_va`.
The concrete implementation is resolved by `find-CNetworkGameServerBase_IsReserved`, which
inherits this slot.

## Output YAML filenames

- Windows (`engine2.dll`): `INetworkGameServer_IsReserved.windows.yaml`
- Linux (`libengine2.so`): `INetworkGameServer_IsReserved.linux.yaml`

## Failure handling

- If the predecessor `CNetworkGameServerBase_RecalculateTags` YAML is missing -> **STOP** and report to user.
- If the target slot call cannot be located even after inspecting the predecessor -> **STOP** and
  report so the user can extend the references.
