---
name: find-INetworkServerService_GetServerSerializersCRC
description: |
  Final-guarantee fallback for the find-INetworkServerService_GetServerSerializersCRC preprocessor.
  Recovers INetworkServerService::GetServerSerializersCRC (a virtual function of the CNetworkServerService
  vtable) in CS2 engine2.dll / libengine2.so by decompiling its known predecessor
  CNetworkGameServer_WriteClassInfosAndSerializesToBuffer and identifying the virtual call on
  g_pNetworkServerService. Use this skill only when the deterministic/LLM preprocessor
  (ida_preprocessor_scripts/find-INetworkServerService_GetServerSerializersCRC.py) could not resolve the target.
  Trigger: INetworkServerService_GetServerSerializersCRC
disable-model-invocation: true
---

# Find INetworkServerService_GetServerSerializersCRC (final-guarantee fallback)

Recover the virtual function `INetworkServerService::GetServerSerializersCRC` in CS2 `engine2.dll` /
`libengine2.so` using IDA Pro MCP tools. This is the **Agent fallback** for the
`find-INetworkServerService_GetServerSerializersCRC` skill: it runs only when the preprocessor script
returned failure (almost always a transient LLM error, or the predecessor's call structure moved).

## Realworld Function References

Read the platform-relevant reference YAMLs before searching in IDA. They contain the annotated virtual
call site (`; 0x148/0x150 = ... = INetworkServerService_GetServerSerializersCRC`). Treat their addresses as
reference-build values only; verify against the current binary.

- Windows baseline: `ida_preprocessor_scripts/references/engine/CNetworkGameServer_WriteClassInfosAndSerializesToBuffer.windows.yaml`
- Linux baseline: `ida_preprocessor_scripts/references/engine/CNetworkGameServer_WriteClassInfosAndSerializesToBuffer.linux.yaml`

## Step 1. Load and decompile the predecessor

**ALWAYS** Use SKILL `/get-func-from-yaml` with
`func_name=CNetworkGameServer_WriteClassInfosAndSerializesToBuffer` to obtain its `func_va`. If it returns an
error, **STOP** and report to user (this fallback cannot run without the predecessor).

Decompile it:

```
mcp__ida-pro-mcp__decompile addr="<CNetworkGameServer_WriteClassInfosAndSerializesToBuffer.func_va>"
```

## Step 2. Locate the virtual call to the target

`INetworkServerService::GetServerSerializersCRC(this)` is an indirect virtual call on the global
`g_pNetworkServerService`. Anchor by its **semantic fingerprint**, not a fixed offset:

- It is the **first** `call qword ptr [reg + <off>]` where `reg = *g_pNetworkServerService` (load the vtable
  from the global, then call through it), near the top of the function.
- It takes no extra argument and returns an integer CRC value that is subsequently written into the
  class-info/serializer buffer being built.

Reference build vtable offsets (verify, do not hardcode):

- Windows: `call qword ptr [rax+148h]` -> `vfunc_offset = 0x148` (328), `vfunc_index = 41`
- Linux: `call qword ptr [rax+150h]` -> `vfunc_offset = 0x150` (336), `vfunc_index = 42`

The vtable offset differs per platform (Linux has the extra top-of-vtable dtor slot); derive it from the
located call instruction on the current binary.

## Step 3. Resolve the vfunc body, generate the signature, and write the YAML

1. From the resolved `vfunc_offset`, read the vtable slot of `CNetworkServerService_vtable` to obtain the
   concrete function address, and rename it to `INetworkServerService_GetServerSerializersCRC` with
   `mcp__ida-pro-mcp__rename`.
2. **ALWAYS** Use SKILL `/generate-signature-for-vfuncoffset` for the vfunc at the resolved address/offset
   to obtain a validated `vfunc_sig`.
3. **ALWAYS** Use SKILL `/write-vfunc-as-yaml` with:
   - `func_name`: `INetworkServerService_GetServerSerializersCRC`
   - `vtable_name`: `CNetworkServerService`
   - `vfunc_sig`: the validated signature from step 2
   - `vfunc_offset` / `vfunc_index`: the resolved values

## Output YAML filenames

Written beside the binary by the writer skill, one file per platform:

- Windows (`engine2.dll`): `INetworkServerService_GetServerSerializersCRC.windows.yaml`
- Linux (`libengine2.so`): `INetworkServerService_GetServerSerializersCRC.linux.yaml`

## Failure handling

- If the predecessor `CNetworkGameServer_WriteClassInfosAndSerializesToBuffer` YAML is missing → **STOP** and
  report to user.
- If the target virtual call cannot be located even after inspecting the predecessor → **STOP** and report
  so the user can extend the references.
