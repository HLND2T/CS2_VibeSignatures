---
name: find-CSteam3ServerS1_InitGameServer-decompiles
description: |
  Final-guarantee fallback for the find-CSteam3ServerS1_InitGameServer-decompiles preprocessor. Recovers the
  INetworkSystem::GetFakeLag and INetworkServerService::IsActiveInGame indirect virtual-call slots in CS2
  engine2.dll / libengine2.so by decompiling CSteam3ServerS1_InitGameServer and following any de-inlined helper.
  Use when the deterministic/LLM preprocessor could not resolve every call because the containing code moved
  across an inline boundary. Trigger: INetworkSystem_GetFakeLag, INetworkServerService_IsActiveInGame
disable-model-invocation: true
---

# Find InitGameServer network interface calls (final-guarantee fallback)

Recover every output of `find-CSteam3ServerS1_InitGameServer-decompiles` in CS2 `engine2.dll` /
`libengine2.so` using IDA Pro MCP. This Agent fallback runs only after the preprocessor fails, so it must
produce any missing output itself while preserving outputs that a partial preprocessor run already wrote.

## Realworld Function References

Read the platform-relevant reference YAML before searching in IDA. Its addresses, offsets, and signatures are
reference-build values only; verify every result against the current binary.

- `ida_preprocessor_scripts/references/engine/CSteam3ServerS1_InitGameServer.windows.yaml`
- `ida_preprocessor_scripts/references/engine/CSteam3ServerS1_InitGameServer.linux.yaml`

## Background and robustness principle

`CSteam3ServerS1_InitGameServer` initializes the game-server networking state. It queries two network-system
values, then uses `INetworkServerService::IsActiveInGame` to select which value to retain. Both targets are
**indirect virtual calls**: their YAML identifies the call instruction and vtable slot, not a concrete function
body.

First inspect the predecessor itself. If either call is absent, enumerate its direct callees, decompile plausible
helpers, and search one or two levels down: an update may de-inline the networking setup into a helper (or inline
it back into the predecessor). Identify calls by their receiver globals and neighboring behavior, never by a
fixed function address or call-site address.

## Output inventory

Both outputs are required on both platforms. The slot values below are from build `14181`; derive and verify the
current value from the instruction before writing YAML.

| Output symbol | Kind | Windows reference | Linux reference | Writer skill |
|---|---|---|---|---|
| `INetworkSystem_GetFakeLag` | indirect vcall | `INetworkSystem`, `0x118`, index `35` | `INetworkSystem`, `0x118`, index `35` | `/write-vfunc-as-yaml` |
| `INetworkServerService_IsActiveInGame` | indirect vcall | `INetworkServerService`, `0xC0`, index `24` | `INetworkServerService`, `0xC8`, index `25` | `/write-vfunc-as-yaml` |

## Step 0. Skip outputs already produced

For each output, check whether `<symbol>.<platform>.yaml` already exists in the active artifact module directory
and parses as a non-empty mapping. Skip an existing output: the preprocessor or an earlier fallback may have
written it. Use the analyzer-reported artifact module directory, not a path derived from the binary directory.

## Step 1. Load and decompile the predecessor

**ALWAYS** use SKILL `/get-func-from-yaml` with `func_name=CSteam3ServerS1_InitGameServer` to obtain `func_va`.
If it fails, stop and report the missing prerequisite. Then decompile that address:

```
mcp__ida-pro-mcp__decompile addr="<CSteam3ServerS1_InitGameServer.func_va>"
```

Record calls made by the predecessor so that a missing direct pattern can be followed into de-inlined helpers.

## Step 2. Resolve INetworkSystem_GetFakeLag

Locate the indirect `call qword ptr [vtable + offset]` whose receiver is loaded from `g_pNetworkSystem`.
Its distinguishing semantic pattern is the first of two adjacent `g_pNetworkSystem` calls: it receives the first
network configuration value and its result becomes one candidate for the server's selected 16-bit value. The next
network-system call is normally slot `0x110`; do not confuse this target with it or with unrelated `+0x118` calls
on `g_pVApplication`.

The current call displacement is the `vfunc_offset`; calculate `vfunc_index = vfunc_offset / 8`. The reference
value is `0x118` on both platforms, but the receiver must be verified as `g_pNetworkSystem` in the current binary.
Use `vtable_name=INetworkSystem`.

## Step 3. Resolve INetworkServerService_IsActiveInGame

Locate the following indirect vcall whose receiver is loaded from `g_pNetworkServerService`. It returns a boolean
used to choose between the two preceding network-system results, before the `SteamGameServer_Init()` logging path.
This receiver-global/data-flow pairing distinguishes it from other virtual calls nearby.

Derive the current displacement and `vfunc_index = vfunc_offset / 8`. Reference values are Windows `0xC0` / index
`24` and Linux `0xC8` / index `25`; do not assume them if the current instruction differs. Use
`vtable_name=INetworkServerService`.

## Step 4. Generate signatures and write YAML

For each missing target, use `/generate-signature-for-vfuncoffset` on the resolved call instruction with its
verified `vfunc_offset`. The `vfunc_sig` must start at that instruction, include the displacement bytes without
wildcards, and be unique in the current binary.

Then use `/write-vfunc-as-yaml` with:

- `func_name`: the output symbol
- `func_addr=None` and `func_sig=None` (these are call-slot outputs, not function bodies)
- `vfunc_sig`: the generated call-instruction signature
- `vfunc_sig_disp=0` (or omit it)
- `vtable_name`: `INetworkSystem` or `INetworkServerService` as identified above
- `vfunc_offset`: the verified instruction displacement
- `vfunc_index`: `vfunc_offset / 8`

Do not rename or resolve a concrete implementation address. The expected YAML contains only `func_name`,
`vtable_name`, `vfunc_offset`, `vfunc_index`, and `vfunc_sig`.

## Failure handling

- If the predecessor YAML is unavailable, stop and report it.
- If a required call is missing from the predecessor, follow its plausible callees before declaring it unresolved.
- If one target remains unresolved, write any other verified missing target, then report exactly which output failed.
- Never write a Windows output while analyzing Linux, or vice versa.

## Output YAML filenames

Write under the active artifact module directory:

- `INetworkSystem_GetFakeLag.windows.yaml` / `INetworkSystem_GetFakeLag.linux.yaml`
- `INetworkServerService_IsActiveInGame.windows.yaml` / `INetworkServerService_IsActiveInGame.linux.yaml`
