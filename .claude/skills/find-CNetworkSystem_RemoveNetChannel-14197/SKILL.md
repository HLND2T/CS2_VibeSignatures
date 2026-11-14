---
name: find-CNetworkSystem_RemoveNetChannel-14197
description: |
  Recover CNetworkSystem_RemoveNetChannel in CS2 networksystem.dll / libnetworksystem.so when
  the deterministic channel-removal pair proof fails. Identify the close helper, channel
  removal body, and address-based sibling from current call and receiver data flow.
  Trigger: CNetworkSystem_RemoveNetChannel
disable-model-invocation: true
---

# Find CNetworkSystem_RemoveNetChannel

Recover the concrete virtual function on the active platform using IDA Pro MCP.
The preprocessor is `ida_preprocessor_scripts/find-CNetworkSystem_RemoveNetChannel-14197.py`;
this fallback must independently inspect the binary when its ctree proof fails.

## Realworld Function References

Read the platform-relevant source-owned artifacts for reference identities and signature styles:

- `bin_artifacts/14197/networksystem/CNetworkSystem_RemoveNetChannel.windows.yaml`
- `bin_artifacts/14197/networksystem/CNetworkSystem_RemoveNetChannel.linux.yaml`
- `bin_artifacts/14197/networksystem/CNetworkSystem_RemoveNetChannelByAddress.windows.yaml`
- `bin_artifacts/14197/networksystem/CNetworkSystem_RemoveNetChannelByAddress.linux.yaml`

These contain reference-build addresses and slots, not current discovery results. Verify the
current vtable and function semantics before using any candidate. The old Linux `shutdown`
literal is absent in build 14197 and cannot identify the target.

## Output inventory

| Output | Kind | Windows 14197 reference | Linux 14197 reference |
|---|---|---|---|
| `CNetworkSystem_RemoveNetChannel` | Concrete vtable function | `0x1800fda80`, index 23 | `0x2edc90`, index 23 |

This output is required on both platforms. Its reference offset is `0xb8`; derive the actual
index and offset from the current `CNetworkSystem` table. Only write this skill's one output.

Required YAML fields: `func_name`, `func_va`, `func_rva`, `func_size`, `func_sig`,
`vtable_name`, `vfunc_offset`, `vfunc_index`.

## Step 0. Check the active artifact directory and session

Use the analyzer-provided artifact module directory (`CS2VIBE_ARTIFACT_DIR`). Do not infer it
from the binary path. If `CNetworkSystem_RemoveNetChannel.<platform>.yaml` already exists
there and parses to a non-empty mapping, skip it. Do not copy the tracked reference artifact
to satisfy an output.

Resolve the current `networksystem.dll` / `libnetworksystem.so` session with `idb_list` /
`idb_open`. Verify the input path and platform before querying it; pass its database/session
identifier to subsequent tools. Use `/get-vtable-from-yaml` with `class_name=CNetworkSystem`
to load `CNetworkSystem_vtable.<platform>.yaml` from the active artifact directory. If the
required table is missing or invalid, stop and report the dependency.

## Step 1. Identify the shared close helper

Find the exact string `CloseSocket` and enumerate its code references. Decompile its owning
functions and inspect direct calls carrying that literal as the fourth of five arguments.
The first argument must be the caller's `this`. Follow thunks if necessary, and deduplicate
repeated calls to the same callee. In build 14197 the shared helper was `0x1800fd040` on
Windows and `0x2e9140` on Linux; these are starting references only.

Do not confuse the public `CloseSocket` virtual entry with the shared helper or select a
function solely because it references the literal. If several helpers remain semantically
plausible, report the ambiguity instead of choosing one by address order.

## Step 2. Prove channel removal and its address-based caller

Intersect the close helper's current code callers with the current vtable entries. Inspect
each candidate and its immediately following entry. Prove all of the following:

1. The removal body receives `(this, channel, flag)`, checks the channel, synchronizes its
   state, closes its underlying connection via the shared helper when needed, and removes
   that channel from a collection on `this`. It may notify listeners and destroy the channel.
2. The next vtable entry implements address-based removal. It receives `(this, socket,
   address)`, locates a channel for that socket/address, and invokes the candidate with the
   same `this`, the located channel, and a constant false flag.
3. Trace the channel value through local aliases. Linux may use a separate
   `(this, socket, address*)` lookup with a local address buffer; Windows may inline a search
   through a collection field also used by the removal body. Follow callees when a search or
   close operation moves across an inline boundary.

If decompiler argument counts, inferred local types, casts, or PLT names obscure the proof,
inspect the disassembly, register assignments, stack addresses, and direct call targets.
Generic `sub_*` names are not evidence that a function is absent. Do not simply invoke the
same failing `_probe_channel_calls` again and treat that as independent verification.

Reject a different receiver, a channel unrelated to the lookup, a nonzero flag, or ambiguous
function pairs. The adjacency is corroborating evidence and is insufficient on its own.

## Step 3. Generate the signature and write YAML

Use `/generate-signature-for-function` with `addr=<proven removal body>` to generate and
validate a unique current `func_sig`. Then use `/write-vfunc-as-yaml` with:

- `artifact_name` and `func_name`: `CNetworkSystem_RemoveNetChannel`
- `func_addr`: the proven removal function entry
- `func_sig`: the validated current signature
- `vtable_name`: `CNetworkSystem`
- `vfunc_index`: the proven current table index
- `vfunc_offset`: `vfunc_index * 8`
- `vfunc_sig`: `None`

Write only `CNetworkSystem_RemoveNetChannel.windows.yaml` or
`CNetworkSystem_RemoveNetChannel.linux.yaml` in the active artifact module directory. Verify
that it parses as a non-empty mapping and its address matches the selected vtable entry.
The analyzer owns canonical field ordering and finalization.

## Failure handling

If dependencies are missing, the pair cannot be proven, or a unique signature cannot be
generated, stop and report the exact unresolved condition and inspected candidates. Never
substitute a fixed reference slot, old signature, or a guessed address to make the task pass.
