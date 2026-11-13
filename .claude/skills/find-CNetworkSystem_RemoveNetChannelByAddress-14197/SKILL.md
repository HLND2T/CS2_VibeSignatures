---
name: find-CNetworkSystem_RemoveNetChannelByAddress-14197
description: |
  Recover CNetworkSystem_RemoveNetChannelByAddress in CS2 networksystem.dll / libnetworksystem.so
  when the deterministic removal-pair proof fails. Validate the fresh removal anchor and trace
  its address-based sibling's channel lookup and constant-false dispatch.
  Trigger: CNetworkSystem_RemoveNetChannelByAddress
disable-model-invocation: true
---

# Find CNetworkSystem_RemoveNetChannelByAddress

Recover the concrete virtual function on the active platform using IDA Pro MCP. Independently
verify the semantic relationship when
`ida_preprocessor_scripts/find-CNetworkSystem_RemoveNetChannelByAddress-14197.py` fails.

## Realworld Function References

- `bin_artifacts/14197/networksystem/CNetworkSystem_RemoveNetChannel.windows.yaml`
- `bin_artifacts/14197/networksystem/CNetworkSystem_RemoveNetChannel.linux.yaml`
- `bin_artifacts/14197/networksystem/CNetworkSystem_RemoveNetChannelByAddress.windows.yaml`
- `bin_artifacts/14197/networksystem/CNetworkSystem_RemoveNetChannelByAddress.linux.yaml`

Read the platform-relevant source-owned artifacts as reference identities and signature styles.
All addresses and offsets are reference-build values; verify against the current binary.
Do not copy a tracked reference YAML to satisfy the output.

## Output inventory

| Output | Kind | Windows 14197 reference | Linux 14197 reference |
|---|---|---|---|
| `CNetworkSystem_RemoveNetChannelByAddress` | Concrete vtable function | `0x1800fcec0`, index 24 | `0x2edf30`, index 24 |

The output is required on both platforms. Its reference offset is `0xc0`; derive the actual
slot from the current table and verify its behavior. Only write this skill's one output.
Required fields: `func_name`, `func_va`, `func_rva`, `func_size`, `func_sig`, `vtable_name`,
`vfunc_offset`, `vfunc_index`.

## Step 0. Check the output and load dependencies

Use the analyzer-provided active artifact module directory (`CS2VIBE_ARTIFACT_DIR`), never
the directory inferred from the binary path. Skip
`CNetworkSystem_RemoveNetChannelByAddress.<platform>.yaml` if it already exists there and
parses to a non-empty mapping.

Resolve the active `networksystem.dll` / `libnetworksystem.so` session with `idb_list` /
`idb_open`, verify its input and platform, and pass its identifier to subsequent tools.
Use `/get-func-from-yaml` with `func_name=CNetworkSystem_RemoveNetChannel` and
`/get-vtable-from-yaml` with `class_name=CNetworkSystem` to read the active dependencies.
Stop if either is missing or invalid.

Verify that removal's `vtable_name` is `CNetworkSystem`, its `vfunc_offset` equals its
`vfunc_index * 8`, and the current table entry at that index equals its `func_va`. Reject a
stale or inconsistent anchor before following the next slot.

## Step 1. Recheck the removal anchor

Decompile the current removal body and trace `(this, channel, flag)`. It checks and locks
the channel, closes its underlying connection when needed, removes it from a collection on
`this`, and may notify listeners and destroy it. The shared connection-close helper can be
identified from direct five-argument calls on `this` whose fourth argument is the exact
`CloseSocket` literal in other callers. The old Linux `shutdown` literal is absent in 14197.

The 14197 close helper references are `0x1800fd040` on Windows and `0x2e9140` on Linux;
removal references are `0x1800fda80` / `0x2edc90`. They are not fixed discovery answers.
If the supplied anchor does not implement removal, stop and report its inconsistent semantics.

## Step 2. Prove the address-based sibling

Read the entry immediately following removal in the current `CNetworkSystem` table. Ensure
the slot exists and its function differs from removal. Decompile the candidate and prove:

1. It receives `(this, socket, address)` and finds a channel corresponding to that socket and
   address. On Linux this may call a separate three-argument lookup using a local converted
   address buffer. On Windows the lookup may be an inline scan of a collection also used by
   removal. Follow de-inlined lookup callees when needed.
2. The successful lookup's channel value, possibly through local aliases, becomes the second
   argument of a direct call to the verified removal body.
3. The removal call uses the original `this` and a constant false third argument. A missing
   channel leads to a failure result; the successful call leads to a success result.

If ctree argument counts, local-buffer types, casts, or unnamed PLT stubs obscure this data
flow, inspect the disassembly, call targets, registers, and stack addresses. Do not merely
rerun the failing deterministic probe. Adjacency without the proven lookup and dispatch is
insufficient. Reject different receivers, unrelated channel values, nonzero flags, stale
anchors, and ambiguous candidates.

## Step 3. Generate a fresh signature and write YAML

Use `/generate-signature-for-function` with `addr=<proven address-based entry>` and validate
the returned unique `func_sig`. Use `/write-vfunc-as-yaml` with:

- `artifact_name` and `func_name`: `CNetworkSystem_RemoveNetChannelByAddress`
- `func_addr`: the proven address-based entry
- `func_sig`: the validated current signature
- `vtable_name`: `CNetworkSystem`
- `vfunc_index`: the verified removal index plus one
- `vfunc_offset`: `vfunc_index * 8`
- `vfunc_sig`: `None`

Write `CNetworkSystem_RemoveNetChannelByAddress.windows.yaml` or
`CNetworkSystem_RemoveNetChannelByAddress.linux.yaml` only in the active artifact module
directory. Verify a non-empty mapping and equality of the output address with the current
table entry. Leave canonicalization to the analyzer.

## Failure handling

If dependencies are missing, the anchor is stale, the data flow is unproven, or no unique
signature is available, stop and report the exact failing condition and inspected addresses.
Never substitute a fixed slot, old signature, or guessed address.
