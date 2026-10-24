---
name: find-CEngineServer_KickClient
description: |
  Recover CEngineServer_KickClient in CS2 engine binaries (Windows and Linux) when the find-CEngineServer_KickClient preprocessor fails.
  Verify current vtable entries and function semantics rather than reusing historical addresses or signatures.
  Trigger: CEngineServer_KickClient
disable-model-invocation: true
---

# Find CEngineServer_KickClient (Agent fallback)

Recover the single output of `find-CEngineServer_KickClient` using the assigned IDA Pro MCP database. The preprocessor
`ida_preprocessor_scripts/find-CEngineServer_KickClient.py` remains the normal fast path.

## Realworld Function References

Read the applicable current inputs and the annotated references below. Source-owned 14192 YAMLs and stored
disassembly are reference-build evidence; verify addresses, slot indices and semantics in the assigned binary.
Never copy a reference target YAML into the active output directory as a substitute for analysis.

- `bin_artifacts/14192/engine/CNetworkGameServerBase_KickClient.windows.yaml`
- `bin_artifacts/14192/engine/CEngineServer_vtable.windows.yaml`
- `bin_artifacts/14192/engine/CNetworkGameServerBase_KickClient.linux.yaml`
- `bin_artifacts/14192/engine/CEngineServer_vtable.linux.yaml`

## Output inventory

Module: `engine`. Platform scope: **Windows and Linux**.
Analyze only the platform of the assigned database; the runner invokes platforms separately.

| Platform | Output filename | 14192 reference entry | Reference slot / offset |
|---|---|---|---|
| windows | `CEngineServer_KickClient.windows.yaml` | `0x1800a33a0` | 97 / `0x308` |
| linux | `CEngineServer_KickClient.linux.yaml` | `0x5380a0` | 97 / `0x308` |

Output metadata uses exactly `vtable_name=CEngineServer_vtable`; the concrete table artifact is `CEngineServer_vtable.<platform>.yaml`.
Generate a validated function signature after identifying the current entry.

## Step 0. Bind the task and skip an existing output

Call `idb_list` and reuse the database assigned by the runner. Confirm the input path, image base and
platform with IDA; do not open, switch, close or quit the runner's database.
The binary is `engine2.dll` / `libengine2.so`.
Resolve the active artifact module directory from `CS2VIBE_ARTIFACT_DIR` (also visible inside IDA's
environment). If unset, stop and request the assigned artifact directory; never write YAML beside the binary.
For the current platform, skip the output if it already exists there and parses as a non-empty mapping.
Do not overwrite a result produced by an earlier alternative.

Load the platform-specific configured inputs named above from that active artifact root, not from the 14192
reference tree. Resolve `../client` or `../server` relative to the active module directory. Missing required
inputs must be reported; do not open another binary to reconstruct them.

## Step 1. Locate and verify the target

Load `CNetworkGameServerBase_KickClient` through /get-func-from-yaml. Enumerate its direct-call and tail-branch references and intersect their entrypoints with the live `CEngineServer_vtable`. Confirm that the selected wrapper forwards the requested client/disconnect arguments to the network game server's kick operation.

Recover code-only vtable entries before interpreting an empty caller set as a semantic change. If the call becomes indirect, trace the receiver's network-server vtable and verify that its current target is the same kick operation; if inlined, inspect the disconnect operation inside the engine wrapper. Reject generic disconnect helpers or a neighbouring vfunc based only on proximity. In particular, 14192 moved this target to slot 97 from historical slot 96; derive the slot from the verified current entry, never from a historical index.

## Step 2. Handle missing IDA function boundaries

A vtable YAML can exist even though IDA has not defined its target functions. For each plausible entry,
verify the live 64-bit slot pointer, executable segment and decoded instruction boundary. If no function
owns the entry, use conservative function definition and wait for analysis, then require the resulting
function start to equal the slot pointer. Never delete bytes, split an existing function, or normalize an
interior pointer to a neighbouring function's start. If a function already owns an unexpected interior
entry, inspect and report the boundary conflict instead of forcing it.

Treat short adjusting thunks as legitimate vtable entrypoints. Follow their destinations for semantic
verification, but preserve the slot's actual entry address in the artifact. Distinct-address candidate
counts are not vtable slot counts. Confirm the target's slot by live pointer equality; use /get-vtable-index
where helpful, and report multiple plausible slots rather than selecting an arbitrary duplicate.

## Signatures and YAML output

Use /generate-signature-for-function on the verified current entry. Validate uniqueness in the assigned binary; do not copy the baseline signature.
Keep the finder's existing generation options: these targets do not enable `func_sig_allow_across_function_boundary`, `func_sig_resolve_jmp_thunk` or `func_sig_skip_degenerate`; do not add those directives. If the fully wildcarded head is ambiguous, compare the competing matches and refine only distinguishing wildcard bytes within the verified function body, following the canonical refinement in `ida_analyze_util.preprocess_gen_func_sig_via_mcp`. Revalidate the pattern at the exact entry. If no valid unique body signature can be obtained, report the unresolved output instead of extending into neighbouring functions.
Use /write-vfunc-as-yaml through its IDA `py_eval` implementation in the assigned session to write the YAML; do not substitute CLI shell or file-edit tools. Parameters:

- `artifact_name=CEngineServer_KickClient` and `func_name=CEngineServer_KickClient`.
- `func_addr`: the verified concrete entry in the assigned binary; emit `func_va`, `func_rva = VA - image_base`
  and the verified current `func_size`. Never emit a bodyless slot-only result for this target.
- `vtable_name=CEngineServer_vtable`, current `vfunc_index` and `vfunc_offset = index * 8`.
- `vfunc_sig=None` and `vfunc_sig_disp=None`; this target describes a concrete function, not a caller's vcall.
- `func_sig`: the validated current function signature.

Write only `CEngineServer_KickClient.windows.yaml` / `CEngineServer_KickClient.linux.yaml` as applicable, under the active artifact module directory. The trusted
analyzer validates and canonicalizes this semantic payload. Read back the output and verify its name, fields,
slot (when applicable), RVA and platform against the live database before reporting success.

## Failure handling

If required inputs are missing, candidates remain ambiguous, entry recovery is unsafe, or no standalone
entry can be verified, stop and report the exact missing output plus the semantic evidence examined.
Do not invent a signature/address, create a placeholder YAML, disable config entries, or claim that a failed
lookup proves the game removed the function. Do not run the failed preprocessor as the fallback's solution.
