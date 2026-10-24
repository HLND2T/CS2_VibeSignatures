---
name: find-CEngineClient_FindOrCreateWorldSession
description: |
  Recover CEngineClient_FindOrCreateWorldSession in CS2 engine binaries (Windows only) when the find-CEngineClient_FindOrCreateWorldSession preprocessor fails.
  Verify current vtable entries and function semantics rather than reusing historical addresses or signatures.
  Trigger: CEngineClient_FindOrCreateWorldSession
disable-model-invocation: true
---

# Find CEngineClient_FindOrCreateWorldSession (Agent fallback)

Recover the single output of `find-CEngineClient_FindOrCreateWorldSession` using the assigned IDA Pro MCP database. The preprocessor
`ida_preprocessor_scripts/find-CEngineClient_FindOrCreateWorldSession.py` remains the normal fast path.

## Realworld Function References

Read the applicable current inputs and the annotated references below. Source-owned 14192 YAMLs and stored
disassembly are reference-build evidence; verify addresses, slot indices and semantics in the assigned binary.
Never copy a reference target YAML into the active output directory as a substitute for analysis.

- `bin_artifacts/14192/engine/CRenderingWorldSession_FindOrCreateWorldSession.windows.yaml`
- `bin_artifacts/14192/engine/CRenderingWorldSession_GetEntityLumpForTemplate.windows.yaml`
- `bin_artifacts/14192/engine/CEngineClient_vtable.windows.yaml`

## Output inventory

Module: `engine`. Platform scope: **Windows only**.
Do not emit a Linux output.

| Platform | Output filename | 14192 reference entry | Reference slot / offset |
|---|---|---|---|
| windows | `CEngineClient_FindOrCreateWorldSession.windows.yaml` | `0x180076320` | 13 / `0x68` |

Output metadata uses exactly `vtable_name=CEngineClient_vtable`; the concrete table artifact is `CEngineClient_vtable.<platform>.yaml`.
Generate a validated function signature after identifying the current entry.

## Step 0. Bind the task and skip an existing output

Call `idb_list` and reuse the database assigned by the runner. Confirm the input path, image base and
platform with IDA; do not open, switch, close or quit the runner's database.
The binary is `engine2.dll`.
Resolve the active artifact module directory from `CS2VIBE_ARTIFACT_DIR` (also visible inside IDA's
environment). If unset, stop and request the assigned artifact directory; never write YAML beside the binary.
For the current platform, skip the output if it already exists there and parses as a non-empty mapping.
Do not overwrite a result produced by an earlier alternative.

Load the platform-specific configured inputs named above from that active artifact root, not from the 14192
reference tree. Resolve `../client` or `../server` relative to the active module directory. Missing required
inputs must be reported; do not open another binary to reconstruct them.

## Step 1. Locate and verify the target

Load `CRenderingWorldSession_FindOrCreateWorldSession` and the exclusion `CRenderingWorldSession_GetEntityLumpForTemplate` through /get-func-from-yaml. Inspect all direct calls and tail jumps to the former and intersect their enclosing entrypoints with the live `CEngineClient_vtable`. The target is the engine-client interface wrapper forwarding world/session arguments; on Windows 14192 it reshuffles registers then tail-jumps to the rendering helper. Reject the entity-lump/template accessor even if it shares the same helper or prologue.

If xrefs have no containing function, start from the live vtable entries and inspect their instructions before recovering boundaries. If forwarding is outlined, follow the wrapper's callee; if it is inlined, verify world/session lookup-or-creation semantics inside the vtable entry. Keep the interface entry as the output, rather than returning the rendering helper's address. The old slot 13 is a reference, not a search rule.

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

- `artifact_name=CEngineClient_FindOrCreateWorldSession` and `func_name=CEngineClient_FindOrCreateWorldSession`.
- `func_addr`: the verified concrete entry in the assigned binary; emit `func_va`, `func_rva = VA - image_base`
  and the verified current `func_size`. Never emit a bodyless slot-only result for this target.
- `vtable_name=CEngineClient_vtable`, current `vfunc_index` and `vfunc_offset = index * 8`.
- `vfunc_sig=None` and `vfunc_sig_disp=None`; this target describes a concrete function, not a caller's vcall.
- `func_sig`: the validated current function signature.

Write only `CEngineClient_FindOrCreateWorldSession.windows.yaml` as applicable, under the active artifact module directory. The trusted
analyzer validates and canonicalizes this semantic payload. Read back the output and verify its name, fields,
slot (when applicable), RVA and platform against the live database before reporting success.

## Failure handling

If required inputs are missing, candidates remain ambiguous, entry recovery is unsafe, or no standalone
entry can be verified, stop and report the exact missing output plus the semantic evidence examined.
Do not invent a signature/address, create a placeholder YAML, disable config entries, or claim that a failed
lookup proves the game removed the function. Do not run the failed preprocessor as the fallback's solution.
