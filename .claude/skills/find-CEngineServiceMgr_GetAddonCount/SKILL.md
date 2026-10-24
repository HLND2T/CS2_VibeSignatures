---
name: find-CEngineServiceMgr_GetAddonCount
description: |
  Recover CEngineServiceMgr_GetAddonCount in CS2 engine binaries (Windows and Linux) when the find-CEngineServiceMgr_GetAddonCount preprocessor fails.
  Verify current vtable entries and function semantics rather than reusing historical addresses or signatures.
  Trigger: CEngineServiceMgr_GetAddonCount
disable-model-invocation: true
---

# Find CEngineServiceMgr_GetAddonCount (Agent fallback)

Recover the single output of `find-CEngineServiceMgr_GetAddonCount` using the assigned IDA Pro MCP database. The preprocessor
`ida_preprocessor_scripts/find-CEngineServiceMgr_GetAddonCount.py` remains the normal fast path.

## Realworld Function References

Read the applicable current inputs and the annotated references below. Source-owned 14192 YAMLs and stored
disassembly are reference-build evidence; verify addresses, slot indices and semantics in the assigned binary.
Never copy a reference target YAML into the active output directory as a substitute for analysis.

- `ida_preprocessor_scripts/references/engine/CNetworkGameClient_DisconnectGame.windows.yaml`
- `ida_preprocessor_scripts/references/engine/CNetworkGameClient_DisconnectGame.linux.yaml`
- `bin_artifacts/14192/engine/CEngineServiceMgr_vtable.windows.yaml`
- `bin_artifacts/14192/engine/IEngineServiceMgr_GetAddonCount.windows.yaml`
- `bin_artifacts/14192/engine/CEngineServiceMgr_vtable.linux.yaml`
- `bin_artifacts/14192/engine/IEngineServiceMgr_GetAddonCount.linux.yaml`

## Output inventory

Module: `engine`. Platform scope: **Windows and Linux**.
Analyze only the platform of the assigned database; the runner invokes platforms separately.

| Platform | Output filename | 14192 reference entry | Reference slot / offset |
|---|---|---|---|
| windows | `CEngineServiceMgr_GetAddonCount.windows.yaml` | `0x180216e70` | 38 / `0x130` |
| linux | `CEngineServiceMgr_GetAddonCount.linux.yaml` | `0x37ee40` | 38 / `0x130` |

Output metadata uses exactly `vtable_name=CEngineServiceMgr`; the concrete table artifact is `CEngineServiceMgr_vtable.<platform>.yaml`.
Omit `func_sig`: this getter/thunk has no stable function signature under the producer contract.

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

## Step 1. Resolve the inherited interface entry

Use /get-func-from-yaml with `func_name=IEngineServiceMgr_GetAddonCount`. The input may contain only interface call-site metadata;
do not require `func_va` or invent a function body for the abstract interface. Check that `vfunc_index` and
`vfunc_offset` agree (`offset = index * 8`). Read that slot in the current concrete table, and verify its live
pointer against the active vtable artifact. Do not use the old target signature or reference slot as identity.

## Step 2. Locate and verify the target

Read `IEngineServiceMgr_GetAddonCount` from the active engine artifact directory and resolve its current slot in the live `CEngineServiceMgr_vtable`. In the annotated DisconnectGame caller, this interface call returns the addon count and is compared against zero to choose the disconnect/cleanup flow.

Confirm the concrete entry is the count getter; Windows 14192 loads a DWORD from this+0x228 and returns. That field displacement alone is not an identity check. The stored reference disassembly uses offset 0x138, whereas the verified 14192 interface artifact uses 0x130 (slot 38). Prefer current upstream metadata and live code; never copy the reference annotation's old displacement. If a helper is outlined, follow it to verify the returned count while keeping the concrete vtable entry as the output.

## Step 3. Handle missing IDA function boundaries

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

Do not generate or carry forward `func_sig`, even if an old artifact contains one.
Use /write-vfunc-as-yaml through its IDA `py_eval` implementation in the assigned session to write the YAML; do not substitute CLI shell or file-edit tools. Parameters:

- `artifact_name=CEngineServiceMgr_GetAddonCount` and `func_name=CEngineServiceMgr_GetAddonCount`.
- `func_addr`: the verified concrete entry in the assigned binary; emit `func_va`, `func_rva = VA - image_base`
  and the verified current `func_size`. Never emit a bodyless slot-only result for this target.
- `vtable_name=CEngineServiceMgr`, current `vfunc_index` and `vfunc_offset = index * 8`.
- `vfunc_sig=None` and `vfunc_sig_disp=None`; this target describes a concrete function, not a caller's vcall.
- `func_sig=None`; ensure the field is absent in the written YAML.

Write only `CEngineServiceMgr_GetAddonCount.windows.yaml` / `CEngineServiceMgr_GetAddonCount.linux.yaml` as applicable, under the active artifact module directory. The trusted
analyzer validates and canonicalizes this semantic payload. Read back the output and verify its name, fields,
slot (when applicable), RVA and platform against the live database before reporting success.

## Failure handling

If required inputs are missing, candidates remain ambiguous, entry recovery is unsafe, or no standalone
entry can be verified, stop and report the exact missing output plus the semantic evidence examined.
Do not invent a signature/address, create a placeholder YAML, disable config entries, or claim that a failed
lookup proves the game removed the function. Do not run the failed preprocessor as the fallback's solution.
