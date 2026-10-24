---
name: find-GetCSWeaponDataFromKey-inlined
description: |
  Recover GetCSWeaponDataFromKey in CS2 server binaries (Windows and Linux) when the find-GetCSWeaponDataFromKey-inlined preprocessor fails.
  Verify current string-key weapon lookup semantics rather than reusing historical addresses or signatures.
  Trigger: GetCSWeaponDataFromKey
disable-model-invocation: true
---

# Find GetCSWeaponDataFromKey (Agent fallback)

Recover the single output of `find-GetCSWeaponDataFromKey-inlined` using the assigned IDA Pro MCP database. The preprocessor
`ida_preprocessor_scripts/find-GetCSWeaponDataFromKey-inlined.py` remains the normal fast path.

## Realworld Function References

Read the applicable current inputs and the annotated references below. Source-owned 14192 YAMLs and stored
disassembly are reference-build evidence; verify addresses, slot indices and semantics in the assigned binary.
Never copy a reference target YAML into the active output directory as a substitute for analysis.

- `ida_preprocessor_scripts/references/server/CSmokeGrenadeProjectile_Create.windows.yaml`
- `ida_preprocessor_scripts/references/server/CSmokeGrenadeProjectile_Create.linux.yaml`
- `bin_artifacts/14192/server/CSmokeGrenadeProjectile_Create.windows.yaml`
- `bin_artifacts/14192/server/CSmokeGrenadeProjectile_Create.linux.yaml`

## Output inventory

Module: `server`. Platform scope: **Windows and Linux**.
Analyze only the platform of the assigned database; the runner invokes platforms separately.

| Platform | Output filename | 14192 reference entry | Reference slot / offset |
|---|---|---|---|
| windows | `GetCSWeaponDataFromKey.windows.yaml` | `0x1805506f0` | not a vfunc |
| linux | `GetCSWeaponDataFromKey.linux.yaml` | `0xef8b80` | not a vfunc |

This is a regular function, with no vtable metadata.
Generate a validated function signature after identifying the current entry.

## Step 0. Bind the task and skip an existing output

Call `idb_list` and reuse the database assigned by the runner. Confirm the input path, image base and
platform with IDA; do not open, switch, close or quit the runner's database.
The binary is `server.dll` / `libserver.so`.
Resolve the active artifact module directory from `CS2VIBE_ARTIFACT_DIR` (also visible inside IDA's
environment). If unset, stop and request the assigned artifact directory; never write YAML beside the binary.
For the current platform, skip the output if it already exists there and parses as a non-empty mapping.
Do not overwrite a result produced by an earlier alternative.

Load the platform-specific configured inputs named above from that active artifact root, not from the 14192
reference tree. Resolve `../client` or `../server` relative to the active module directory. Missing required
inputs must be reported; do not open another binary to reconstruct them.

## Step 1. Locate and verify the target

Use /get-func-from-yaml with `func_name=CSmokeGrenadeProjectile_Create`. Decompile and inspect the current Create body. Follow the weapon/item-definition lookup branch, then inspect its direct calls and any actual intermediate wrapper; stop after the lookup's semantics are established instead of blindly following a fixed number of calls.

The desired function accepts a data type and a STRING key, guards the string, hashes it, looks up weapon data and checks the type. For the smoke call, type is 1: ECX=1 and string in RDX on Windows; EDI=1 and string in RSI on Linux. Murmur landmarks are seed 0x31415926 and multiplier 0x5BD1E995. Linux commonly inlines hashing; Windows may pass the seed to a separate directly called hash routine, so inspect that callee for the multiplier. Treat the constants plus argument dataflow as evidence, not constants alone.

The old `CSmokeGrenadeProjectile_GetCSWeaponData` intermediate may be inlined. Its current legacy YAML may already point to the final string lookup; verify the emitted func_name and body before descending again. Reject the internal table/type/HASH lookup (14192 Linux reference 0xef8320), which takes a numeric hash rather than the source string. Also reject the unrelated coordinate-update routine previously mislabeled as the Windows smoke helper (14192 reference 0x1809d6140). The verified final string lookup is the desired output whether Create reaches it directly or through a real wrapper.


## Signatures and YAML output

Use /generate-signature-for-function on the verified current entry. Validate uniqueness in the assigned binary; do not copy the baseline signature.
Keep the finder's existing generation options: these targets do not enable `func_sig_allow_across_function_boundary`, `func_sig_resolve_jmp_thunk` or `func_sig_skip_degenerate`; do not add those directives. If the fully wildcarded head is ambiguous, compare the competing matches and refine only distinguishing wildcard bytes within the verified function body, following the canonical refinement in `ida_analyze_util.preprocess_gen_func_sig_via_mcp`. Revalidate the pattern at the exact entry. If no valid unique body signature can be obtained, report the unresolved output instead of extending into neighbouring functions.
Use /write-func-as-yaml through its IDA `py_eval` implementation in the assigned session to write the YAML; do not substitute CLI shell or file-edit tools. Parameters:

- `artifact_name=GetCSWeaponDataFromKey` and `func_name=GetCSWeaponDataFromKey`.
- `func_addr`: the verified concrete entry in the assigned binary; emit `func_va`, `func_rva = VA - image_base`
  and the verified current `func_size`. Never emit a bodyless slot-only result for this target.

- `func_sig`: the validated current function signature.

Write only `GetCSWeaponDataFromKey.windows.yaml` / `GetCSWeaponDataFromKey.linux.yaml` as applicable, under the active artifact module directory. The trusted
analyzer validates and canonicalizes this semantic payload. Read back the output and verify its name, fields,
slot (when applicable), RVA and platform against the live database before reporting success.

## Failure handling

If required inputs are missing, candidates remain ambiguous, entry recovery is unsafe, or no standalone
entry can be verified, stop and report the exact missing output plus the semantic evidence examined.
Do not invent a signature/address, create a placeholder YAML, disable config entries, or claim that a failed
lookup proves the game removed the function. Do not run the failed preprocessor as the fallback's solution.
