---
title: ida_skill_preprocessor
type: note
permalink: cs2-vibesignatures/ida-skill-preprocessor
---

# ida_skill_preprocessor

## Overview
`ida_skill_preprocessor.py` now acts as the "preprocessing dispatch entry": it establishes the IDA MCP session, retrieves `image_base`, and then delegates concrete preprocessing logic to `ida_preprocessor_scripts/{skill_name}.py`.

Unlike the old flow, output-type branching is no longer hardcoded in the entry point. The concrete workflow is decided by each skill script.

## Responsibilities
- Dynamically load and cache the exported method `preprocess_skill` from `ida_preprocessor_scripts/{skill_name}.py`.
- Connect to MCP (`ClientSession` + `streamable_http_client`) and initialize the session in a unified way.
- Retrieve `image_base` via a single `py_eval` call and pass it as a context parameter to skill scripts.
- Invoke the skill script's exported method (supports async/sync) and normalize the result to a boolean for upper-layer return.
- Return `False` when script is missing, export method is missing, script execution fails, or MCP connection fails, so upper layers can fall back to Agent flow.

## Files Involved (no line numbers)
- ida_skill_preprocessor.py
- ida_analyze_util.py
- ida_preprocessor_scripts/*.py
- ida_preprocessor_scripts/find-CTriggerPush_vtable.py
- ida_preprocessor_scripts/find-CTriggerPush_Touch.py
- ida_preprocessor_scripts/find-CCSPlayer_MovementServices_FullWalkMove_SpeedClamp.py
- ida_analyze_bin.py

## Architecture
Entry point `preprocess_single_skill_via_mcp(...)`:
1. Load `ida_preprocessor_scripts/{skill_name}.py` via `_get_preprocess_entry(skill_name)`.
   - The script is expected to export a callable `preprocess_skill`.
   - Script entry points are cached to avoid repeated import overhead.
2. If the script does not exist or exported method is invalid, return `False` directly.
3. Establish MCP session and initialize it.
4. Retrieve `image_base` via one `py_eval` call.
5. Call the script's exported method:
   - Pass parameters: `session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug`.
   - If the return value is awaitable, `await` it; final preprocessing result is `bool(result)`.
6. Any exception returns `False`.

### Skill Script Conventions
- File name: `ida_preprocessor_scripts/{skill_name}.py`
- Exported method: `preprocess_skill(...)`
- Most scripts only need to declare constants and delegate to `preprocess_common_skill`:
  - func/vfunc scripts: declare `TARGET_FUNCTION_NAMES`, pass `func_names=TARGET_FUNCTION_NAMES`
  - func xref scripts: declare `TARGET_FUNCTION_NAMES` and `FUNC_XREFS` (list of `(func_name, xref_strings_list, xref_funcs_list, exclude_funcs_list)` tuples), pass both `func_names=TARGET_FUNCTION_NAMES` and `func_xrefs=FUNC_XREFS`. Unified xref lookup is used as a fallback when `func_sig` reuse fails.
  - gv scripts: declare `TARGET_GLOBALVAR_NAMES`, pass `gv_names=TARGET_GLOBALVAR_NAMES`
  - patch scripts: declare `TARGET_PATCH_NAMES`, pass `patch_names=TARGET_PATCH_NAMES`
  - vtable scripts: declare `TARGET_CLASS_NAME`, pass `vtable_class_names=[TARGET_CLASS_NAME]`
  - mixed scripts: can pass multiple parameter groups at once
- Special scripts (e.g., CTriggerPush_Touch, CBaseTrigger_StartTouch, CPointTeleport_Teleport) implement custom logic and directly use lower-level methods.
- Entity-input handler skills (`DEFINE_INPUTFUNC` legacy and 14182+ `_API` input registration descriptors, handler offsets and ABI caveats): see [[_define_inputfunc]].

## Common Capabilities in ida_analyze_util.py

- MCP result parsing: `parse_mcp_result`
- vtable py_eval template and builder: `_VTABLE_PY_EVAL_TEMPLATE`, `_build_vtable_py_eval`
- YAML writers: `write_vtable_yaml`, `write_func_yaml`, `write_gv_yaml`, `write_patch_yaml`, `write_struct_offset_yaml`
- `preprocess_vtable_via_mcp`: locate and read vtables in IDA by class name, output standardized vtable YAML data.
- `preprocess_func_sig_via_mcp`: prioritize old `func_sig` reuse to locate functions; if missing, fall back to `vfunc_sig` + vtable index and complete new function metadata.
- `preprocess_gen_func_sig_via_mcp`: auto-generate the shortest unique `func_sig` from function prologue for function relocation in new versions and YAML writing.
- `preprocess_gen_gv_sig_via_mcp`: generate the shortest unique `gv_sig` around instructions accessing global variables, and return instruction-offset metadata.
- `preprocess_gv_sig_via_mcp`: relocate global variables in new binaries by reusing old `gv_sig` and rebuild `gv_*` fields.
- `preprocess_patch_via_mcp`: reuse `patch_sig/patch_bytes` from old patch YAML and only succeed when `patch_sig` has exactly one `find_bytes` hit in new binary (`== 1`).
- `preprocess_struct_offset_sig_via_mcp`: reuse old offset signatures to parse struct member offsets and sizes.
- `preprocess_index_based_vfunc_via_mcp`: resolve new addresses and metadata for inherited vfuncs via old base-class `vfunc_index` + new vtable.
- `preprocess_func_xrefs_via_mcp`: locate functions through unified xref constraints, combining string xrefs, dependency-function xrefs, optional vtable-entry filtering, and exclude-function filtering before generating or recovering function YAML data.
- **`preprocess_common_skill`**: unified `preprocess_skill` template that supports combined target types including func/vfunc, gv, patch, struct-member, vtable, inherit-vfunc, and unified xref-based function lookup. Most skill scripts only need constants plus delegation.

YAML writers consistently use `yaml.safe_dump`:
- Ensure key set and ordering control (`sort_keys=False`)
- Scalar quoting/style specifics are decided by PyYAML

## Dependencies
- PyYAML (YAML read/write)
- mcp Python SDK (`ClientSession`, `streamable_http_client`)
- IDA MCP tools: `py_eval`, `find_bytes`
- Standard library: `importlib.util`, `inspect`, `re`, `pathlib`, `json`, `os`

## Notes
- Preprocessing is an "acceleration path": returning `False` is acceptable, and upper layers will fall back to Agent SKILL.
- Now preprocessing success is controlled by each script; scripts should ensure output completeness on their own.
- `preprocess_func_sig_via_mcp` requires unique `find_bytes` hit; both 0 and multiple hits fail.
- `preprocess_patch_via_mcp` also requires unique `patch_sig` hit (`==1`); no hit or multiple hits both fail.
- vfunc offset is still computed as `index * 8` (64-bit assumption).
- If script is missing or export contract is invalid, that skill goes directly to Agent SKILL and does not block the main flow.

## Callers (optional)
- `process_binary` in `ida_analyze_bin.py` (called before `run_skill`)

## Lesson: undefined function recovery and MCP Python namespaces

- **Trigger:** old `func_sig` misses, string xrefs exist outside functions, but
  recovery reports `blocked_existing_function` or defines a function that does
  not cover the requested xref. A Python 3.12 local run can pass while CI on
  Python 3.11 fails on the same IDB.
- **Root cause:** MCP `py_eval` snapshots persistent locals into a separate
  globals dictionary. In Python 3.11, comprehensions resolve captured variables
  through that globals dictionary. The operand-target comprehension in
  `_probe_func_start_or_entry_candidate` could therefore use an earlier `xref`
  instead of the current loop reference, missing the real entry or selecting
  the adjacent thunk. A single-namespace fake session hides this bug.
- **Correct approach:** use an ordinary operand loop in the generated snippet.
  Preserve the conservative entry evidence and coverage verification; do not
  broaden recovery by guessing entries or deleting existing functions.
- **Verification:** run `TestArrayInitializedFunctionRecovery` on Python 3.11
  with separate globals and persistent locals, including a stale unrelated
  `xref`. Replay the actual CI warm IDB rather than only a freshly analyzed or
  artificially modified database. PR #1145 run `38721615799` reproduced the
  failure with the cached 14191 Linux server IDB, SHA-256
  `2225143ff0b823ca0c9aa01da9b21a843686df0e52bda95240788bd9c36891a8`;
  corrected recovery identifies the registration thunk at `0x22ba960`.
- **Scope:** generated IDA `py_eval` snippets with comprehensions or nested
  helpers that reference recently assigned locals. Avoid assuming host Python
  and IDA worker Python use the same minor version or execution semantics.
- **Fallback:** `.claude/skills/find-RegisterSchemaTypeOverride_CEntityHandle/SKILL.md`
  identifies the exact `CEntityHandle`/`ehandle` thunk from raw xrefs and validates
  a unique signature when preprocessing cannot finish safely.

## Lesson: unique wrapper signatures can silently select a sibling

- **Trigger:** IDA analysis reports success, but the Linux C++ ABI gate for
  `IVEngineServer2` finds `GetPlayerNetworkIDString` at slot 39 instead of 40 and
  `SynchronizeAndBlockUntilLoaded` at slot 63 instead of 66 (PR #1145, run
  `38764646029`). Other vtable references and the Windows gate pass.
- **Root cause:** the old signatures include a shared wrapper prologue and a
  partly fixed RIP-relative displacement. After code moves, each signature can
  still match exactly once, at a different wrapper loading the same global.
  The signature fast path then bypasses the finder's semantic xref constraints.
  Uniqueness and membership in the same vtable do not establish function identity.
- **Correct approach:** these `CEngineServer` finders ignore the old signature
  map and resolve from the current-version helper call plus the current vtable.
  Keep the noinline/inlined fallback pair: Linux calls the standalone network-ID
  helper, while Windows calls the client helper directly. Preserve the spawn-think
  exclusion for the synchronization finder. Generate a fresh unique signature.
- **Verification:** regress both a unique wrong old match and an unavailable
  current anchor; the latter must fail without writing an output. Replay the
  unmodified warm IDB through the real MCP pipeline on Python 3.11. In 14191 Linux,
  the correct callers are `0x52a530` (slot 40, calls `0x521580`) and `0x527f80`
  (slot 66, calls `0x51aaa0`); the erroneous neighbors are `0x52a570` and `0x527fc0`.
  Rebuild the candidate and run the C++ ABI gate against the corrected outputs.
  This replay passes all 19 configured tests on Linux (Ubuntu WSL) and Windows,
  with zero differences across 20 vtable and two record-layout comparisons each.
- **Scope:** short forwarding wrappers with independent current-version semantic
  anchors. Diagnose an ABI mismatch against actual call targets before editing
  headers or treating a unique signature match as proof of identity.


## Lesson: repair artifact generators together with verified semantic names

- **Trigger:** a manually corrected `func_name`/`member_name` passes ABI comparison, but the next analysis writes the old name again.
- **Root cause:** finder targets historically serve as artifact filenames, dependency keys, LLM response identifiers, and semantic names. Correcting only the YAML does not change these producers; globally renaming targets breaks inherited dependencies and collides for chained event names.
- **Correct approach:** each affected finder declares `OUTPUT_NAME_MAP`, mapping a stable artifact key to its verified full semantic symbol name. `preprocess_common_skill` applies it after signature reuse and fresh analysis, including inherited vfuncs and struct members; pending IDA function renames use emitted names. LLM requests explain the semantic mapping while keeping legacy result identifiers. The IGameSystem dispatch helper handles the same mapping directly without recursive name substitution. Agent writers take a separate `artifact_name` and must honor the same mapping. Stale existing semantic names must not trigger output-skipping.
- **Verification:** exercise legacy-name signature payloads, inherited dependency keys, LLM member fallback with already-corrected old metadata, unrelated-member rejection, ownership checks, stale outputs, and the two-event collision. Replay the affected finders against actual Windows/Linux IDBs into a temporary artifact root, using original old metadata and empty signature maps for deterministic fresh paths; then build a candidate from regenerated outputs and rerun both native C++ ABI gates. Do not count an inlined-only finder as passing on a binary with the helper out of line.
- **Scope:** semantic corrections where logical artifact identities must remain compatible. See `docs/cpp-abi-reference-validation.md`; do not rewrite historical reference files merely to change compatibility keys.


## Lesson: corrected caller anchors can move virtual dispatch into a helper

- **Trigger:** PR #1210 run `40460512874` failed on Linux with `expected 1 indirect vcall target, got 0`, then a missing fallback SKILL.md; the required `INetworkGameClient_SendStringCmd.linux.yaml` was absent.
- **Root cause / constraint:** the corrected ServerCmd artifact points to slot 50 (`0x5096d0`) instead of a sibling at slot 101 (`0x506eb0`). The old sibling contains a direct virtual dispatch, while ServerCmd directly tail-jumps to `0x4d47a0`. That helper loads `[vtable+0x130]` and dispatches through `jmp rax` at `0x4d4914`, with other unrelated virtual calls in its inlined default path. A unique source signature does not guarantee that downstream call-shape assumptions remain valid.
- **Correct approach:** keep the corrected artifact identity and declared dependency. `preprocess_indirect_vcall_target_skill(..., follow_direct_tail_jump=True)` may follow one unique external direct jump only after an empty successful source scan, then scan only helper tail jumps. Failed/ambiguous scans and multiple external targets must fail without emitting output. The SendStringCmd finder enables this only for Linux; other callers keep the default behavior. Do not hard-code addresses or copy old offsets to make regeneration pass.
- **Verification:** regress missing/ambiguous tail targets and virtual slots, failed source scans, and Windows direct dispatch. Real 14192 Windows/Linux IDB replay regenerated 10 required dependency nodes and both final artifacts retained offset `0x130`, index 38. Config inspection found no downstream finder consumers. A 4073-artifact composed candidate passed canonical inventory validation and both native C++ ABI gates (28 layout comparisons, 26 vtable comparisons per platform, zero differences); 1542 unit tests (18 skipped) and 124 repository-contract tests passed. Source artifact bytes remained unchanged. See `docs/cpp-abi-reference-validation.md`.
- **Scope:** deterministic interface-slot finders whose caller may directly tail-call a helper containing guarded virtual dispatch. Use distinct Windows and WSL virtual environments when replaying ABI gates from one shared checkout.
