---
name: create-preprocessor-scripts
description: |
  Create a new find-XXXX preprocessor Python script from scratch (no existing SKILL.md),
  add config.yaml skill and symbol entries. Covers xref-string-based and LLM_DECOMPILE-based
  discovery patterns. Use when a GitHub issue or user instruction specifies a new function to find.
disable-model-invocation: true
---

# Create Preprocessor Scripts from Scratch

Create an `ida_preprocessor_scripts/find-XXXX.py` preprocessor script and add the corresponding
`config.yaml` entries for a newly requested function, vtable, or struct member offset.

## When to Use

- A GitHub issue or user instruction requests adding support for finding a new function/symbol
- No existing `.claude/skills/find-XXXX/SKILL.md` needs conversion (for that, use `convert-finder-skill-to-preprocessor-scripts`)

## Inputs

The user or issue will provide some or all of:

| Field | Description | Example |
|-------|-------------|---------|
| **Function name(s)** | Target symbol(s) to find | `CPlayer_MovementServices_PlayWaterStepSound` |
| **Module** | Which DLL/SO the function lives in | `server`, `engine`, `networksystem`, `client` |
| **Category** | Symbol type | `func`, `vfunc`, `structmember`, `patch`, `vtable` |
| **xref_strings** | Debug strings for xref-based discovery | `"CT_Water.StepLeft"` |
| **xref_gvs** | Global variable VA (e.g. vtable address) to find functions that reference it | vtable VA from `SomeClass_vtable.{platform}.yaml` |
| **xref_funcs** | Known callee function name to find its callers | `"CPlayerCommandQueue_ctor"` |
| **Predecessor function** | Function to decompile for LLM_DECOMPILE patterns | `CBaseEntity_TakeDamageOld` |
| **VTable class** | Class owning the vtable (for vfuncs) | `CBasePlayerPawn` |
| **Desired YAML fields** | Which fields the output YAML needs | `func_name, func_sig, func_va, func_rva, func_size` |
| **Dependencies** | Input YAMLs this skill depends on | `CCSPlayer_MovementServices_vtable.{platform}.yaml` |
| **Aliases** | Alternative names for the symbol | `CPlayer_MovementServices::PlayWaterStepSound` |

## Overview

Eleven preprocessor patterns exist. The discovery method and target type determine which to use:

| Pattern | Discovery Method | Has FUNC_XREFS | Has LLM_DECOMPILE | Has INHERIT_VFUNCS | Has FUNC_VTABLE_RELATIONS | preprocess_skill has llm_config |
|---------|-----------------|-----------------|---------------------|--------------------|---------------------------|-------------------------------|
| **A** -- Regular function via xref strings | `find_regex` + `xrefs_to` on debug strings | Yes | No | No | No | No |
| **B** -- Virtual function via xref strings | Same as A, but function is in a vtable | Yes | No | No | Yes | No |
| **C** -- Virtual function via LLM_DECOMPILE | Decompile a known predecessor function, identify vfunc call offsets | No | Yes | No | Yes | Yes |
| **D** -- Regular function via LLM_DECOMPILE | Decompile a known predecessor function, identify direct call targets | No | Yes | No | No | Yes |
| **E** -- Struct member offset via LLM_DECOMPILE | Decompile a known predecessor function, identify struct field access offsets | No | Yes | No | No | Yes |
| **F** -- Virtual function via INHERIT_VFUNCS | Inherit vtable slot index from a known base-class vfunc, look up same slot in derived-class vtable (standard); or slot-only mode for abstract/interface vfuncs where only offset/index is needed | No | No | Yes | No | No |
| **G** -- ConCommand handler function | Find the handler callback registered via `RegisterConCommand` by matching command name and help string | No (uses COMMAND_NAME/HELP_STRING) | No | No | No | No |
| **H** -- Secondary (ordinal) vtable | Locate a class's secondary vtable via mangled symbol (Windows) or offset-to-top (Linux) | No | No | No | No | No |
| **I** -- Interface vfunc offset via thunk instruction walk | Walk a known concrete-class thunk via `py_eval` + `idaapi.decode_insn`, extract `jmp [reg+disp]` displacement as vfunc_offset | No | No | No | No | No |
| **J** -- IGameSystem vfunc via dispatch scan | Scan `IGameSystem_DispatchCall(idx, callback, ...)` call sites in a known predecessor; map targets by scan/index order using `_igamesystem_dispatch_common` | No | No | No | No | No |
| **K** -- IGameSystem vfunc via slot dispatch scan | Walk an `IGameSystem_Loop*AllSystems` dispatcher function body; extract `[rax+offset]` vtable call displacements via `_igamesystem_slot_dispatch_common`; output is slot-only (no `func_sig`) | No | No | No | No | No |

Additionally, **struct member offsets** can be mixed into any pattern as a secondary target (see "Struct Member Mixin" section below).

---

## Step 1: Determine the Pattern

From the user's input, determine:

1. **Is the target a function, vfunc, or struct member offset?**
   - Has `xref_strings` + category `func` -> **Pattern A**
   - Has `xref_strings` + category `vfunc` -> **Pattern B**
   - Has `xref_gvs` (vtable VA from a vtable YAML) + category `func` -> **Pattern A** with dynamic FUNC_XREFS (read vtable VA at runtime; see "Dynamic FUNC_XREFS via xref_gvs" note)
   - Has `xref_gvs` (vtable VA from a vtable YAML) + category `vfunc` -> **Pattern B** with dynamic FUNC_XREFS
   - Has `xref_funcs` (known callee function name) + category `func` -> **Pattern A** (static FUNC_XREFS; see "xref_funcs: finding callers of a known function" note)
   - Has `xref_funcs` (known callee function name) + category `vfunc` -> **Pattern B** (static FUNC_XREFS)
   - Has predecessor function + category `vfunc` -> **Pattern C**
   - Has predecessor function + category `func` -> **Pattern D**
   - Has predecessor function + category `structmember` -> **Pattern E**
   - Has base vfunc name + category `vfunc` (derived-class override of known base vfunc) -> **Pattern F**
     - If the target is an **abstract/interface vfunc** (no real function body, only `vfunc_offset`/`vfunc_index` needed) -> use **Pattern F slot-only**: `generate_func_sig=False`, desired fields = `{func_name, vtable_name, vfunc_offset, vfunc_index}`, NO vtable YAML required for the interface class
   - Has `COMMAND_NAME` + `HELP_STRING` (ConCommand handler callback) -> **Pattern G**
   - Has mangled vtable symbol / offset-to-top + category `vtable` (secondary vtable for a class) -> **Pattern H**
   - Target is an **interface vfunc offset** with no feasible `func_sig`/`vfunc_sig`, and the offset can be read from a concrete-class thunk's `jmp [reg+disp]` instruction -> **Pattern I**
   - Target is an `IGameSystem` vfunc visible as the callback argument to `IGameSystem_DispatchCall(...)` in a known predecessor's decompile -> **Pattern J**
   - Target is an `IGameSystem` abstract vfunc (slot-only output: `func_name, vtable_name, vfunc_offset, vfunc_index`; no `func_sig`) dispatched by a known `IGameSystem_Loop*AllSystems` function that iterates all game systems via vtable; the dispatcher's output YAML (`func_va`) is already available -> **Pattern K**

2. **Do xref strings differ between Windows and Linux?** If yes, use platform-specific `FUNC_XREFS_WINDOWS` / `FUNC_XREFS_LINUX` variant.

3. **Are there multiple functions?** If they share the same discovery method and starting point, put them in the same script with `-AND-` in the name. Otherwise, split into separate scripts.

**CRITICAL -- LLM_DECOMPILE dependency chains:** When LLM_DECOMPILE targets form a chain (FuncA -> FuncB -> FuncC, where each is the predecessor of the next), they **MUST** be in separate scripts -- one script per link in the chain. A single script CANNOT handle chained LLM_DECOMPILE predecessors because the LLM_DECOMPILE fallback resolves the predecessor's address from its output YAML (`func_va` field), and within a single script run the predecessor's output YAML doesn't exist yet. The IDA name-lookup fallback also fails because the predecessor wasn't renamed yet.

---

## Step 2: Create the Preprocessor Script

Script location: `ida_preprocessor_scripts/find-{skill_name}.py`

The filename MUST match the `name` field in `config.yaml` skill entry.

Read the reference for your chosen pattern:

- [Pattern A -- Regular function via xref strings](references/pattern-A.md)
- [Pattern B -- Virtual function via xref strings](references/pattern-B.md)
- [Pattern C -- Virtual function via LLM_DECOMPILE](references/pattern-C.md)
- [Pattern D -- Regular function via LLM_DECOMPILE](references/pattern-D.md)
- [Pattern E -- Struct member offset via LLM_DECOMPILE](references/pattern-E.md)
- [Pattern F -- Virtual function via INHERIT_VFUNCS](references/pattern-F.md) (standard + slot-only variant)
- [Pattern G -- ConCommand handler function](references/pattern-G.md)
- [Pattern H -- Secondary (ordinal) vtable](references/pattern-H.md)
- [Pattern I -- Interface vfunc offset via thunk walk](references/pattern-I.md)
- [Pattern J -- IGameSystem vfunc via dispatch scan](references/pattern-J.md)

### Cross-Cutting Notes

#### FULLMATCH: Prefix for Xref Strings (Patterns A & B)

When the xref string is short or generic (e.g. `"Precache"`, `"userid"`, `"team"`), use the `FULLMATCH:` prefix to require **exact string matching** instead of substring matching. Without it, `"Precache"` would match `"PrecacheModel"`, `"PrecacheSound"`, etc.

```python
FUNC_XREFS = [
    {
        "func_name": "CEntityInstance_Precache",
        "xref_strings": [
            "FULLMATCH:Precache",  # Only matches the exact string "Precache"
        ],
        "xref_gvs": [], "xref_signatures": [], "xref_funcs": [],
        "exclude_funcs": [], "exclude_strings": [], "exclude_gvs": [], "exclude_signatures": [],
    },
]
```

#### Dynamic FUNC_XREFS via `xref_gvs` (vtable VA)

When the target function is the **constructor** (or any other function that references a class's vtable), use `xref_gvs` with the vtable's virtual address. Because the vtable VA is only known after IDA analysis, it cannot be hardcoded -- it must be read from the vtable's output YAML at runtime.

This requires a custom `preprocess_skill` that:
1. Reads `vtable_va` from `{VtableClass}_vtable.{platform}.yaml` in `new_binary_dir`
2. Builds `func_xrefs` dynamically with the VA in `xref_gvs`
3. Passes the dynamic list to `preprocess_common_skill`

```python
import os
try:
    import yaml
except ImportError:
    yaml = None

def _read_vtable_va(yaml_path):
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            va = data.get("vtable_va")
            if va:
                return str(va)
    except Exception:
        pass
    return None

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    vtable_yaml_path = os.path.join(new_binary_dir, f"SomeClass_vtable.{platform}.yaml")
    vtable_va = _read_vtable_va(vtable_yaml_path)
    if not vtable_va:
        if debug:
            print("    Preprocess: SomeClass_vtable vtable_va not found, cannot resolve xref_gvs")
        return False

    func_xrefs = [
        {
            "func_name": "SomeClass_ctor",
            "xref_strings": [],
            "xref_gvs": [str(vtable_va)],
            "xref_signatures": [],
            "xref_funcs": [],
            "exclude_funcs": [],
            "exclude_strings": [],
            "exclude_gvs": [],
            "exclude_signatures": [],
        },
    ]
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=func_xrefs,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
```

**config.yaml `expected_input`:** must include the vtable YAML so it is guaranteed to be resolved before this script runs.

**Multiple xrefs / `exclude_signatures`:** If more than one function references the vtable (e.g. constructor + destructor), the intersection yields >1 result and the skill fails. Use `exclude_signatures` to exclude the unwanted function(s). If the ambiguity is platform-specific, make the exclusion conditional:

```python
exclude_signatures = ["66 83 ?? FF"] if platform == "linux" else []
```

To find the right bytes to exclude: look up the two candidate addresses in IDA, read the first ~4 bytes of the function to exclude, and use those as the `exclude_signatures` pattern with `??` wildcards where needed.

#### `xref_funcs`: Finding Callers of a Known Function (Patterns A & B)

When the target function is discoverable as a **caller** of another already-known function, use `xref_funcs` with the callee's name. Unlike `xref_gvs`, the function name is available at script-write time, so `FUNC_XREFS` can be a static module-level constant -- no dynamic building required.

```python
FUNC_XREFS = [
    {
        "func_name": "TargetFunc",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["KnownCalleeFunc"],   # callee that the target calls
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]
```

**config.yaml `expected_input`:** include the callee's output YAML to guarantee it is renamed in IDA before this script runs (the name lookup requires the rename to have happened):

```yaml
        expected_input:
          - KnownCalleeFunc.{platform}.yaml        # ensures callee is renamed first
          - TargetClass_vtable.{platform}.yaml     # if target is a vfunc (Pattern B)
```

#### Struct Member Mixin (for any pattern)

Struct member offsets can also be **mixed into** a function-finding script when they are discovered from the same function via signature matching (not LLM_DECOMPILE). Add `TARGET_STRUCT_MEMBER_NAMES` alongside `TARGET_FUNCTION_NAMES` and pass `struct_member_names=` to `preprocess_common_skill`:

```python
TARGET_FUNCTION_NAMES = [
    "SomeFunction",
]

TARGET_STRUCT_MEMBER_NAMES = [
    "SomeStruct_m_someField",
]

GENERATE_YAML_DESIRED_FIELDS = [
    ("SomeFunction", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
    ("SomeStruct_m_someField", ["struct_name", "member_name", "offset", "size", "offset_sig", "offset_sig_disp"]),
]

# In preprocess_skill:
    return await preprocess_common_skill(
        ...
        func_names=TARGET_FUNCTION_NAMES,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        ...
    )
```

#### CRITICAL -- FUNC_VTABLE_RELATIONS and vfunc fields

**`FUNC_VTABLE_RELATIONS` is required for ANY target whose `GENERATE_YAML_DESIRED_FIELDS` includes `vtable_name` or `vfunc_sig`** -- not just Pattern B and C. Without it, the LLM_DECOMPILE slot-only fallback fails with `"slot-only fallback missing vtable_name"` and the entire skill fails.

This applies even when:
- The target is a **vfunc call-site offset** (e.g. `call [rax+128h]`) rather than an actual function body in a vtable
- **No vtable YAML exists** for that class in config.yaml (no `expected_input` for the vtable needed)
- The script also finds **non-vfunc targets** (global variables, struct offsets) alongside the vfunc target

The `vtable_name` from `FUNC_VTABLE_RELATIONS` is used as **metadata** written to the output YAML -- it does NOT require an actual vtable lookup. For example, `("IGameTypes_CreateWorkshopMapGroup", "IGameTypes")` provides the vtable class name `IGameTypes` even though no `IGameTypes_vtable.{platform}.yaml` exists.

**Rule of thumb:** If any field in `GENERATE_YAML_DESIRED_FIELDS` starts with `vfunc_` or equals `vtable_name`, the target MUST have an entry in `FUNC_VTABLE_RELATIONS`.

### Key Differences Between Patterns

| Aspect | Pattern A (func + xref) | Pattern B (vfunc + xref) | Pattern C (vfunc + LLM) | Pattern D (func + LLM) | Pattern E (structmember + LLM) | Pattern F (vfunc + inherit) | Pattern G (ConCommand handler) | Pattern H (ordinal vtable) | Pattern I (iface vfunc thunk walk) | Pattern J (IGameSystem dispatch) | Pattern K (IGameSystem slot dispatch) |
|--------|------------------------|--------------------------|------------------------|------------------------|-------------------------------|---------------------------|-------------------------------|---------------------------|-----------------------------------|----------------------------------|---------------------------------------|
| FUNC_XREFS | Yes | Yes | No | No | No | No | No (uses COMMAND_NAME/HELP_STRING) | No | No | No | No |
| FUNC_VTABLE_RELATIONS | No | Yes | Yes | No | No | No | No | No | No | No | No |
| INHERIT_VFUNCS | No | No | No | No | No | Yes | No | No | No | No | No |
| LLM_DECOMPILE | No | No | Yes | Yes | Yes | No | No | No | No | No | No |
| `llm_config` param | No | No | Yes | Yes | Yes | No | No | No | No | No | No |
| Helper module | `preprocess_common_skill` | `preprocess_common_skill` | `preprocess_common_skill` | `preprocess_common_skill` | `preprocess_common_skill` | `preprocess_common_skill` | `preprocess_registerconcommand_skill` | `preprocess_ordinal_vtable_via_mcp` | `py_eval` + `write_func_yaml` (custom) | `preprocess_igamesystem_dispatch_skill` | `preprocess_igamesystem_slot_dispatch_skill` (from `_igamesystem_slot_dispatch_common`) |
| Target list | `TARGET_FUNCTION_NAMES` | `TARGET_FUNCTION_NAMES` | `TARGET_FUNCTION_NAMES` | `TARGET_FUNCTION_NAMES` | `TARGET_STRUCT_MEMBER_NAMES` | (none -- defined in INHERIT_VFUNCS) | `TARGET_FUNCTION_NAMES` | `TARGET_CLASS_NAME` (single string) | `TARGET_FUNC_NAME` + `PREDECESSOR_STEM` (module-level constants) | `TARGET_SPECS` (list of dicts with `target_name`, `rename_to`, optional `dispatch_rank`) | `TARGET_SPECS` (list of dicts with `target_name`, `vtable_name`, optional `dispatch_rank`) |
| preprocess param | `func_names=` | `func_names=` | `func_names=` | `func_names=` | `struct_member_names=` | `inherit_vfuncs=` | `command_name=`, `help_string=` | `class_name=`, `ordinal=` | (custom: reads YAML, calls `py_eval`) | `source_yaml_stem=`, `target_specs=`, `via_internal_wrapper=`, `multi_order=` | `dispatcher_yaml_stem=`, `target_specs=`, `multi_order=`, `expected_dispatch_count=` |
| YAML fields | func_name, func_sig, func_va, func_rva, func_size | Same + vtable_name, vfunc_offset, vfunc_index | func_name, func_va, func_rva, func_size, vfunc_sig, vfunc_offset, vfunc_index, vtable_name | func_name, func_sig, func_va, func_rva, func_size | struct_name, member_name, offset, size, offset_sig, offset_sig_disp | Standard: func_name, func_va, func_rva, func_size, func_sig, vtable_name, vfunc_offset, vfunc_index; Slot-only: func_name, vtable_name, vfunc_offset, vfunc_index | func_name, func_sig, func_va, func_rva, func_size | (vtable YAML via write_vtable_yaml) | func_name, vtable_name, vfunc_offset, vfunc_index | func_name, func_va, func_rva, func_size, func_sig, vtable_name, vfunc_offset, vfunc_index | func_name, vtable_name, vfunc_offset, vfunc_index |
| config category | `func` | `vfunc` | `vfunc` | `func` | `structmember` | `vfunc` | `func` | `vtable` | `vfunc` | `vfunc` | `vfunc` |

---

## Step 3: Update config.yaml

### 3a. Skills Section

Each preprocessor script needs a corresponding skill entry under the appropriate module's `skills:` list.

Find the module section (e.g. `server`, `engine`, `networksystem`) and add entries in logical order (near related functions).

**Template:**

```yaml
      - name: find-{SKILL_NAME}
        expected_output:
          - {FUNC_NAME_1}.{platform}.yaml
          # - {FUNC_NAME_2}.{platform}.yaml  # One per target function
        # expected_input only if the skill depends on other YAMLs:
        expected_input:
          - {PREDECESSOR_FUNC}.{platform}.yaml    # For Patterns C & D: the reference function
          - {VTABLE_CLASS}_vtable.{platform}.yaml  # For Patterns B & C: the vtable
```

**Rules:**
- `expected_output`: One `.{platform}.yaml` per target function in the script
- `expected_input`: Include predecessor function YAML (Patterns C & D) and/or vtable YAML (Patterns B & C & F)
- Pattern A with no vtable: typically NO `expected_input`
- Pattern F (standard): needs both the derived class vtable YAML and the base vfunc YAML in `expected_input`
- Pattern F (slot-only): needs ONLY the base vfunc YAML in `expected_input` -- no vtable YAML for the interface class
- Pattern J: needs both the predecessor function YAML and `IGameSystem_vtable.{platform}.yaml` in `expected_input`
- Pattern K: needs ONLY `{DISPATCHER_YAML_STEM}.{platform}.yaml` in `expected_input` -- no `IGameSystem_vtable.{platform}.yaml` needed
- Multi-function scripts use `-AND-` in the name: `find-FuncA-AND-FuncB`
- Place the new entry near related functions (e.g. `CCSPlayer_MovementServices_*` entries together)

**Dependency chain example** (multi-script):

```yaml
      # Pattern A: found via xref string, no dependencies
      - name: find-FuncA
        expected_output:
          - FuncA.{platform}.yaml

      # Pattern C: found by decompiling FuncA, needs FuncA + vtable
      - name: find-FuncB
        expected_output:
          - FuncB.{platform}.yaml
        expected_input:
          - FuncA.{platform}.yaml
          - SomeClass_vtable.{platform}.yaml
```

### 3b. Symbols Section

For each target function, add a symbol entry under the same module's `symbols:` list (if not already present).

```yaml
      # Regular function (Pattern A)
      - name: {FUNC_NAME}
        category: func
        alias:
          - {ClassName}::{MethodName}   # e.g. CPlayer_MovementServices::PlayWaterStepSound

      # Virtual function (Patterns B & C)
      - name: {FUNC_NAME}
        category: vfunc
        alias:
          - {ClassName}::{MethodName}   # e.g. CBasePlayerPawn::OnTakeDamage

      # Struct member offset (Pattern E)
      - name: {STRUCT_MEMBER_NAME}
        category: structmember
        struct: {STRUCT_NAME}
        member: {MEMBER_NAME}
        alias:
          - {StructName}::{MemberName}
```

**Check existing symbols before adding -- do NOT create duplicates.**

Place the new symbol near related symbols (same class/subsystem).

---

## Step 4: Handle Reference YAMLs (Patterns C, D & E only)

Pattern C, D, and E scripts reference a predecessor function's YAML at:
`ida_preprocessor_scripts/references/{module}/{PREDECESSOR_FUNC}.{platform}.yaml`

**Check** if the reference YAML already exists:
- `ida_preprocessor_scripts/references/{module}/{PREDECESSOR_FUNC}.linux.yaml`
- `ida_preprocessor_scripts/references/{module}/{PREDECESSOR_FUNC}.windows.yaml`

If NOT present, generate them using `generate_reference_yaml.py`:

```bash
# Windows -- always pass -platform windows explicitly
uv run generate_reference_yaml.py -func_name {PREDECESSOR_FUNC} -auto_start_mcp -binary "bin/{gamever}/{module}/{binary_name}.dll" -platform windows -debug

# Linux -- always pass -platform linux explicitly
uv run generate_reference_yaml.py -func_name {PREDECESSOR_FUNC} -auto_start_mcp -binary "bin/{gamever}/{module}/lib{module}.so" -platform linux -debug
```

where `{gamever}` can be obtained from `.env` -> `CS2VIBE_GAMEVER`.

**IMPORTANT -- Always pass `-platform` explicitly.** While `-platform` can theoretically be inferred from the binary extension (`.dll` -> windows, `.so` -> linux), auto-inference is unreliable and may produce the wrong platform's reference YAML. Always pass `-platform windows` or `-platform linux` explicitly.

**IMPORTANT -- Run `generate_reference_yaml.py` sequentially, NOT in parallel.** All invocations share the same IDA MCP connection. Running them in parallel will cause connection conflicts and failures. Run one command at a time, waiting for each to complete before starting the next.

YOU MUST: rename known symbols / add necessary comments in the generated reference YAMLs so the LLM can find desired symbols by comparing reference ones with raw procedure/disassembly read from new binaries. See the `convert-finder-skill-to-preprocessor-scripts` SKILL.md Step 5 for detailed annotation examples.

**IMPORTANT -- When the predecessor is a NEW function (no existing output YAMLs):** If the predecessor function is brand new (discovered by another new script you're creating at the same time), its output YAMLs don't exist yet and `generate_reference_yaml.py` cannot resolve its address. You must use a **multi-phase workflow**:

1. **Phase 1:** Create ALL scripts (vtable, xref_string, LLM_DECOMPILE) and update config.yaml
2. **Phase 2:** Run `uv run ida_analyze_bin.py -debug` -- the vtable and xref_string scripts will succeed and populate the NEW predecessor's output YAMLs. The LLM_DECOMPILE script will fail (no reference YAML yet) or be skipped.
3. **Phase 3:** Now that the predecessor has output YAMLs, run `generate_reference_yaml.py` to create reference YAMLs, then annotate them.
4. **Phase 4:** Run `uv run ida_analyze_bin.py -debug` again -- this time the LLM_DECOMPILE path runs and the full pipeline is validated.

---

## Step 5: Run Tests

After all creation steps are complete, run the full preprocessor test to validate the new script works.

Because the output is very long, redirect it to a temp file and then read just the summary:

```bash
uv run ida_analyze_bin.py -debug > /tmp/ida_test_output.txt 2>&1; tail -10 /tmp/ida_test_output.txt
```

Check the **Summary** at the end of the output:
- **Failed: 0** means the creation is correct
- If any failures, search the full output for the failing skill name to investigate:
  ```bash
  grep -A 5 "Failed\|Error" /tmp/ida_test_output.txt
  ```

This step is mandatory -- do not report completion without running and passing this validation.

---

## Step 6: Commit Changes

After validation passes, commit all changes to git.

**IMPORTANT -- Never commit directly to the `main` branch.** If the current branch is `main`, create and switch to a `dev` branch first:

```bash
# Check current branch
git branch --show-current

# If on main, switch to dev (create it if it doesn't exist)
git checkout dev 2>/dev/null || git checkout -b dev
```

Then commit:

```bash
git add ida_preprocessor_scripts/find-{SKILL_NAME}.py config.yaml
git commit -m "Add find-{SKILL_NAME} preprocessor script"
```

Include all files changed:
- The new preprocessor script
- config.yaml changes
- Any reference YAMLs generated (for Patterns C/D/E)

---

## Checklist

Before finishing, verify:

- [ ] Preprocessor script file name matches the `name` field in config.yaml skill entry
- [ ] `GENERATE_YAML_DESIRED_FIELDS` uses correct field set for the pattern
- [ ] config.yaml `expected_output` has one entry per target
- [ ] config.yaml `expected_input` correctly chains dependencies
- [ ] config.yaml `symbols` section has entries for all targets (no duplicates)
- [ ] Pattern-specific checks pass (see the Checklist section in the chosen pattern reference file)
- [ ] `uv run ida_analyze_bin.py -debug` passes with 0 failures
- [ ] All changes committed to git (on `dev` branch, NOT `main`)

## Real-World Examples

### Example: Regular function via xref string (Pattern A)

**Issue says:** `CPlayer_MovementServices_PlayWaterStepSound` is a regular function in server dll. xref_strings: `"CT_Water.StepLeft"`. Fields needed: `func_name, func_sig, func_va, func_rva, func_size`.

**Result:** `ida_preprocessor_scripts/find-CPlayer_MovementServices_PlayWaterStepSound.py` with:
- `FUNC_XREFS` containing `"CT_Water.StepLeft"`
- `GENERATE_YAML_DESIRED_FIELDS` with `func_name, func_sig, func_va, func_rva, func_size`
- No `FUNC_VTABLE_RELATIONS`, no `LLM_DECOMPILE`
- config.yaml skill entry with `expected_output: CPlayer_MovementServices_PlayWaterStepSound.{platform}.yaml`
- config.yaml symbol entry with `category: func`, alias `CPlayer_MovementServices::PlayWaterStepSound`

### Example: Virtual function via xref string (Pattern B)

**Issue says:** `CSource2GameEntities_CheckTransmit` is a vfunc of `CSource2GameEntities` in server dll. xref_strings: `"CSource2GameEntities::CheckTransmit"` (Windows), `"./gameinterface.cpp:30"` (Linux).

**Result:** `ida_preprocessor_scripts/find-CSource2GameEntities_CheckTransmit.py` with:
- Platform-specific `FUNC_XREFS_WINDOWS` / `FUNC_XREFS_LINUX`
- `FUNC_VTABLE_RELATIONS`: `("CSource2GameEntities_CheckTransmit", "CSource2GameEntities")`
- `GENERATE_YAML_DESIRED_FIELDS` with vtable fields
- config.yaml `expected_input: CSource2GameEntities_vtable.{platform}.yaml`

### Example: Multiple functions from same xref (Pattern A, multi-target)

**Issue says:** Find both `FuncA` and `FuncB` in server. Both use xref string `"SharedDebugString"`.

**Result:** `ida_preprocessor_scripts/find-FuncA-AND-FuncB.py` with:
- Two entries in `TARGET_FUNCTION_NAMES`
- Two entries in `FUNC_XREFS` (each with the same or different xref strings)
- Two entries in `GENERATE_YAML_DESIRED_FIELDS`
- config.yaml skill name: `find-FuncA-AND-FuncB`
- config.yaml: two `expected_output` entries, two symbol entries

### Example: Derived-class vfunc via INHERIT_VFUNCS (Pattern F)

**Issue says:** `CBaseEntity_Precache` is a vfunc on `CBaseEntity` that overrides `CEntityInstance::Precache` at the same vtable slot. `CEntityInstance_Precache` is already found by another script.

**Result:** `ida_preprocessor_scripts/find-CBaseEntity_Precache.py` with:
- `INHERIT_VFUNCS`: `("CBaseEntity_Precache", "CBaseEntity", "CEntityInstance_Precache", True)`
- `GENERATE_YAML_DESIRED_FIELDS` with vtable fields
- No FUNC_XREFS, no LLM_DECOMPILE, no FUNC_VTABLE_RELATIONS
- config.yaml `expected_input`: `CBaseEntity_vtable.{platform}.yaml` + `CEntityInstance_Precache.{platform}.yaml`
- config.yaml symbol: category `vfunc`, alias `CBaseEntity::Precache`

### Example: Virtual function via xref string with FULLMATCH (Pattern B)

**Issue says:** `CEntityInstance_Precache` is a vfunc on `CEntityInstance`. xref_string: `"Precache"` (exact match needed since substring would hit `PrecacheModel`, etc.).

**Result:** `ida_preprocessor_scripts/find-CEntityInstance_Precache.py` with:
- `FUNC_XREFS` containing `"FULLMATCH:Precache"` (exact match)
- `FUNC_VTABLE_RELATIONS`: `("CEntityInstance_Precache", "CEntityInstance")`
- `GENERATE_YAML_DESIRED_FIELDS` with vtable fields
- config.yaml `expected_input`: `CEntityInstance_vtable.{platform}.yaml`

### Example: vtable + xref-string vfunc + LLM_DECOMPILE regular function (vtable + Patterns B + D, multi-phase)

**User says:** Find `LegacyGameEventListener` in server. It's a regular function called from `CSource2GameClients::StartHLTVServer` (a vfunc of `CSource2GameClients`). The xref string for StartHLTVServer is `"CSource2GameClients::StartHLTVServer: game event %s not found"`.

**Result -- three scripts:**

1. `ida_preprocessor_scripts/find-CSource2GameClients_vtable.py` (vtable discovery):
   - `TARGET_CLASS_NAMES`: `["CSource2GameClients"]`
   - Pure vtable lookup, no dependencies

2. `ida_preprocessor_scripts/find-CSource2GameClients_StartHLTVServer.py` (Pattern B):
   - `FUNC_XREFS` containing `"CSource2GameClients::StartHLTVServer: game event %s not found"`
   - `FUNC_VTABLE_RELATIONS`: `("CSource2GameClients_StartHLTVServer", "CSource2GameClients")`
   - config.yaml `expected_input`: `CSource2GameClients_vtable.{platform}.yaml`

3. `ida_preprocessor_scripts/find-LegacyGameEventListener.py` (Pattern D):
   - `LLM_DECOMPILE` referencing `references/server/CSource2GameClients_StartHLTVServer.{platform}.yaml`
   - No `FUNC_VTABLE_RELATIONS` (regular function)
   - Reference YAMLs annotated: `sub_180B1AC80` / `sub_1516AB0` renamed to `LegacyGameEventListener` in both disasm and procedure
   - config.yaml `expected_input`: `CSource2GameClients_StartHLTVServer.{platform}.yaml`

**config.yaml dependency chain:**
```yaml
      - name: find-CSource2GameClients_vtable
        expected_output:
          - CSource2GameClients_vtable.{platform}.yaml

      - name: find-CSource2GameClients_StartHLTVServer
        expected_output:
          - CSource2GameClients_StartHLTVServer.{platform}.yaml
        expected_input:
          - CSource2GameClients_vtable.{platform}.yaml

      - name: find-LegacyGameEventListener
        expected_output:
          - LegacyGameEventListener.{platform}.yaml
        expected_input:
          - CSource2GameClients_StartHLTVServer.{platform}.yaml
```

**Key insight -- multi-phase workflow required:** `CSource2GameClients_StartHLTVServer` was a brand-new function with no existing output YAMLs. `generate_reference_yaml.py` needs `func_va` from the predecessor's output YAML to locate it in IDA. So the workflow was:
1. Create all 3 scripts + config entries
2. Run `ida_analyze_bin.py -debug` -> vtable + xref scripts succeed and create StartHLTVServer YAMLs
3. Run `generate_reference_yaml.py` using the newly created output YAMLs
4. Annotate reference YAMLs
5. Run `ida_analyze_bin.py -debug` again -> LLM_DECOMPILE path runs and succeeds

### Example: ConCommand handler function (Pattern G)

**User says:** Find `BotKill_CommandHandler` in server. It's the handler callback for the `bot_kill` console command. COMMAND_NAME=`"bot_kill"`, HELP_STRING=`"bot_kill <all> <t|ct> <type> <difficulty> <name> - Kills a specific bot, or all bots, matching the given criteria."`.

**Result:** `ida_preprocessor_scripts/find-BotKill_CommandHandler.py` with:
- `COMMAND_NAME = "bot_kill"`
- `HELP_STRING = "bot_kill <all> <t|ct> <type> <difficulty> <name> - Kills a specific bot, or all bots, matching the given criteria."`
- `SEARCH_WINDOW_BEFORE_CALL = 96`, `SEARCH_WINDOW_AFTER_XREF = 96`
- Uses `preprocess_registerconcommand_skill()` from `_registerconcommand.py`
- `GENERATE_YAML_DESIRED_FIELDS` with `func_name, func_sig, func_va, func_rva, func_size`
- config.yaml skill entry with no `expected_input`
- config.yaml symbol entry with `category: func`, alias `CCSBotManager::BotKillCommand`

### Example: ConCommand handler + LLM_DECOMPILE virtual function (Patterns G + C, multi-phase)

**User says:** Find `CBasePlayerPawn_CommitSuicide` in server. It's a vfunc on `CBasePlayerPawn` called from the `bot_kill` command handler via `call qword ptr [rax+0xC80]`. The handler iterates matched bots and calls `pPlayerPawn->CommitSuicide(false, false)`.

**Result -- two scripts:**

1. `ida_preprocessor_scripts/find-BotKill_CommandHandler.py` (Pattern G):
   - `COMMAND_NAME = "bot_kill"`, `HELP_STRING = "bot_kill <all> ..."`
   - No dependencies

2. `ida_preprocessor_scripts/find-CBasePlayerPawn_CommitSuicide.py` (Pattern C):
   - `LLM_DECOMPILE` referencing `references/server/BotKill_CommandHandler.{platform}.yaml`
   - `FUNC_VTABLE_RELATIONS`: `("CBasePlayerPawn_CommitSuicide", "CBasePlayerPawn")`
   - Reference YAMLs annotated with `; 0xC80 = CBasePlayerPawn_CommitSuicide` in disasm and `// 3200LL = 0xC80 = CBasePlayerPawn_CommitSuicide` in procedure

**config.yaml dependency chain:**
```yaml
      - name: find-BotKill_CommandHandler
        expected_output:
          - BotKill_CommandHandler.{platform}.yaml

      - name: find-CBasePlayerPawn_CommitSuicide
        expected_output:
          - CBasePlayerPawn_CommitSuicide.{platform}.yaml
        expected_input:
          - BotKill_CommandHandler.{platform}.yaml
          - CBasePlayerPawn_vtable.{platform}.yaml
```

**Multi-phase workflow:** BotKill_CommandHandler is a new function, so:
1. Create both scripts + config entries
2. Run `ida_analyze_bin.py -debug` -> Pattern G script succeeds, creates BotKill_CommandHandler YAMLs
3. Run `generate_reference_yaml.py` for both platforms
4. Annotate reference YAMLs with CommitSuicide vfunc call comments
5. Run `ida_analyze_bin.py -debug` again -> LLM_DECOMPILE path runs and succeeds

### Example: xref-string function + LLM_DECOMPILE global variable & vfunc offset (Patterns A + LLM_DECOMPILE with gv + vfunc, multi-phase)

**User says:** Find `g_pGameTypes` (global variable) and `IGameTypes_CreateWorkshopMapGroup` (vfunc offset at `call [rax+128h]`) in server. They are found by decompiling `CDedicatedServerWorkshopManager_SwitchToWorkshopMapGroup`, which is discoverable via xref string `"mapgroup workshop"`.

**Result -- two scripts:**

1. `ida_preprocessor_scripts/find-CDedicatedServerWorkshopManager_SwitchToWorkshopMapGroup.py` (Pattern A):
   - `FUNC_XREFS` containing `"mapgroup workshop"`
   - `GENERATE_YAML_DESIRED_FIELDS` with `func_name, func_sig, func_va, func_rva, func_size`
   - No `FUNC_VTABLE_RELATIONS`, no `LLM_DECOMPILE`

2. `ida_preprocessor_scripts/find-g_pGameTypes-AND-IGameTypes_CreateWorkshopMapGroup.py` (LLM_DECOMPILE):
   - `TARGET_FUNCTION_NAMES`: `["IGameTypes_CreateWorkshopMapGroup"]`
   - `TARGET_GLOBALVAR_NAMES`: `["g_pGameTypes"]`
   - `LLM_DECOMPILE` with two entries (one per target), both referencing the same predecessor YAML
   - **CRITICAL:** `FUNC_VTABLE_RELATIONS`: `("IGameTypes_CreateWorkshopMapGroup", "IGameTypes")` -- required because `GENERATE_YAML_DESIRED_FIELDS` includes `vtable_name` and `vfunc_sig`. Without this, fails with `"slot-only fallback missing vtable_name"`. Note: no `IGameTypes_vtable` YAML exists -- the vtable name is purely metadata.
   - `GENERATE_YAML_DESIRED_FIELDS` for IGameTypes_CreateWorkshopMapGroup: `func_name, vtable_name, vfunc_offset, vfunc_index, vfunc_sig`
   - `GENERATE_YAML_DESIRED_FIELDS` for g_pGameTypes: `gv_name, gv_va, gv_rva, gv_sig, gv_sig_va, gv_inst_offset, gv_inst_length, gv_inst_disp`
   - config.yaml symbols: `g_pGameTypes` with `category: gv`, `IGameTypes_CreateWorkshopMapGroup` with `category: vfunc`

**config.yaml dependency chain:**
```yaml
      - name: find-CDedicatedServerWorkshopManager_SwitchToWorkshopMapGroup
        expected_output:
          - CDedicatedServerWorkshopManager_SwitchToWorkshopMapGroup.{platform}.yaml

      - name: find-g_pGameTypes-AND-IGameTypes_CreateWorkshopMapGroup
        expected_output:
          - g_pGameTypes.{platform}.yaml
          - IGameTypes_CreateWorkshopMapGroup.{platform}.yaml
        expected_input:
          - CDedicatedServerWorkshopManager_SwitchToWorkshopMapGroup.{platform}.yaml
```

**Key insight -- FUNC_VTABLE_RELATIONS for vfunc offsets:** Even though `IGameTypes_CreateWorkshopMapGroup` is a vfunc call-site offset (not a function in a vtable we own), `FUNC_VTABLE_RELATIONS` is still required because the `GENERATE_YAML_DESIRED_FIELDS` include `vtable_name` and `vfunc_sig`. The system uses the vtable class name from `FUNC_VTABLE_RELATIONS` as metadata -- it does NOT attempt to look up an `IGameTypes_vtable` YAML.

### Example: Secondary vtable via ordinal lookup (Pattern H)

**User says:** Find `CLoopTypeClientServerService_vtable2` in engine. Windows mangled name: `??_7CLoopTypeClientServerService@@6B@_0`. Linux: `_ZTI28CLoopTypeClientServerService` with `dq -56 ; offset to this`.

**Result:** `ida_preprocessor_scripts/find-CLoopTypeClientServerService_vtable2.py` with:
- `TARGET_CLASS_NAME = "CLoopTypeClientServerService"`
- `TARGET_OUTPUT_STEM = "CLoopTypeClientServerService_vtable2"`
- `WINDOWS_SYMBOL_ALIASES = ["??_7CLoopTypeClientServerService@@6B@_0"]`
- `LINUX_EXPECTED_OFFSET_TO_TOP = -56`
- Uses `preprocess_ordinal_vtable_via_mcp` with `ordinal=0`
- config.yaml skill entry with no `expected_input`
- config.yaml symbol entry with `category: vtable`

### Example: Interface vfunc offset via thunk instruction walk (Pattern I)

**User says:** Find `ILoopMode_HandleInputEvent` in engine. It's a vfunc of `ILoopMode` (shared interface). The offset can be read from `CLoopTypeClientServerService_HandleInputEvent`, a thin thunk that does:
```
Windows: mov rcx, [rcx+0E0h] / mov rax, [rcx] / jmp [rax+28h]
Linux:   mov rdi, [rdi+0E0h] / mov rax, [rdi] / jmp [rax+28h]
```
No unique `func_sig` is feasible for the thunk (2-3 generic instructions). `func_sig` for the jmp itself is also not unique.

**Result:** `ida_preprocessor_scripts/find-ILoopMode_HandleInputEvent.py` with:
- `PREDECESSOR_STEM = "CLoopTypeClientServerService_HandleInputEvent"`
- `TARGET_FUNC_NAME = "ILoopMode_HandleInputEvent"`
- `VTABLE_CLASS = "ILoopMode"`
- `_PY_EVAL_TEMPLATE` walks `idaapi.decode_insn` loop, finds first `jmp` with `op.type == idaapi.o_displ`, reads `op.addr & 0xFFFF_FFFF` as `vfunc_offset`
- Writes `func_name, vtable_name, vfunc_offset, vfunc_index` via `write_func_yaml`
- "Reuse previous gamever" fast path reads `vfunc_offset` from `old_yaml_map[TARGET_FUNC_NAME]`

**config.yaml:**
```yaml
      - name: find-ILoopMode_HandleInputEvent
        expected_output:
          - ILoopMode_HandleInputEvent.{platform}.yaml
        expected_input:
          - CLoopTypeClientServerService_HandleInputEvent.{platform}.yaml
```

**Output YAML (both platforms):**
```yaml
func_name: ILoopMode_HandleInputEvent
vtable_name: ILoopMode
vfunc_offset: '0x28'
vfunc_index: 5
```

**Key insight -- when to choose Pattern I over B/C:**
- Pattern B would need an `xref_signature` for the thunk body -- but `48 8B ?? 48 FF 60 ??` (Windows) / `48 8B ?? FF 60 ??` (Linux) are too generic to sign uniquely without the concrete displacement byte filled in
- Pattern C (LLM_DECOMPILE) would work but is heavyweight for a 2-3 instruction function; the LLM also requires a SKILL.md file which generates a "Skill file not found" error if missing
- Pattern I avoids both issues: no signature needed, no LLM needed -- the displacement byte is read deterministically via `idaapi.decode_insn`

### Example: Interface vfunc slot index via INHERIT_VFUNCS slot-only (Pattern F slot-only)

**User says:** Find `ILoopMode_LoopInit` in client and server. It's a vfunc of the abstract interface `ILoopMode`. `CLoopModeGame_LoopInit` already overrides it at the same vtable slot. No `func_sig` or `vfunc_sig` needed.

**Result:** `ida_preprocessor_scripts/find-ILoopMode_LoopInit.py` with:
- `INHERIT_VFUNCS`: `("ILoopMode_LoopInit", "ILoopMode", "CLoopModeGame_LoopInit", False)`
- `GENERATE_YAML_DESIRED_FIELDS`: exactly `func_name, vtable_name, vfunc_offset, vfunc_index` -- triggers slot-only mode
- No `FUNC_XREFS`, no `LLM_DECOMPILE`, no `FUNC_VTABLE_RELATIONS`
- config.yaml `expected_input`: ONLY `CLoopModeGame_LoopInit.{platform}.yaml` -- **no** `ILoopMode_vtable.{platform}.yaml`
- config.yaml symbol: `category: vfunc`, alias `ILoopMode::LoopInit`
- Same single script file referenced in BOTH `client` and `server` module sections of config.yaml

**config.yaml entry (in both client and server sections):**
```yaml
      - name: find-ILoopMode_LoopInit
        expected_output:
          - ILoopMode_LoopInit.{platform}.yaml
        expected_input:
          - CLoopModeGame_LoopInit.{platform}.yaml
```

**Output YAML:**
```yaml
func_name: ILoopMode_LoopInit
vtable_name: ILoopMode
vfunc_offset: '0x28'
vfunc_index: 5
```

**Key insight -- slot-only vs Pattern I:** `ILoopMode_HandleInputEvent` used Pattern I (thunk instruction walk) because its offset comes from reading `jmp [reg+disp]` inside a thin wrapper. `ILoopMode_LoopInit` uses Pattern F slot-only because `CLoopModeGame_LoopInit` already has a `vfunc_index` in its output YAML -- no instruction walking needed, just copy the slot index with a different `vtable_name`.

### Example: IGameSystem vfuncs via dispatch scan -- single predecessor, two targets (Pattern J)

**User says:** Find `IGameSystem_OnServerPreEntityThink` and `IGameSystem_OnServerPostEntityThink` in server. Both appear as callback arguments to `IGameSystem_DispatchCall(...)` in `CSource2Server_GameFrame`. The decompile shows:
```c
IGameSystem_DispatchCall(v30, (__int64 (__fastcall *)(...))GameSystem_OnServerPreEntityThink, (__int64)&v45);
// ... entity simulation ...
IGameSystem_DispatchCall(v37, (__int64 (__fastcall *)(...))GameSystem_OnServerPostEntityThink, (__int64)&v45);
```

**Result:** `ida_preprocessor_scripts/find-IGameSystem_OnServerPreEntityThink-AND-IGameSystem_OnServerPostEntityThink.py` with:
- `SOURCE_YAML_STEM = "CSource2Server_GameFrame"` -- predecessor already found by a Pattern B script
- `TARGET_SPECS`: two entries, `rename_to` values taken directly from the decompile callback names
- `VIA_INTERNAL_WRAPPER = False` -- `CSource2Server_GameFrame` contains the dispatch calls directly (no nested helper)
- `INTERNAL_RENAME_TO = None`
- `MULTI_ORDER = "index"` -- two targets, two dispatches, use index order for stable mapping
- No `EXPECTED_DISPATCH_COUNT` -- target count equals dispatch count (2 == 2), default is sufficient
- config.yaml `expected_input`: `CSource2Server_GameFrame.{platform}.yaml` + `IGameSystem_vtable.{platform}.yaml`

```python
SOURCE_YAML_STEM = "CSource2Server_GameFrame"
TARGET_SPECS = [
    {"target_name": "IGameSystem_OnServerPreEntityThink",  "rename_to": "GameSystem_OnServerPreEntityThink"},
    {"target_name": "IGameSystem_OnServerPostEntityThink", "rename_to": "GameSystem_OnServerPostEntityThink"},
]
VIA_INTERNAL_WRAPPER = False
INTERNAL_RENAME_TO = None
MULTI_ORDER = "index"
```

**config.yaml:**
```yaml
      - name: find-IGameSystem_OnServerPreEntityThink-AND-IGameSystem_OnServerPostEntityThink
        expected_output:
          - IGameSystem_OnServerPreEntityThink.{platform}.yaml
          - IGameSystem_OnServerPostEntityThink.{platform}.yaml
        expected_input:
          - CSource2Server_GameFrame.{platform}.yaml
          - IGameSystem_vtable.{platform}.yaml
```

**Key insight -- choosing `MULTI_ORDER`:**
- `"scan"` preserves the textual order of `IGameSystem_DispatchCall` sites as they appear in the function body -- safe only when there is exactly 1 target or when all targets are extracted (no `dispatch_rank` filtering).
- `"index"` sorts collected entries by `(vfunc_index, vfunc_offset)` before mapping -- required for multi-target scripts because compiler instruction scheduling can reorder `lea rdx, callback` emissions independently of semantic call order, making index-based sorting more stable across game updates.

**Key insight -- `VIA_INTERNAL_WRAPPER`:**
- Set to `False` when the predecessor function itself contains the `IGameSystem_DispatchCall` sites directly (like `CSource2Server_GameFrame`).
- Set to `True` when the predecessor immediately tail-calls or inlines a distinct named sub-function that holds the actual dispatch calls (e.g. `CLoopModeGame_OnClientPreOutput` → `CLoopModeGame_OnClientPreOutputInternal`). In that case also set `INTERNAL_RENAME_TO` to the wrapper's intended name so it gets annotated in IDA.

### Example: IGameSystem abstract vfunc via slot dispatch scan (Pattern K)

**User says:** Find `IGameSystem_OnGamePreShutdown` in server. It's an abstract `IGameSystem` vfunc (slot-only, no `func_sig` needed) dispatched by `IGameSystem_LoopPreShutdownAllSystems`, which iterates all game systems and calls their `GamePreShutdown` vfunc via `[rax+offset]`. The dispatcher YAML stem is `IGameSystem_LoopPreShutdownAllSystems`.

**Result:** `ida_preprocessor_scripts/find-IGameSystem_OnGamePreShutdown.py` with:

```python
from ida_preprocessor_scripts._igamesystem_slot_dispatch_common import (
    preprocess_igamesystem_slot_dispatch_skill,
)

DISPATCHER_YAML_STEM = "IGameSystem_LoopPreShutdownAllSystems"

TARGET_SPECS = [
    {
        "target_name": "IGameSystem_OnGamePreShutdown",
        "vtable_name": "IGameSystem",
        "dispatch_rank": 0,
    },
]

EXPECTED_DISPATCH_COUNT = 1

async def preprocess_skill(session, skill_name, expected_outputs, old_yaml_map,
                           new_binary_dir, platform, image_base, debug=False):
    _ = skill_name; _ = old_yaml_map; _ = image_base
    return await preprocess_igamesystem_slot_dispatch_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        dispatcher_yaml_stem=DISPATCHER_YAML_STEM,
        target_specs=TARGET_SPECS,
        multi_order="index",
        expected_dispatch_count=EXPECTED_DISPATCH_COUNT,
        debug=debug,
    )
```

**config.yaml:**
```yaml
      - name: find-IGameSystem_OnGamePreShutdown
        expected_output:
          - IGameSystem_OnGamePreShutdown.{platform}.yaml
        expected_input:
          - IGameSystem_LoopPreShutdownAllSystems.{platform}.yaml
```

**config.yaml symbol entry:**
```yaml
      - name: IGameSystem_OnGamePreShutdown
        category: vfunc
        alias:
          - IGameSystem::GamePreShutdown
```

**Output YAML (both platforms):**
```yaml
func_name: IGameSystem_OnGamePreShutdown
vtable_name: IGameSystem
vfunc_offset: '0x...'
vfunc_index: ...
```

**Key insight -- Pattern K vs Pattern J vs Pattern F slot-only:**
- **Pattern J** (`_igamesystem_dispatch_common`): the target IS the `callback` function argument passed to `IGameSystem_DispatchCall(...)` -- a full concrete function with `func_va`, `func_sig`, etc. Use when the dispatch scan is done inside a game-loop function like `CSource2Server_GameFrame`.
- **Pattern K** (`_igamesystem_slot_dispatch_common`): the target is an abstract vfunc offset extracted from a dedicated `IGameSystem_Loop*AllSystems` dispatcher. The dispatcher walks all game systems and calls their vfunc at a fixed `[rax+offset]`. Output is slot-only (no `func_sig`). Use when the dispatcher is one of the `IGameSystem_Loop*AllSystems` family.
- **Pattern F slot-only**: use when a concrete override of the same slot already has a known `vfunc_index` in its output YAML. Pattern K is preferred when no concrete override YAML exists yet but the `IGameSystem_Loop*AllSystems` dispatcher YAML is available.

**`EXPECTED_DISPATCH_COUNT`:** Set to the number of unique vtable call sites in the dispatcher. For `IGameSystem_Loop*AllSystems` functions that dispatch exactly one vfunc, set it to `1`. If the dispatcher has `N` unique `[rax+offset]` calls mapping to `N` different abstract vfuncs, set it to `N` and add all `N` targets to `TARGET_SPECS` with unique `dispatch_rank` values.

**`preprocess_skill` signature note:** Pattern K does NOT take an `llm_config` parameter (unlike Patterns C/D/E). The signature is:
```python
async def preprocess_skill(session, skill_name, expected_outputs, old_yaml_map,
                           new_binary_dir, platform, image_base, debug=False):
```

### Example: Constructor via vtable xref_gvs (Pattern A, dynamic FUNC_XREFS)

**User says:** Find `CPlayerCommandQueue_ctor` in server. It's the constructor -- identifiable as the function that writes the `CPlayerCommandQueue` vtable pointer. Find it via `xref_gvs` on `CPlayerCommandQueue_vtable`.

**Result:** Two scripts required (vtable first, then ctor):

1. `ida_preprocessor_scripts/find-CPlayerCommandQueue_vtable.py` (vtable discovery, same as any other vtable script):
   - `TARGET_CLASS_NAMES = ["CPlayerCommandQueue"]`

2. `ida_preprocessor_scripts/find-CPlayerCommandQueue_ctor.py` (Pattern A, dynamic FUNC_XREFS):
   - Imports `os` and `yaml`
   - `_read_vtable_va()` helper reads `vtable_va` from the vtable YAML
   - `preprocess_skill` builds `func_xrefs` at runtime with `xref_gvs: [vtable_va]`
   - Linux had 2 xref candidates; added `exclude_signatures = ["66 83 ?? FF"] if platform == "linux" else []`

**config.yaml:**
```yaml
      - name: find-CPlayerCommandQueue_vtable
        expected_output:
          - CPlayerCommandQueue_vtable.{platform}.yaml

      - name: find-CPlayerCommandQueue_ctor
        expected_output:
          - CPlayerCommandQueue_ctor.{platform}.yaml
        expected_input:
          - CPlayerCommandQueue_vtable.{platform}.yaml
```

**Key insight -- vtable VA is runtime-only:** The vtable VA changes with every binary update, so it cannot be hardcoded. The `_read_vtable_va()` helper reads it from the vtable YAML written earlier in the same `ida_analyze_bin.py` run. The vtable skill must appear first in config.yaml (via `expected_input`) so it executes before the ctor skill.

**Key insight -- multiple xref candidates:** A vtable is typically written by the constructor AND sometimes by a destructor or copy constructor. If >1 function is found, the skill fails with `"xref intersection yielded N function(s) (need exactly 1)"`. Read the first few bytes of each candidate in IDA, pick the non-constructor, and add an `exclude_signatures` entry. Use a platform conditional if the ambiguity only appears on one platform.

### Example: Virtual function via xref_funcs (Pattern B, static FUNC_XREFS)

**User says:** Find `CCSPlayerController_Connect` in server. It's a vfunc of `CCSPlayerController`. It calls `CPlayerCommandQueue_ctor` internally, so use `xref_funcs: ["CPlayerCommandQueue_ctor"]`.

**Result:** `ida_preprocessor_scripts/find-CCSPlayerController_Connect.py` with:
- Static `FUNC_XREFS` -- no dynamic building needed, function name is known at write time
- `xref_funcs: ["CPlayerCommandQueue_ctor"]`
- `FUNC_VTABLE_RELATIONS`: `("CCSPlayerController_Connect", "CCSPlayerController")`
- `GENERATE_YAML_DESIRED_FIELDS` with `func_name, func_sig, func_va, func_rva, func_size, vtable_name, vfunc_offset, vfunc_index`

**config.yaml:**
```yaml
      - name: find-CCSPlayerController_Connect
        expected_output:
          - CCSPlayerController_Connect.{platform}.yaml
        expected_input:
          - CPlayerCommandQueue_ctor.{platform}.yaml
          - CCSPlayerController_vtable.{platform}.yaml
```

**Key insight -- `expected_input` for `xref_funcs`:** The `xref_funcs` lookup resolves the callee by its IDA name. The callee is only renamed when its output YAML is written. Always list the callee's YAML in `expected_input` to guarantee it runs (and gets renamed in IDA) before this script executes. Without this ordering, the name lookup silently finds nothing and the skill fails.
