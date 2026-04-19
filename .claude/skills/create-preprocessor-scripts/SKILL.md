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
| **Predecessor function** | Function to decompile for LLM_DECOMPILE patterns | `CBaseEntity_TakeDamageOld` |
| **VTable class** | Class owning the vtable (for vfuncs) | `CBasePlayerPawn` |
| **Desired YAML fields** | Which fields the output YAML needs | `func_name, func_sig, func_va, func_rva, func_size` |
| **Dependencies** | Input YAMLs this skill depends on | `CCSPlayer_MovementServices_vtable.{platform}.yaml` |
| **Aliases** | Alternative names for the symbol | `CPlayer_MovementServices::PlayWaterStepSound` |

## Overview

Nine preprocessor patterns exist. The discovery method and target type determine which to use:

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

Additionally, **struct member offsets** can be mixed into any pattern as a secondary target (see "Struct Member Mixin" section below).

---

## Step 1: Determine the Pattern

From the user's input, determine:

1. **Is the target a function, vfunc, or struct member offset?**
   - Has `xref_strings` + category `func` -> **Pattern A**
   - Has `xref_strings` + category `vfunc` -> **Pattern B**
   - Has predecessor function + category `vfunc` -> **Pattern C**
   - Has predecessor function + category `func` -> **Pattern D**
   - Has predecessor function + category `structmember` -> **Pattern E**
   - Has base vfunc name + category `vfunc` (derived-class override of known base vfunc) -> **Pattern F**
     - If the target is an **abstract/interface vfunc** (no real function body, only `vfunc_offset`/`vfunc_index` needed) → use **Pattern F slot-only**: `generate_func_sig=False`, desired fields = `{func_name, vtable_name, vfunc_offset, vfunc_index}`, NO vtable YAML required for the interface class
   - Has `COMMAND_NAME` + `HELP_STRING` (ConCommand handler callback) -> **Pattern G**
   - Has mangled vtable symbol / offset-to-top + category `vtable` (secondary vtable for a class) -> **Pattern H**
   - Target is an **interface vfunc offset** with no feasible `func_sig`/`vfunc_sig`, and the offset can be read from a concrete-class thunk's `jmp [reg+disp]` instruction -> **Pattern I**

2. **Do xref strings differ between Windows and Linux?** If yes, use platform-specific `FUNC_XREFS_WINDOWS` / `FUNC_XREFS_LINUX` variant.

3. **Are there multiple functions?** If they share the same discovery method and starting point, put them in the same script with `-AND-` in the name. Otherwise, split into separate scripts.

**CRITICAL — LLM_DECOMPILE dependency chains:** When LLM_DECOMPILE targets form a chain (FuncA → FuncB → FuncC, where each is the predecessor of the next), they **MUST** be in separate scripts — one script per link in the chain. A single script CANNOT handle chained LLM_DECOMPILE predecessors because the LLM_DECOMPILE fallback resolves the predecessor's address from its output YAML (`func_va` field), and within a single script run the predecessor's output YAML doesn't exist yet. The IDA name-lookup fallback also fails because the predecessor wasn't renamed yet.

---

## Step 2: Create the Preprocessor Script

Script location: `ida_preprocessor_scripts/find-{skill_name}.py`

The filename MUST match the `name` field in `config.yaml` skill entry.

### Pattern A -- Regular function via xref strings

Use when: function is non-virtual, discovered via debug string cross-references.

```python
#!/usr/bin/env python3
"""Preprocess script for find-{SKILL_NAME} skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "{FUNC_NAME}",
]

FUNC_XREFS = [
    {
        "func_name": "{FUNC_NAME}",
        "xref_strings": [
            "{XREF_STRING_1}",  # Debug string from user input
        ],
        "xref_gvs": [],          # global variable names if needed, usually empty
        "xref_signatures": [],    # byte patterns if needed, usually empty
        "xref_funcs": [],         # known caller function names if needed
        "exclude_funcs": [],      # function names to exclude from results
        "exclude_strings": [],    # strings to exclude
        "exclude_gvs": [],        # global variable names to exclude
        "exclude_signatures": [], # byte patterns to exclude
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "{FUNC_NAME}",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
```

### Pattern B -- Virtual function via xref strings

Same as Pattern A, but adds `FUNC_VTABLE_RELATIONS` and vtable fields to `GENERATE_YAML_DESIRED_FIELDS`:

```python
#!/usr/bin/env python3
"""Preprocess script for find-{SKILL_NAME} skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "{FUNC_NAME}",
]

FUNC_XREFS = [
    {
        "func_name": "{FUNC_NAME}",
        "xref_strings": [
            "{XREF_STRING_1}",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("{FUNC_NAME}", "{VTABLE_CLASS}"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "{FUNC_NAME}",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
```

### Platform-Specific Xref Strings (Patterns A & B variant)

When xref strings differ between Windows and Linux, split into two variables:

```python
FUNC_XREFS_WINDOWS = [
    {
        "func_name": "{FUNC_NAME}",
        "xref_strings": [
            "CSource2GameEntities::CheckTransmit",  # Full assertion string on Windows
        ],
        "xref_gvs": [], "xref_signatures": [], "xref_funcs": [],
        "exclude_funcs": [], "exclude_strings": [], "exclude_gvs": [], "exclude_signatures": [],
    },
]

FUNC_XREFS_LINUX = [
    {
        "func_name": "{FUNC_NAME}",
        "xref_strings": [
            "./gameinterface.cpp:30",  # Shorter path-based string on Linux
        ],
        "xref_gvs": [], "xref_signatures": [], "xref_funcs": [],
        "exclude_funcs": [], "exclude_strings": [], "exclude_gvs": [], "exclude_signatures": [],
    },
]
```

Then in `preprocess_skill`, use a ternary to select the right one:

```python
        func_xrefs=FUNC_XREFS_WINDOWS if platform == "windows" else FUNC_XREFS_LINUX,
```

### Pattern C -- Virtual function via LLM_DECOMPILE

Use when: function IS virtual (has vtable slot), discovered by decompiling a known predecessor function.

**IMPORTANT — `func_va` in output YAMLs:** If this function will be used as a **predecessor** by a downstream LLM_DECOMPILE script (i.e., another script decompiles this function to find further targets), you **MUST** include `func_va`, `func_rva`, and `func_size` in `GENERATE_YAML_DESIRED_FIELDS`. The downstream script resolves the predecessor's address by reading `func_va` from the output YAML. Without it, the LLM_DECOMPILE fallback fails with "failed to resolve llm_decompile target function address". When in doubt, always include `func_va` — it never hurts.

```python
#!/usr/bin/env python3
"""Preprocess script for find-{SKILL_NAME} skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "{FUNC_NAME_1}",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "{FUNC_NAME_1}",
        "prompt/call_llm_decompile.md",
        "references/{MODULE}/{PREDECESSOR_FUNC}.{platform}.yaml",
    ),
]

FUNC_VTABLE_RELATIONS = [
    # (func_name, vtable_class)
    ("{FUNC_NAME_1}", "{VTABLE_CLASS}"),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # Include func_va/func_rva/func_size if this function is a predecessor for downstream LLM_DECOMPILE
    (
        "{FUNC_NAME_1}",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "vfunc_sig",
            "vfunc_offset",
            "vfunc_index",
            "vtable_name",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):

    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_vtable_relations=FUNC_VTABLE_RELATIONS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
```

### Pattern D -- Regular function via LLM_DECOMPILE

Use when: function is NOT virtual, discovered by decompiling a known predecessor function.

```python
#!/usr/bin/env python3
"""Preprocess script for find-{SKILL_NAME} skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "{FUNC_NAME}",
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "{FUNC_NAME}",
        "prompt/call_llm_decompile.md",
        "references/{MODULE}/{PREDECESSOR_FUNC}.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "{FUNC_NAME}",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever func_sig to locate target function(s) and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
```

### Pattern E -- Struct member offset via LLM_DECOMPILE

Use when: target is a **struct member offset** (not a function), discovered by decompiling a known predecessor function.

```python
#!/usr/bin/env python3
"""Preprocess script for find-{SKILL_NAME} skill."""

from ida_analyze_util import preprocess_common_skill

TARGET_STRUCT_MEMBER_NAMES = [
    "{STRUCT_MEMBER_NAME}",  # e.g. "CCheckTransmitInfo_m_nPlayerSlot"
]

LLM_DECOMPILE = [
    # (symbol_name, path_to_prompt, path_to_reference)
    (
        "{STRUCT_MEMBER_NAME}",
        "prompt/call_llm_decompile.md",
        "references/{MODULE}/{PREDECESSOR_FUNC}.{platform}.yaml",
    ),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "{STRUCT_MEMBER_NAME}",
        [
            "struct_name",
            "member_name",
            "offset",
            "size",
            "offset_sig",
            "offset_sig_disp",
        ],
    ),
]

async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
    """Reuse previous gamever offset_sig to locate target struct offset and write YAML."""
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
```

**Key differences from Pattern D:**
- Uses `TARGET_STRUCT_MEMBER_NAMES` instead of `TARGET_FUNCTION_NAMES`
- Passes `struct_member_names=` instead of `func_names=` to `preprocess_common_skill`
- YAML fields are struct-specific: `struct_name, member_name, offset, size, offset_sig, offset_sig_disp`
- No `FUNC_VTABLE_RELATIONS`
- config.yaml symbol category is `structmember` (not `func` or `vfunc`)

### Pattern F -- Virtual function via INHERIT_VFUNCS

Use when: the target is a **derived-class override** of a known base-class virtual function. The base vfunc has already been found (by another script), and this script inherits its vtable slot index to look up the same slot in the derived class's vtable.

This is the simplest pattern -- no xref strings, no LLM decompilation needed. Just a vtable slot lookup.

```python
#!/usr/bin/env python3
"""Preprocess script for find-{SKILL_NAME} skill."""

from ida_analyze_util import preprocess_common_skill

INHERIT_VFUNCS = [
    # (target_func_name, inherit_vtable_class, base_vfunc_name, generate_func_sig)
    ("{DERIVED_FUNC_NAME}", "{DERIVED_VTABLE_CLASS}", "{BASE_VFUNC_NAME}", True),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    (
        "{DERIVED_FUNC_NAME}",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
        ],
    ),
]

async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    """Reuse old func_sig first; fallback to vtable index + generated signature when needed."""
    _ = skill_name

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=INHERIT_VFUNCS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
```

**INHERIT_VFUNCS tuple fields:**
- `target_func_name` -- name for the derived-class function (e.g. `"CBaseEntity_Precache"`)
- `inherit_vtable_class` -- class whose vtable to look up (e.g. `"CBaseEntity"`); for slot-only mode this is used only as metadata in the output YAML
- `base_vfunc_name` -- YAML artifact stem of the base-class vfunc that defines the slot index (e.g. `"CEntityInstance_Precache"`). Can be cross-module: `"../engine/INetworkMessages_FindNetworkGroup"`
- `generate_func_sig` -- (optional, default True) whether to generate a func_sig if no old YAML exists; set to `False` for slot-only mode

**Key differences from other patterns:**
- No `TARGET_FUNCTION_NAMES`, `FUNC_XREFS`, `LLM_DECOMPILE`, or `FUNC_VTABLE_RELATIONS`
- Uses `inherit_vfuncs=` parameter instead of `func_names=`
- No `llm_config` parameter in `preprocess_skill`
- Standard mode: config.yaml `expected_input` must include both the base vfunc YAML and the derived class vtable YAML
- Slot-only mode: config.yaml `expected_input` needs ONLY the base vfunc YAML — no vtable YAML for the interface class
- config.yaml symbol category is `vfunc`

#### Pattern F (slot-only variant) -- Abstract/interface vfunc slot index only

Use when: the target is a **pure interface or abstract-class vfunc** (e.g. `ILoopMode::LoopInit`) where:
- No real function body exists (pure virtual), so `func_va`, `func_sig` are not applicable
- Only `vfunc_offset` and `vfunc_index` are needed to identify the vtable slot
- A concrete-class implementation that overrides this slot is already found by another script

The engine automatically activates **slot-only mode** when both conditions are true:
1. `generate_func_sig=False` (4th INHERIT_VFUNCS tuple element)
2. `GENERATE_YAML_DESIRED_FIELDS` contains **exactly** `{func_name, vtable_name, vfunc_offset, vfunc_index}` — nothing more, nothing less

In slot-only mode the engine reads `vfunc_index` directly from the base vfunc's YAML and returns early, **skipping the vtable lookup entirely**. No `{INTERFACE_CLASS}_vtable.{platform}.yaml` needs to exist.

```python
#!/usr/bin/env python3
"""Preprocess script for find-{SKILL_NAME} skill."""

from ida_analyze_util import preprocess_common_skill

INHERIT_VFUNCS = [
    # (target_func_name, inherit_vtable_class, base_vfunc_name, generate_func_sig)
    ("{INTERFACE_FUNC_NAME}", "{INTERFACE_CLASS}", "{CONCRETE_IMPL_FUNC_NAME}", False),
]

GENERATE_YAML_DESIRED_FIELDS = [
    # (symbol_name, generate_yaml_fields)
    # IMPORTANT: must be exactly these four fields to trigger slot-only mode
    (
        "{INTERFACE_FUNC_NAME}",
        [
            "func_name",
            "vtable_name",
            "vfunc_offset",
            "vfunc_index",
        ],
    ),
]

async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    """Reuse old vfunc slot; fallback to inheriting slot index from {CONCRETE_IMPL_FUNC_NAME}."""
    _ = skill_name

    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=INHERIT_VFUNCS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
```

**Output YAML (both platforms):**
```yaml
func_name: ILoopMode_LoopInit
vtable_name: ILoopMode
vfunc_offset: '0x28'
vfunc_index: 5
```

**Slot-only vs standard Pattern F — when to use which:**
- **Standard** (`generate_func_sig=True`, full field set): target is a concrete derived class that has a real function body — you want `func_va`, `func_sig`, etc.
- **Slot-only** (`generate_func_sig=False`, four-field set): target is an abstract/interface method — you only need the vtable slot position, no implementation address

### Pattern G -- ConCommand handler function

Use when: the target is a **ConCommand handler callback** identified by matching the command name string and/or help string in the binary. The `_registerconcommand.py` helper scans for exact string matches, finds xrefs to those strings, locates nearby `RegisterConCommand` calls, and recovers the handler function pointer from the call arguments.

```python
#!/usr/bin/env python3
"""Preprocess script for find-{SKILL_NAME} skill."""

from ida_preprocessor_scripts._registerconcommand import (
    preprocess_registerconcommand_skill,
)


TARGET_FUNCTION_NAMES = [
    "{HANDLER_NAME}",
]

COMMAND_NAME = "{command_name}"
HELP_STRING = (
    "{help_string_part1}"
    "{help_string_part2}"  # Split long strings across lines for readability
)
SEARCH_WINDOW_BEFORE_CALL = 96
SEARCH_WINDOW_AFTER_XREF = 96

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "{HANDLER_NAME}",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
]


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    _ = skill_name, old_yaml_map
    return await preprocess_registerconcommand_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        target_name=TARGET_FUNCTION_NAMES[0],
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        command_name=COMMAND_NAME,
        help_string=HELP_STRING,
        rename_to=TARGET_FUNCTION_NAMES[0],
        search_window_before_call=SEARCH_WINDOW_BEFORE_CALL,
        search_window_after_xref=SEARCH_WINDOW_AFTER_XREF,
        debug=debug,
    )
```

**Key differences from Pattern A:**
- Imports `preprocess_registerconcommand_skill` from `ida_preprocessor_scripts._registerconcommand` instead of `preprocess_common_skill` from `ida_analyze_util`
- Uses `COMMAND_NAME` and `HELP_STRING` variables instead of `FUNC_XREFS`
- Uses `SEARCH_WINDOW_BEFORE_CALL` and `SEARCH_WINDOW_AFTER_XREF` (typically 96 bytes each) to control the scan window around xrefs
- The `preprocess_skill` function ignores `old_yaml_map` (`_ = skill_name, old_yaml_map`)
- Calls `preprocess_registerconcommand_skill()` with `command_name=`, `help_string=`, `rename_to=` instead of `func_xrefs=`
- config.yaml category is `func`, no `expected_input` needed
- The handler function is always a regular function (not virtual), so no `FUNC_VTABLE_RELATIONS`

### Pattern H -- Secondary (ordinal) vtable

Use when: the target is a **secondary vtable** (`_vtable2`) for a class that has multiple inheritance. Located via the mangled symbol name on Windows (e.g. `??_7ClassName@@6B@_0`) and via matching `offset-to-top` on Linux.

This pattern does NOT use `preprocess_common_skill`. It uses the `_ordinal_vtable_common` helper instead.

**User inputs for Pattern H:**
- **Class name** -- e.g. `CLoopTypeClientServerService`
- **Windows mangled symbol** -- e.g. `??_7CLoopTypeClientServerService@@6B@_0` (the `@_0` suffix distinguishes the secondary vtable)
- **Linux offset-to-top** -- e.g. `-56` (a negative decimal value from `dq -NN ; offset to this` in the vtable layout)

```python
#!/usr/bin/env python3
"""Preprocess script for find-{CLASS_NAME}_vtable2 skill."""

from pathlib import Path

from ida_analyze_util import write_vtable_yaml
from ida_preprocessor_scripts._ordinal_vtable_common import (
    preprocess_ordinal_vtable_via_mcp,
)


TARGET_CLASS_NAME = "{CLASS_NAME}"
TARGET_OUTPUT_STEM = "{CLASS_NAME}_vtable2"
WINDOWS_SYMBOL_ALIASES = ["??_7{CLASS_NAME}@@6B@_0"]
LINUX_EXPECTED_OFFSET_TO_TOP = {OFFSET_TO_TOP}  # negative decimal, e.g. -8, -56


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    _ = skill_name, old_yaml_map, new_binary_dir

    expected_filename = f"{TARGET_OUTPUT_STEM}.{platform}.yaml"
    matching_outputs = [
        output_path
        for output_path in expected_outputs
        if Path(output_path).name == expected_filename
    ]
    if len(matching_outputs) != 1:
        return False

    if platform == "windows":
        symbol_aliases = WINDOWS_SYMBOL_ALIASES
        expected_offset_to_top = None
    elif platform == "linux":
        symbol_aliases = None
        expected_offset_to_top = LINUX_EXPECTED_OFFSET_TO_TOP
    else:
        return False

    result = await preprocess_ordinal_vtable_via_mcp(
        session=session,
        class_name=TARGET_CLASS_NAME,
        ordinal=0,
        image_base=image_base,
        platform=platform,
        debug=debug,
        symbol_aliases=symbol_aliases,
        expected_offset_to_top=expected_offset_to_top,
    )
    if not result:
        return False

    write_vtable_yaml(matching_outputs[0], result)
    return True
```

**Key differences from all other patterns:**
- Does NOT use `preprocess_common_skill` -- uses `preprocess_ordinal_vtable_via_mcp` from `_ordinal_vtable_common` plus `write_vtable_yaml` from `ida_analyze_util`
- No `TARGET_FUNCTION_NAMES`, `FUNC_XREFS`, `LLM_DECOMPILE`, `FUNC_VTABLE_RELATIONS`, or `INHERIT_VFUNCS`
- config.yaml category is `vtable`, no `expected_input` needed
- Output stem is `{CLASS_NAME}_vtable2`, config.yaml symbol name matches
- Windows uses `WINDOWS_SYMBOL_ALIASES` (mangled name with `@_0` suffix)
- Linux uses `LINUX_EXPECTED_OFFSET_TO_TOP` (negative decimal offset-to-top value)
- The `ordinal=0` parameter selects the first secondary vtable (use `ordinal=1` for a third vtable, etc.)
- The `expected_filename` variable in the f-string uses the curly-brace trick: define `TARGET_OUTPUT_STEM` as a plain string, then build the filename with `f"{TARGET_OUTPUT_STEM}.{platform}.yaml"`

### Pattern I -- Interface vfunc offset via thunk instruction walk

Use when: the target is a **pure interface vfunc** (e.g. `ILoopMode::HandleInputEvent`) where:
- No unique `func_sig` or `vfunc_sig` is feasible (the function is just a generic `jmp [reg+disp]` thunk, too short to sign uniquely)
- A concrete-class thunk function that wraps the interface call is already found (via its output YAML)
- That thunk body ends with exactly `jmp [reg+disp]` and the displacement IS the vtable offset

The script reads the thunk's `func_va` from its YAML, uses `py_eval` + `idaapi.decode_insn` to walk the function body, finds the first `jmp` instruction with an `o_displ` operand, and records the displacement as `vfunc_offset`.

**User inputs for Pattern I:**
- **Interface name** -- e.g. `ILoopMode`
- **Target vfunc name** -- e.g. `ILoopMode_HandleInputEvent`
- **Thunk function name** (predecessor) -- e.g. `CLoopTypeClientServerService_HandleInputEvent` (a concrete-class wrapper that does `jmp [reg+disp]`)
- **Module** -- where the thunk lives (e.g. `engine`)

```python
#!/usr/bin/env python3
"""Preprocess script for find-{TARGET_FUNC_NAME} skill.

Resolves {INTERFACE_CLASS}::{METHOD_NAME} vfunc_offset by walking instructions
inside {THUNK_FUNC_NAME} (a thin thunk) and reading the displacement byte of
the first 'jmp [reg+disp]' encountered. No LLM decompile required.
"""

import json
import os

try:
    import yaml
except ImportError:
    yaml = None

from ida_analyze_util import parse_mcp_result, write_func_yaml

PREDECESSOR_STEM = "{THUNK_FUNC_NAME}"
TARGET_FUNC_NAME = "{TARGET_FUNC_NAME}"
VTABLE_CLASS = "{INTERFACE_CLASS}"

_PY_EVAL_TEMPLATE = r"""
import idaapi, json

func_va = FUNC_VA_PLACEHOLDER

insn = idaapi.insn_t()
func = idaapi.get_func(func_va)
if func is None:
    result = json.dumps({"error": "function not found at " + hex(func_va)})
else:
    vfunc_offset = None
    ea = func.start_ea
    while ea < func.end_ea:
        length = idaapi.decode_insn(insn, ea)
        if length == 0:
            break
        mnem = insn.get_canon_mnem()
        if mnem == "jmp":
            op = insn.Op1
            # o_displ = displaced memory operand, e.g. [rax+28h]
            if op.type == idaapi.o_displ:
                vfunc_offset = int(op.addr) & 0xFFFF_FFFF
                break
        ea += length
    if vfunc_offset is not None:
        result = json.dumps({"vfunc_offset": vfunc_offset})
    else:
        result = json.dumps({"error": "no jmp+disp instruction found in function"})
"""


def _read_func_va(yaml_path):
    """Return func_va as int from a function YAML, or None on failure."""
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            va = data.get("func_va")
            if va is not None:
                return int(str(va), 0)
    except Exception:
        pass
    return None


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    """Walk {THUNK_FUNC_NAME} instructions to extract {INTERFACE_CLASS} vfunc_offset."""
    _ = skill_name

    if yaml is None:
        if debug:
            print("    Preprocess: PyYAML is required")
        return False

    # Determine expected output path
    expected_filename = f"{TARGET_FUNC_NAME}.{'{'}platform{'}'}.yaml"
    matching_outputs = [p for p in expected_outputs if os.path.basename(p) == expected_filename]
    if len(matching_outputs) != 1:
        if debug:
            print(f"    Preprocess: expected exactly one output for {expected_filename}, got {matching_outputs}")
        return False
    output_path = matching_outputs[0]

    # Reuse previous gamever result if available
    if TARGET_FUNC_NAME in old_yaml_map:
        old_data = old_yaml_map[TARGET_FUNC_NAME]
        vfunc_offset_raw = old_data.get("vfunc_offset")
        if vfunc_offset_raw is not None:
            try:
                vfunc_offset = int(str(vfunc_offset_raw), 0)
                if debug:
                    print(f"    Preprocess: reusing old vfunc_offset={hex(vfunc_offset)} for {TARGET_FUNC_NAME}")
                write_func_yaml(output_path, {
                    "func_name": TARGET_FUNC_NAME,
                    "vtable_name": VTABLE_CLASS,
                    "vfunc_offset": hex(vfunc_offset),
                    "vfunc_index": vfunc_offset // 8,
                })
                return True
            except (ValueError, TypeError):
                pass

    # Read thunk func_va from its output YAML
    predecessor_yaml = os.path.join(new_binary_dir, f"{PREDECESSOR_STEM}.{'{'}platform{'}'}.yaml")
    func_va = _read_func_va(predecessor_yaml)
    if func_va is None:
        if debug:
            print(f"    Preprocess: failed to read func_va from {predecessor_yaml}")
        return False

    if debug:
        print(f"    Preprocess: walking instructions at {hex(func_va)} to find jmp displacement")

    # Walk instructions via IDA to find the first jmp [reg+disp]
    py_code = _PY_EVAL_TEMPLATE.replace("FUNC_VA_PLACEHOLDER", str(func_va))
    try:
        raw = await session.call_tool("py_eval", {"code": py_code})
        result_data = parse_mcp_result(raw)
    except Exception as exc:
        if debug:
            print(f"    Preprocess: py_eval error: {exc}")
        return False

    result_str = None
    if isinstance(result_data, dict):
        if debug:
            stderr = result_data.get("stderr", "")
            if stderr:
                print(f"    Preprocess py_eval stderr: {stderr.strip()}")
        result_str = result_data.get("result", "")
    if not result_str:
        if debug:
            print("    Preprocess: empty py_eval result")
        return False

    try:
        payload = json.loads(result_str)
    except (json.JSONDecodeError, TypeError) as exc:
        if debug:
            print(f"    Preprocess: JSON parse error: {exc} — raw: {result_str[:200]}")
        return False

    if "error" in payload:
        if debug:
            print(f"    Preprocess: py_eval reported error: {payload['error']}")
        return False

    vfunc_offset = payload.get("vfunc_offset")
    if vfunc_offset is None:
        if debug:
            print("    Preprocess: vfunc_offset missing from py_eval result")
        return False

    vfunc_offset = int(vfunc_offset)
    vfunc_index = vfunc_offset // 8

    if debug:
        print(f"    Preprocess: resolved vfunc_offset={hex(vfunc_offset)} vfunc_index={vfunc_index}")

    write_func_yaml(output_path, {
        "func_name": TARGET_FUNC_NAME,
        "vtable_name": VTABLE_CLASS,
        "vfunc_offset": hex(vfunc_offset),
        "vfunc_index": vfunc_index,
    })
    return True
```

**Key differences from all other patterns:**
- Does NOT use `preprocess_common_skill` — uses `py_eval` + `parse_mcp_result` + `write_func_yaml` directly
- No `TARGET_FUNCTION_NAMES`, `FUNC_XREFS`, `LLM_DECOMPILE`, `FUNC_VTABLE_RELATIONS`, or `INHERIT_VFUNCS`
- Imports: `json`, `os`, `yaml`, `parse_mcp_result` and `write_func_yaml` from `ida_analyze_util`
- Output fields: only `func_name`, `vtable_name`, `vfunc_offset`, `vfunc_index` — no `func_va`, `func_sig`, or `vfunc_sig`
- Has a "reuse previous gamever" fast path that reads `vfunc_offset` from `old_yaml_map` before falling back to the instruction walk
- The `_PY_EVAL_TEMPLATE` uses a raw string (`r"""..."""`) to avoid f-string issues; `FUNC_VA_PLACEHOLDER` is replaced at runtime via `.replace()`
- `op.addr` is masked with `& 0xFFFF_FFFF` to strip any sign-extension artifacts from IDA's 64-bit representation
- config.yaml category is `vfunc`; `expected_input` is the thunk function's YAML (NOT `expected_input` for any vtable)
- No `llm_config` parameter in `preprocess_skill`

**When NOT to use Pattern I:**
- If a unique `func_sig` is feasible for the concrete thunk → use Pattern B (`xref_signatures` on the thunk body bytes, combined with `FUNC_VTABLE_RELATIONS`)
- If the interface vfunc has a real function body (not just a thunk) → use Pattern B or C
- If the offset is in a `call [reg+disp]` rather than `jmp [reg+disp]` → the same template works, but change `mnem == "jmp"` to `mnem == "call"`

### FULLMATCH: Prefix for Xref Strings (Patterns A & B)

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

### Struct Member Mixin (for any pattern)

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

### CRITICAL -- FUNC_VTABLE_RELATIONS and vfunc fields

**`FUNC_VTABLE_RELATIONS` is required for ANY target whose `GENERATE_YAML_DESIRED_FIELDS` includes `vtable_name` or `vfunc_sig`** -- not just Pattern B and C. Without it, the LLM_DECOMPILE slot-only fallback fails with `"slot-only fallback missing vtable_name"` and the entire skill fails.

This applies even when:
- The target is a **vfunc call-site offset** (e.g. `call [rax+128h]`) rather than an actual function body in a vtable
- **No vtable YAML exists** for that class in config.yaml (no `expected_input` for the vtable needed)
- The script also finds **non-vfunc targets** (global variables, struct offsets) alongside the vfunc target

The `vtable_name` from `FUNC_VTABLE_RELATIONS` is used as **metadata** written to the output YAML -- it does NOT require an actual vtable lookup. For example, `("IGameTypes_CreateWorkshopMapGroup", "IGameTypes")` provides the vtable class name `IGameTypes` even though no `IGameTypes_vtable.{platform}.yaml` exists.

**Rule of thumb:** If any field in `GENERATE_YAML_DESIRED_FIELDS` starts with `vfunc_` or equals `vtable_name`, the target MUST have an entry in `FUNC_VTABLE_RELATIONS`.

### Key Differences Between Patterns

| Aspect | Pattern A (func + xref) | Pattern B (vfunc + xref) | Pattern C (vfunc + LLM) | Pattern D (func + LLM) | Pattern E (structmember + LLM) | Pattern F (vfunc + inherit) | Pattern G (ConCommand handler) | Pattern H (ordinal vtable) | Pattern I (iface vfunc thunk walk) |
|--------|------------------------|--------------------------|------------------------|------------------------|-------------------------------|---------------------------|-------------------------------|---------------------------|-----------------------------------|
| FUNC_XREFS | Yes | Yes | No | No | No | No | No (uses COMMAND_NAME/HELP_STRING) | No | No |
| FUNC_VTABLE_RELATIONS | No | Yes | Yes | No | No | No | No | No | No |
| INHERIT_VFUNCS | No | No | No | No | No | Yes | No | No | No |
| LLM_DECOMPILE | No | No | Yes | Yes | Yes | No | No | No | No |
| `llm_config` param | No | No | Yes | Yes | Yes | No | No | No | No |
| Helper module | `preprocess_common_skill` | `preprocess_common_skill` | `preprocess_common_skill` | `preprocess_common_skill` | `preprocess_common_skill` | `preprocess_common_skill` | `preprocess_registerconcommand_skill` | `preprocess_ordinal_vtable_via_mcp` | `py_eval` + `write_func_yaml` (custom) |
| Target list | `TARGET_FUNCTION_NAMES` | `TARGET_FUNCTION_NAMES` | `TARGET_FUNCTION_NAMES` | `TARGET_FUNCTION_NAMES` | `TARGET_STRUCT_MEMBER_NAMES` | (none -- defined in INHERIT_VFUNCS) | `TARGET_FUNCTION_NAMES` | `TARGET_CLASS_NAME` (single string) | `TARGET_FUNC_NAME` + `PREDECESSOR_STEM` (module-level constants) |
| preprocess param | `func_names=` | `func_names=` | `func_names=` | `func_names=` | `struct_member_names=` | `inherit_vfuncs=` | `command_name=`, `help_string=` | `class_name=`, `ordinal=` | (custom: reads YAML, calls `py_eval`) |
| YAML fields | func_name, func_sig, func_va, func_rva, func_size | Same + vtable_name, vfunc_offset, vfunc_index | func_name, func_va, func_rva, func_size, vfunc_sig, vfunc_offset, vfunc_index, vtable_name | func_name, func_sig, func_va, func_rva, func_size | struct_name, member_name, offset, size, offset_sig, offset_sig_disp | Standard: func_name, func_va, func_rva, func_size, func_sig, vtable_name, vfunc_offset, vfunc_index; Slot-only: func_name, vtable_name, vfunc_offset, vfunc_index | func_name, func_sig, func_va, func_rva, func_size | (vtable YAML via write_vtable_yaml) | func_name, vtable_name, vfunc_offset, vfunc_index |
| config category | `func` | `vfunc` | `vfunc` | `func` | `structmember` | `vfunc` | `func` | `vtable` | `vfunc` |

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
- Pattern F (slot-only): needs ONLY the base vfunc YAML in `expected_input` — no vtable YAML for the interface class
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
# Windows — always pass -platform windows explicitly
uv run generate_reference_yaml.py -func_name {PREDECESSOR_FUNC} -auto_start_mcp -binary "bin/{gamever}/{module}/{binary_name}.dll" -platform windows -debug

# Linux — always pass -platform linux explicitly
uv run generate_reference_yaml.py -func_name {PREDECESSOR_FUNC} -auto_start_mcp -binary "bin/{gamever}/{module}/lib{module}.so" -platform linux -debug
```

where `{gamever}` can be obtained from `.env` -> `CS2VIBE_GAMEVER`.

**IMPORTANT — Always pass `-platform` explicitly.** While `-platform` can theoretically be inferred from the binary extension (`.dll` → windows, `.so` → linux), auto-inference is unreliable and may produce the wrong platform's reference YAML. Always pass `-platform windows` or `-platform linux` explicitly.

**IMPORTANT — Run `generate_reference_yaml.py` sequentially, NOT in parallel.** All invocations share the same IDA MCP connection. Running them in parallel will cause connection conflicts and failures. Run one command at a time, waiting for each to complete before starting the next.

YOU MUST: rename known symbols / add necessary comments in the generated reference YAMLs so the LLM can find desired symbols by comparing reference ones with raw procedure/disassembly read from new binaries. See the `convert-finder-skill-to-preprocessor-scripts` SKILL.md Step 5 for detailed annotation examples.

**IMPORTANT — When the predecessor is a NEW function (no existing output YAMLs):** If the predecessor function is brand new (discovered by another new script you're creating at the same time), its output YAMLs don't exist yet and `generate_reference_yaml.py` cannot resolve its address. You must use a **multi-phase workflow**:

1. **Phase 1:** Create ALL scripts (vtable, xref_string, LLM_DECOMPILE) and update config.yaml
2. **Phase 2:** Run `uv run ida_analyze_bin.py -debug` — the vtable and xref_string scripts will succeed and populate the NEW predecessor's output YAMLs. The LLM_DECOMPILE script will fail (no reference YAML yet) or be skipped.
3. **Phase 3:** Now that the predecessor has output YAMLs, run `generate_reference_yaml.py` to create reference YAMLs, then annotate them.
4. **Phase 4:** Run `uv run ida_analyze_bin.py -debug` again — this time the LLM_DECOMPILE path runs and the full pipeline is validated.

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

**IMPORTANT — Never commit directly to the `main` branch.** If the current branch is `main`, create and switch to a `dev` branch first:

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
- [ ] `TARGET_FUNCTION_NAMES` lists all functions the script should find
- [ ] `FUNC_XREFS` xref strings match the user's specified debug strings (Pattern A/B)
- [ ] `LLM_DECOMPILE` reference path points to the correct predecessor function YAML (Patterns C/D/E)
- [ ] `FUNC_VTABLE_RELATIONS` lists correct vtable class for EVERY target that has `vtable_name` or `vfunc_sig` in its `GENERATE_YAML_DESIRED_FIELDS` -- required even for vfunc call-site offsets and even if no vtable YAML exists (Patterns B/C, and any LLM_DECOMPILE target with vfunc fields)
- [ ] `INHERIT_VFUNCS` lists correct (target, inherit_class, base_vfunc, gen_sig) tuples (Pattern F only)
- [ ] For Pattern F slot-only: `generate_func_sig=False` AND desired fields are exactly `{func_name, vtable_name, vfunc_offset, vfunc_index}` — adding any extra field (e.g. `func_va`) will silently exit slot-only mode and require a vtable YAML
- [ ] `GENERATE_YAML_DESIRED_FIELDS` uses correct field set for the pattern
- [ ] `preprocess_skill` signature includes `llm_config=None` if and only if LLM_DECOMPILE is used (NOT for Pattern F)
- [ ] `preprocess_common_skill` call passes all relevant lists (`func_xrefs`, `func_vtable_relations`, `llm_decompile_specs`, `llm_config`, `inherit_vfuncs`)
- [ ] config.yaml `expected_output` has one entry per target function
- [ ] config.yaml `expected_input` correctly chains dependencies
- [ ] config.yaml `symbols` section has entries for all target functions (no duplicates)
- [ ] Reference YAMLs exist or generated (Patterns C/D/E)
- [ ] For Pattern I: `PREDECESSOR_STEM` matches the thunk function's YAML stem; `_PY_EVAL_TEMPLATE` checks `mnem == "jmp"` (or `"call"` if appropriate) and `op.type == idaapi.o_displ`; `write_func_yaml` called with `func_name`, `vtable_name`, `vfunc_offset` (hex string), `vfunc_index` (int)
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

**Result — three scripts:**

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

**Key insight — multi-phase workflow required:** `CSource2GameClients_StartHLTVServer` was a brand-new function with no existing output YAMLs. `generate_reference_yaml.py` needs `func_va` from the predecessor's output YAML to locate it in IDA. So the workflow was:
1. Create all 3 scripts + config entries
2. Run `ida_analyze_bin.py -debug` → vtable + xref scripts succeed and create StartHLTVServer YAMLs
3. Run `generate_reference_yaml.py` using the newly created output YAMLs
4. Annotate reference YAMLs
5. Run `ida_analyze_bin.py -debug` again → LLM_DECOMPILE path runs and succeeds

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

**Result — two scripts:**

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
2. Run `ida_analyze_bin.py -debug` → Pattern G script succeeds, creates BotKill_CommandHandler YAMLs
3. Run `generate_reference_yaml.py` for both platforms
4. Annotate reference YAMLs with CommitSuicide vfunc call comments
5. Run `ida_analyze_bin.py -debug` again → LLM_DECOMPILE path runs and succeeds

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
No unique `func_sig` is feasible for the thunk (2–3 generic instructions). `func_sig` for the jmp itself is also not unique.

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

**Key insight — when to choose Pattern I over B/C:**
- Pattern B would need an `xref_signature` for the thunk body — but `48 8B ?? 48 FF 60 ??` (Windows) / `48 8B ?? FF 60 ??` (Linux) are too generic to sign uniquely without the concrete displacement byte filled in
- Pattern C (LLM_DECOMPILE) would work but is heavyweight for a 2–3 instruction function; the LLM also requires a SKILL.md file which generates a "Skill file not found" error if missing
- Pattern I avoids both issues: no signature needed, no LLM needed — the displacement byte is read deterministically via `idaapi.decode_insn`

### Example: Interface vfunc slot index via INHERIT_VFUNCS slot-only (Pattern F slot-only)

**User says:** Find `ILoopMode_LoopInit` in client and server. It's a vfunc of the abstract interface `ILoopMode`. `CLoopModeGame_LoopInit` already overrides it at the same vtable slot. No `func_sig` or `vfunc_sig` needed.

**Result:** `ida_preprocessor_scripts/find-ILoopMode_LoopInit.py` with:
- `INHERIT_VFUNCS`: `("ILoopMode_LoopInit", "ILoopMode", "CLoopModeGame_LoopInit", False)`
- `GENERATE_YAML_DESIRED_FIELDS`: exactly `func_name, vtable_name, vfunc_offset, vfunc_index` — triggers slot-only mode
- No `FUNC_XREFS`, no `LLM_DECOMPILE`, no `FUNC_VTABLE_RELATIONS`
- config.yaml `expected_input`: ONLY `CLoopModeGame_LoopInit.{platform}.yaml` — **no** `ILoopMode_vtable.{platform}.yaml`
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

**Key insight — slot-only vs Pattern I:** `ILoopMode_HandleInputEvent` used Pattern I (thunk instruction walk) because its offset comes from reading `jmp [reg+disp]` inside a thin wrapper. `ILoopMode_LoopInit` uses Pattern F slot-only because `CLoopModeGame_LoopInit` already has a `vfunc_index` in its output YAML — no instruction walking needed, just copy the slot index with a different `vtable_name`.
