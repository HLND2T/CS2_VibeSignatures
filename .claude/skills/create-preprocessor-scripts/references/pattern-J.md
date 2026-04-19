# Pattern J -- IGameSystem vfunc via dispatch scan

**Use when:** Target is an `IGameSystem` virtual function that appears as the `callback` argument to `IGameSystem_DispatchCall(...)` calls in a known predecessor function's decompile. The predecessor's decompile shows `IGameSystem_DispatchCall(idx, GameSystem_OnXxx, args)` where `GameSystem_OnXxx` identifies the target.

## How It Works

`_igamesystem_dispatch_common.preprocess_igamesystem_dispatch_skill` scans the predecessor function (or its internal wrapper) for all `IGameSystem_DispatchCall` call sites and collects their callback targets:

- **Windows:** scans for `lea rdx, callback` instructions, then reads the callback's first `call/jmp [reg+disp]` to extract the vfunc offset
- **Linux:** scans for `mov esi/rsi, odd_imm` + next `call`, computes `vfunc_off = imm - 1`

Only non-negative, 8-byte-aligned offsets are accepted.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `SOURCE_YAML_STEM` | str | Yes | Stem of the predecessor function's output YAML (e.g. `"CSource2Server_GameFrame"`) |
| `TARGET_SPECS` | list[dict] | Yes | Each dict has `target_name` (output name), `rename_to` (callback name in decompile), optional `dispatch_rank` |
| `VIA_INTERNAL_WRAPPER` | bool | Yes | `True` if the predecessor delegates to a named internal helper that contains the actual dispatch calls |
| `INTERNAL_RENAME_TO` | str\|None | Yes | Name to assign to the internal wrapper (when `VIA_INTERNAL_WRAPPER=True`); `None` otherwise |
| `MULTI_ORDER` | str | Yes | `"scan"` to preserve scan order; `"index"` to sort by `(vfunc_index, vfunc_offset)` for stable multi-target mapping |
| `EXPECTED_DISPATCH_COUNT` | int | No | Total dispatch entries expected; defaults to `target_count` (no `dispatch_rank`) or `max(dispatch_rank)+1` |

## Choosing Parameters

| Scenario | `dispatch_rank` | `EXPECTED_DISPATCH_COUNT` | `MULTI_ORDER` |
|----------|-----------------|--------------------------|---------------|
| 1 target, 1 dispatch in source | omit | omit | `"scan"` |
| 1 target among N dispatches | set to rank (0-based) | set to N | `"scan"` |
| N targets, N dispatches (all targets) | omit | omit | `"index"` |
| N targets among M>N dispatches | set each rank | set to M | `"index"` |

## Finding `rename_to` from the Decompile

In the predecessor's decompile output, each dispatch looks like:

```c
IGameSystem_DispatchCall(
  idx,
  (__int64 (__fastcall *)(_QWORD, __int64))GameSystem_OnServerPreEntityThink,
  (__int64)&args);
```

The cast-stripped function name (`GameSystem_OnServerPreEntityThink`) is the `rename_to` value. If the function is still unnamed (e.g. `sub_180XXXXXX`), it will be renamed by the preprocessor to that string as a best-effort step.

## Template

```python
#!/usr/bin/env python3
"""Preprocess script for find-{SKILL_NAME} skill."""

from ida_preprocessor_scripts._igamesystem_dispatch_common import (
    preprocess_igamesystem_dispatch_skill,
)

SOURCE_YAML_STEM = "{PREDECESSOR_FUNC}"
TARGET_SPECS = [
    {"target_name": "{TARGET_FUNC_NAME}", "rename_to": "{CALLBACK_NAME_IN_DECOMPILE}"},
    # For multi-target with dispatch_rank:
    # {"target_name": "{TARGET_FUNC_NAME}", "rename_to": "{CALLBACK_NAME}", "dispatch_rank": 0},
]
VIA_INTERNAL_WRAPPER = False   # True if dispatcher is in a nested internal helper
INTERNAL_RENAME_TO = None      # Set to wrapper name when VIA_INTERNAL_WRAPPER=True
MULTI_ORDER = "scan"           # "index" for multi-target stable ordering
# EXPECTED_DISPATCH_COUNT = N  # Uncomment when total dispatch count > target count


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
    """Resolve target function(s) via IGameSystem dispatch and write YAML."""
    _ = skill_name, old_yaml_map
    return await preprocess_igamesystem_dispatch_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        source_yaml_stem=SOURCE_YAML_STEM,
        target_specs=TARGET_SPECS,
        via_internal_wrapper=VIA_INTERNAL_WRAPPER,
        internal_rename_to=INTERNAL_RENAME_TO,
        multi_order=MULTI_ORDER,
        # expected_dispatch_count=EXPECTED_DISPATCH_COUNT,
        debug=debug,
    )
```

## Checklist

- [ ] `SOURCE_YAML_STEM` matches the predecessor function's output YAML stem (not a reference YAML stem)
- [ ] Each `rename_to` matches the callback function name visible in the predecessor's decompile
- [ ] `VIA_INTERNAL_WRAPPER` is `True` only when the predecessor does not directly contain the dispatch calls but delegates to a named sub-function
- [ ] `MULTI_ORDER = "index"` when finding multiple targets (for stable ordering across compiler reorderings)
- [ ] `dispatch_rank` is set (and `EXPECTED_DISPATCH_COUNT` set to total) when selecting a subset of dispatches
- [ ] No `FUNC_XREFS`, no `FUNC_VTABLE_RELATIONS`, no `LLM_DECOMPILE`, no `INHERIT_VFUNCS`
- [ ] config.yaml `expected_input` includes both the predecessor YAML **and** `IGameSystem_vtable.{platform}.yaml`
- [ ] config.yaml `symbols` entries use `category: vfunc`
