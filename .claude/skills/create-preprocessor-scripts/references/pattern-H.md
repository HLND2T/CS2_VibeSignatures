# Pattern H -- Secondary (ordinal) vtable

**Use when:** the target is a **secondary vtable** (`_vtable2`) for a class that has multiple inheritance. Located via the mangled symbol name on Windows (e.g. `??_7ClassName@@6B@_0`) and via matching `offset-to-top` on Linux.

This pattern does NOT use `preprocess_common_skill`. It uses the `_ordinal_vtable_common` helper instead.

## User inputs

- **Class name** -- e.g. `CLoopTypeClientServerService`
- **Windows mangled symbol** -- e.g. `??_7CLoopTypeClientServerService@@6B@_0` (the `@_0` suffix distinguishes the secondary vtable)
- **Linux offset-to-top** -- e.g. `-56` (a negative decimal value from `dq -NN ; offset to this` in the vtable layout)

## Template

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

## Key differences from all other patterns

- Does NOT use `preprocess_common_skill` -- uses `preprocess_ordinal_vtable_via_mcp` from `_ordinal_vtable_common` plus `write_vtable_yaml` from `ida_analyze_util`
- No `TARGET_FUNCTION_NAMES`, `FUNC_XREFS`, `LLM_DECOMPILE`, `FUNC_VTABLE_RELATIONS`, or `INHERIT_VFUNCS`
- config.yaml category is `vtable`, no `expected_input` needed
- Output stem is `{CLASS_NAME}_vtable2`, config.yaml symbol name matches
- Windows uses `WINDOWS_SYMBOL_ALIASES` (mangled name with `@_0` suffix)
- Linux uses `LINUX_EXPECTED_OFFSET_TO_TOP` (negative decimal offset-to-top value)
- The `ordinal=0` parameter selects the first secondary vtable (use `ordinal=1` for a third vtable, etc.)
- The `expected_filename` variable in the f-string uses the curly-brace trick: define `TARGET_OUTPUT_STEM` as a plain string, then build the filename with `f"{TARGET_OUTPUT_STEM}.{platform}.yaml"`

## Checklist

- [ ] `TARGET_CLASS_NAME` and `TARGET_OUTPUT_STEM` match (stem = `{CLASS_NAME}_vtable2`)
- [ ] `WINDOWS_SYMBOL_ALIASES` contains the correct mangled name (e.g. `??_7ClassName@@6B@_0`)
- [ ] `LINUX_EXPECTED_OFFSET_TO_TOP` is the correct negative decimal value
- [ ] Uses `preprocess_ordinal_vtable_via_mcp` + `write_vtable_yaml` (NOT `preprocess_common_skill`)
- [ ] config.yaml symbol category is `vtable`, no `expected_input` needed
