# Pattern G -- ConCommand handler function

**Use when:** the target is a **ConCommand handler callback** identified by matching the command name string and/or help string in the binary. The `_registerconcommand.py` helper scans for exact string matches, finds xrefs to those strings, locates nearby `RegisterConCommand` calls, and recovers the handler function pointer from the call arguments.

## Template

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

## Key differences from Pattern A

- Imports `preprocess_registerconcommand_skill` from `ida_preprocessor_scripts._registerconcommand` instead of `preprocess_common_skill` from `ida_analyze_util`
- Uses `COMMAND_NAME` and `HELP_STRING` variables instead of `FUNC_XREFS`
- Uses `SEARCH_WINDOW_BEFORE_CALL` and `SEARCH_WINDOW_AFTER_XREF` (typically 96 bytes each) to control the scan window around xrefs
- The `preprocess_skill` function ignores `old_yaml_map` (`_ = skill_name, old_yaml_map`)
- Calls `preprocess_registerconcommand_skill()` with `command_name=`, `help_string=`, `rename_to=` instead of `func_xrefs=`
- config.yaml category is `func`, no `expected_input` needed
- The handler function is always a regular function (not virtual), so no `FUNC_VTABLE_RELATIONS`

## Checklist

- [ ] `TARGET_FUNCTION_NAMES` lists the handler function name
- [ ] `COMMAND_NAME` matches the exact console command string
- [ ] `HELP_STRING` matches the exact help text registered with the command
- [ ] Uses `preprocess_registerconcommand_skill` (NOT `preprocess_common_skill`)
- [ ] config.yaml symbol category is `func`, no `expected_input` needed
