# Pattern A -- Regular function via xref strings

**Use when:** function is non-virtual, discovered via debug string cross-references.

## Template

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

## Platform-Specific Xref Strings Variant

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
            "./gameinterface.cpp:3",  # Shorter path-based string on Linux
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

This variant also applies to [Pattern B](pattern-B.md).

## Checklist

- [ ] `TARGET_FUNCTION_NAMES` lists all functions the script should find
- [ ] `FUNC_XREFS` xref strings match the user's specified debug strings
- [ ] `preprocess_common_skill` call passes `func_names=` and `func_xrefs=`
- [ ] No `FUNC_VTABLE_RELATIONS`, no `LLM_DECOMPILE`, no `llm_config` parameter
