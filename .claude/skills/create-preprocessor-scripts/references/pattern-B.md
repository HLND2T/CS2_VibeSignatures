# Pattern B -- Virtual function via xref strings

**Use when:** function IS virtual (has vtable slot), discovered via debug string cross-references. Same as Pattern A, but adds `FUNC_VTABLE_RELATIONS` and vtable fields to `GENERATE_YAML_DESIRED_FIELDS`.

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

## Platform-Specific Xref Strings Variant

When xref strings differ between Windows and Linux, use `FUNC_XREFS_WINDOWS` / `FUNC_XREFS_LINUX` and a ternary in `preprocess_skill`. See [Pattern A](pattern-A.md#platform-specific-xref-strings-variant) for the full example -- the same approach applies to Pattern B.

## Checklist

- [ ] `TARGET_FUNCTION_NAMES` lists all functions the script should find
- [ ] `FUNC_XREFS` xref strings match the user's specified debug strings
- [ ] `FUNC_VTABLE_RELATIONS` lists correct vtable class for each target that has `vtable_name` or `vfunc_*` in its `GENERATE_YAML_DESIRED_FIELDS`
- [ ] `preprocess_common_skill` call passes `func_names=`, `func_xrefs=`, and `func_vtable_relations=`
- [ ] config.yaml `expected_input` includes the vtable YAML
- [ ] No `LLM_DECOMPILE`, no `llm_config` parameter
