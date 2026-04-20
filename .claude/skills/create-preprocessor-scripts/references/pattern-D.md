# Pattern D -- Regular function via LLM_DECOMPILE

**Use when:** function is NOT virtual, discovered by decompiling a known predecessor function.

## Template

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

## Checklist

- [ ] `TARGET_FUNCTION_NAMES` lists all functions the script should find
- [ ] `LLM_DECOMPILE` reference path points to the correct predecessor function YAML
- [ ] `preprocess_skill` signature includes `llm_config=None`
- [ ] `preprocess_common_skill` call passes `func_names=`, `llm_decompile_specs=`, and `llm_config=`
- [ ] No `FUNC_VTABLE_RELATIONS` (regular function, not virtual)
- [ ] config.yaml `expected_input` includes the predecessor YAML
- [ ] Reference YAMLs exist or generated for both platforms
