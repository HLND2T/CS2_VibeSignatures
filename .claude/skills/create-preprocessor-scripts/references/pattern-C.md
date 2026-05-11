# Pattern C -- Virtual function via LLM_DECOMPILE

**Use when:** function IS virtual (has vtable slot), discovered by decompiling a known predecessor function.

## CRITICAL -- `vfunc_sig` is ALWAYS required for Pattern C

For ANY vfunc discovered via LLM_DECOMPILE, `GENERATE_YAML_DESIRED_FIELDS` **MUST** include `vfunc_sig`. This rule applies regardless of whether the script also emits `func_va`/`func_rva`/`func_size`. Pure slot-only (`func_name, vtable_name, vfunc_offset, vfunc_index` only, no `vfunc_sig`) is reserved for Pattern F slot-only / Pattern I / Pattern K -- it is NOT a valid output shape for Pattern C.

Why: LLM_DECOMPILE picks the slot from a decompile of the predecessor; without a `vfunc_sig` the discovered slot has no signature anchor for cross-binary stability. `vfunc_sig` provides the signature byte pattern of the actual vfunc body so it can be re-located across binary updates even if the vtable layout shifts.

The two valid Pattern C field sets are:

- **Standard Pattern C** (also a downstream predecessor): `func_name, func_va, func_rva, func_size, vfunc_sig, vfunc_offset, vfunc_index, vtable_name`
- **Slim Pattern C** (not a predecessor): `func_name, vfunc_sig, vfunc_offset, vfunc_index, vtable_name`

## Important -- `func_va` in output YAMLs

If this function will be used as a **predecessor** by a downstream LLM_DECOMPILE script (i.e., another script decompiles this function to find further targets), you **MUST** also include `func_va`, `func_rva`, and `func_size` in `GENERATE_YAML_DESIRED_FIELDS` (Standard Pattern C). The downstream script resolves the predecessor's address by reading `func_va` from the output YAML. Without it, the LLM_DECOMPILE fallback fails with "failed to resolve llm_decompile target function address". When in doubt, always include `func_va` -- it never hurts.

## Template

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
    # ALWAYS include "vfunc_sig" for Pattern C.
    # Include func_va/func_rva/func_size only if this function is a predecessor for downstream LLM_DECOMPILE.
    (
        "{FUNC_NAME_1}",
        [
            "func_name",
            "func_va",      # omit if not a downstream predecessor
            "func_rva",     # omit if not a downstream predecessor
            "func_size",    # omit if not a downstream predecessor
            "vfunc_sig",    # REQUIRED -- never omit for Pattern C
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

## Checklist

- [ ] `TARGET_FUNCTION_NAMES` lists all functions the script should find
- [ ] `LLM_DECOMPILE` reference path points to the correct predecessor function YAML
- [ ] `GENERATE_YAML_DESIRED_FIELDS` includes `vfunc_sig` for EVERY target (mandatory for Pattern C)
- [ ] `FUNC_VTABLE_RELATIONS` lists correct vtable class for each target that has `vtable_name` or `vfunc_*` in its `GENERATE_YAML_DESIRED_FIELDS`
- [ ] `preprocess_skill` signature includes `llm_config=None`
- [ ] `preprocess_common_skill` call passes `func_names=`, `func_vtable_relations=`, `llm_decompile_specs=`, and `llm_config=`
- [ ] config.yaml `expected_input` includes both the predecessor YAML and the vtable YAML
- [ ] Reference YAMLs exist or generated for both platforms
