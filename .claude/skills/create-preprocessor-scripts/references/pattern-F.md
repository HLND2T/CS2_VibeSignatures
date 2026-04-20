# Pattern F -- Virtual function via INHERIT_VFUNCS

**Use when:** the target is a **derived-class override** of a known base-class virtual function. The base vfunc has already been found (by another script), and this script inherits its vtable slot index to look up the same slot in the derived class's vtable.

This is the simplest pattern -- no xref strings, no LLM decompilation needed. Just a vtable slot lookup.

## Standard Mode Template

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

## INHERIT_VFUNCS tuple fields

- `target_func_name` -- name for the derived-class function (e.g. `"CBaseEntity_Precache"`)
- `inherit_vtable_class` -- class whose vtable to look up (e.g. `"CBaseEntity"`); for slot-only mode this is used only as metadata in the output YAML
- `base_vfunc_name` -- YAML artifact stem of the base-class vfunc that defines the slot index (e.g. `"CEntityInstance_Precache"`). Can be cross-module: `"../engine/INetworkMessages_FindNetworkGroup"`
- `generate_func_sig` -- (optional, default True) whether to generate a func_sig if no old YAML exists; set to `False` for slot-only mode

## Key differences from other patterns

- No `TARGET_FUNCTION_NAMES`, `FUNC_XREFS`, `LLM_DECOMPILE`, or `FUNC_VTABLE_RELATIONS`
- Uses `inherit_vfuncs=` parameter instead of `func_names=`
- No `llm_config` parameter in `preprocess_skill`
- Standard mode: config.yaml `expected_input` must include both the base vfunc YAML and the derived class vtable YAML
- Slot-only mode: config.yaml `expected_input` needs ONLY the base vfunc YAML -- no vtable YAML for the interface class
- config.yaml symbol category is `vfunc`

---

## Slot-Only Variant -- Abstract/interface vfunc slot index only

**Use when:** the target is a **pure interface or abstract-class vfunc** (e.g. `ILoopMode::LoopInit`) where:
- No real function body exists (pure virtual), so `func_va`, `func_sig` are not applicable
- Only `vfunc_offset` and `vfunc_index` are needed to identify the vtable slot
- A concrete-class implementation that overrides this slot is already found by another script

The engine automatically activates **slot-only mode** when both conditions are true:
1. `generate_func_sig=False` (4th INHERIT_VFUNCS tuple element)
2. `GENERATE_YAML_DESIRED_FIELDS` contains **exactly** `{func_name, vtable_name, vfunc_offset, vfunc_index}` -- nothing more, nothing less

In slot-only mode the engine reads `vfunc_index` directly from the base vfunc's YAML and returns early, **skipping the vtable lookup entirely**. No `{INTERFACE_CLASS}_vtable.{platform}.yaml` needs to exist.

### Template

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

### Output YAML (both platforms)

```yaml
func_name: ILoopMode_LoopInit
vtable_name: ILoopMode
vfunc_offset: '0x28'
vfunc_index: 5
```

### Slot-only vs standard -- when to use which

- **Standard** (`generate_func_sig=True`, full field set): target is a concrete derived class that has a real function body -- you want `func_va`, `func_sig`, etc.
- **Slot-only** (`generate_func_sig=False`, four-field set): target is an abstract/interface method -- you only need the vtable slot position, no implementation address

## Checklist

- [ ] `INHERIT_VFUNCS` lists correct `(target_func_name, inherit_vtable_class, base_vfunc_name, generate_func_sig)` tuples
- [ ] For slot-only: `generate_func_sig=False` AND desired fields are exactly `{func_name, vtable_name, vfunc_offset, vfunc_index}` -- adding any extra field (e.g. `func_va`) will silently exit slot-only mode and require a vtable YAML
- [ ] For standard: config.yaml `expected_input` includes both the derived-class vtable YAML and the base vfunc YAML
- [ ] For slot-only: config.yaml `expected_input` includes ONLY the base vfunc YAML -- no vtable YAML for the interface class
- [ ] No `FUNC_XREFS`, `LLM_DECOMPILE`, `FUNC_VTABLE_RELATIONS`, or `llm_config` parameter
- [ ] `preprocess_common_skill` call passes `inherit_vfuncs=`
