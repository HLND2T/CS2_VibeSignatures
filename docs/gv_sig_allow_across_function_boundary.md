# gv_sig_allow_across_function_boundary

## Why this feature was added

When generating a unique byte signature for a global variable access (`gv_sig`), the signature generator collects instruction bytes starting from the GV-accessing instruction and extending forward. By default, it stops at the owning function's end boundary (`f.end_ea`).

This becomes a problem when the GV-accessing instruction is near the end of its function. For example, `g_CCSPlayerController_InventoryUpdateThink` is the last global stored in `CCSPlayerController_RegisterThink`. The `mov cs:g_CCSPlayerController_InventoryUpdateThink, rax` instruction at `0x134679E` has only a few instructions remaining before the function ends at `0x13467B5` -- not enough bytes to form a unique signature.

Without this feature, `preprocess_gen_gv_sig_via_mcp` fails with:
```
Preprocess: failed to generate a unique gv-access signature for 0x239a998
```

## What the feature does

When `gv_sig_allow_across_function_boundary` is enabled for a symbol, the signature generator removes the `f.end_ea` constraint and continues collecting bytes past the function boundary -- across CC (`INT3`) padding and into the next function -- until it has enough bytes for a unique match.

For example, the generated signature for `g_CCSPlayerController_InventoryUpdateThink`:
```
48 89 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? E9 ?? ??
?? ?? CC CC CC CC CC CC CC 55 48 8D 05 ?? ?? ?? ??
```
extends past the function end, through 7 bytes of CC padding, and into the prologue of the next function.

## How to use

In a preprocessor script's `GENERATE_YAML_DESIRED_FIELDS`, add the directive as a `"key: value"` string entry in the field list for the target symbol:

```python
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "g_SomeGlobalVar",
        [
            "gv_name",
            "gv_va",
            "gv_rva",
            "gv_sig",
            "gv_sig_va",
            "gv_inst_offset",
            "gv_inst_length",
            "gv_inst_disp",
            "gv_sig_allow_across_function_boundary: true",  # extend past func end
        ],
    ),
]
```

This follows the same `"key: value"` directive pattern used by `vfunc_sig_max_match:N`.

## What happens at each stage

1. **Parsing** (`_normalize_generate_yaml_desired_fields`): The `"gv_sig_allow_across_function_boundary: true"` string is parsed as a generation option. The field name `gv_sig_allow_across_function_boundary` is added to `desired_output_fields` and the boolean value is stored in `generation_options`.

2. **Signature generation** (`preprocess_gen_gv_sig_via_mcp`): The `allow_across_function_boundary` parameter controls the embedded IDA Python code. When `True`, `_collect_sig_stream` uses `inst_ea + max_sig_bytes` as the limit instead of `min(f.end_ea, inst_ea + max_sig_bytes)`, and the loop condition drops the `cursor < f.end_ea` check.

3. **YAML output**: The field `gv_sig_allow_across_function_boundary: true` is written to the output YAML file on disk. This is ensured by:
   - Adding the field to `GV_YAML_ORDER`
   - Injecting `gv_data["gv_sig_allow_across_function_boundary"] = True` before `_assemble_symbol_payload` runs

4. **Signature reuse** (`preprocess_gv_sig_via_mcp`): When reading an old YAML for signature reuse, the flag is propagated from `old_data` into the returned dict. The reuse path itself doesn't need the flag (it just runs `find_bytes` on the stored signature), but propagating it ensures the flag persists across game version updates.

## Files changed

- `ida_analyze_util.py`:
  - `GV_YAML_ORDER`: Added `gv_sig_allow_across_function_boundary`
  - `_normalize_generate_yaml_desired_fields`: Parse the `"gv_sig_allow_across_function_boundary: true"` directive
  - `preprocess_gen_gv_sig_via_mcp`: Added `allow_across_function_boundary` parameter; modified embedded `_collect_sig_stream` to optionally skip `f.end_ea` limit
  - `_preprocess_direct_gv_sig_via_mcp`: Thread the parameter through
  - `preprocess_common_skill`: Extract the flag from `generation_options` and pass to `_preprocess_direct_gv_sig_via_mcp`; inject the flag into `gv_data` before assembly
  - `preprocess_gv_sig_via_mcp`: Propagate the flag from old YAML to the returned result
