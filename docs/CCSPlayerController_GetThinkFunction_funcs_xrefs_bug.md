# Bug: `preprocess_func_xrefs_via_mcp` fails to locate `CCSPlayerController_GetThinkFunction`

## Symptom

```
Preprocess: trying func_xrefs fallback for CCSPlayerController_GetThinkFunction
Preprocess: common_funcs before excludes = []
Preprocess: common_funcs after excludes = []
Preprocess: xref intersection yielded 0 function(s) for CCSPlayerController_GetThinkFunction (need exactly 1)
Preprocess: failed to locate CCSPlayerController_GetThinkFunction
```

The intersection of candidate sets is empty even though the target function **does** satisfy all configured xref criteria.

## Script Configuration

From `find-CCSPlayerController_GetThinkFunction.py`:

```python
FUNC_XREFS = [{
    "func_name": "CCSPlayerController_GetThinkFunction",
    "xref_strings": ["FULLMATCH:CCSPlayerControllerInventoryUpdateThink"],
    "xref_signatures": ["E8 ?? ?? ?? ?? 85 C0"],
    ...
}]
```

Two candidate sets are built and intersected:

1. **String xref set** — functions referencing `"CCSPlayerControllerInventoryUpdateThink"` (exact match).
2. **Signature xref set** — functions containing the byte pattern `E8 ?? ?? ?? ?? 85 C0`.

## Root Cause

### IDA investigation results

| Address | Function | Refs string? | Contains signature? |
|---------|----------|-------------|---------------------|
| `0x1390E70` | `sub_1390E70` | Yes (at `0x1390EC5`) | No |
| `0x13914A0` | `CCSPlayerController_GetThinkFunction` | Yes (at `0x13914AB`) | Yes (at `0x13914B6`) |

The string xref set = `{0x1390E70, 0x13914A0}` — correct.

However, `_collect_xref_func_starts_for_signature` (`ida_analyze_util.py:5884`) calls `find_bytes` **without** specifying a `limit`:

```python
find_result = await session.call_tool(
    name="find_bytes",
    arguments={"patterns": [xref_signature]},
)
```

The MCP `find_bytes` tool defaults to `limit=1000`. The pattern `E8 ?? ?? ?? ?? 85 C0` (`call rel32; test eax, eax`) is extremely common — it produces **10,000+ matches** in `libserver.so`. The first 1000 matches only cover addresses up to roughly `~0x9BB4EA`, but the actual match inside `CCSPlayerController_GetThinkFunction` is at `0x13914B6` — well beyond the 1000-match cutoff.

As a result, the signature candidate set never includes the target function, and the intersection with the string xref set is empty.

## Suggested Infrastructure Fix

The current approach (enumerate all global matches of the signature, then intersect) is fundamentally fragile for common byte patterns. A more robust design:

**Probe-based filtering instead of global enumeration.**

When the other xref sources (strings, gvs, funcs) have already narrowed candidates to a small set, use per-function `bin_search` to check if each candidate contains the signature — the same approach `_func_contains_signature_via_mcp` already uses for `exclude_signatures`.

Sketch of the change in `_collect_xref_func_starts_for_signature` (or at the intersection level):

```
Instead of:
  1. find_bytes(pattern) -> global_matches  (may be truncated!)
  2. normalize to func starts -> signature_set
  3. intersect signature_set with other candidate sets

Do:
  If other candidate sets are already populated and small (< some threshold):
    1. For each candidate in the intersection so far, check if the function
       contains the signature via bin_search within [func.start_ea, func.end_ea]
    2. Keep only candidates that pass
  Else (signature is the only/first source):
    Fall back to global find_bytes, but with limit=10000 or pagination
```

This avoids the truncation problem entirely for the common case where signatures are used as a secondary filter alongside string/gv/func xrefs.
