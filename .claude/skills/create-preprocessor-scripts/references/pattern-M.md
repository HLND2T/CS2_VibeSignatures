# Pattern M -- Inline/noinline fallback chain (de-inlined helper)

**Use when:** a target `X` was found by a single Pattern A/B finder that anchors on a debug
string a helper owns (or on a call `X` makes into that helper), and CS2 **inlines that helper
into `X` on some builds but compiles it as a separate function on others** (the compiler flips
this across gamevers/platforms). Once the helper de-inlines, the anchor leaves `X`, the single
finder stops producing `X.{platform}.yaml` on that build, and because `ida_analyze_bin.py` is
fail-fast the rest of the module aborts.

**Symptom:** `X.{platform}.yaml` is present for older gamevers / one platform but missing for
the newest gamever / other platform, and the module run aborts partway through.

**Fix:** replace the single `find-X` skill with a **3-skill fallback chain**. The original
finder is renamed to `find-X-inlined` (see the [rename-preprocessor-scripts](../../rename-preprocessor-scripts/SKILL.md)
skill for the `git mv` + docstring mechanics); a helper finder and a `-noinline` finder are
added around it. Reference chains in this repo: `CEngineServer_ChangeLevel`,
`CLoopTypeClientServer_DeactivateLoop`, `CNetworkGameServer_DirectUpdate`,
`CMsgSource2NetworkFlowQuality_PrintStats` (inverted -- see last section).

## The 3-skill chain

| Skill | Role | Positive source | configs/<GAMEVER>.yaml fields |
|-------|------|-----------------|--------------------|
| `find-{HELPER}` | resolve the de-inlined helper | `xref_strings` on the helper's own debug string (or `xref_funcs` on a stable callee) | `optional_output: {HELPER}` + `skip_if_exists: {TARGET}` -- **no** `expected_input` |
| `find-{TARGET}-noinline` | resolve TARGET as the helper's caller | `xref_funcs: [{HELPER}]` (+ `FUNC_VTABLE_RELATIONS` if vfunc) | `optional_output: {TARGET}` + `expected_input: <vtable>` (if vfunc) + `prerequisite: [find-{HELPER}]` |
| `find-{TARGET}-inlined` | the ORIGINAL finder, renamed | unchanged (the original `xref_strings`/`xref_funcs` anchor) | `expected_output: {TARGET}` + `expected_input: <vtable>` + `skip_if_exists: {TARGET}` + `prerequisite: [find-{TARGET}-noinline]` |

Order the three configs/<GAMEVER>.yaml entries exactly as above (HELPER -> -noinline -> -inlined). The
vanilla chain is **cross-platform** -- no `platform:` field (the inverted variant is the
exception).

## Templates

### 1. `find-{HELPER}.py` -- Pattern A, resolves the helper by its string

```python
#!/usr/bin/env python3
"""Preprocess script for find-{HELPER} skill (deinline-fix chain, link 1/3)."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["{HELPER}"]

FUNC_XREFS = [
    {
        "func_name": "{HELPER}",
        "xref_strings": ["FULLMATCH:{ANCHOR_STRING}"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    ("{HELPER}", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]

# preprocess_skill body is identical to Pattern A: pass func_names, func_xrefs,
# generate_yaml_desired_fields into preprocess_common_skill.
```

### 2. `find-{TARGET}-noinline.py` -- Pattern B, the helper's (vtable-filtered) caller

```python
#!/usr/bin/env python3
"""Preprocess script for find-{TARGET}-noinline skill (deinline-fix chain, link 2/3)."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["{TARGET}"]

FUNC_XREFS = [
    {
        "func_name": "{TARGET}",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["{HELPER}"],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNC_VTABLE_RELATIONS = [
    ("{TARGET}", "{VTABLE_CLASS}"),   # omit this constant entirely if TARGET is a regular func
]

GENERATE_YAML_DESIRED_FIELDS = [
    ("{TARGET}", [
        "func_name", "func_va", "func_rva", "func_size",
        "func_sig",                                      # keep/drop per the func_sig rule below
        "vtable_name", "vfunc_offset", "vfunc_index",    # vfunc only
    ]),
]

# preprocess_skill body is identical to Pattern B: pass func_names, func_xrefs,
# func_vtable_relations, generate_yaml_desired_fields into preprocess_common_skill.
```

### 3. `find-{TARGET}-inlined.py`

The original finder, unchanged except for the `git mv` rename and docstring update. It stays a
Pattern A/B `xref_strings`(+vtable) finder. Its `GENERATE_YAML_DESIRED_FIELDS` must match the
`-noinline` skill's `func_sig` choice (see rules).

## configs/<GAMEVER>.yaml chain

```yaml
      - name: find-{HELPER}
        optional_output:
          - {HELPER}.{platform}.yaml
        skip_if_exists:
          - {TARGET}.{platform}.yaml
      - name: find-{TARGET}-noinline
        optional_output:
          - {TARGET}.{platform}.yaml
        expected_input:
          - {VTABLE_CLASS}_vtable.{platform}.yaml   # vfunc only
        prerequisite:
          - find-{HELPER}
      - name: find-{TARGET}-inlined
        expected_output:
          - {TARGET}.{platform}.yaml
        expected_input:
          - {VTABLE_CLASS}_vtable.{platform}.yaml   # vfunc only
        skip_if_exists:
          - {TARGET}.{platform}.yaml
        prerequisite:
          - find-{TARGET}-noinline
```

Register only `{TARGET}` under `symbols:` -- **not** `{HELPER}` (see rules).

## How each build resolves

- **De-inlined build:** `find-{HELPER}` finds the standalone helper by its anchor;
  `find-{TARGET}-noinline` finds TARGET as the (vtable-filtered) caller of that helper.
  `find-{TARGET}-inlined` skips (`{TARGET}` already exists).
- **Inlined build:** the anchor lives inside TARGET, so `find-{HELPER}` resolves to **TARGET's
  own address** (harmless -- see rules); `find-{TARGET}-noinline` finds no callers but re-selects
  TARGET via the **vtable-self fallback** (`func_xrefs` uses the callee itself when it has no
  callers but its address is in the target vtable). `find-{TARGET}-inlined` skips.
- **Ambiguous inlined anchor** (the inlined string has >1 xref): `find-{HELPER}` and
  `find-{TARGET}-noinline` both soft-skip, and `find-{TARGET}-inlined`'s string-cap-vtable
  intersection is the load-bearing path -- which is exactly why the original finder must stay in
  the chain.

## Key rules

- **`optional_output`, not `expected_output`, on HELPER and -noinline.** They must *soft-skip*
  (not hard-fail) when their path doesn't apply, so control falls through to the next skill.
  Only `find-{TARGET}-inlined` carries `expected_output`.
- **Depend on the helper via `prerequisite`, never `expected_input`.** The helper is optional and
  may be absent; a missing `expected_input` hard-fails. Put the *vtable* in `expected_input`.
- **Do NOT register `{HELPER}` as a gamedata `symbol`.** In the inlined case its YAML points at
  TARGET's own address, which would be a wrong gamedata entry. It is an intermediate only.
- **`func_sig` keep/drop** (apply the same choice to **both** -noinline and -inlined so TARGET's
  output shape does not flip per build):
  - vfunc with a **substantial** de-inlined body -> **keep** `func_sig` (it signs uniquely; e.g.
    ChangeLevel, DirectUpdate).
  - vfunc that de-inlines to a **tiny forwarding thunk** -> **drop** `func_sig` on both paths (the
    head bytes aren't unique; the vtable slot `vfunc_offset`/`vfunc_index` is the stable locator;
    e.g. DeactivateLoop, RegisterEventMap). Keep `func_name, func_va, func_rva, func_size,
    vtable_name, vfunc_offset, vfunc_index`.
  - regular func (no vtable) -> **keep** `func_sig` on all three (it is the only stable locator).

## Validate on BOTH inline states

`bin_artifacts/*.yaml` are tracked source truth. Validate with a scratch config and a checkout-external artifact root;
seed each tested GAMEVER from tracked artifacts, then remove TARGET only in those scratch copies. Use
`-oldgamever none` to force the xref paths; version reuse would short-circuit `-noinline`:

```bash
# _scratch.yaml = just this module (real paths) + the 3 new skills + TARGET's symbol entry
# <scratch-artifacts> is checkout-external and contains the unaffected artifacts for each tested version.
uv run ida_analyze_bin.py -configyaml=_scratch.yaml -gamever <deinlined_ver> -artifactdir <scratch-artifacts> -oldartifactdir bin_artifacts -oldgamever none -modules=<mod> -force_all -debug
uv run ida_analyze_bin.py -configyaml=_scratch.yaml -gamever <inlined_ver> -artifactdir <scratch-artifacts> -oldartifactdir bin_artifacts -oldgamever none -modules=<mod> -force_all -debug
```

Confirm **both** gamevers x **both** platforms resolve TARGET to the same vtable slot (or
`func_sig`) with `Failed 0`. Copy only the selected PR GAMEVER's validated affected/downstream closure into tracked
`bin_artifacts`, run the repository artifact contract, and delete `_scratch.yaml` before committing.

## Worked example: `CNetworkGameServer_DirectUpdate` (engine, 14168)

`CNetworkStringTableContainer::DirectUpdate` (owns the `"CNetworkStringTableContainer::DirectUpdate"`
VProf string) de-inlined out of the `CNetworkGameServer::DirectUpdate` vfunc on Linux at 14168,
so the string left the vfunc and `CNetworkGameServer_DirectUpdate.linux.yaml` stopped building.

1. `git mv find-CNetworkGameServer_DirectUpdate.py find-CNetworkGameServer_DirectUpdate-inlined.py`
   (original = `xref_strings` on the VProf string + `CNetworkGameServer_vtable`); update its docstring.
2. New `find-CNetworkStringTableContainer_DirectUpdate.py`: `xref_strings` on the same string;
   fields `func_name/func_sig/func_va/func_rva/func_size`.
3. New `find-CNetworkGameServer_DirectUpdate-noinline.py`:
   `xref_funcs: ["CNetworkStringTableContainer_DirectUpdate"]` +
   `FUNC_VTABLE_RELATIONS: [("CNetworkGameServer_DirectUpdate", "CNetworkGameServer_vtable")]`;
   **kept** `func_sig` (substantial body).
4. `configs/<GAMEVER>.yaml`: replaced the one skill entry with the 3-skill chain; left the
   `CNetworkGameServer_DirectUpdate` symbol entry as-is; did NOT add a helper symbol.
5. Validated 14167 (inlined) + 14168 (Linux de-inlined) x win/linux, `-oldgamever none`: all four
   -> vtable index 59 / offset 0x1d8, `Failed 0` (the 14168 Linux de-inlined body signs at 7 bytes
   `83 7F ?? ?? 76 ?? 55` = the `m_nMaxClients > 1` guard).

## Inverted topology (string-LESS guard wrapper)

If the de-inline instead splits a thin **string-less guard wrapper** off a string-heavy body
(the public function is the wrapper; the body keeps the string -- e.g.
`CMsgSource2NetworkFlowQuality_PrintStats`), the vanilla recipe mis-resolves: the helper finder
finds the body on *both* builds, and the `-noinline` target has no anchor but the body as its
only named callee, so it collides with structurally-identical vtable-mates. Extra handling:
`find-{HELPER}` is `platform:`-scoped and unregistered; `find-{TARGET}-noinline` adds a
guard-thunk `xref_signatures` (a positive identity unique to the extracted wrapper) plus
`exclude_funcs`/`exclude_callees` for the colliders. Treat this as a special case and diff
against the `PrintStats` chain before writing it.

## Checklist

- [ ] Original finder `git mv`'d to `find-{TARGET}-inlined` + docstring updated
- [ ] `find-{HELPER}` created (`optional_output`, `skip_if_exists: {TARGET}`, no `expected_input`, unregistered symbol)
- [ ] `find-{TARGET}-noinline` created (`xref_funcs: [{HELPER}]` + vtable if vfunc; `optional_output`, `prerequisite: [find-{HELPER}]`)
- [ ] `find-{TARGET}-inlined` config = `expected_output` + `skip_if_exists` + `prerequisite: [find-{TARGET}-noinline]`
- [ ] `func_sig` kept/dropped consistently on both -noinline and -inlined per the rule above
- [ ] `{HELPER}` NOT added as a gamedata `symbol`
- [ ] configs/<GAMEVER>.yaml entries ordered HELPER -> -noinline -> -inlined
- [ ] Validated on an inlined AND a de-inlined gamever, both platforms, `-oldgamever none`, `Failed 0`
- [ ] Scratch config/root deleted; the 3 skill files, `configs/<GAMEVER>.yaml`, and computed `bin_artifacts` closure committed
