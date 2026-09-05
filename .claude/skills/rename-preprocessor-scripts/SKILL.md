---
name: rename-preprocessor-scripts
description: |
  Rename a symbol (function, vfunc, vtable, struct member, global variable) across all
  preprocessor scripts, configs/<GAMEVER>.yaml entries, and tracked source-owned YAML artifacts.
  Use when a symbol's name changes (class rename, naming-convention fix, etc.), or when
  splitting a single finder into an inline/noinline fallback chain because a helper
  de-inlined and the target's YAML stopped being produced on some gamever/platform.
disable-model-invocation: true
---

# Rename Preprocessor Scripts

Rename a symbol from `OldName` to `NewName` across all files in the preprocessor pipeline:
the Python script, `configs/<GAMEVER>.yaml`, and the matching tracked YAML artifacts under
`bin_artifacts/<GAMEVER>/`.

Resolve `GAMEVER` from the user's explicit request or `CS2VIBE_GAMEVER`; edit only
`configs/$GAMEVER.yaml` and stop if it is missing.

## When to Use

- A symbol's name changes (e.g. class renamed from `ILoopType` to `CLoopTypeBase`)
- A naming-convention fix applies to one or more existing preprocessor scripts
- **Deinline-fix:** a single `find-X` finder must be split into an inline/noinline chain
  because a helper that used to be inlined became a separate function (de-inlined) on some
  build. This skill covers the `find-X-inlined` rename step (Step 1–3 below); the full
  3-skill chain recipe lives in
  [create-preprocessor-scripts Pattern M](../create-preprocessor-scripts/references/pattern-M.md)

## Inputs

| Field | Description | Example |
|-------|-------------|---------|
| **Old name** | Current symbol name to replace | `ILoopType_EngineLoop` |
| **New name** | New symbol name | `CLoopTypeBase_EngineLoop` |
| **Old class** (optional) | Old vtable class name, if applicable | `ILoopType` |
| **New class** (optional) | New vtable class name, if applicable | `CLoopTypeBase` |

> If only the symbol suffix changes (e.g. `Foo_Bar` → `Foo_Baz`) and the vtable class stays
> the same, skip the class rename steps below.

> **Multiple renames at once:** run all steps for every symbol in a single pass — batch the
> `sed` calls with multiple `-e` flags rather than doing separate passes per symbol.

---

## Step 1: Find All Affected Files

Search for every occurrence of the old name across the entire repo:

```bash
grep -r "OldName" --include="*.py" --include="*.yaml" -l
```

Expected hits fall into these categories:

| File type | Path pattern | What changes |
|-----------|-------------|--------------|
| Preprocessor script | `ida_preprocessor_scripts/find-OldName.py` | File renamed + content updated |
| configs/<GAMEVER>.yaml | `configs/<GAMEVER>.yaml` | Skill name, `expected_output`, `skip_if_exists`, symbol `name` + `alias` |
| Source-owned YAMLs | `bin_artifacts/<GAMEVER>/client\|engine/OldName.{platform}.yaml` | Tracked rename + canonical payload update |
| Reference YAMLs | `ida_preprocessor_scripts/references/**/*.yaml` | File renamed (if named after symbol) or comment strings updated |
| Test files | `tests/*.py` | Fixture data, assertions, class/method names updated |

Also check whether any **other** scripts list `OldName.{platform}.yaml` as an `expected_input`
(i.e. downstream dependents). If found, those scripts' `INHERIT_VFUNCS` / `LLM_DECOMPILE` /
`FUNC_XREFS` constants and their `configs/<GAMEVER>.yaml` `expected_input` entries must be updated too.

---

## Step 2: Rename the Preprocessor Script

Use `git mv` to preserve history:

```bash
git mv ida_preprocessor_scripts/find-OldName.py \
        ida_preprocessor_scripts/find-NewName.py
```

> **Compound script names:** scripts may bundle multiple symbols with `-AND-` separators
> (e.g. `find-IGameSystemFactory_Allocate-AND-IGameSystemFactory_DoesGameSystemReallocate-AND-IGameSystem_SetName.py`)
> or have an `-impl` suffix. Only rename the part that changed — leave unrelated symbol names
> and suffixes intact.

---

## Step 3: Update the Script Contents

In the renamed `.py` file, replace every occurrence of the old symbol name and old class name:

| Location | Old value | New value |
|----------|-----------|-----------|
| Module docstring | `find-OldName skill` | `find-NewName skill` |
| `INHERIT_VFUNCS` tuple (1st element) | `"OldName"` | `"NewName"` |
| `INHERIT_VFUNCS` tuple (2nd element, vtable class) | `"OldClass"` | `"NewClass"` |
| `GENERATE_YAML_DESIRED_FIELDS` key | `"OldName"` | `"NewName"` |
| `FUNC_XREFS` `func_name` field | `"OldName"` | `"NewName"` |
| `FUNC_VTABLE_RELATIONS` tuple (1st element) | `"OldName"` | `"NewName"` |
| `FUNC_VTABLE_RELATIONS` tuple (2nd element, vtable class) | `"OldClass"` | `"NewClass"` |
| `LLM_DECOMPILE` target `name` field | `"OldName"` | `"NewName"` |
| `TARGET_FUNCTION_NAMES` / `TARGET_STRUCT_MEMBER_NAMES` | `"OldName"` | `"NewName"` |

Only touch fields that are actually present in the script; skip inapplicable rows.

---

## Step 4: Update configs/<GAMEVER>.yaml

Four locations may need editing. Use a single `sed` invocation with multiple `-e` flags to
handle both the `_` symbol name and the `::` alias form in one pass:

```bash
sed -i \
  -e 's/OldName/NewName/g' \
  -e 's/OldClass::OldMethodSuffix/NewClass::NewMethodSuffix/g' \
  configs/<GAMEVER>.yaml
```

> The `alias` field uses `::` notation (`IGameSystemFactory::Allocate`), which a plain
> `s/OldName/NewName/` will **not** match because the symbol name uses `_` separators.
> Always add a separate `-e` expression for the alias form when the method suffix changes.

### 4a. Skill entry (under `skills:`)

```yaml
# Before
      - name: find-OldName
        expected_output:
          - OldName.{platform}.yaml

# After
      - name: find-NewName
        expected_output:
          - NewName.{platform}.yaml
```

`expected_input` entries are only changed if they reference `OldName.{platform}.yaml` directly.

### 4b. Symbol entry (under `symbols:`)

```yaml
# Before
      - name: OldName
        category: vfunc          # (or func / structmember / vtable / gv)
        alias:
          - OldClass::OldMethodSuffix

# After
      - name: NewName
        category: vfunc
        alias:
          - NewClass::NewMethodSuffix
```

### 4c. Downstream `expected_input` entries (if any)

If any other skill lists `OldName.{platform}.yaml` as an `expected_input`, update those entries
to `NewName.{platform}.yaml`.

### 4d. `skip_if_exists` entries (if any)

If any skill has `skip_if_exists: - OldName.{platform}.yaml`, update to `NewName.{platform}.yaml`.

---

## Step 5: Rebuild the Source-Owned Artifact Closure

Artifacts under `bin_artifacts/` are tracked Git truth. Do not use plain `mv`, hand-edit scalar formatting, or modify
unrelated game versions. For the selected GAMEVER and module, preserve history for the direct rename with `git mv`.
Use a checkout-external seeded root for targeted iteration without `-force_all`; module/skill filters are intentionally
incompatible with the full execution contract:

```bash
git mv "bin_artifacts/<GAMEVER>/<module>/OldName.windows.yaml" \
       "bin_artifacts/<GAMEVER>/<module>/NewName.windows.yaml"
git mv "bin_artifacts/<GAMEVER>/<module>/OldName.linux.yaml" \
       "bin_artifacts/<GAMEVER>/<module>/NewName.linux.yaml"
uv run ida_analyze_bin.py -gamever <GAMEVER> -modules <module> -skill find-NewName \
  -artifactdir <CHECKOUT_EXTERNAL_SEEDED_ROOT> -oldartifactdir bin_artifacts -debug
```

Before copying the closure back, run the complete config from a different, fresh empty root and emit execution evidence:

```bash
uv run ida_analyze_bin.py -gamever <GAMEVER> -configyaml configs/<GAMEVER>.yaml \
  -artifactdir <CHECKOUT_EXTERNAL_EMPTY_ROOT> -oldartifactdir bin_artifacts \
  -oldgamever <PRIOR_GAMEVER-or-none> -execution_report <CHECKOUT_EXTERNAL_EXECUTION_REPORT.json> \
  -force_all -debug
```

Apply only paths that exist and include platform-specific variants. The central finalizer must update identity fields and
canonical bytes; binary-derived values change only when the rebuild proves they changed. Run the repository artifact
contract and confirm the old path is absent, the new path has exactly one producer group, and every downstream artifact
required by the config is included.

---

## Step 6: Update Reference YAMLs (if any)

Reference YAMLs under `ida_preprocessor_scripts/references/` may need two kinds of treatment:

**A. Reference YAML named after the symbol** (e.g. `references/client/OldName.windows.yaml`):
rename the file and update its contents:

```bash
mv ida_preprocessor_scripts/references/client/OldName.windows.yaml \
   ida_preprocessor_scripts/references/client/NewName.windows.yaml
mv ida_preprocessor_scripts/references/client/OldName.linux.yaml \
   ida_preprocessor_scripts/references/client/NewName.linux.yaml
sed -i "s/OldName/NewName/g" \
  ida_preprocessor_scripts/references/client/NewName.windows.yaml \
  ida_preprocessor_scripts/references/client/NewName.linux.yaml
```

**B. Reference YAML named after a different symbol** (e.g. `references/client/IGameSystem_AddByName.windows.yaml`
contains inline comments referencing `OldName`): update contents only:

```bash
sed -i "s/OldName/NewName/g" \
  ida_preprocessor_scripts/references/client/SomeFile.windows.yaml \
  ida_preprocessor_scripts/references/client/SomeFile.linux.yaml
```

---

## Step 7: Update Test Files (if any)

Test files under `tests/` may reference `OldName` in fixture data, skill-name strings,
file-name strings, `func_vtable_relations` assertions, and test class / method names.

If the Step 1 grep found any test files, do a bulk replace first:

```bash
sed -i "s/OldName/NewName/g" tests/test_ida_analyze_bin.py tests/test_ida_preprocessor_scripts.py
```

Then check for remaining stale vtable-class references in `func_vtable_relations` assertions
(the bulk replace will have renamed the symbol but not the class):

```bash
grep -n "func_vtable_relations.*OldClass" tests/test_ida_preprocessor_scripts.py
```

Fix any hits manually: `("NewName", "OldClass")` → `("NewName", "NewClass")`.

---

## Step 8: Update Downstream Script Contents (if any)

If any other preprocessor scripts reference `OldName` (e.g. in `INHERIT_VFUNCS` as the
`base_vfunc_name`, or in `LLM_DECOMPILE` as a predecessor), update those references to
`NewName` in their `.py` source and in their `configs/<GAMEVER>.yaml` `expected_input` entries.

> **`INHERIT_VFUNCS` `base_vfunc_name` gotcha:** the 3rd element of the tuple is a path like
> `"../client/OldName"` (without `.yaml`). A grep on the full symbol name will find it, but
> a sed that only matches `OldName.{platform}.yaml` will not. Make sure the plain
> `s/OldName/NewName/g` pass covers it.

---

## Step 9: Verify

Run a final grep to confirm no stale references remain:

```bash
grep -r "OldName" --include="*.py" --include="*.yaml"
```

The only acceptable remaining hits are comments or documentation that explicitly reference
the old name for historical context.

---

## Step 10: Run Regression Tests

Run the non-MCP unittest suite:

```bash
uv run python -c "from pathlib import Path; import sys, unittest; excluded={'test_ida_mcp_session', 'test_smoke_ida_mcp_2'}; modules=[f'tests.{path.stem}' for path in Path('tests').glob('test_*.py') if path.stem not in excluded]; result=unittest.TextTestRunner(buffer=True).run(unittest.defaultTestLoader.loadTestsFromNames(modules)); sys.exit(not result.wasSuccessful())"
```

This intentionally excludes the IDA MCP adapter and smoke modules (`test_ida_mcp_session`,
`test_smoke_ida_mcp_2`) to keep preprocessor work fast. Run those modules separately when changing
MCP routing or lifecycle code.

**Keep 0 selected unittest failures before delivery.** If any test fails, investigate and fix it before staging
the rename.

---

## Step 11: Commit Changes to `dev`

After validation passes, ensure the delivery branch is `dev`. Never commit directly to `main`. If the local `dev`
branch exists, switch to it. Otherwise, switch to `main` first and create `dev` from `main`:

```bash
if git show-ref --verify --quiet refs/heads/dev; then
  git switch dev
else
  git switch main
  git switch -c dev
fi
```

If any branch switch fails, stop and report the error. Review `git status --short`, then explicitly stage every
task-related renamed or modified source path and the computed `bin_artifacts` closure. Never use `git add -A`:

```bash
git add -- <source-config-reference-paths> <bin_artifacts-closure-paths>
git diff --cached --name-only
```

Stop if the staged-path list contains anything unrelated to this task. Commit only the staged task changes using
the repository commit format:

```bash
git commit -m "refactor(preprocessor): rename OldName to NewName" -m "Co-Authored-By: Codex <codex@openai.com>"
```

The staged diff must contain the tracked artifact A/M/D/R required by the rename and no Release-derived outputs. Do not
call `/create-pr`, push the branch, or open a
pull request unless the user separately requests it. Finish by reporting the commit hash and the non-MCP unittest
result.

---

## Checklist

- [ ] Old Python file removed / renamed via `git mv`
- [ ] New Python file has all `OldName` / `OldClass` occurrences replaced
- [ ] `configs/<GAMEVER>.yaml` skill `name` and `expected_output` updated
- [ ] `configs/<GAMEVER>.yaml` symbol `name` and `alias` updated (alias uses `::` — needs separate sed expression)
- [ ] `configs/<GAMEVER>.yaml` downstream `expected_input` entries updated (if any)
- [ ] `configs/<GAMEVER>.yaml` `skip_if_exists` entries updated (if any)
- [ ] Selected `bin_artifacts/<GAMEVER>/*/OldName.*.yaml` paths renamed to `NewName.*.yaml`
- [ ] Central finalizer rebuilt canonical payloads and the complete downstream closure
- [ ] Reference YAMLs in `ida_preprocessor_scripts/references/` renamed and/or updated (if any)
- [ ] Test files in `tests/` bulk-replaced; vtable class in assertions corrected (if any)
- [ ] Downstream preprocessor script `.py` and `configs/<GAMEVER>.yaml` entries updated (if any)
- [ ] Final grep shows zero stale references
- [ ] Non-MCP unittest command above passes with 0 failures
- [ ] The current branch is `dev` (created from `main` when it did not already exist)
- [ ] Every task-related source path and tracked `bin_artifacts` closure path is explicitly staged and committed
- [ ] `/create-pr` was not called; no push or PR was performed without a separate user request

---

## Real-World Examples

### Simple (no reference YAMLs or tests)

**User says:** Rename `ILoopType_EngineLoop` to `CLoopTypeBase_EngineLoop`.

**Affected files found:**
- `ida_preprocessor_scripts/find-ILoopType_EngineLoop.py`
- `configs/<GAMEVER>.yaml` (skill entry, symbol entry)
- `bin_artifacts/<GAMEVER>/engine/ILoopType_EngineLoop.{windows,linux}.yaml`

No downstream dependents, no reference YAMLs, no test files hit.

**Changes made:**

1. `git mv find-ILoopType_EngineLoop.py find-CLoopTypeBase_EngineLoop.py`
2. In the renamed script:
   - Docstring: `find-ILoopType_EngineLoop` → `find-CLoopTypeBase_EngineLoop`
   - `INHERIT_VFUNCS`: `("ILoopType_EngineLoop", "ILoopType", ...)` → `("CLoopTypeBase_EngineLoop", "CLoopTypeBase", ...)`
   - `GENERATE_YAML_DESIRED_FIELDS` key: `"ILoopType_EngineLoop"` → `"CLoopTypeBase_EngineLoop"`
3. `configs/<GAMEVER>.yaml` skill: `find-ILoopType_EngineLoop` / `ILoopType_EngineLoop.{platform}.yaml` → new names
4. `configs/<GAMEVER>.yaml` symbol: `name: ILoopType_EngineLoop`, `alias: ILoopType::EngineLoop` → new names
5. `git mv` the selected GAMEVER artifacts; the analyzer/finalizer rebuilt identity fields and canonical bytes

---

### Complex (reference YAMLs, test files, skip_if_exists)

**User says:** Rename `ILoopType_DeallocateLoopMode` to `CLoopTypeBase_DeallocateLoopMode`.

**Affected files found:**
- `ida_preprocessor_scripts/find-ILoopType_DeallocateLoopMode.py`
- `configs/<GAMEVER>.yaml` (`skip_if_exists` in `find-CEngineServiceMgr_DeactivateLoop`, skill entry, symbol entry)
- `bin_artifacts/<GAMEVER>/engine/ILoopType_DeallocateLoopMode.{windows,linux}.yaml`
- `ida_preprocessor_scripts/references/engine/CEngineServiceMgr_DeactivateLoop.{windows,linux}.yaml`
- `tests/test_ida_analyze_bin.py`
- `tests/test_ida_preprocessor_scripts.py`

**Changes made:**

1. `git mv find-ILoopType_DeallocateLoopMode.py find-CLoopTypeBase_DeallocateLoopMode.py`
2. In the renamed script (bulk replace then fix vtable class):
   - All `ILoopType_DeallocateLoopMode` → `CLoopTypeBase_DeallocateLoopMode`
   - `FUNC_VTABLE_RELATIONS`: `("CLoopTypeBase_DeallocateLoopMode", "ILoopType")` → `(..., "CLoopTypeBase")`
3. `configs/<GAMEVER>.yaml`: `skip_if_exists` entry + skill entry + symbol entry all updated
4. `git mv` the tracked artifacts; the analyzer/finalizer regenerated the selected GAMEVER closure
5. `sed -i` on both reference YAML files (comments in IDA disassembly snippets)
6. `sed -i` bulk replace across both test files; then manually fixed `func_vtable_relations`
   assertion: `("CLoopTypeBase_DeallocateLoopMode", "ILoopType")` → `(..., "CLoopTypeBase")`

---

### Batch (two renames at once, compound script name, downstream INHERIT_VFUNCS, reference YAML rename)

**User says:** Rename `IGameSystemFactory_Allocate` → `IGameSystemFactory_CreateGameSystem`
and `IGameSystemFactory_Deallocate` → `IGameSystemFactory_DestroyGameSystem`.

**Affected files found (both symbols combined):**
- `ida_preprocessor_scripts/find-IGameSystemFactory_Allocate-AND-IGameSystemFactory_DoesGameSystemReallocate-AND-IGameSystem_SetName.py`
- `ida_preprocessor_scripts/find-IGameSystem_GetName-AND-IGameSystemFactory_Deallocate.py`
- `configs/<GAMEVER>.yaml` (2 skill entries, 2 symbol entries, 1 downstream `expected_input`)
- `bin_artifacts/<GAMEVER>/client/IGameSystemFactory_Allocate.{platform}.yaml`
- `bin_artifacts/<GAMEVER>/client/IGameSystemFactory_Deallocate.{platform}.yaml`
- `ida_preprocessor_scripts/references/client/IGameSystem_AddByName.{windows,linux}.yaml` (content only)
- `ida_preprocessor_scripts/references/client/IGameSystem_DestroyAllGameSystems.{windows,linux}.yaml` (content only)
- `ida_preprocessor_scripts/find-CGameSystemReallocatingFactory_CSpawnGroupMgrGameSystem_DestroyGameSystem-impl.py`
  (downstream: `INHERIT_VFUNCS` `base_vfunc_name` = `"../client/IGameSystemFactory_Deallocate"`)
- `tests/test_ida_preprocessor_scripts.py`

**Key observations:**

- The Allocate script name is compound (`-AND-`): only `IGameSystemFactory_Allocate` changes in
  the filename, the rest stays.
- `configs/<GAMEVER>.yaml` aliases are `IGameSystemFactory::Allocate` / `IGameSystemFactory::Deallocate` —
  a plain `s/IGameSystemFactory_Allocate/...` sed will not touch them; need separate `-e` clauses:
  ```bash
  sed -i \
    -e 's/IGameSystemFactory_Allocate/IGameSystemFactory_CreateGameSystem/g' \
    -e 's/IGameSystemFactory::Allocate/IGameSystemFactory::CreateGameSystem/g' \
    -e 's/IGameSystemFactory_Deallocate/IGameSystemFactory_DestroyGameSystem/g' \
    -e 's/IGameSystemFactory::Deallocate/IGameSystemFactory::DestroyGameSystem/g' \
    configs/<GAMEVER>.yaml
  ```
- The downstream script's `INHERIT_VFUNCS` has `base_vfunc_name = "../client/IGameSystemFactory_Deallocate"` —
  a plain `s/IGameSystemFactory_Deallocate/IGameSystemFactory_DestroyGameSystem/g` on that file catches it.
- Reference YAMLs for these symbols are named after a different symbol (AddByName, DestroyAllGameSystems) —
  content-only update, no file rename needed.
- Both renames were batched in a single commit.

---

## Deinline-Fix Variant (see create-preprocessor-scripts Pattern M)

When a helper that used to be inlined into a target **de-inlines** on some build, its anchor (the
debug string it owns, or the call the target made into it) leaves the target, so the single
`find-X` finder stops producing `X.{platform}.yaml` there and the fail-fast run aborts the module.
The fix is a **3-skill inline/noinline fallback chain**: the original finder is renamed to
`find-X-inlined` using this skill's Step 1–3 `git mv` + content-update mechanics, and a helper
finder plus a `find-X-noinline` finder are added around it (`optional_output` / `prerequisite` /
`skip_if_exists` wiring).

The de-inline fix is fundamentally a script-*creation* pattern -- only the `-inlined` rename step
belongs to this skill. The full recipe (script templates, the `configs/<GAMEVER>.yaml` chain, the `func_sig`
keep/drop rule, validation on both inline states, the `CNetworkGameServer_DirectUpdate` worked
example, and the inverted string-less-wrapper variant) lives in
**[create-preprocessor-scripts Pattern M](../create-preprocessor-scripts/references/pattern-M.md)**.
