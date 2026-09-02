---
name: create-agent-skill-fallback
description: |
  Create an Agent SKILL.md fallback for an existing find-XXXX finder that relies on a fragile discovery
  foundation — above all LLM_DECOMPILE (patterns C/D/E), which matches the decompiled shape of a predecessor
  function against a stored reference and breaks when a symbol is inlined or de-inlined in a way the reference
  does not cover. The generated fallback coexists with the preprocessor and runs only when it returns failure,
  recovering every target robustly by decompiling the predecessor and following the inline/de-inline boundary
  with semantic anchors. Use when a finder broke on a game update, or you want to durably backstop one before it
  does. The recipe generalizes to any finder foundation.
  Triggers: create agent skill fallback, add SKILL.md fallback, robust fallback for finder, backstop LLM_DECOMPILE finder, final guarantee skill
disable-model-invocation: true
---

# Create an Agent SKILL.md Fallback for a Finder

Given a target `find-XXXX` finder whose preprocessor uses a fragile foundation (most often **LLM_DECOMPILE**),
author `.claude/skills/find-XXXX/SKILL.md` — the **Agent fallback** that `ida_analyze_bin.py` runs only when the
preprocessor returns failure. The preprocessor stays as-is; this skill adds a durable backstop beside it.

This is the robustness-oriented sibling of `/convert-finder-skill-to-preprocessor-scripts` (that skill turns a
SKILL.md *into* a preprocessor; this one gives a preprocessor a SKILL.md *fallback*).

## When to Use

- A `find-XXXX` finder failed on a new game version because a member/vfunc/function was **inlined or
  de-inlined** relative to what its LLM_DECOMPILE reference expects (classic symptom: one target in a
  multi-target `-decompiles` skill can no longer be found, aborting the module).
- You want to **pre-emptively** backstop an LLM_DECOMPILE-based finder (patterns C/D/E) whose correctness hinges
  on a predecessor keeping a fixed decompiled shape.
- The recipe also applies to xref-string / found_call / index-based finders — the foundation differs, but the
  same "self-contained, skip-existing, anchor semantically, follow the callee" method holds.

Do **not** use this to replace a working preprocessor. The fallback is a safety net; the preprocessor remains
the fast path.

## The one constraint that drives the whole design

When the preprocessor fails, `agent_runner.run_skill` launches the agent with a prompt of **only
`/{skill_name}`** (see `_build_claude_command`, profile `sig-finder`). The skill's `expected_yaml_paths` is used
**only** for post-run missing-file verification (`_missing_expected_outputs` / `_result_failure_reason`) — it is
**never** injected into the prompt, and the missing list is not fed back to the agent on retry.

Consequence: the fallback SKILL.md you generate MUST be **fully self-contained**. It must enumerate every
output, gate each by platform, and tell the agent to **skip outputs whose YAML already exists** (the
preprocessor may have written most of them before failing; earlier fallback skills may have written others).

## Inputs to gather (read these before writing anything)

For target finder `find-XXXX` in module `<module>` (`server`, `engine`, `networksystem`, …):

1. **Preprocessor** `ida_preprocessor_scripts/find-XXXX.py` — the source of truth for *what* to find:
   - `TARGET_FUNCTION_NAMES`, `TARGET_STRUCT_MEMBER_NAMES`, `TARGET_GLOBALVAR_NAMES` and any
     `*_WINDOWS` / `*_LINUX` variants → the output symbols and their **platform gating**.
   - `LLM_DECOMPILE` (and `_WINDOWS`/`_LINUX`) → the **predecessor** reference each target is mined from
     (`references/<module>/<predecessor>.{platform}.yaml`).
   - `FUNC_VTABLE_RELATIONS` → which targets are vtable-related (`vtable_name`).
   - `GENERATE_YAML_DESIRED_FIELDS` → the **exact fields and kind** for each target (this tells you whether a
     target is a struct member, an indirect-vcall vfunc, a real vfunc, a regular func, or a global var — see the
     kind table below).
   - any `FUNC_XREFS` (string/gv anchors) — extra fingerprints you can reuse.
2. **`configs/<GAMEVER>.yaml` skill entry** — `expected_output` / `expected_output_windows` / `expected_output_linux`
   (authoritative output list per platform), `expected_input` (the predecessor YAML), `platform`,
   `prerequisite`.
3. **Reference YAMLs** `ida_preprocessor_scripts/references/<module>/<predecessor>.{platform}.yaml` — the
   `disasm_code` + `procedure` carry the annotations `; 0xNN = Class::member` and
   `; 0xNN = Class::vfunc` / `// NNNN = 0xNN = …` at each access/call site. **These annotations are the semantic
   fingerprints** you translate into the fallback's anchors. Also collect any real-world helper or alternate
   inline/de-inline reference YAML that materially helps locate the targets.
4. **Source-owned output YAMLs** `bin_artifacts/<gamever>/<module>/<target>.{platform}.yaml` — the
   **authoritative** offsets, vfunc indices, and signature styles the finder currently produces. Mine these for
   the reference values in the inventory table. Resolve an exact configured `<gamever>`; these files are tracked
   Git truth. Document their values as update- and platform-specific references, never as fixed answers.

Cross-check every value across the reference annotation AND the ground-truth YAML; where they disagree, trust
the ground-truth YAML and note the discrepancy (references occasionally mis-annotate — see the decoy caution).

## Workflow

### Step 1 — Build the output inventory

From the preprocessor `.py` + config entry, list every output as `(symbol, kind, platform, predecessor,
desired-fields)`. Determine `kind` from `GENERATE_YAML_DESIRED_FIELDS` using this table:

| Kind | Tell-tale desired fields | Sig-gen skill | Writer skill |
|------|--------------------------|---------------|--------------|
| struct member | `struct_name, member_name, offset, offset_sig[, size, offset_sig_disp]` | `/generate-signature-for-structoffset` | `/write-structoffset-as-yaml` |
| indirect vcall (`call [reg+disp]`, no body) | `vfunc_sig, vfunc_offset, vfunc_index, vtable_name` and **no** `func_va`/`func_sig` | `/generate-signature-for-vfuncoffset` | `/write-vfunc-as-yaml` (`func_addr=None`, `func_sig=None`) |
| real vtable vfunc (has a body) | `func_va/func_sig` **and** `vtable_name/vfunc_offset/vfunc_index` | `/generate-signature-for-function` | `/write-vfunc-as-yaml` (+ vtable fields) |
| regular function | `func_name, func_sig, func_va, func_rva, func_size` (no vtable fields) | `/generate-signature-for-function` | `/write-func-as-yaml` |
| global variable | `gv_name, gv_va, gv_sig, gv_inst_*` | `/generate-signature-for-globalvar` | `/write-globalvar-as-yaml` |

The indirect-vcall kind is easy to miss: its YAML has **no `func_va`** and its `vfunc_sig` is the signature of
the *call instruction itself* (e.g. `FF 90 A0 00 00 00` = `call qword ptr [rax+0A0h]`), not of any target
function body. Treat it as such — do not try to resolve a concrete implementation address.

### Step 2 — Confirm platform gating and the predecessor

From the config entry, record which outputs are cross-platform vs `expected_output_windows` /
`expected_output_linux`, and the predecessor(s) from `expected_input`. A symbol that is de-inlined into a
separate function on one platform but inlined on the other is common (that asymmetry is often *why* the finder
is fragile).

### Step 3 — Extract per-target fingerprints

For each target, read its access/call site in the reference `disasm_code` + `procedure` and write down:
- the **semantic anchor**: the nearest stable landmark — a string literal, a magic constant, a named
  global/interface call, a distinctive helper — that identifies the site independent of address;
- the **`this`-relative offset** (members) or **call displacement** (indirect vcalls) or **vtable index**;
- the **reference value** from the source-owned `bin_artifacts/` YAML (both platforms where they differ).

### Step 4 — Write the fallback SKILL.md

Create `.claude/skills/find-XXXX/SKILL.md` from the template below. Fill every placeholder; keep only the
target kinds that actually occur. The output filename MUST equal the finder's skill name so
`agent_runner.run_skill` finds it.

The generated fallback MUST contain `## Realworld Function References` near the top, before the background.
List one exact repo-relative YAML path per bullet for every platform-relevant predecessor and useful
inline/de-inline helper or variant. Spell out `.windows.yaml` and `.linux.yaml` paths separately; do not use
`{platform}` shorthand in this section, because the agent must be able to open each reference directly. State
that addresses and offsets are reference-build values that still require verification against the current
binary.

### Step 5 — Validate

- `uv run python -m unittest discover -s tests -b` (guard; a pure-doc addition should not affect tests).
- Re-read the generated SKILL.md against the inventory: is every output listed, platform-gated, and mapped to a
  sig-gen + writer skill with correct params?
- Run the fallback itself in the real IDA/MCP environment, bypassing both old-version reuse and preprocessing:

  ```bash
  uv run ida_analyze_bin.py -gamever <gamever> -oldgamever none -modules=<module> -debug -skip_pp -skill=<skill_name>
  ```

  The selected game version must contain the module binary and every configured `expected_input`. Seed a
  checkout-external scratch artifact root from `bin_artifacts/<gamever>/`, remove the target outputs only in that
  scratch copy, and pass it with `-artifactdir` (plus tracked `bin_artifacts` as `-oldartifactdir`). Never delete or
  rewrite tracked expected artifacts merely to force the test. A run that says all outputs already exist and skips
  the skill is **not** a valid Agent-Skill-only test.
- Require the log to show `Agent Skill only mode: enabled (-skip_pp)`, `Skipping preprocess: <skill_name>
  (-skip_pp)`, and `Starting agent skill: <skill_name>`, followed by `Success` and summary `Failed: 0`. Verify
  that every expected YAML for the tested platform was produced and parses as a non-empty mapping.

Do not report the fallback as complete unless this end-to-end Agent-Skill-only test passes. If the real IDA/MCP
environment is unavailable, report the validation as blocked rather than substituting a preprocessor run or a
ground-truth-only review.

### Step 6 — Commit Changes to `dev`

After the end-to-end fallback test has produced and verified its YAMLs, copy the validated canonical target outputs
from the isolated root into `bin_artifacts/<gamever>/<module>/`, include their computed downstream closure, and run the
repository artifact contract. Record the required one-line memory pointer
per the repo workflow. Ensure the delivery branch is `dev`; never commit directly to `main`. If the local `dev`
branch exists, switch to it. Otherwise, switch to `main` first and create `dev` from `main`:

```bash
if git show-ref --verify --quiet refs/heads/dev; then
  git switch dev
else
  git switch main
  git switch -c dev
fi
```

If any branch switch fails, stop and report the error. Review `git status --short`, then explicitly stage the new
fallback skill, source-owned artifact closure, and that memory update; never use `git add -A`:

```bash
git add -- .claude/skills/find-XXXX/SKILL.md bin_artifacts/<gamever>/<module>/<target-yamls> <memory-pointer-path>
git diff --cached --name-only
```

Stop if the staged-path list contains anything unrelated to this task. Commit only the staged task changes using
the repository commit format:

```bash
git commit -m "feat(skills): add find-XXXX fallback" -m "Co-Authored-By: Codex <codex@openai.com>"
```

Do not call `/create-pr`, push the branch, or open a pull request unless the user separately requests it. Finish by
reporting the commit hash, tested game version, unittest result, and Agent-Skill-only result.

---

## Fallback SKILL.md template

Fill placeholders `<...>`; drop sections for kinds that do not apply.

````markdown
---
name: find-XXXX
description: |
  Final-guarantee fallback for the find-XXXX preprocessor. Recovers <one-line summary of the targets> in CS2
  <module binaries> by decompiling <PREDECESSOR> and following de-inlined callees when a target is no longer
  accessed directly. Use when the deterministic/LLM preprocessor (ida_preprocessor_scripts/find-XXXX.py) could
  not resolve every target because a symbol was inlined or de-inlined in a way the LLM_DECOMPILE references do
  not cover.
  Trigger: <every target symbol, comma-separated>
disable-model-invocation: true
---

# Find XXXX (final-guarantee fallback)

Recover every symbol the find-XXXX preprocessor produces, in CS2 `<binary.dll>` / `<libbinary.so>`, using IDA
Pro MCP tools. This is the Agent fallback: it runs only when the preprocessor returned failure — which almost
always means a target's access pattern **moved** across the inline/de-inline boundary.

## Realworld Function References

Read the platform-relevant real-world YAMLs before searching in IDA. Treat their addresses and offsets as
reference-build values only; verify every result against the current binary.

- `ida_preprocessor_scripts/references/<module>/<predecessor>.windows.yaml`
- `ida_preprocessor_scripts/references/<module>/<predecessor>.linux.yaml`
- `ida_preprocessor_scripts/references/<module>/<relevant-helper-or-variant>.windows.yaml`
- `ida_preprocessor_scripts/references/<module>/<relevant-helper-or-variant>.linux.yaml`

Spell out each existing path literally and drop non-applicable placeholders or platforms.

## Background — <PREDECESSOR> and what it wires up

<2–5 sentences: what the predecessor does and which targets it touches, in source terms. Note that all member
accesses are relative to `this` (arg1: rcx/rsi on Windows, rdi/rbx on Linux) — the key to robustness.>

## Robustness principle — follow the de-inline boundary

For every target: (1) look for its access pattern inside `<PREDECESSOR>`; (2) if absent, it was de-inlined —
enumerate the functions `<PREDECESSOR>` calls, decompile the plausible ones, and search there (the helper
receives `this` as its first argument, so the same `this + offset` reappears; recurse a level or two);
(3) conversely a target the reference expected in a separate function may have been inlined back into
`<PREDECESSOR>`. Anchor each target by its semantic fingerprint (string / constant / neighboring call), never by
a fixed address or containing function.

## Output inventory

`struct_name` is `<STRUCT>` where applicable. Offsets/indices are **reference values from build <gamever> —
verify against the binary, do not assume**.

| # | Output symbol | Kind | Windows | Linux | Writer skill |
|---|---------------|------|---------|-------|--------------|
| 1 | `<symbol>` | <kind> | `<value or "inlined — skip">` | `<value or "inlined — skip">` | `/write-...-as-yaml` |
| … | | | | | |

Platform gating: <list cross-platform vs windows-only / linux-only outputs>.

## Step 0. Skip targets already produced

For each output, if `<name>.<platform>.yaml` already exists in the active artifact module directory and parses to a
non-empty mapping, skip it — the preprocessor or an earlier fallback wrote it. Use the analyzer-reported artifact
module directory; never derive the artifact path from the binary directory.

`/get-func-from-yaml` also reports existence for functions/vfuncs.

## Step 1. Load and decompile the predecessor

**ALWAYS** Use SKILL `/get-func-from-yaml` with `func_name=<PREDECESSOR>` to get its `func_va`. If it errors,
**STOP** and report to user. Then:

```
mcp__ida-pro-mcp__decompile addr="<PREDECESSOR.func_va>"
```

Note the `this` register and keep the list of called functions for the de-inline search.

## Step 2…N. Resolve each target

<One subsection per target (or per cluster sharing a call site). For each: the semantic anchor, the
this-relative offset / call displacement / vtable index, the reference value, and how to handle de-inline. Note
any decoys.>

## Signatures and YAML output

<Per kind, the sig-gen skill + writer skill + exact params — copy from the kind table. E.g. struct members →
/generate-signature-for-structoffset → /write-structoffset-as-yaml with struct_name/member_name/offset/size=None/
offset_sig/offset_sig_disp; indirect vcalls → /generate-signature-for-vfuncoffset → /write-vfunc-as-yaml with
func_addr=None, func_sig=None, vfunc_sig, vtable_name, vfunc_offset, vfunc_index=offset/8.>

## Failure handling

- Predecessor YAML missing → **STOP** and report.
- A required target unresolved even after following callees → resolve the rest, then **STOP** and report exactly
  which output(s) failed so the user can extend the references.
- Never emit a platform-gated symbol on the wrong platform.

## Output YAML filenames

Written under the active artifact module directory, one per symbol: `<symbol>.windows.yaml` / `<symbol>.linux.yaml`.
````

---

## Robustness principles (the heart of a good fallback)

1. **Anchor semantically, not positionally.** A fixed address or "it's in function F" breaks on the next update.
   A string literal, a magic constant (e.g. an FNV seed `0x811C9DC5`), a named interface call, or a distinctive
   helper survives.
2. **`this + offset` is stable across the inline boundary.** Struct offsets are relative to the class pointer
   (arg1). Whether the access is inlined in the predecessor or de-inlined into a helper that receives `this`,
   the same `this + offset` appears — so members are recoverable either way.
3. **Follow the callee (the core move).** If a target isn't in the predecessor, enumerate the predecessor's
   calls, decompile them, and recurse. This is what makes the fallback a *guarantee* rather than a re-run of the
   fragile reference match. Cover the inline-back case too.
4. **Know the indirect-vcall shape.** For `call qword ptr [reg + disp]` on an interface pointer, the output is
   `vtable_name` + `vfunc_offset = disp` + `vfunc_index = disp/8` + a `vfunc_sig` pinning the call instruction;
   there is **no `func_va`**. Resolve the interface from the receiver global's type.
5. **Watch for decoys.** References sometimes annotate two nearby offsets with the same member name. Trust the
   source-owned `bin_artifacts/` YAML. (Real example: `CEntitySystem::m_eNetworkSerializationMode` is the DWORD at
   `0xBBC`, set from the mode param and re-read at the SetNetworkSerializationContextData call — **not** the byte
   flag at `0xBDA`, even though the reference labels both.)
6. **The offset is the must-have; the signature is best-effort.** For struct members, `offset` is the required
   output; `offset_sig` is for relocation and may legitimately be omitted (write offset only) when a unique
   signature can't be found — especially for members whose access spans a function boundary.

## Checklist

- [ ] Read the target preprocessor `.py`, its config entry, its reference YAMLs, and its `bin_artifacts/` source-owned
      output YAMLs.
- [ ] Output inventory lists **every** symbol with kind + platform + predecessor + reference value.
- [ ] Fallback SKILL.md filename equals the finder's skill name.
- [ ] `## Realworld Function References` lists exact, directly openable repo-relative YAML paths for each
      relevant platform and inline/de-inline helper or variant; it contains no `{platform}` shorthand.
- [ ] SKILL.md is self-contained: enumerates all outputs, gates by platform, has the Step-0 skip-existing step.
- [ ] Each target has a semantic anchor and the follow-the-callee instruction; decoys are called out.
- [ ] Each kind is mapped to the correct sig-gen + writer skill with correct params (indirect vcalls use
      `func_addr=None`/`func_sig=None` + `vfunc_sig`).
- [ ] Failure handling + output-filename sections present.
- [ ] `unittest discover -s tests -b` passes.
- [ ] Values cross-checked against `bin_artifacts/` Git truth.
- [ ] Real Agent-Skill-only test passed with `uv run ida_analyze_bin.py -gamever <gamever> -oldgamever none
      -modules=<module> -debug -skip_pp -skill=<skill_name>`; the log proves preprocessing was skipped, the
      Agent Skill actually started, all expected YAMLs were produced, and the summary reports `Failed: 0`.
- [ ] The current branch is `dev` (created from `main` when it did not already exist).
- [ ] New SKILL.md, computed `bin_artifacts` closure, and memory pointer are explicitly staged and committed.
- [ ] `/create-pr` was not called; no push or PR was performed without a separate user request.

## Worked example — `find-CEntitySystem_Init-decompiles`

The canonical output of this workflow lives at
`.claude/skills/find-CEntitySystem_Init-decompiles/SKILL.md` (commit `a31fdf4`). Study it as the reference.

- **Fragile foundation:** `ida_preprocessor_scripts/find-CEntitySystem_Init-decompiles.py` mines 11 targets by
  LLM_DECOMPILE off one predecessor, `CEntitySystem_Init`
  (reference `references/server/CEntitySystem_Init.{platform}.yaml`).
- **What broke:** on Windows 14168, `CEntitySystem_InitEntityMaterialAttributes` was de-inlined out of
  `CEntitySystem_Init`, so the `m_EntityMaterialAttributes` access left the predecessor and the LLM match
  failed, aborting the module.
- **What the fallback covers:** all 11 targets — 7 cross-platform struct members, 2 indirect-vcall vtable
  offsets (`INetworkMessages_SetNetworkSerializationContextData` @0xA0/idx20,
  `IFlattenedSerializers_CreateFieldChangedEventQueue` @0x118/idx35), Linux-only
  `CEntitySystem_ProcessEntityRegistration`, and Windows-only `m_EntityMaterialAttributes` (@0x2070) — each
  anchored by a fingerprint (the `"string_t_table"` call, the `CUtlScratchMemoryPool::Init(_, 0x400, …)` call,
  the FNV material-hash loop, …) and recoverable whether inlined or de-inlined.
- It demonstrates every section of the template: directly openable real-world function references, the
  inventory table, Step-0 skip, follow-the-callee, the indirect-vcall shape, the `0xBBC`-vs-`0xBDA` decoy note,
  and the offset-is-must-have caveat for the field-change trio.
