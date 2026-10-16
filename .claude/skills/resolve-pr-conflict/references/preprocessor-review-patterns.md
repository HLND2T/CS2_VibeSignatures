# Preprocessor PR Review Patterns

Use this reference for changes to `ida_preprocessor_scripts/`, `configs/`, analysis reference YAML, or tracked source-owned symbol artifacts.

## 1. Coalesce LLM Decompilation by Predecessor

### Trigger signals

- The PR adds a new script with `LLM_DECOMPILE`.
- Another base-tree script already decompiles the same `reference_yaml_paths` predecessor.
- The new and old targets can be recovered independently from one predecessor decompilation.
- Config contains adjacent finders with identical required input YAML.

### Review method

1. Extract each changed `LLM_DECOMPILE` spec's predecessor reference YAML.
2. Search the base tree for every script referencing that same YAML.
3. Compare prompt path, dependency policy, module, platform behavior, and expected result sections.
4. Decide whether a single predecessor-oriented `*-decompiles.py` script can contain all target specs in one preprocessing unit.
5. Verify config can replace separate finders with one finder whose `expected_output` lists all targets.

### Finding rule

Raise a finding when the PR introduces a separate finder and therefore repeats an LLM decompilation that an existing finder already performs or should own. Prefer grouping by decompiled predecessor rather than by discovered target.

Canonical example: commit `46517b323314f06423aa065a6825b1495e965a28` replaced separate `find-CNetworkGameServer_GetFreeClient.py` and `find-CNetworkGameServerBase_CheckPassword.py` with `find-CNetworkGameServerBase_ConnectClient-decompiles.py`. Its single preprocessing unit contains both `LLM_DECOMPILE` specs based on `CNetworkGameServerBase_ConnectClient.{platform}.yaml`, and one config entry produces both outputs.

Do not raise this finding merely because two scripts use LLMs. Keep them separate when predecessors, modules, dependency policies, ordering, failure semantics, or output lifecycles materially differ.

## 2. Preserve Interface Ownership at Indirect Vcalls

### Trigger signals

- A predecessor locates a target through `call qword ptr [reg+offset]` or equivalent virtual dispatch.
- The receiver is an interface pointer or global typed as an interface, such as `g_pSource2Server`.
- The PR names the recovered slot after a concrete implementation class.
- The concrete implementation lives in another module or has its own vtable YAML.

### Review method

1. Inspect disassembly/decompilation around the call and identify the receiver expression, not only the eventual runtime implementation.
2. Determine the static vtable owner visible at that callsite.
3. Name the caller-anchored `found_vcall` result for the interface slot.
4. If a concrete implementation symbol is also required, require a second finder in the implementation module using `INHERIT_VFUNCS` with:
   - the concrete target name;
   - the concrete vtable class;
   - the cross-module interface-vfunc YAML as the base;
   - signature generation enabled only when viable.
5. Verify config order: interface finder produces the interface YAML first; concrete finder consumes it plus the concrete vtable YAML.
6. Verify module-local symbol declarations and aliases distinguish `IClass_Method` from `CClass_Method`.

### Finding rule

Raise a finding when a callsite proves only an interface vtable slot but the PR labels it as a concrete implementation function. The vcall offset identifies a slot contract; it does not by itself identify which concrete function body occupies that slot in another binary.

Canonical example: PR #711, merged as `d5f71bdc78a775ff120e0ed7b0669155a1db8a42`, corrected the earlier design by locating `ISource2Server_GetAllServerClasses` from `CNetworkGameServer_Shutdown`, then locating `CSource2Server_GetAllServerClasses` in the server module through `INHERIT_VFUNCS` and `CSource2Server_vtable`.

## 3. Request Only Generatable YAML Fields

### Trigger signals

- A new `GENERATE_YAML_DESIRED_FIELDS` entry requests `func_sig`.
- The target is a tiny thunk, trivial accessor, shared stub, or otherwise has non-unique head bytes.
- Existing comments, old YAML, validation logs, or sibling patterns say no unique signature exists.
- `INHERIT_VFUNCS` uses `generate_func_sig=True` without evidence that generation succeeds on both platforms.

### Review method

1. Separate fields needed for identity (`func_name`, vtable index/offset/name) from optional address and signature fields.
2. Check whether `func_sig` can be unique in each target binary and platform.
3. Inspect historical YAML or generator behavior for a rejected/non-unique signature.
4. Ensure `INHERIT_VFUNCS`'s signature-generation flag and desired fields agree.

### Finding rule

Raise a finding when the configuration requires a field the analysis cannot reliably generate. For a particularly simple `CSource2Server_GetAllServerClasses` body, omit `func_sig` from `GENERATE_YAML_DESIRED_FIELDS` and disable inherited signature generation rather than making a non-unique signature a required output. Retain vtable metadata and address/size fields only when the pipeline can produce them reliably.

## 4. Cross-Check Config and Generated Outputs

For every changed finder, verify:

- the script name matches the config `name` exactly;
- every `expected_output` has one intended producer;
- every required reference appears in `expected_input` with the correct relative module path;
- producer entries precede consumers;
- removed scripts have no remaining config entries or tests;
- renamed interface/concrete symbols are reflected in symbol declarations, aliases, reference annotations, source-owned artifacts, and Release-derived consumers;
- artifact changes cover the affected/downstream closure and are a consequence of the design change, not the only evidence supporting it.

Treat an exact-byte artifact rebuild as necessary but insufficient: it validates reproducibility of the current config, not semantic symbol ownership or efficient analysis design.

## 5. Reject Stale-Gamever Config Changes

### Trigger signals

- The PR modifies `configs/<GAMEVER>.yaml`, `bin_artifacts/<GAMEVER>/`, or a forbidden legacy output namespace.
- `<GAMEVER>` is not the latest version in `download.yaml`.
- The same symbol/finder change also exists (or belongs) in the latest gamever's config.

### Review method

1. Read the last `tag:` entry in `download.yaml`; that is the canonical latest gamever. The list is chronological, so the newest version is always last (matching `init_gamebin.py`'s `LATEST_GAMEVER=versions[-1]`).
2. Collect every `<GAMEVER>` that appears in `configs/<GAMEVER>.yaml` or `bin_artifacts/<GAMEVER>/`; independently reject tracked `gamesymbols/`, `gamedata/`, and `release-manifests/`.
3. Flag each one that is not the latest gamever.
4. Distinguish "stale config change" from "historical backport": a stale change adds/removes symbols or finders in an old config as if it were the current analysis model; a legitimate historical fix would be scoped and justified. Treat the stale change as a defect unless the PR explicitly documents a backport intent.
5. When the latest gamever config already has (or should have) the same finders/symbols, require the PR to carry the change only in the latest config and verify the computed `bin_artifacts` closure reflects it.

### Finding rule

Raise a finding when the PR changes a config or source-owned artifact for a non-latest GAMEVER without an explicit,
coherent historical-backport intent. Producers, expected inputs, symbol definitions, aliases, and artifact closure must
belong to the same version contract. Tracked Release-derived namespaces are always a hard-stop finding.

## 6. Block Fixed Offsets

Fixed offsets are not allowed. Every vtable slot, struct member offset, or displacement that a preprocessor emits or uses to pick its target must be derived from the binary being analyzed on every run. A value copied from a reference build must not stand in for that derivation.

### Trigger signals

- An added or modified script under `ida_preprocessor_scripts/` (including shared `_*.py` helpers) has a numeric literal for a game-build layout fact: a vtable slot offset or index, a struct member offset, an instruction displacement, or a per-platform table of these (e.g. `VFUNC_OFFSETS = {"windows": 0x110, "linux": 0x108}`, `VFUNC_INDEX = 34`, `MEMBER_OFFSET = 0x1A8`, `direct_vfunc_offset="0x..."`).
- The literal ends up in output YAML (`vfunc_offset`, `vfunc_index`, `offset`, ...), is passed as a direct slot or offset argument, or is the needle used to select or "verify" the target.
- The "verification" only checks that the constant appears somewhere in a predecessor (any `[reg+disp]` operand, any immediate, any 8-byte-aligned value in a range). It does not read the value from one semantically anchored instruction.
- A comment or docstring calls the value "known", "stable", "from the reference build", or "the server-init slot".

### Review method

1. List every numeric literal, and every constant whose name contains `OFFSET`, `INDEX`, `SLOT`, or `DISP`, on the added or modified lines of preprocessor scripts and helpers. Trace each one to where it is used.
2. Decide whether each value is a game-layout fact (it changes when Valve reorders a class, struct, or vtable) or an ABI/toolchain constant (see "Not in scope").
3. For each game-layout value, confirm the emitted result comes from the current binary through a repository mechanism: Pattern L (`_indirect_vcall_target_common.py`) scanning a thunk or caller with exactly one indirect vcall; Pattern C `LLM_DECOMPILE` `found_vcall` with a mandatory `vfunc_sig`; Pattern F `INHERIT_VFUNCS` from a base YAML whose slot was itself derived; Pattern E/`offset_sig` for struct members; Pattern I/J/K slot scans; or old-gamever reuse that is re-validated by a signature match on the new binary.
4. Compare the anchor with the PR request. When the PR body asks for a specific predecessor or pattern, a script that swaps in another predecessor plus a constant does not satisfy the request.

### Not in scope

- ABI/toolchain constants that do not depend on game layout: pointer size and vtable slot stride `8`, the Itanium vtable address point `0x10`, and RTTI/PE/ELF format parsing constants.
- Pattern H's `LINUX_EXPECTED_OFFSET_TO_TOP`, used only as a match key to select a secondary vtable. It is documented in `create-preprocessor-scripts`, never emitted, and a mismatch fails loudly.
- Pre-existing base-tree constants that the PR does not add or modify.

### Finding rule

Raise a blocking `P1` finding whenever a fixed game-layout offset decides an emitted value or the target's identity. A presence-check "verification" does not clear the finding. Neither does a green exact-byte artifact rebuild: the constant reproduces today's bytes by construction, and after a layout shift the presence check will likely still match some unrelated displacement and silently emit the wrong slot. The repair must replace the constant with one of the derivation mechanisms from the review method, anchored on the predecessor the PR requested.

Canonical example: PR #989 ([review comment](https://github.com/HLND2T/CS2_VibeSignatures/pull/989#discussion_r4118387913), "**Fixed offset** is not allowed!!!"). `find-INetworkSystem_GetLocalAdr.py` declared `VFUNC_OFFSETS = {"windows": 0x110, "linux": 0x108}` and scanned `CNetworkGameServerBase_Init` only to check that the constant appeared among any 8-byte-aligned `[reg+disp]` operand `<= 0x200`. It then wrote the constant as `vfunc_offset`/`vfunc_index`. It also replaced the requested `LLM_DECOMPILE` anchor, `INetworkGameServer_GetServerNetworkAddress`, with a different predecessor.
