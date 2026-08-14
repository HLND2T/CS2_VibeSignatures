# Preprocessor PR Review Patterns

Use this reference for changes to `ida_preprocessor_scripts/`, `configs/`, analysis reference YAML, or generated symbol snapshots.

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
- renamed interface/concrete symbols are reflected in symbol declarations, aliases, reference annotations, snapshots, and gamedata consumers;
- generated output changes are a consequence of the design change, not the only evidence supporting it.

Treat a green snapshot comparison as necessary but insufficient: it validates reproducibility of the current config, not semantic symbol ownership or efficient analysis design.
