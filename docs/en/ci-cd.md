[Back to README](../../README.md) | [中文](../zh-CN/ci-cd.md)

# CI/CD and Jenkins workflow reference

## Pull requests and Merge Queue

`source-artifact-required.yml` runs the default-branch planner against the exact prospective merge tree. Light changes run hosted tests. Full changes compute affected producer groups and downstream closure, then `pr-self-runner.yml` performs an empty-root rebuild for every affected GAMEVER and compares the result with `bin_artifacts` Git blobs under the [anchor drift contract](#anchor-drift-contract).

Source/config/reference PRs therefore include their computed `bin_artifacts` changes. PR CI never writes `gamesymbols/`, `gamedata/`, or release manifests back to the branch. New GAMEVER bootstrap is the only source-branch writer: a hosted, environment-protected publisher may fast-forward only `bump-download/<GAMEVER>`, and the artifact-bearing head must pass validation again.

The stable required checks are `source-artifact-required` and `pr-validate`. Merge Queue validation must additionally be installed as a GitHub ruleset Required Workflow (or another external trust root) so a prospective workflow change cannot self-report the required check.

## Anchor drift contract

An `LLM_DECOMPILE` producer asks the model to pick one reference instruction and then expands a deterministic
signature from it, so two equally rule-conformant runs may sample different instructions for the same symbol. PR and
Release validation therefore compare a rebuilt artifact against Git truth under one rule: the symbol identity and the
resolved address or offset must match byte-for-byte, and only the fields describing *how* the symbol was located may
differ.

| category | may drift | pinned |
| --- | --- | --- |
| `gv` | `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp` | `gv_name`, `gv_va`, `gv_rva` |
| `vfunc` | `vfunc_sig`, `vfunc_sig_disp` | `func_name`, `func_va/rva/size`, `func_sig`, `vtable_name`, `vfunc_offset`, `vfunc_index` |
| `structmember` | `offset_sig`, `offset_sig_disp` | `struct_name`, `member_name`, `offset`, `size` |
| `func`, `vtable`, `patch` | nothing | every field |

Search-policy switches (`*_max_match`, `*_allow_across_function_boundary`) stay pinned: tolerating them would accept a
different search rather than an equivalent sampling of the same one. An artifact that omits its resolved fact keeps the
byte-exact gate, because there the signature is the only truth. Every accepted drift is printed per artifact, and any
other difference still fails closed.

Because a rebuild may legitimately differ from the checkout, it is reproducibility evidence only: the snapshot, gamedata,
BinSync projection, and archives a Release publishes are all derived from the committed `bin_artifacts` tree.

## Warm IDB and accepted binaries

PR and Release analysis call `warmup-idb.yml`. It binds configured binary hashes and the IDA runtime to an immutable cache generation. Accepted-bin materialization is an exact configured-binary cache: YAML, IDA databases, BinSync state, and undeclared side files are rejected. These caches are performance layers, never symbol truth.

Warm IDB probe/publish creates a persistent lease under the shared GAMEVER file lock and returns the generation,
cache key, lease ID, and lease SHA-256. The lease binds the repository, producer run/attempt, GAMEVER, generation,
and manifest digest. PR, Release, bootstrap, and bridge consumers use the producer's exact outputs instead of
probing for another selection. Prune honors all live leases while downstream jobs wait. Restore holds the same
lock through verification, copying every binary/IDB, and checking the restored identity; only full success
atomically releases that consumer's lease.

Leases last 36 days, with an additional one-hour clock grace for pruning. Partial restore failures retain protection;
abandoned producers, failed output delivery, and cancelled jobs are eventually reclaimed by expiration.
Missing, released, expired, corrupt, or mismatched leases fail explicitly. Unreadable or corrupt leases also stop
pruning until the storage problem is resolved. After successful restore followed by analysis failure, or when a
GitHub rerun changes the attempt, rerun the full workflow including its producer. Attempt binding applies only to
temporary cache leases; it does not change the Release publication transaction identity below.

Payloads, READY, leases, and file locks now live under `PERSISTED_WORKSPACE/idb-cache-v2/`, isolated from old pruners.
The first use requires fresh warmup. The old `idb-cache/` is neither migrated nor deleted automatically; confirm all
old workflows have finished before cleaning it up. Existing GAMEVER warmup concurrency remains, while file locks
also serialize interleaved producer/consumer access. Rollout validation should interleave producers, pruning, and
restore on two Windows/SMB runners sharing a cache, and observe initial warmup disk usage and duration.

`warmup_idb.py --max-memory-mib <MiB>` (or `IDB_WARMUP_MAX_MEMORY_MIB`) enables memory-aware admission.
Windows uses an aggregate Job Object cap. Linux selects a cgroup v2 child cap when the existing delegation permits
it; otherwise `cap=reservation-only` reports the reason and applies per-worker `RLIMIT_AS` plus a producer-side RSS
watchdog. The fallback has no kernel-enforced aggregate cap; RSS is sampled every two seconds and may overshoot
between samples. No system cgroup delegation settings are changed by the producer. A cgroup sibling must remain
inside the runner's delegated unit; the producer never moves out to its containing systemd slice or bypasses a
memory limit on its source leaf. It restores the source cgroup after warmup.

`IDB_WARMUP_INITIAL_WORKER_RESERVATION_MIB` defaults to 4096 MiB. It controls admission reservation and, in the
fallback, each worker's RSS cap and address-space limit (the latter has a 256 MiB minimum). Tune it for IDA's measured
address-space and resident-memory peaks. Baseline usage plus one reservation must fit within 85% of the total budget
or warmup fails immediately. Unset memory budget disables these controls; already-warm databases skip setup.
Worker limit failures invalidate partial IDBs. This selects by the host OS, not the binary's target platform.

## Immutable Release pipeline

After a version source commit reaches the default branch:

1. Source preflight proves the configured GAMEVER has a complete tracked artifact tree.
2. A hosted job creates and initializes any missing per-module BinSync remotes for the GAMEVER from the tracked binary lock, pinned to the same immutable source SHA and run outside the self-hosted read proxy: a new GAMEVER has no remotes yet, and the builder only clones them.
3. A self-hosted builder performs fresh `-force_all -rename`, verifies the rebuilt artifacts against the tracked tree under the [anchor drift contract](#anchor-drift-contract), and creates credential-free BinSync and Release candidates from the committed `bin_artifacts`.
4. Hosted jobs independently verify candidate bundles, archive allowlists, manifests, checksums, C++ evidence, and BinSync target-state identity.
5. The protected BinSync publisher performs fast-forward-only ref updates.
6. The protected Release publisher creates/reuses the source tag, uploads exact immutable assets, publishes once, and dispatches Pages.
7. Pages hydrates only published Release assets, verifies manifest/SHA256SUMS/archive inventories, builds all released versions, and verifies CDN bytes.

The workflow transaction identity is stable across GitHub reruns (`run_id`); `run_attempt` is transport metadata only.
`publish` never replaces published content. Manual standard and rebuild-free workflows also offer `republish`;
automatic flows continue to use `publish`. The trigger CLI accepts `--mode republish` with either build path.

The manual rebuild-free path (`rebuild-free-release.yml`, `source_artifact_mode: tracked`) publishes the tracked
`bin_artifacts/<GAMEVER>` tree instead of rebuilding it. It analyzes nothing, so it runs no IDA at all: `warmup-idb.yml`,
the BinSync candidate export, and both BinSync verification and publication are skipped whole, and no BinSync remote is
read or written. Binaries are provisioned and lock-verified by the build job's own `init_gamebin.py prepare`. Its Release
manifest records `binsync`, `ida_runtime_identity`, `warm_idb_generation`, and `warm_idb_cache_key` as `null`, and
`release_bundle.py` binds that to the source binding mode both ways: a tracked binding may not claim that evidence, and a
rebuilt binding may not omit it. The binding applies only to manifests that declare `full_rebuild.binding_rule_version`;
a manifest published before the rule existed declares none and is waived from that single rule, so the older tracked
releases that still name BinSync and a warm IDB keep hydrating while every other manifest check still applies to them.
The Pages hydration receipt records the binding rule version of every Release it stages. BinSync symbols are therefore
never published for a rebuild-free release.

`republish` requires an existing mutable Release and its direct commit tag. It preserves the Release ID and tag URL,
converts the Release to a draft, moves the tag with an explicit old-SHA lease, updates metadata and reconciles assets,
then verifies exact bytes and BinSync targets before publishing and dispatching Pages. Asset IDs may change. Missing
targets must use `publish`; GitHub `immutable: true` Releases are rejected. Full source/bundle verification still applies.
The target is checked before BinSync publication and checked again by the Release publisher. Moving the tag orphans the
draft, so the metadata update rebinds the real tag name before any tag-addressed asset work, and a rerun repairs an
orphaned draft left behind by an interrupted republish. Both checks need push access, because GitHub only lists draft
Releases to tokens that have it.

Downloads are temporarily unavailable while the Release is a draft. An upload or verification failure leaves that draft
for a same-bundle rerun to resume; no automatic old-content rollback is performed. If publication succeeded but its final
verification fails, the publisher attempts to restore draft status and reports any recovery failure. Inspect the receipt
in logs/job summary (Release ID, old/new SHA, bundle digest and stage) before recovery. A fresh CLI dispatch selects the
current `origin/main`; rerun the existing publication job to reuse its bundle. Both modes share the per-version lock.

See [Snapshots, gamedata, and C++ validation](snapshot-and-gamedata.md) for local candidate commands and artifact ownership.
