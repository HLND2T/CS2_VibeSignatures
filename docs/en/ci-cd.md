[Back to README](../../README.md) | [中文](../zh-CN/ci-cd.md)

# CI/CD and Jenkins workflow reference

## Pull requests and Merge Queue

`source-artifact-required.yml` runs the default-branch planner against the exact prospective merge tree. Light changes run hosted tests. Full changes compute affected producer groups and downstream closure, then `pr-self-runner.yml` performs an empty-root rebuild for every affected GAMEVER and compares the result with `bin_artifacts` Git blobs under the [anchor drift contract](#anchor-drift-contract).

Source/config/reference PRs therefore include their computed `bin_artifacts` changes. PR CI never writes `gamesymbols/`, `gamedata/`, or release manifests back to the branch. New GAMEVER bootstrap is the only source-branch writer: a hosted, environment-protected publisher may fast-forward only `bump-download/<GAMEVER>`, and the artifact-bearing head must pass validation again.

The stable required checks are `source-artifact-required` and `pr-validate`. Merge Queue validation must additionally be installed as a GitHub ruleset Required Workflow (or another external trust root) so a prospective workflow change cannot self-report the required check.

## Workflow artifact retention

Temporary plans, bump/bootstrap candidates, analysis logs, failure diagnostics, and PR C++ inputs/evidence use
`retention-days: 3`, so GitHub expires them three days after upload. Prepared Release assets and finalized bundles
retain their 30-day lifetime; Release C++ inputs/results/evidence retain 14 days; temporary Pages artifacts retain one day.
This policy covers workflow artifacts. GitHub Release assets and S3 binary/IDB caches have separate lifecycles.
The new retention periods apply only to new uploads; existing artifacts keep their original expiry dates.

The three downloads in `pr-self-runner.yml` pin `actions/download-artifact` v6 by full commit SHA, including the
upstream [download-timeout promise rejection fix](https://github.com/actions/toolkit/pull/2124). The old implementation
could leave an incomplete file while reporting a successful download step. After merging this default-branch CI fix,
trigger validation using the new workflow revision; rerunning an old run continues to use its old implementation.

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
and archives a Release publishes are all derived from the committed `bin_artifacts` tree.

## Warm IDB and accepted binaries

PR and Release analysis call `warmup-idb.yml`. It binds configured binary hashes and the IDA runtime to an immutable cache generation. Accepted-bin materialization is an exact configured-binary cache: YAML, IDA databases, legacy analysis state, and undeclared side files are rejected. These caches are performance layers, never symbol truth.

Persistence uses the pinned portable `hzqst/actions-cache` restore/save fork with the bucket
`actions-cache-cs2-vibesignatures`. The `win64` environment supplies `S3_ENDPOINT_URL`,
`S3_ACCESS_KEY_ID`, and `S3_SECRET_ACCESS_KEY`. The URL must be an HTTP(S) origin:
`http://HZVM:8333` becomes `endpoint: HZVM`, `port: 8333`, and `insecure: true`; HTTPS sets it to false.
Runners must support Node 24 actions (also required by the existing `actions/checkout@v5`).
GitHub cache fallback is disabled. An independent lookup checks each upload; required restore failures stop the job.

Keys isolate repositories and the versioned transport namespace. Both runner operating systems use `shared` keys.
Producers restore shared data first, then identity-scoped legacy Windows, Linux and macOS keys; verified legacy
binary caches and IDB generations are published into shared keys without deleting or overwriting old objects.
`cache-restored` includes compatible legacy restores; `cache-hit` means the primary shared key was found.
Depot archives contain
only source-lock-declared download files, keyed by download identity and target selection, never downloader login state.
Accepted binaries use exact source-lock/target keys; restored hits undergo inventory and hash verification.
A depot-only hit materializes accepted binaries before initialization to avoid another download. Keys contain no path
separators, avoiding Windows `path.join` normalization in the action's object naming.
IDB generations retain the existing binary/IDA identity. Each producer creates a fresh lease even on a generation hit.
Immutable generation payloads/manifests and current-run leases are separate objects. Consumers restore the producer's
exact generation, cache key, lease ID, and lease digest, with no fallback selection or upload of analyzed IDBs.

Every job restores into a clean `.ci-cache/store/`; existing `--persisted-root` arguments refer only to this local staging
area. Archive members use workspace-relative paths, independent of runner drives or checkout locations. Transport tools
are checked out separately at the workflow SHA into `.cache-tools/`, including when the source SHA predates this migration.
Local restore still holds a file lock through lease-owner, manifest, and binary/IDB verification, then releases the local
lease. Leases remain valid for 36 days; missing, expired, corrupt, or mismatched selections fail. A GitHub rerun that changes
the attempt must include the producer. Remote leases are immutable transport copies; local release does not update them.

CI no longer prunes shared directories and does not delete remote objects or configure bucket lifecycle rules. Local file
locks are not distributed locks; existing GAMEVER warmup concurrency remains. Cold S3 caches provision and warm again;
pre-S3 shared-directory cache data is neither imported nor deleted. Validate a cold run, a repeat hit, and recovery on a clean
workspace, plus binary/IDA changes, corrupted caches, and S3 failures. GitHub artifacts still carry release candidates and
logs; tracked `bin_artifacts` remain the symbol truth.

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
2. A self-hosted builder performs fresh `-force_all -rename`, verifies the rebuilt artifacts under the [anchor drift contract](#anchor-drift-contract), and creates credential-free Release candidates from committed `bin_artifacts`.
3. Hosted jobs independently verify bundles, archive allowlists, manifests, checksums, and C++ evidence.
4. The protected Release publisher creates/reuses the source tag, uploads exact immutable assets, publishes once, and dispatches Pages.
5. Pages hydrates published assets, verifies manifest/SHA256SUMS/archive inventories, builds all released versions, and verifies CDN bytes.

The self-hosted builder uses `release_bundle.py prepare` to verify local candidate sessions and construct portable
assets without a publication manifest or C++ success claim. `cpp-validation.yml` tests the same snapshot/configuration
and exact source SDK gitlink on hosted Windows and Ubuntu. Its aggregate requires both results and combines logs in
Windows/Linux order. Hosted `release_bundle.py finalize` validates the prepared inventory and evidence identities,
records the combined log hash in the existing `cpp_validation_sha256`, writes final manifest/checksums and verifies
the bundle. New bundles use manifest schema 3; readers also accept published schema-2 manifests without rewriting their bytes. Independent Release verification
also repeats both hosted ABI tests.

PR/full-bridge validation and new-GAMEVER bootstrap use the same hosted gate. Bootstrap creates its canonical candidate
and gate evidence only after both results are accepted, before the protected publisher. Sessions bound to local
paths/inodes stay local; cross-job evidence binds snapshot/configuration/source/SDK content. Old versions without
Linux tests report `no-tests`; an unsupported configured ABI fails.

The workflow transaction identity is stable across GitHub reruns (`run_id`); `run_attempt` is transport metadata only.
`publish` never replaces published content. All three manual build paths also offer `republish`;
automatic flows continue to use `publish`. The trigger CLI accepts `--mode republish` with any build path.

The trigger CLI's `--workflow full-rebuild` dispatches `build-on-self-runner.yml` with
`source_artifact_mode: full-rebuild`. It rebuilds every configured artifact into an empty external root using
`-force_all -rename -oldgamever none`, with the old-artifact root also isolated from tracked artifacts. No prior-version
artifacts serve as references or old-signatures sources; verification rejects execution evidence with a prior GAMEVER
or a non-isolated old-artifact root. The standard `release` path retains automatic prior-version reuse. Both paths
use source-controlled preprocessor references, verify against the target GAMEVER's committed artifacts, and publish
from that committed tree under the same anchor drift contract. Warm IDB handling is the same for both.

A rebuilt Release publishes `gamebin-with-idb-<GAMEVER>.7z` alongside `gamebin-<GAMEVER>.7z`: the warm IDA database
(`<binary>.i64`) of every configured binary, taken from the exact generation the build analyzed against. `init_gamebin.py
check-idb <GAMEVER>` probes that archive for the local `init-gamebin` skill, and `init_gamebin.py prepare --with-idb`
merges it so the slow local warmup can be skipped. The archive is derived from the same binary inventory as the gamebin
archive, so it never depends on whatever database happens to exist on disk.

The manual rebuild-free path (`rebuild-free-release.yml`, `source_artifact_mode: tracked`) publishes the tracked
`bin_artifacts/<GAMEVER>` tree without running IDA or warmup. The build provisions and lock-verifies binaries through
`init_gamebin.py prepare`. Its manifest records null IDA runtime and warm IDB identities and declares no IDB archive.
Rebuilt releases require these identities and the exact configured IDB archive. Historical schema-2 manifests retain
their versioned evidence rules; Pages preserves their original checksums and records each binding rule version.
New schema-3 manifests omit retired publication fields. Bootstrap gate evidence uses schema 3 and candidate schema 4;
older temporary bootstrap candidates must be rebuilt.

`republish` requires an existing mutable Release and its direct commit tag. It preserves the Release ID and tag URL,
converts the Release to a draft, moves the tag with an explicit old-SHA lease, updates metadata and reconciles assets,
then verifies exact bytes before publishing and dispatching Pages. Asset IDs may change. Missing
targets must use `publish`; GitHub `immutable: true` Releases are rejected. Full source/bundle verification still applies.
The target is checked before publication and checked again by the Release publisher. Moving the tag orphans the
draft, so the metadata update rebinds the real tag name before any tag-addressed asset work, and a rerun repairs an
orphaned draft left behind by an interrupted republish. Both checks need push access, because GitHub only lists draft
Releases to tokens that have it.

Downloads are temporarily unavailable while the Release is a draft. An upload or verification failure leaves that draft
for a same-bundle rerun to resume; no automatic old-content rollback is performed. If publication succeeded but its final
verification fails, the publisher attempts to restore draft status and reports any recovery failure. Inspect the receipt
in logs/job summary (Release ID, old/new SHA, bundle digest and stage) before recovery. A fresh CLI dispatch selects the
current `origin/main`; rerun the existing publication job to reuse its bundle. Both modes share the per-version lock.

See [Snapshots, gamedata, and C++ validation](snapshot-and-gamedata.md) for local candidate commands and artifact ownership.
