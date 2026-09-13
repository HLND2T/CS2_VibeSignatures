[Back to README](../../README.md) | [中文](../zh-CN/ci-cd.md)

# CI/CD and Jenkins workflow reference

## Pull requests and Merge Queue

`source-artifact-required.yml` runs the default-branch planner against the exact prospective merge tree. Light changes run hosted tests. Full changes compute affected producer groups and downstream closure, then `pr-self-runner.yml` performs an empty-root rebuild for every affected GAMEVER and compares the result byte-for-byte with `bin_artifacts` Git blobs.

Source/config/reference PRs therefore include their computed `bin_artifacts` changes. PR CI never writes `gamesymbols/`, `gamedata/`, or release manifests back to the branch. New GAMEVER bootstrap is the only source-branch writer: a hosted, environment-protected publisher may fast-forward only `bump-download/<GAMEVER>`, and the artifact-bearing head must pass validation again.

The stable required checks are `source-artifact-required` and `pr-validate`. Merge Queue validation must additionally be installed as a GitHub ruleset Required Workflow (or another external trust root) so a prospective workflow change cannot self-report the required check.

## Warm IDB and accepted binaries

PR and Release analysis call `warmup-idb.yml`. It binds configured binary hashes and the IDA runtime to an immutable cache generation. Accepted-bin materialization is an exact configured-binary cache: YAML, IDA databases, BinSync state, and undeclared side files are rejected. These caches are performance layers, never symbol truth.

## Immutable Release pipeline

After a version source commit reaches the default branch:

1. Source preflight proves the configured GAMEVER has a complete tracked artifact tree.
2. A self-hosted builder performs fresh `-force_all -rename`, verifies exact artifact bytes, and creates credential-free BinSync and Release candidates.
3. Hosted jobs independently verify candidate bundles, archive allowlists, manifests, checksums, C++ evidence, and BinSync target-state identity.
4. The protected BinSync publisher performs fast-forward-only ref updates.
5. The protected Release publisher creates/reuses the source tag, uploads exact immutable assets, publishes once, and dispatches Pages.
6. Pages hydrates only published Release assets, verifies manifest/SHA256SUMS/archive inventories, builds all released versions, and verifies CDN bytes.

The workflow transaction identity is stable across GitHub reruns (`run_id`); `run_attempt` is transport metadata only.
`publish` never replaces published content. Manual standard and rebuild-free workflows also offer `republish`;
automatic flows continue to use `publish`. The trigger CLI accepts `--mode republish` with either build path.

`republish` requires an existing mutable Release and its direct commit tag. It preserves the Release ID and tag URL,
converts the Release to a draft, moves the tag with an explicit old-SHA lease, updates metadata and reconciles assets,
then verifies exact bytes and BinSync targets before publishing and dispatching Pages. Asset IDs may change. Missing
targets must use `publish`; GitHub `immutable: true` Releases are rejected. Full source/bundle verification still applies.
The target is checked before BinSync publication and checked again by the Release publisher. Moving the tag orphans the
draft, so the metadata update rebinds the real tag name before any tag-addressed asset work, and a rerun repairs an
orphaned draft left behind by an interrupted republish.

Downloads are temporarily unavailable while the Release is a draft. An upload or verification failure leaves that draft
for a same-bundle rerun to resume; no automatic old-content rollback is performed. If publication succeeded but its final
verification fails, the publisher attempts to restore draft status and reports any recovery failure. Inspect the receipt
in logs/job summary (Release ID, old/new SHA, bundle digest and stage) before recovery. A fresh CLI dispatch selects the
current `origin/main`; rerun the existing publication job to reuse its bundle. Both modes share the per-version lock.

See [Snapshots, gamedata, and C++ validation](snapshot-and-gamedata.md) for local candidate commands and artifact ownership.
