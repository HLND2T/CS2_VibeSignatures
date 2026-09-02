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

The workflow transaction identity is stable across GitHub reruns (`run_id`); `run_attempt` is transport metadata only. Published tags/assets are never clobbered or republished with different content.

See [Snapshots, gamedata, and C++ validation](snapshot-and-gamedata.md) for local candidate commands and artifact ownership.
