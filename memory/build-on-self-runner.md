---
title: build-on-self-runner
type: note
permalink: cs2-vibesignatures/build-on-self-runner
---

# Build On Self Runner

## Overview
`.github/workflows/build-on-self-runner.yml` is the credential-minimized Release producer for an immutable default-branch source SHA. It performs a fresh full `-force_all -rename` rebuild against tracked `bin_artifacts`, derives credential-free release-local assets from the committed tree, then hands exact bytes to hosted verification and protected publishers.
## Responsibilities
- Preflight an allowlisted repository/source SHA, complete GAMEVER artifact inventory, binary/download identity, and the
  exact `s2sdk` gitlink stored in that source commit.
- Restore binary-only accepted state and the exact warm IDB generation.
- Rebuild the complete GAMEVER in an empty checkout-external artifact root and compare it with Git truth under the anchor drift contract; derive every published asset from the committed `bin_artifacts` tree.
- Apply rename/comment side effects only to release-local IDB state.
- Generate snapshot, metadata, gamedata, C++ evidence, archives, checksums, Release manifest.
- Upload stable run-id candidate artifacts for hosted verification; hold no source/Release write credential.
## Involved Files & Symbols
- `.github/workflows/build-on-self-runner.yml` - preflight, warmup, build, verify, and publisher DAG.
- `release_source_preflight.py`, `release_artifact_rebuild.py` - immutable source and fresh rebuild contracts.
- `release_bundle.py` - exact archive/manifest construction and hosted verification; the published artifact root is always tracked `bin_artifacts`.
- `gamesymbol_snapshot_lib/anchor_drift.py` - which rebuilt fields may differ from Git truth; read [[anchor_drift]] before changing what the release byte gate tolerates or where published assets are derived from.
- `release_publish.py`, `.github/workflows/publish-release-bundle.yml` - immutable tag/assets publisher.
- `pages_release_input.py` - published Release to Pages handoff.
## Architecture
```text
immutable main SHA preflight
  -> exact warm IDB restore
  -> empty-root full -force_all -rename rebuild
  -> actual artifacts == Git blobs modulo accepted anchor drift
  -> release-local snapshot/gamedata/C++/archives from committed bin_artifacts
  -> hosted verification
  -> protected immutable Release publish
  -> Pages from published assets
```
## Dependencies
- Complete tracked `bin_artifacts/<GAMEVER>`, source-owned `binary_locks/<GAMEVER>.json`, and exact SDK gitlink identity.
- Binary-only accepted cache and immutable warm IDB generation.
- Separate hosted verifier, protected `release` environment, and external repository rulesets.
## Notes
- No generated-output branch/PR, release-staging correctness source, or accepted-bin YAML promotion remains.
- Stable transaction identity is `run_id`; rerun attempt is transport metadata and must not change candidate identity.
- Self-hosted build has read-only source access and no publication credentials. The Release publisher is isolated.
- Release preflight, warmup, and required accepted-bin restore must agree on the same [[binary_lock]] digest. Release preparation
  checks local binary bytes before analysis and again afterward; hosted Release verifiers reload the lock from the
  immutable source SHA.
- C++ validation and the gamedata archive always use the source commit's SDK gitlink; mutable `cs2-<GAMEVER>` branches are
  never runtime Release inputs.
- Same-version published assets are exact-idempotent only; different content must use a new version.
- Preflight parses its JSON with `ConvertFrom-Json -DateKind String`. PowerShell 7 (Json.NET) otherwise coerces the
  ISO-8601 `source_publish_time` into `[datetime]`, so both the format check and the `GITHUB_OUTPUT` value fail.
- The self-hosted Windows runner defines a machine-level `url.http://HZVM:8080/.insteadOf=https://github.com/` git
  proxy and hands out 8.3 short-name temp roots, so tests and path guards must not pin a proxy host or compare a raw
  spelling against a resolved path.
- `source_artifact_mode=tracked` (only from the manual, protected `rebuild-free-release.yml`) skips the fresh
  `-force_all -rename` rebuild and binds the tracked `bin_artifacts/<GAMEVER>` instead: it proves the published
  artifacts equal that source SHA's tracked truth, but never proves they can be rebuilt. The automatic
  `tag-bump-after-merge` path never sets the input, so it always rebuilds.
- Because `warmup-idb.yml` also provisions binaries and syncs accepted-bin, the tracked build job drops `--required`
  from `accepted_bin.py restore` and skips the warmup/preflight binary-lock cross-check; `init_gamebin.py prepare`
  then provisions the binaries and verifies them against the same source-owned `binary_locks/<GAMEVER>.json`, so the
  binary identity guarantee is unchanged.
- Downstream jobs that follow a whole-job skip need `!cancelled()` plus explicit `needs.<job>.result` checks that
  accept `skipped`; a plain `if:` expression is implicitly `success()` and would skip the dependent job instead.
## Full rebuild without prior-version artifacts
- Trigger: a manual release request must rebuild every configured artifact without using any oldgamever artifacts as references or old-signatures sources.
- Root cause: `-force_all` forces producers to execute, but an omitted `-oldgamever` still auto-selects the latest prior version under `-oldartifactdir`.
- Implementation: `.claude/skills/trigger-release-build` accepts `--workflow full-rebuild` and dispatches `build-on-self-runner.yml` with `source_artifact_mode=full-rebuild`. Preparation records `full_rebuild: true`; both the recorded and actual analysis commands use `-oldgamever none` and set `-oldartifactdir` to the fresh checkout-external actual root. The preparation flag is optional for compatibility with existing rebuild preparations.
- Verification: `release_artifact_rebuild._load_execution_report` rejects a full-rebuild report unless `prior_gamever` is null and `old_artifact_root` resolves to the isolated actual root. Focused tests cover CLI dispatch, no baseline lookup, execution-evidence rejection, and unchanged tracked artifacts.
- Scope: `release` retains automatic prior-version reuse and `rebuild-free` remains tracked-only. Static source-controlled preprocessor references, target-version Git comparison/publication truth, warm IDB and protected publication gates still apply to full-rebuild.

## Callers
- Provenance-verified release dispatch for an immutable default-branch source SHA.
- Explicit authorized recovery reruns using the same stable transaction identity.

## Warm IDB archive (issue #1126)
- A rebuilt Release publishes `gamebin-with-idb-<GAMEVER>.7z` beside `gamebin-<GAMEVER>.7z`: the `.i64` of every
  configured binary, staged by `release_bundle._stage_ida_databases` from `bin/<GAMEVER>` (the warm generation
  `idb-restore` placed and `release-analyze` opened; nothing strips it before bundle time). The archive is derived from
  the same `binary_inventory` as the gamebin archive, so its file set is each configured binary's canonical
  `<binary>.i64` and nothing else; a missing database, an unexpected IDA side file, or a symlink fails closed. It uses
  `IDB_ARCHIVE_COMPRESSION_LEVEL = 5` (the ~3.4 GB of databases compresses ~8-14x, far under the 2 GiB asset cap).
- Body is ~400-450 MB per GAMEVER, so it stays under GitHub's 2 GiB per-asset limit.
- `init_gamebin.py check-idb <gamever>` downloads only the manifest+SHA256SUMS and reports whether the archive is
  declared; `prepare --with-idb` downloads, verifies and non-overwritingly merges it. `.claude/skills/init-gamebin`
  probes with `check-idb`, asks the user, then either uses `--with-idb` (and skips the local Warm Up IDB step) or falls
  back to local warmup.
- `verify_release_bundle` keeps the generic `for path, expected in manifest["archives"].items(): _verify_archive(...)`
  round-trip and adds `_verify_idb_archive_inventory`, which binds the archive to `_binary_records(binary_inventory)`.

## Aborted IDA diagnostics and Release IDB staging
- Trigger: run `39408513511`, job `118581256484`, failed in `release-bundle-prepare` with `unexpected warm IDA database file` under `bin/14191/client/.ida-aborted/`; the platform log recorded a graceful-quit `TimeoutError` followed by forced cleanup and quarantine. `server.dll` also produced quarantine data.
- Root cause: `ida_analyze_bin._settle_unpacked_ida_database` intentionally preserves current-launch unpacked database parts beneath each module's `.ida-aborted`; `release_bundle._stage_ida_databases` recursively scanned those diagnostic files as live database candidates.
- Correct approach: exclude only the configured modules' `.ida-aborted` descendants from IDB staging, retain their original bytes, and keep the exact canonical `.i64` inventory. Unexpected live-tree databases, missing canonical databases, and symlinks (including inside quarantine) still fail. Do not widen this exclusion to every hidden directory or treat a quarantined `.i64` as a fallback database.
- Verification: `tests.test_release_bundle.IdaDatabaseStagingTests` covers client/server and Windows/Linux binary names, diagnostic preservation, exact staged inventory, missing canonical databases, unexpected paths, and quarantine symlinks. `ReleaseBundleTests.test_builds_and_hosted_verifies_exact_release_bundle` additionally builds and verifies an archive with quarantine present.
- Scope: Release IDB archive staging only. The MCP shutdown timeout and forensic retention behavior remain independent; an immutable failed-source rerun will not incorporate a later code fix.

## Retired publication integration and manifest compatibility
- Trigger: remove the external synchronization dependency from initialization, bootstrap, and Release publication.
- Constraint: immutable historical Releases are still read together by Pages and compared byte-for-byte on a rerun.
- Current behavior: schema-3 manifests contain no retired publication field; schema-2 readers retain only historical format/notes compatibility, without importing an exporter or querying its remote refs. Original manifest bytes remain checksum inputs.
- Verification, publication, and target preflight execute trusted tools from `github.workflow_sha`; `--repo-root` and expected source identities still bind the selected historical checkout. Running the old checkout's scripts would reject current bundles and restore retired dependency requirements.
- IDA evidence uses `IDA_EVIDENCE_RULE_VERSION = 1`; `IDB_ARCHIVE_RULE_VERSION = 2` retains its historical meaning. Tracked bindings omit runtime/warm IDB identity and archive; rebuilt bindings require them. Current manifests cannot downgrade to a pre-rule binding.
- Bootstrap gate schema 3 contains snapshot/gamedata/C++ digests only; candidate schema 4 invalidates prior temporary candidates for rebuild.
- Verification: Release bundle/publish, Pages mixed-schema hydration, bootstrap, IDB, and cache regression tests. Dedicated old-state suffix filters only prevent cache contamination.
- Scope: repository code and local disposable state; system packages, remote repositories, and published Releases are unchanged.
