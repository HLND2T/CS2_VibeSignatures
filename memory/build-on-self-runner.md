---
title: build-on-self-runner
type: note
permalink: cs2-vibesignatures/build-on-self-runner
---

# Build On Self Runner

## Overview
`.github/workflows/build-on-self-runner.yml` is the credential-minimized Release producer for an immutable default-branch source SHA. It performs a fresh full `-force_all -rename` rebuild against tracked `bin_artifacts`, derives release-local assets and a credential-free BinSync candidate from the committed tree, then hands exact bytes to hosted verification and protected publishers.
## Responsibilities
- Preflight an allowlisted repository/source SHA, complete GAMEVER artifact inventory, binary/download identity, and the
  exact `hl2sdk_cs2` gitlink stored in that source commit.
- Restore binary-only accepted state and the exact warm IDB generation.
- Rebuild the complete GAMEVER in an empty checkout-external artifact root and compare it with Git truth under the anchor drift contract; derive every published asset from the committed `bin_artifacts` tree.
- Apply rename/comment side effects only to release-local IDB/BinSync state; prove no remote ref changed during build.
- Generate snapshot, metadata, gamedata, C++ evidence, archives, checksums, Release manifest, and canonical BinSync bundles.
- Upload stable run-id candidate artifacts for hosted verification; hold no source/BinSync/Release write credential.
## Involved Files & Symbols
- `.github/workflows/build-on-self-runner.yml` - preflight, warmup, build, verify, and publisher DAG.
- `release_source_preflight.py`, `release_artifact_rebuild.py` - immutable source and fresh rebuild contracts.
- `release_bundle.py` - exact archive/manifest construction and hosted verification; the published artifact root is always tracked `bin_artifacts`.
- `gamesymbol_snapshot_lib/anchor_drift.py` - which rebuilt fields may differ from Git truth; read [[anchor_drift]] before changing what the release byte gate tolerates or where published assets are derived from.
- `binsync_candidate.py`, `binsync_verify.py`, `binsync_publish.py` - credential-free candidate, hosted proof, protected fast-forward publication.
- `release_publish.py`, `.github/workflows/publish-release-bundle.yml` - immutable tag/assets publisher.
- `pages_release_input.py` - published Release to Pages handoff.
## Architecture
```text
immutable main SHA preflight
  -> exact warm IDB restore
  -> empty-root full -force_all -rename rebuild
  -> actual artifacts == Git blobs modulo accepted anchor drift
  -> release-local snapshot/gamedata/C++/archives + BinSync bundles from committed bin_artifacts
  -> hosted verification
  -> protected fast-forward BinSync publish
  -> protected immutable Release publish
  -> Pages from published assets
```
## Dependencies
- Complete tracked `bin_artifacts/<GAMEVER>`, source-owned `binary_locks/<GAMEVER>.json`, and exact SDK gitlink identity.
- Binary-only accepted cache and immutable warm IDB generation.
- Separate hosted verifier, `binsync-release` environment, `release` environment, and external repository rulesets.
## Notes
- No generated-output branch/PR, release-staging correctness source, or accepted-bin YAML promotion remains.
- Stable transaction identity is `run_id`; rerun attempt is transport metadata and must not change candidate identity.
- Self-hosted build has read-only source access and no publication credentials. BinSync and Release publishers are isolated.
- Release preflight, warmup, and required accepted-bin restore must agree on the same [[binary_lock]] digest. Release preparation
  checks local binary bytes before analysis and again afterward; hosted Release/BinSync verifiers reload the lock from the
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
- `source_artifact_mode=tracked` also runs no IDA at all. The only remaining IDB consumer in that mode was the BinSync
  candidate export (`push_binsync_symbols.py` -> `headless_force_push.py` opens the `.i64` via idalib), so dropping
  BinSync and dropping the warm IDB are one decision, not two. The tracked path therefore skips the whole `warmup-idb`
  job, `resolve-consumer-ida`, `restore-idb-cache`, `binsync-prepare`/`upload-binsync-candidate`, `verify-binsync`,
  `publish-binsync`, and `rebuild-free-release.yml`'s BinSync remote provisioning. BinSync symbols are never published
  for such a release.
- Because `warmup-idb.yml` also provisions binaries and syncs accepted-bin, the tracked build job drops `--required`
  from `accepted_bin.py restore` and skips the warmup/preflight binary-lock cross-check; `init_gamebin.py prepare`
  then provisions the binaries and verifies them against the same source-owned `binary_locks/<GAMEVER>.json`, so the
  binary identity guarantee is unchanged.
- The Release manifest keeps `binsync` / `ida_runtime_identity` / `warm_idb_generation` / `warm_idb_cache_key` in its
  exact field set but stores `null` for a tracked binding. `release_bundle.py` enforces the biconditional in both
  `build_release_bundle` and `validate_release_manifest`: a tracked binding must omit that evidence and a rebuilt
  binding must supply it, so a normal release cannot be silently downgraded by omitting CLI arguments.
- `validate_release_manifest` applies that biconditional only to manifests that declare
  `full_rebuild.binding_rule_version` (`release_artifact_rebuild.BINDING_RULE_VERSION`); both producer paths write it
  before digesting, so the whole binding document stays covered by `verification_sha256`. A manifest published before
  the rule existed declares none and is waived from that one rule, because the producer that built it never had the
  choice the rule constrains; every other check still applies to it. The key lives inside `full_rebuild` because the
  top-level field set is compared for strict equality, which any new top-level field would break for all legacy
  manifests. `pages_release_input.py` records the declared version per staged Release in its hydration receipt and warns
  on stderr when a Release is below the enforced version. Regression this fixes: `14180` / `14181` / `14182` are tracked
  bindings that still carry BinSync and warm IDB evidence, so the Pages hydration - which validates every published
  Release - failed wholesale from `9169638f4` until the gate was added.
- Downstream jobs that follow a whole-job skip need `!cancelled()` plus explicit `needs.<job>.result` checks that
  accept `skipped`; a plain `if:` expression is implicitly `success()` and would skip the dependent job instead.
- Missing per-module BinSync remotes for an unpublished GAMEVER are provisioned by
  `init_gamebin.py ensure-binsync-remotes <gamever> --user release-automation`, which reads the authoritative md5 from
  tracked `binary_locks/<GAMEVER>.json` and needs no binary download. `build-on-self-runner.yml` runs it in its own
  `ensure-binsync-remotes` job (`ubuntu-latest`, protected `binsync-remotes` environment, `HLND2T_GH_TOKEN`, pinned to
  the immutable source SHA) gated on `source_artifact_mode != 'tracked'`, and the build job depends on it (`success` or
  `skipped`, like `warmup-idb`). Pinning matters because the remote's `binary_hash` must equal the lock the build
  validates; provisioning off a drifted default branch would create a remote the build then rejects.
- The provisioning job must stay on a hosted runner: the HZVM:8080 read proxy on the self-hosted runner turns a missing
  upstream repository into `502 upstream fetch failed`, so a build-side `git clone` of an unprovisioned remote reports a
  misleading proxy error instead of a missing repo.
- Regression this fixes: `9169638f4` deleted `rebuild-free-release.yml`'s `ensure-binsync-remotes` job (correct for the
  tracked path, which exports no BinSync candidate) but that job was the only CI place that ever created a new GAMEVER's
  remotes, so the next automatic release (`14182b`) failed at `binsync-prepare` on `git clone` with proxy 502. A new
  GAMEVER stays broken until something provisions its 16 remotes; `bootstrap-new-gamever-artifacts.yml` deliberately does
  not (it uses `--bootstrap-local-init` and never writes any remote).

## Full rebuild without prior-version artifacts
- Trigger: a manual release request must rebuild every configured artifact without using any oldgamever artifacts as references or old-signatures sources.
- Root cause: `-force_all` forces producers to execute, but an omitted `-oldgamever` still auto-selects the latest prior version under `-oldartifactdir`.
- Implementation: `.claude/skills/trigger-release-build` accepts `--workflow full-rebuild` and dispatches `build-on-self-runner.yml` with `source_artifact_mode=full-rebuild`. Preparation records `full_rebuild: true`; both the recorded and actual analysis commands use `-oldgamever none` and set `-oldartifactdir` to the fresh checkout-external actual root. The preparation flag is optional for compatibility with existing rebuild preparations.
- Verification: `release_artifact_rebuild._load_execution_report` rejects a full-rebuild report unless `prior_gamever` is null and `old_artifact_root` resolves to the isolated actual root. Focused tests cover CLI dispatch, no baseline lookup, execution-evidence rejection, and unchanged tracked artifacts.
- Scope: `release` retains automatic prior-version reuse and `rebuild-free` remains tracked-only. Static source-controlled preprocessor references, target-version Git comparison/publication truth, warm IDB, BinSync, and protected publication gates still apply to full-rebuild.

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
- `source_artifact_mode=tracked` publishes no IDB archive and its manifest declares none, exactly like the BinSync/warm
  IDB evidence biconditional: it runs no IDA at all, so it has no warm bytes.
- Versioned gating: `release_artifact_rebuild` now exposes `BINSYNC_EVIDENCE_RULE_VERSION = 1`,
  `IDB_ARCHIVE_RULE_VERSION = 2`, and `BINDING_RULE_VERSION = IDB_ARCHIVE_RULE_VERSION = 2`. `validate_release_manifest`
  gates the BinSync evidence rule on `>= 1` and the IDB-archive allowlist on `>= 2`, so a version-1 published manifest
  is still held to the BinSync rule and keeps its four public assets, while a version-2 manifest must add the archive
  (rebuild) or must not (tracked). `pages_release_input.py`'s low-version warning uses `BINSYNC_EVIDENCE_RULE_VERSION`.
  `public_assets` (list) and `archives` (dict) are not strict-equal, so the added file does not break legacy manifests.
- `init_gamebin.py check-idb <gamever>` downloads only the manifest+SHA256SUMS and reports whether the archive is
  declared; `prepare --with-idb` downloads, verifies and non-overwritingly merges it. `.claude/skills/init-gamebin`
  probes with `check-idb`, asks the user, then either uses `--with-idb` (and skips the local Warm Up IDB step) or falls
  back to local warmup. `--with-idb` is orthogonal to `--binsync`.
- `verify_release_bundle` keeps the generic `for path, expected in manifest["archives"].items(): _verify_archive(...)`
  round-trip and adds `_verify_idb_archive_inventory`, which binds the archive to `_binary_records(binary_inventory)`.
