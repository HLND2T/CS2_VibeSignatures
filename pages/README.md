# CS2 VibeSignatures Process Dashboard

React + TypeScript + Vite implementation of the Process Reporter web dashboard.

## Development

```powershell
npm ci
npm run dev
```

The first visit asks for the Process API address. The default is `http://127.0.0.1:8000`; a different build-time default can be supplied with `VITE_API_BASE_URL`.

Start the local API for Vite development with:

```powershell
$env:CS2VIBE_API_CORS_ORIGINS="http://localhost:5173"
uv run uvicorn process_api:app --host 127.0.0.1 --port 8000
```

## Pages deployment

`esa.jsonc` publishes `dist/` and uses SPA fallback routing. A public Pages application still calls the localhost of the computer running the browser; the CDN cannot reach a different computer's localhost.

Pages development and deployment build from `PAGES_RELEASE_INPUT_ROOT`, a fresh staging tree hydrated from compatible published immutable GitHub Releases. The hydration step revalidates each direct tag/source binding, canonical Release manifest, exact SHA256SUMS and public asset allowlist, then safely extracts only the manifest-bound gamedata subtree. Repository-root `gamesymbols/` and `gamedata/` are not compatibility inputs; development/build fails closed when the explicit Release staging root is absent.

Historical versions without compatible Releases are restored from a pinned `pages-snapshots` commit. `pages/legacy-inputs.json` fixes `archiveCommit`, the complete historical file inventory, the selected game-symbol index entries and the import provenance:

- The build job reads the pinned `archiveCommit` read-only, verifies the checkout SHA and the exact inventory, then supplements the staging tree with every historical `gamedata/<version>/` subtree the triggering Release set does not already provide. An existing whole version is left untouched.
- The archive job reads the same pinned commit and merges all archived `gamesymbols/<version>.<sha256>.json` files into the build output, adding index entries only for historical versions the current Release set does not cover. Current-build entries win for the same version, while archived digests keep the old content-addressed URLs reachable.
- Deployment aborts if any required historical input is missing or fails byte verification. Normal deployments never download historical Release assets, never extract historical 7z files and never write to the archive branch.

The Vite build validates each staged schema-5 snapshot and emits index schema v4. Every symbol and gamedata response remains content-addressed, and after deployment the workflow fetches the public Pages responses and recomputes their bytes so CDN delivery is checked against the exact build.

### Re-deploying an existing Release with updated deployment code (maintainers only)

An automatic `pages-release-published` deployment checks out and builds the deployment code from the triggering Release's `source_sha`, so re-running an old Release keeps running the old Pages code. A manual `workflow_dispatch` may pass `deployment_sha`: a full commit SHA that must already be in trusted `main` history. Pages code, scripts and the pinned historical manifest then come from that commit, while the Release tag, manifest, SHA256SUMS and assets keep being verified against the unchanged `source_sha`. Both commits are recorded in the run summary. The override fails closed before building when the commit is unknown or is not an ancestor of `main`; leaving `deployment_sha` empty reproduces the automatic behavior.

### Updating the pinned historical archive (maintainers only)

`pages/legacy_inputs_tool.py` is the maintainer-only offline importer. The deployment workflow never calls its download or extraction commands.

1. `reproduce-index --source-commit 6ec673d1^ --out index.json` reproduces the pre-switch game-symbol index from the tracked source in an isolated worktree.
2. `archive-gamedata --worktree <dir> --source-archive-commit e8538377… --content-source-worktree <worktree> --content-source-commit <sha> --selection-reason "<why>" --report report.json` downloads the pinned `pages/legacy-gamedata-sources.json` Release assets and verifies their repository, Release/asset identity, size and SHA-256, preflights the 7z listing and extracts only `gamedata/<version>/`, then commits the candidate into a detached worktree recorded on `refs/heads/pages-snapshots-legacy-candidate` without pushing. With `--content-source-worktree` the tool requires a clean git worktree pinned at `--content-source-commit` and archives its `gamedata/` bytes; the report records the source kind, commit, subtree, inventory SHA-256, the reviewer-supplied selection reason and every byte difference (both sides' hashes) against the Release assets. Without it the Release-extracted bytes are archived and the differences list must be empty.
3. `select --reproduced-index index.json --archive-root <worktree> --archive-report report.json … --manifest-out pages/legacy-inputs.json` verifies that the archive worktree HEAD equals the declared commit and that its two data subtrees are byte-clean, validates every selected snapshot body through the Node verifier, and writes the pinned manifest with the content-source provenance embedded under `importProvenance.gamedataSource`.
4. Publish the candidate with a fast-forward push, then pin its full SHA as `archiveCommit`. The workflow cannot be enabled until that commit is reachable from the archive branch.

The recorded checksums prove byte identity of the imported historical assets; they are not build attestations for new-format Releases. The archive commit carries a root `.gitattributes` marking both data subtrees `text eol=lf` so a checkout on any platform yields the exact bytes the manifest pins; without it Windows checkouts would rewrite line endings and fail verification.

The pinned record is spread across two version-controlled files. `pages/legacy-inputs.json` fixes `archiveCommit`, the complete historical inventory, the per-version selected index entries, `excluded[]`, and `importProvenance` (`sourceArchiveCommit`, `importBaseCommit`, `selectedBasis`, the `gamedataSource` selection reason with both-side hashes for every byte difference, and the original Release/asset identities). `pages/legacy-gamedata-sources.json` lists the 14 pinned gamedata Release assets and the 18 excluded pre-canonical versions. Update both whenever the archive changes.

### First enablement and refreshing the pinned archive (maintainers only)

The pinned archive commit must be reachable from `pages-snapshots` before any deployment consumes a manifest that references it:

1. Publish the reviewed archive commit with a fast-forward push; never rewrite published archive history.
2. Merge the pinned manifest together with the scripts and workflow that consume it.
3. Trigger `Deploy Pages` from `main`. Either publish a new Release whose `source_sha` contains the change, or dispatch manually with `deployment_sha` set to the `main` commit that contains it — the manual path needs no new Release.

A refresh follows the same order: run the importer, review its diff/inventory/volume report, publish the new archive commit, then update `archiveCommit` together with the inventory, selected entries and provenance in a PR before deploying.

### Local deployment build and failure modes (maintainers only)

Reproduce the deployment chain locally:

```powershell
# 0. Check out the pinned archive read-only (archiveCommit from pages/legacy-inputs.json)
git clone --filter=blob:none https://github.com/HLND2T/CS2_VibeSignatures.git pages-snapshots
git -C pages-snapshots checkout <archiveCommit>

# 1. Hydrate a fresh verified Release staging tree (the output root must not exist yet)
$env:GH_TOKEN = "<token>"
uv run python pages_release_input.py `
  --repository HLND2T/CS2_VibeSignatures `
  --release-id <id> --release-tag <tag> `
  --source-sha <sha> --manifest-sha256 <sha256> `
  --output-root "$env:TEMP\pages-release-input" `
  --receipt "$env:TEMP\pages-release-input.json"

# 2. Supplement historical gamedata into the staging tree
uv run python pages_legacy_input.py `
  --manifest pages\legacy-inputs.json `
  --archive-root pages-snapshots `
  --staging "$env:TEMP\pages-release-input" `
  --receipt "$env:TEMP\pages-legacy-gamedata.json"

# 3. Build, merge historical game symbols, verify
$env:PAGES_RELEASE_INPUT_ROOT = "$env:TEMP\pages-release-input"
cd pages
npm ci
npm run build
node mergeLegacyGameSymbols.mjs `
  --directory dist/gamesymbols `
  --archive ..\pages-snapshots\gamesymbols `
  --manifest legacy-inputs.json `
  --receipt "$env:TEMP\pages-legacy-gamesymbols.json"
npm run verify:gamesymbols
npm run verify:gamedata
```

Repeated runs must produce byte-identical assets; a second `pages_legacy_input.py` run reports versions it already staged as `skipped_existing` without comparing or overwriting them. Every failure is fail-closed and names the input that disagreed:

- `PAGES_RELEASE_INPUT_ROOT is required for Pages development and builds` (`pages/vite.config.ts`) — the staging root is unset or absent.
- Release hydration rejects a repository outside the allowlist, a Release whose tag/source/manifest SHA disagrees with its manifest, an asset allowlist or `SHA256SUMS` mismatch, or extracted gamedata that differs from the manifest, then removes the staging root it was building.
- The manifest parser rejects non-canonical bytes, duplicate JSON keys, unknown or missing fields, unsafe paths, and unsorted inventories.
- Historical gamedata supplementation aborts on any archive inventory or byte mismatch and removes only the versions it added, leaving existing inputs intact.
- The game-symbol merge aborts on archive inventory drift, same-path different bytes, a selected body that is not indexable schema 3, or an index entry that disagrees with its body, and leaves the previous valid `dist/gamesymbols` in place.
- Deploy-time archive verification compares `rev-parse HEAD` with `archiveCommit` and requires the object to exist; it deliberately performs no ancestry check because the deploy checkout is shallow.
- A Windows checkout that rewrites line endings fails verification. The archive commit marks both data subtrees `text eol=lf`; compare git blob hashes rather than worktree bytes when investigating.
- Post-deploy CDN verification failing means the public response bytes differ from the built `dist`; the run fails after publishing, and the manifests in that run's verification artifact show which asset disagreed.

For an exact Pages origin:

```powershell
$env:CS2VIBE_API_CORS_ORIGINS="https://status.example.com"
$env:CS2VIBE_API_ALLOW_PRIVATE_NETWORK="true"
uv run uvicorn process_api:app --host 127.0.0.1 --port 8000
```

Do not use a wildcard CORS origin with private-network access.

## Verification

```powershell
npm run lint
npm test
npm run build
npm run verify:gamesymbols
npm run test:e2e
```
