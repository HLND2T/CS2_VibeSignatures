# Source-owned binary locks

`<GAMEVER>.json` is the canonical Git-owned identity for every binary declared by
`configs/<GAMEVER>.yaml`. Each lock binds the configured module/platform/path set and complete file hashes to the exact
Steam depot manifests and optional branch selected by `download.yaml`.

The initial 16 locks were deterministically migrated from the immutable historical snapshot blobs at
`1e69d6b963ce6e2e4b9277910de4071343901486`. A second read-only verification compared all 256 configured local binaries
with those locks: 256 matched, with no missing or mismatched files.

For `14167` through `14172`, the binary metadata originated in the repository's historical snapshot backfill. The Git
blobs are immutable and the current binaries independently match them, but this does not constitute an external
cryptographic proof that the bytes came from the declared Steam depot. Later versions also have historical Release
manifest evidence.

Normal new-GAMEVER enrollment must create the lock from a fresh, checkout-external download of the declared depot
manifests before any accepted-bin or warm-IDB cache is trusted. Historical snapshots are a one-shot migration input only.

Reproduce the migration check without rewriting files:

```powershell
uv run python source_binary_lock_bootstrap.py `
  --snapshot-revision 1e69d6b963ce6e2e4b9277910de4071343901486 `
  --check `
  --verify-local-binaries
```
