[Back to README](../../README.md) | [中文](../zh-CN/snapshot-and-gamedata.md)

# Snapshots, gamedata, and C++ validation

Per-symbol YAML remains ignored under `bin/<GAMEVER>/<module>/`. The Git-tracked canonical analysis lockfile is `gamesymbols/<GAMEVER>.yaml`, whose file set is derived from the required and optional YAML outputs declared by `configs/<GAMEVER>.yaml`.

## Generate gamedata

Convert a canonical symbol snapshot into versioned gamedata:

```bash
uv run update_gamedata.py -gamever 14168 -snapshot gamesymbols/14168.yaml -modulesdir gamedata-generators -outputdir gamedata/14168 -download_latest -strict [-debug]
```

## Run C++ layout validation

```bash
uv run run_cpp_tests.py -gamever 14168 -snapshot gamesymbols/14168.yaml [-debug]
```

Use the project-level `fix-cppheaders` skill to repair reported `hl2sdk_cs2` header differences. The skill runs `run_cpp_tests.py` to collect fresh layout differences and verify the edits.

## Immutable candidate transaction

After a successful top-level analysis transaction, build one candidate immediately. Both downstream consumers read that same immutable candidate; publication copies its original bytes only after both validations succeed:

```bash
CANDIDATE_DIR="$(mktemp -d)"
CANDIDATE_SNAPSHOT="$CANDIDATE_DIR/14168.yaml"
CANDIDATE_SESSION="$CANDIDATE_DIR/14168.session.json"
GAMEDATA_ROOT="$CANDIDATE_DIR/gamedata-candidate"
GAMEDATA_SESSION="$CANDIDATE_DIR/14168.gamedata.session.json"
uv run gamesymbol_candidate.py build -gamever 14168 -bindir bin -configyaml configs/14168.yaml -output "$CANDIDATE_SNAPSHOT" -session "$CANDIDATE_SESSION"
uv run gamedata_candidate.py build -gamever 14168 -build-id local-1 -snapshot "$CANDIDATE_SNAPSHOT" -configyaml configs/14168.yaml -candidate-root "$GAMEDATA_ROOT" -session "$GAMEDATA_SESSION"
uv run gamedata_candidate.py guard -session "$GAMEDATA_SESSION"
uv run gamesymbol_candidate.py mark -candidate "$CANDIDATE_SNAPSHOT" -session "$CANDIDATE_SESSION" -step gamedata
uv run run_cpp_tests.py -gamever 14168 -configyaml configs/14168.yaml -snapshot "$CANDIDATE_SNAPSHOT"
uv run gamesymbol_candidate.py mark -candidate "$CANDIDATE_SNAPSHOT" -session "$CANDIDATE_SESSION" -step cpp_tests
uv run gamesymbol_candidate.py publish -candidate "$CANDIDATE_SNAPSHOT" -session "$CANDIDATE_SESSION" -snapshot gamesymbols/14168.yaml
uv run gamedata_candidate.py publish -session "$GAMEDATA_SESSION" -outputdir gamedata/14168
```

## Restore and verify snapshots

Restore a clean analysis baseline or verify the current workspace without modifying the tracked snapshot:

```bash
uv run gamesymbol_snapshot.py restore -gamever 14168
uv run gamesymbol_snapshot.py restore -gamever 14168 -replace
uv run gamesymbol_snapshot.py verify -gamever 14168
uv run gamesymbol_snapshot.py check-contract -gamever 14168 -json
uv run gamesymbol_snapshot.py migrate -gamever 14168
```

Default restore creates missing YAML and refuses to overwrite semantically different files. `-replace` removes only YAML under `bin/<GAMEVER>/`, preserves binaries and IDA databases, then rebuilds the snapshot contents.

Candidate `build` and low-level/bootstrap `pack` reject missing required outputs and undeclared YAML. `verify` enforces canonical bytes and both required round trips. Schema 1 snapshots imply frozen config digest v1 and remain byte-stable; new writers emit schema 2 with explicit, domain-separated config digest v2.

`check-contract` is a read-only trust probe: exit `0` means trusted, exit `3` reports a machine-readable untrusted reason, and invocation, configuration, or operational errors remain hard failures. `migrate` explicitly upgrades a validated schema-1 snapshot without changing its `files` payload; it never runs implicitly during restore or verify.

## Pull-request output contract

Pull requests that can affect analysis or gamedata generator output must commit matching `gamesymbols/<GAMEVER>.yaml` and `gamedata/<GAMEVER>/` outputs when their bytes change.

PR CI uses a trusted base snapshot for restore and targeted invalidation. A missing base snapshot bootstraps from clean YAML; an untrusted base snapshot emits a warning and takes the same clean full-rebuild path without restoring any baseline payload.

The workflow then strict-packs an actual symbol candidate, compares it with the PR head snapshot, builds guarded gamedata from that actual candidate, and compares its inventory with raw gamedata blobs from the explicit PR head Git revision. Head outputs are expected-only; downstream validation uses the actual candidate transaction. The ordinary PR workflow never repairs, stages, commits, publishes, or rewrites missing tracked outputs.

## Supported gamedata

### [CounterStrikeSharp](https://github.com/roflmuffin/CounterStrikeSharp)

```text
gamedata/<GAMEVER>/CounterStrikeSharp/config/addons/counterstrikesharp/gamedata/gamedata.json
```

Two symbols are skipped:

- `GameEventManager`: no longer used by CounterStrikeSharp.
- `CEntityResourceManifest_AddResource`: rarely changes on game updates.

### [CS2Fixes](https://github.com/Source2ZE/CS2Fixes)

```text
gamedata/<GAMEVER>/CS2Fixes/gamedata/cs2fixes.jsonc
```

`CCSPlayerPawn_GetMaxSpeed` is skipped because it is not present in `server.dll`.

### [CS2FOW](https://gitlab.com/karola3vax-group/cs2fow)

```text
gamedata/<GAMEVER>/CS2FOW/gamedata/cs2fow.games.txt
```

CS2FOW output is generated for game version `14174` and later. Server binary size and CRC32 values come from the
same immutable symbol snapshot as the generated offsets and RVAs.

### [swiftlys2](https://github.com/swiftly-solution/swiftlys2)

```text
gamedata/<GAMEVER>/swiftlys2/plugin_files/gamedata/cs2/core/offsets.jsonc
gamedata/<GAMEVER>/swiftlys2/plugin_files/gamedata/cs2/core/signatures.jsonc
```

### [plugify](https://github.com/untrustedmodders/plugify-plugin-s2sdk)

```text
gamedata/<GAMEVER>/plugify-plugin-s2sdk/assets/gamedata.jsonc
```

### [cs2kz-metamod](https://github.com/KZGlobalTeam/cs2kz-metamod)

```text
gamedata/<GAMEVER>/cs2kz-metamod/gamedata/cs2kz-core.games.txt
```

### [modsharp](https://github.com/Kxnrl/modsharp-public)

```text
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/core.games.jsonc
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/engine.games.jsonc
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/EntityEnhancement.games.jsonc
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/log.games.jsonc
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/server.games.jsonc
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/tier0.games.jsonc
```

### [CS2Surf/Timer](https://github.com/CS2Surf-CN/Timer)

```text
gamedata/<GAMEVER>/cs2surf/gamedata/cs2surf-core.games.jsonc
```
