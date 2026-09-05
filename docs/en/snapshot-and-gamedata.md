[Back to README](../../README.md) | [中文](../zh-CN/snapshot-and-gamedata.md)

# Snapshots, gamedata, and C++ validation

Per-symbol YAML under `bin_artifacts/<GAMEVER>/<module>/` is the only normal Git truth. The formal required/optional file set, producer groups, and downstream closure come from `configs/<GAMEVER>.yaml`. `bin/<GAMEVER>/` contains only disposable binaries and analysis cache state.

## Local candidate validation

After analysis has finalized canonical bytes in `bin_artifacts`, build one release-local snapshot candidate. Gamedata and C++ validation consume those same immutable candidate bytes:

```bash
CANDIDATE_DIR="$(mktemp -d)"
CANDIDATE_SNAPSHOT="$CANDIDATE_DIR/14168.yaml"
CANDIDATE_SESSION="$CANDIDATE_DIR/14168.session.json"
GAMEDATA_ROOT="$CANDIDATE_DIR/gamedata-candidate"
GAMEDATA_SESSION="$CANDIDATE_DIR/14168.gamedata.session.json"
uv run gamesymbol_candidate.py build -gamever 14168 -bindir bin -artifactdir bin_artifacts -configyaml configs/14168.yaml -output "$CANDIDATE_SNAPSHOT" -session "$CANDIDATE_SESSION"
uv run gamedata_candidate.py build -gamever 14168 -build-id local-1 -snapshot "$CANDIDATE_SNAPSHOT" -configyaml configs/14168.yaml -candidate-root "$GAMEDATA_ROOT" -session "$GAMEDATA_SESSION"
uv run gamedata_candidate.py guard -session "$GAMEDATA_SESSION"
uv run gamesymbol_candidate.py mark -candidate "$CANDIDATE_SNAPSHOT" -session "$CANDIDATE_SESSION" -step gamedata
uv run run_cpp_tests.py -gamever 14168 -configyaml configs/14168.yaml -snapshot "$CANDIDATE_SNAPSHOT"
uv run gamesymbol_candidate.py mark -candidate "$CANDIDATE_SNAPSHOT" -session "$CANDIDATE_SESSION" -step cpp_tests
```

These commands do not publish tracked snapshot/gamedata directories. Release builds reconstruct the same candidate from an immutable source SHA, verify a fresh `-force_all -rename` rebuild against Git blobs, and package snapshot, metadata, gamedata, archives, and checksums as immutable Release assets.

Use the project-level `fix-cppheaders` skill to repair reported `hl2sdk_cs2` header differences.

## Historical snapshot compatibility

Snapshot restore is rollback/migration compatibility only. It requires an explicit historical snapshot and a checkout-external artifact root; it must never hydrate `bin/` or overwrite tracked `bin_artifacts`:

```bash
uv run gamesymbol_snapshot.py check-contract -gamever 14168 -snapshot path/to/14168.yaml -json
uv run gamesymbol_snapshot.py restore -gamever 14168 -snapshot path/to/14168.yaml -artifactdir D:/isolated/bin_artifacts
```

## Pull-request artifact contract

A source/config/reference change must include the computed affected producer-group and downstream artifact closure under `bin_artifacts/`. A new GAMEVER includes config/download identity and its complete artifacts atomically; the bootstrap publisher may add an artifact-only direct child commit, after which the new PR head must pass validation again.

The default-branch planner binds the exact prospective merge tree. Full validation rebuilds each affected GAMEVER into a checkout-external empty root, verifies producer-group execution evidence and exact Git bytes, then derives snapshot/gamedata/C++ evidence without writing Release outputs to the PR branch. `gamesymbols/`, `gamedata/`, and `release-manifests/` are forbidden tracked namespaces.

## Supported gamedata

### [CounterStrikeSharp](https://github.com/roflmuffin/CounterStrikeSharp)

```text
gamedata/<GAMEVER>/CounterStrikeSharp/config/addons/counterstrikesharp/gamedata/gamedata.json
```

* Full support

* Two symbols are skipped:

- `GameEventManager`: no longer used by CounterStrikeSharp.
- `CEntityResourceManifest_AddResource`: rarely changes on game updates.

### [CS2Fixes](https://github.com/Source2ZE/CS2Fixes)

```text
gamedata/<GAMEVER>/CS2Fixes/gamedata/cs2fixes.jsonc
```

* Full support

* `CCSPlayerPawn_GetMaxSpeed` is skipped because it has been inlined into it's caller in `server.dll`.

### [CS2FOW](https://gitlab.com/karola3vax-group/cs2fow)

```text
gamedata/<GAMEVER>/CS2FOW/gamedata/cs2fow.games.txt
```

* Full support

### [swiftlys2](https://github.com/swiftly-solution/swiftlys2)

```text
gamedata/<GAMEVER>/swiftlys2/plugin_files/gamedata/cs2/core/offsets.jsonc
gamedata/<GAMEVER>/swiftlys2/plugin_files/gamedata/cs2/core/signatures.jsonc
```

* Partial support

### [plugify](https://github.com/untrustedmodders/plugify-plugin-s2sdk)

```text
gamedata/<GAMEVER>/plugify-plugin-s2sdk/assets/gamedata.jsonc
```

* Partial support

### [cs2kz-metamod](https://github.com/KZGlobalTeam/cs2kz-metamod)

```text
gamedata/<GAMEVER>/cs2kz-metamod/gamedata/cs2kz-core.games.txt
```

* Partial support

### [modsharp](https://github.com/Kxnrl/modsharp-public)

```text
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/core.games.jsonc
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/engine.games.jsonc
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/EntityEnhancement.games.jsonc
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/log.games.jsonc
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/server.games.jsonc
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/tier0.games.jsonc
```

* Partial support

### [CS2Surf/Timer](https://github.com/CS2Surf-CN/Timer)

```text
gamedata/<GAMEVER>/cs2surf/gamedata/cs2surf-core.games.jsonc
```

* Partial support
