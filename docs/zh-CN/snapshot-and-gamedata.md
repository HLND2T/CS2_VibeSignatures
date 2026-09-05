[返回中文 README](../../README_CN.md) | [English](../en/snapshot-and-gamedata.md)

# Snapshot、gamedata 与 C++ 验证

`bin_artifacts/<GAMEVER>/<module>/` 下的 per-symbol YAML 是唯一正常 Git truth。formal required/optional file set、producer groups 与 downstream closure 均由 `configs/<GAMEVER>.yaml` 定义。`bin/<GAMEVER>/` 只保存可删除的 binaries 与 analysis cache state。

## 本地 candidate 验证

analysis 将 canonical bytes finalize 到 `bin_artifacts` 后，构建一份 release-local snapshot candidate；gamedata 与 C++ validation 消费完全相同的 immutable candidate bytes：

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

这些命令不会发布 tracked snapshot/gamedata 目录。Release build 会从 immutable source SHA 重建同一 candidate，使用 fresh `-force_all -rename` 与 Git blobs 做 exact-byte 验证，再将 snapshot、metadata、gamedata、archives 与 checksums 打包为 immutable Release assets。

需要修复 `hl2sdk_cs2` header 差异时，使用项目级 `fix-cppheaders` skill。

## Historical snapshot compatibility

snapshot restore 仅用于 rollback/migration compatibility。必须显式提供 historical snapshot 与 checkout-external artifact root；禁止 hydrate `bin/` 或覆盖 tracked `bin_artifacts`：

```bash
uv run gamesymbol_snapshot.py check-contract -gamever 14168 -snapshot path/to/14168.yaml -json
uv run gamesymbol_snapshot.py restore -gamever 14168 -snapshot path/to/14168.yaml -artifactdir D:/isolated/bin_artifacts
```

## Pull request artifact contract

source/config/reference change 必须同时提交 `bin_artifacts/` 下计算出的 affected producer-group 与 downstream artifact closure。新 GAMEVER 的 config/download identity 和完整 artifacts 必须原子进入同一 PR；bootstrap publisher 可以追加 artifact-only direct-child commit，但新的 PR head 必须重新完成 validation。

default-branch planner 绑定 exact prospective merge tree。full validation 在 checkout-external empty root 中重建每个 affected GAMEVER，验证 producer-group execution evidence 与 exact Git bytes，再派生 snapshot/gamedata/C++ evidence，绝不向 PR branch 写入 Release outputs。Git 禁止跟踪 `gamesymbols/`、`gamedata/` 与 `release-manifests/`。

## 支持的 gamedata

### [CounterStrikeSharp](https://github.com/roflmuffin/CounterStrikeSharp)

```text
gamedata/<GAMEVER>/CounterStrikeSharp/config/addons/counterstrikesharp/gamedata/gamedata.json
```

* 完整支持，所有符号均支持自动更新

* 跳过两个符号：

- `GameEventManager`：CounterStrikeSharp 已不再使用。
- `CEntityResourceManifest_AddResource`：游戏更新时极少变化。

### [CS2Fixes](https://github.com/Source2ZE/CS2Fixes)

```text
gamedata/<GAMEVER>/CS2Fixes/gamedata/cs2fixes.jsonc
```

* 完整支持，所有符号均支持自动更新

* 跳过 `CCSPlayerPawn_GetMaxSpeed`，因为在 `server.dll` 中被内联进了它的唯一调用者。

### [CS2FOW](https://gitlab.com/karola3vax-group/cs2fow)

```text
gamedata/<GAMEVER>/CS2FOW/gamedata/cs2fow.games.txt
```

* 完整支持，所有符号均支持自动更新

### [swiftlys2](https://github.com/swiftly-solution/swiftlys2)

```text
gamedata/<GAMEVER>/swiftlys2/plugin_files/gamedata/cs2/core/offsets.jsonc
gamedata/<GAMEVER>/swiftlys2/plugin_files/gamedata/cs2/core/signatures.jsonc
```

* 仅限部分支持

### [plugify](https://github.com/untrustedmodders/plugify-plugin-s2sdk)

```text
gamedata/<GAMEVER>/plugify-plugin-s2sdk/assets/gamedata.jsonc
```

* 仅限部分支持

### [cs2kz-metamod](https://github.com/KZGlobalTeam/cs2kz-metamod)

```text
gamedata/<GAMEVER>/cs2kz-metamod/gamedata/cs2kz-core.games.txt
```

* 仅限部分支持

### [modsharp](https://github.com/Kxnrl/modsharp-public)

```text
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/core.games.jsonc
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/engine.games.jsonc
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/EntityEnhancement.games.jsonc
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/log.games.jsonc
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/server.games.jsonc
gamedata/<GAMEVER>/modsharp-public/.asset/gamedata/tier0.games.jsonc
```

* 仅限部分支持

### [CS2Surf/Timer](https://github.com/CS2Surf-CN/Timer)

```text
gamedata/<GAMEVER>/cs2surf/gamedata/cs2surf-core.games.jsonc
```

* 仅限部分支持
