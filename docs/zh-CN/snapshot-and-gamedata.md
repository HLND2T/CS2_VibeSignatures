[返回中文 README](../../README_CN.md) | [English](../en/snapshot-and-gamedata.md)

# Snapshot、gamedata 与 C++ 验证

单个 symbol YAML 继续作为 ignored 文件保存在 `bin/<GAMEVER>/<module>/`。Git 跟踪的 canonical analysis lockfile 是 `gamesymbols/<GAMEVER>.yaml`，其文件集合由 `configs/<GAMEVER>.yaml` 声明的 required 和 optional YAML 输出推导。

## 生成 gamedata

将 canonical symbol snapshot 转换为按版本保存的 gamedata：

```bash
uv run update_gamedata.py -gamever 14168 -snapshot gamesymbols/14168.yaml -modulesdir gamedata-generators -outputdir gamedata/14168 -download_latest -strict [-debug]
```

## 运行 C++ layout 验证

```bash
uv run run_cpp_tests.py -gamever 14168 -snapshot gamesymbols/14168.yaml [-debug]
```

需要修复报告的 `hl2sdk_cs2` header 差异时，使用项目级 `fix-cppheaders` skill。该 skill 会调用 `run_cpp_tests.py` 获取最新 layout diff，并在修改后验证结果。

## Immutable candidate transaction

top-level analysis transaction 成功后应立即 build 一个 candidate。两个 downstream consumer 只读取同一个 immutable candidate；全部验证成功后，publication 只复制 candidate 的原始字节：

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

## 恢复与验证 snapshot

恢复干净的分析基线，或在不修改 tracked snapshot 的情况下验证当前工作区：

```bash
uv run gamesymbol_snapshot.py restore -gamever 14168
uv run gamesymbol_snapshot.py restore -gamever 14168 -replace
uv run gamesymbol_snapshot.py verify -gamever 14168
uv run gamesymbol_snapshot.py check-contract -gamever 14168 -json
uv run gamesymbol_snapshot.py migrate -gamever 14168
```

默认 restore 只创建缺失的 YAML，并拒绝覆盖语义不同的文件。`-replace` 只删除 `bin/<GAMEVER>/` 下的 YAML，保留二进制和 IDA database，再重建 snapshot 内容。

candidate `build` 与 low-level/bootstrap `pack` 会拒绝缺失 required output 和 undeclared YAML。`verify` 还会强制检查 canonical bytes 与两类 round trip。schema 1 snapshot 隐含冻结的 config digest v1 并保持 byte-stable；新 writer 输出 schema 2，并显式记录带 domain separator 的 config digest v2。

`check-contract` 是只读 trust probe：exit `0` 表示可信，exit `3` 报告 machine-readable untrusted reason；调用、配置和运行错误仍会硬失败。`migrate` 只显式升级已验证的 schema-1 snapshot，且不改变其 `files` payload；restore 和 verify 不会隐式执行迁移。

## Pull request 输出合约

可能影响分析或 gamedata generator 输出的 PR，必须在实际 bytes 变化时同时提交匹配的 `gamesymbols/<GAMEVER>.yaml` 和 `gamedata/<GAMEVER>/` 输出。

PR CI 使用可信的 base snapshot 执行 restore 和 targeted invalidation。base snapshot 缺失时从干净 YAML bootstrap；base snapshot 不可信时输出 warning，并在不恢复 baseline payload 的情况下走同一个 clean full-rebuild 路径。

随后，工作流会 strict-pack actual symbol candidate，将其与 PR head snapshot 比较，再由 actual candidate 构建 guarded gamedata，并与显式 PR head Git revision 中的 raw gamedata blob inventory 比较。head output 只代表 expected result；downstream validation 使用 actual candidate transaction。普通 PR workflow 不会自动修复、stage、commit、publish 或改写缺失的 tracked output。

## 支持的 gamedata

### [CounterStrikeSharp](https://github.com/roflmuffin/CounterStrikeSharp)

```text
gamedata/<GAMEVER>/CounterStrikeSharp/config/addons/counterstrikesharp/gamedata/gamedata.json
```

跳过两个符号：

- `GameEventManager`：CounterStrikeSharp 已不再使用。
- `CEntityResourceManifest_AddResource`：游戏更新时极少变化。

### [CS2Fixes](https://github.com/Source2ZE/CS2Fixes)

```text
gamedata/<GAMEVER>/CS2Fixes/gamedata/cs2fixes.jsonc
```

跳过 `CCSPlayerPawn_GetMaxSpeed`，因为它并不存在于 `server.dll` 中。

### [CS2FOW](https://gitlab.com/karola3vax-group/cs2fow)

```text
gamedata/<GAMEVER>/CS2FOW/gamedata/cs2fow.games.txt
```

CS2FOW 从游戏版本 `14174` 开始生成。server binary size 和 CRC32 与 offsets、RVA 均来自同一个 immutable
symbol snapshot。

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
