[返回中文 README](../../README_CN.md) | [English](../en/ci-cd.md)

# CI/CD 与 Jenkins 工作流参考

以下 Windows batch 片段展示带 guard 的工作流阶段。

## 下载二进制

```batch
@echo Download latest game binaries

uv run download_depot.py -tag %CS2_GAMEVER%
uv run copy_depot_bin.py -gamever %CS2_GAMEVER% -platform %CS2_PLATFORM%
```

## 分析二进制

GitHub Actions 中的 PR 与 release 分析不允许临时创建 IDB。两个流程都会先调用 reusable
`.github/workflows/warmup-idb.yml` producer。它在隔离 workspace 中准备配置声明的 binaries，根据 binary
inventory 与 IDA 版本生成 cache identity，并且只有在所有 `.i64` 与完整 payload inventory 都通过校验后，
才会把 immutable generation 发布到 `PERSISTED_WORKSPACE/idb-cache/<GAMEVER>/generations/`。

producer 会把精确的 generation 与 cache key 返回调用方。PR/release job 不再从
`PERSISTED_WORKSPACE/bin/<GAMEVER>` 复制 `.i64`，而是恢复该 generation，并使用 `-require_warm_idb` 运行
`ida_analyze_bin.py`。warm cache 缺失、损坏、identity 不匹配或生产失败都会阻止分析；CI 不允许回退到 inline
IDA auto-analysis。因此即使 generated-output PR 尚未合并，普通 PR 也能消费已经发布的 warm cache。

release staging 仍会把分析后的 workspace `bin/<GAMEVER>` 整体复制到 `release-staging`；generated-output PR
合并后，promotion 会事务性替换 accepted `PERSISTED_WORKSPACE/bin/<GAMEVER>`。其中的 `.i64` 属于 release
state，但不再是后续 PR/release 的 cache 来源。

```batch
@echo Analyze game binaries

uv run ida_analyze_bin.py -gamever %CS2_GAMEVER% -agent=claude.cmd -platform %CS2_PLATFORM% -debug
```

## 构建 immutable symbol candidate

```batch
@echo Build the immutable candidate immediately after analysis

set "CANDIDATE_ID=%RANDOM%"
set "CANDIDATE_ROOT=%TEMP%\cs2vibe-%CS2_GAMEVER%-%CANDIDATE_ID%"
set "CANDIDATE_SNAPSHOT=%CANDIDATE_ROOT%\%CS2_GAMEVER%.yaml"
set "CANDIDATE_SESSION=%CANDIDATE_ROOT%\%CS2_GAMEVER%.session.json"
set "GAMEDATA_ROOT=%CANDIDATE_ROOT%\gamedata-candidate"
set "GAMEDATA_SESSION=%CANDIDATE_ROOT%\%CS2_GAMEVER%.gamedata.session.json"
if not exist "%CANDIDATE_ROOT%" mkdir "%CANDIDATE_ROOT%"
uv run gamesymbol_candidate.py build -gamever %CS2_GAMEVER% -bindir bin -configyaml configs/%CS2_GAMEVER%.yaml -output "%CANDIDATE_SNAPSHOT%" -session "%CANDIDATE_SESSION%"
```

## 构建并 guard gamedata candidate

```batch
@echo Build gamedata from the immutable symbol candidate

uv run gamedata_candidate.py build -gamever %CS2_GAMEVER% -build-id %CANDIDATE_ID% -snapshot "%CANDIDATE_SNAPSHOT%" -configyaml configs/%CS2_GAMEVER%.yaml -candidate-root "%GAMEDATA_ROOT%" -session "%GAMEDATA_SESSION%"
uv run gamedata_candidate.py guard -session "%GAMEDATA_SESSION%"
uv run gamesymbol_candidate.py mark -candidate "%CANDIDATE_SNAPSHOT%" -session "%CANDIDATE_SESSION%" -step gamedata
```

## 验证 C++ headers 并发布 candidates

```batch
@echo Validate and publish the guarded candidates

uv run run_cpp_tests.py -gamever %CS2_GAMEVER% -configyaml configs/%CS2_GAMEVER%.yaml -snapshot "%CANDIDATE_SNAPSHOT%" -debug
uv run gamesymbol_candidate.py mark -candidate "%CANDIDATE_SNAPSHOT%" -session "%CANDIDATE_SESSION%" -step cpp_tests
uv run gamesymbol_candidate.py publish -candidate "%CANDIDATE_SNAPSHOT%" -session "%CANDIDATE_SESSION%" -snapshot gamesymbols/%CS2_GAMEVER%.yaml
uv run gamedata_candidate.py publish -session "%GAMEDATA_SESSION%" -outputdir gamedata/%CS2_GAMEVER%
```

candidate 状态保证、restore 行为与 pull request 输出规则见 [Snapshot、gamedata 与 C++ 验证](snapshot-and-gamedata.md)。
