# CS2 VibeSignatures

[English README](README.md) | [GUI](https://hlnd2t.github.io/CS2_VibeSignatures/)

CS2 VibeSignatures 用于生成 CS2 signatures 和 offsets，通过 Agent skills 与 MCP calls 更新 HL2SDK_CS2 C++ headers，并生成按版本保存的 downstream gamedata。

本项目的设计目标是在无需人工干预的情况下更新 signatures、offsets 与 C++ headers。目前可自动处理 CounterStrikeSharp、CS2Fixes 及其他受支持项目所需的 signatures 和 offsets。

## 快速开始

先安装[依赖](docs/zh-CN/requirements.md)，再准备并分析一个游戏版本：

```bash
uv sync
uv run download_depot.py -tag 14156
uv run copy_depot_bin.py -gamever 14156 -platform all-platform
uv run ida_analyze_bin.py -gamever 14156 -oldgamever 14155
```

这些命令会填充 `bin/<GAMEVER>/`，并运行已配置的确定性、LLM-assisted 与 Agent-assisted 分析。发布 tracked output 前，还需继续执行 immutable candidate、gamedata 与 C++ 验证流程。

## 工作流

1. [下载 CS2 depot 并复制目标二进制](docs/zh-CN/analysis.md)。
2. [分析 `configs/<GAMEVER>.yaml` 声明的符号](docs/zh-CN/analysis.md)。
3. [构建同一个 immutable symbol 与 gamedata candidate](docs/zh-CN/snapshot-and-gamedata.md)。
4. [针对该 candidate 运行 C++ layout 验证](docs/zh-CN/snapshot-and-gamedata.md)。
5. [发布验证后的 snapshot 与版本化 gamedata](docs/zh-CN/snapshot-and-gamedata.md)。

canonical tracked output 是 `gamesymbols/<GAMEVER>.yaml` 与 `gamedata/<GAMEVER>/`。单个 symbol 的分析 YAML 仍作为私有可变状态保存在 `bin/<GAMEVER>/`。

## 文档

- [依赖与环境配置](docs/zh-CN/requirements.md)
- [开发检查：格式化与测试](docs/zh-CN/development.md)
- [二进制获取与符号分析](docs/zh-CN/analysis.md)
- [进度上报、调度与看板](docs/zh-CN/process-monitoring.md)
- [`LLM_DECOMPILE` reference YAML](docs/zh-CN/reference-yaml.md)
- [Snapshot、gamedata 与 C++ 验证](docs/zh-CN/snapshot-and-gamedata.md)
- [创建符号分析 skill](docs/zh-CN/creating-skills.md)
- [CI/CD 与 Jenkins 工作流参考](docs/zh-CN/ci-cd.md)

## 支持的 gamedata

本项目为 CounterStrikeSharp、CS2Fixes、CS2FOW、swiftlys2、plugify、cs2kz-metamod、modsharp 和 CS2Surf/Timer 生成按版本保存的 gamedata。具体路径与例外见[支持的 gamedata](docs/zh-CN/snapshot-and-gamedata.md)。
