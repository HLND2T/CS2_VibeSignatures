[返回中文 README](../../README_CN.md) | [English](../en/requirements.md)

# 依赖与环境配置

## 必需工具

1. [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. [DepotDownloader](https://github.com/SteamRE/DepotDownloader)，并确保 `depotdownloader.exe` 位于 `PATH` 中
3. 一个受支持的 Agent CLI：Claude Code、Codex 或 OpenCode
4. IDA Pro 9.0+
5. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
6. [idalib](https://docs.hex-rays.com/user-guide/idalib)
7. Clang/LLVM，并确保 `clang` 位于 `PATH` 中。推荐安装 [llvm-msvc](https://github.com/backengineering/llvm-msvc)
8. [binsync](https://github.com/binsync/binsync)

克隆仓库后安装 Python 依赖：

```bash
uv sync
```

## 初始化最新游戏版本的 binaries

对于新检出的仓库，在运行符号分析前请使用 `SKILL: init-gamebin` 初始化 `download.yaml` 中最新游戏版本的
binaries。请明确这样请求 agent：

```text
Use SKILL: init-gamebin to initialize the latest game version's binaries.
```

该 skill 会从仓库版本列表解析最新的游戏版本号，下载或合并对应的 binaries 且不会覆盖已有文件，然后委托
`restore-from-snapshot` 恢复 symbol YAML。如果没有指定游戏版本，skill 会先列出可用版本并要求用户选择。

## 故障排查

### `error: could not create 'ida.egg-info': access denied`

在以下目录中以管理员权限运行 `python py-activate-idalib.py`：

```text
C:\Program Files\IDA Professional 9.0\idalib\python
```

### `Could not find idalib64.dll in .........`

为当前 shell 设置 `IDADIR`，或将其添加到系统环境变量：

```batch
set IDADIR=C:\Program Files\IDA Professional 9.0
```
