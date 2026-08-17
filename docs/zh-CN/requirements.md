[返回中文 README](../../README_CN.md) | [English](../en/requirements.md)

# 依赖与环境配置

## 必需工具

1. [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. [DepotDownloader](https://github.com/SteamRE/DepotDownloader)，并确保 `depotdownloader.exe` 位于 `PATH` 中
3. 一个受支持的 Agent CLI：Claude Code、Codex 或 OpenCode
4. IDA Pro 9.0+
5. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
6. [idalib](https://docs.hex-rays.com/user-guide/idalib)
7. Clang/LLVM，并确保 `clang` 位于 `PATH` 中。推荐使用 [llvm-msvc](https://github.com/backengineering/llvm-msvc)
8. [GitHub CLI](https://cli.github.com/)
9. [binsync](https://github.com/HLND2T/binsync) （可选，必须使用我的fork，你可以clone仓库后让claude/codex帮你从源码安装）

克隆仓库后安装 Python 依赖：

```bash
uv sync
```