[返回中文 README](../../README_CN.md) | [English](../en/requirements.md)

# 依赖与环境配置

## 必需工具

1. [uv](https://docs.astral.sh/uv/getting-started/installation/)
2. [DepotDownloader](https://github.com/SteamRE/DepotDownloader)，并确保原生 `DepotDownloader` 位于 `PATH` 中
3. 一个受支持的 Agent CLI：Claude Code、Codex 或 OpenCode
4. IDA Pro 9.0+
5. [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
6. [idalib](https://docs.hex-rays.com/user-guide/idalib)
7. Clang/LLVM，本地测试需要 `clang++` 位于 `PATH` 中。Windows 推荐使用 [llvm-msvc](https://github.com/backengineering/llvm-msvc)
8. [GitHub CLI](https://cli.github.com/)
9. [binsync](https://github.com/HLND2T/binsync) （可选，必须使用我的fork，你可以clone仓库后让claude/codex帮你从源码安装）

克隆仓库后安装 Python 依赖：

```bash
uv sync
```

## 跨平台自托管 CI

七个自托管 workflow 使用 `[self-hosted, cross-platform]`。将该自定义标签分配给预期的 x64 Ubuntu 或 Windows
runner，每个 job 选择其中一台。两种系统均沿用历史命名的 `win64` Environment 的 secrets 和保护策略。
Linux 使用 Bash，仅 Windows 需要 PowerShell；Actions 要求支持 Node 24 runtime。

Ubuntu 需要有授权的 Linux IDA/Hex-Rays、支持 idalib 的 `python` 与匹配的 `idalib-mcp` 位于宿主 PATH、配置的
agent CLI、Git/GitHub CLI、原生 DepotDownloader，以及现有 S3 服务的网络访问。IDA 应独立于 uv 项目依赖环境，
consumer preflight 会验证版本和 MCP 安装；Release 构建和验证还需要 7-Zip（`7z`）。

C++ CI 运行在 GitHub-hosted `windows-latest` 和 `ubuntu-latest`，使用精确的 source/SDK checkout、配置和 immutable
snapshot，分别初始化 MSVC/Windows SDK 环境和 Linux 编译器，不需要自托管游戏二进制、IDA、S3 凭据或分析 secrets。
