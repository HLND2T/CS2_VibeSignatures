---
title: Steam anonymous depot access only serves the current manifest
type: lesson
permalink: cs2-vibesignatures/lessons/steam-anonymous-depot-access-only-serves-the-current-manifest
tags:
- depot
- steam
- credential
- bump-download
- ci-cd
---

# Steam 匿名账号只能取「当前」manifest，历史 manifest 必须带账密

## 触发信号

- `.github/workflows/bump-download.yml` 的 `bump / Preview download bump` 步骤失败，日志为
  `Failed to authenticate with Steam: Exception of type 'SteamKit2.AsyncJobFailedException' was thrown.`
  紧接着 `Error: InitializeSteam failed`，重试 3 次后 `Error: command failed with exit code 1`（见 run 38107941614）。
- 失败命令形如 `DepotDownloader -app 730 -depot 2347770 -os all-platform -dir <tmp> -username *** -remember-password -manifest-only`。

## 根因 / 约束

- 认证失败来自 **`DEPOTDOWNLOADER_STEAM_USERNAME/PASSWORD` 凭据本身失效**，而不是"缺少凭据"。去掉账密即可绕过。
- Steam 对 app 730（CS2）的 depot manifest 有两套可见性：
  - **当前 default-branch manifest**：匿名（dedicated-server）账号即可取 `-manifest-only` 与文件内容；实测 depot 2347770/2347771/2347773 全部成功。
  - **历史 manifest id**：匿名取会返回 `Encountered 401 for depot manifest <depot> <manifest>`（DepotDownloader 自带提示 `Try logging in with -username as old manifests may not be available for anonymous accounts.`）。实测 `3558451520161040527`、`366892905078765270` 均 401。
- 匿名适用于 bump 发现/登记以及新版本 bootstrap 的当前 public manifest 下载。通用下载器和可能回放历史 GAMEVER 的 warmup 仍须保留账号能力；不能根据 download.yaml 最后一项就保证目标仍是 Steam 当前版本。

## 正确做法

- bump 路径（`bump_download.py`、`bump-enroll`/`bump-apply`）只请求当前 manifest，不传 `-username/-password/-remember-password`。
- `download_depot.py` 默认保留账密能力；`-anonymous` 或 `DEPOTDOWNLOADER_ANONYMOUS=1` 强制忽略环境变量、.env 和命令行中的认证参数。
- `warmup-idb.yml` 的 `depot_anonymous` 默认 false；新 GAMEVER bootstrap 显式传 true，job 同时清空两个 Steam 账密变量。其他历史版本调用保留原有行为。
- 匿名失败时只重试 download.yaml 锁定的 manifest，不退回账号，也不切换到 Steam 新版本。排队期间目标变成历史 manifest 时明确失败；历史重跑使用账号路径。
- 本地验证覆盖匿名环境/CLI 覆盖、默认账号行为，以及下载成功和失败重试时 manifest 不变；尚未运行修改后的远端 CI。

## 验证方式

- 匿名实测：`DepotDownloader -app 730 -depot 2347770 -os all-platform -dir <tmp> -manifest-only`（无账密）成功；用当前 manifest id 对 2347771/2347773 下载文件成功；用历史 manifest id 复现 401。
- `uv run bump_download.py -config download.yaml -configs-dir configs -depotdir <tmp> -dry-run` 在命令行不含任何凭据时返回 0。
- `tests/test_bump_download.py` 用 `assertNotIn("-username"/"-password"/"-remember-password", command)` 锁死不回归。

## 适用范围

- 任何调用 DepotDownloader 拉取 Steam depot manifest/内容的脚本；判定依据是"该路径是否可能命中非当前 manifest"。
- 相关：issue #1130，PR #1131。
