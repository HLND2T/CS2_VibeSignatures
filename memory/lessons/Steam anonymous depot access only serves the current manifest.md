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
- 因此匿名化只能用于**永远只取当前版本**的 bump 发现/登记路径；任何可能回放历史 GAMEVER 的路径必须保留账密。

## 正确做法

- bump 路径（`bump_download.py`、`bump-enroll`/`bump-apply`）只请求当前 manifest，**不应**传 `-username/-password/-remember-password`；对应的 `DEPOTDOWNLOADER_STEAM_*` env 也应从 bump job 移除。
- `download_depot.py`（被 `init_gamebin.py` 的 depot fallback 与 release/warmup 使用）会按 `download.yaml` 里的历史 manifest id 下载，**必须保留**账密与 `DEPOTDOWNLOADER_STEAM_*` env。
- 需要"两者兼容"时不要写"匿名失败再带账密重试"——那会把失效凭据重新塞回关键路径；按路径职责静态区分即可。

## 验证方式

- 匿名实测：`DepotDownloader -app 730 -depot 2347770 -os all-platform -dir <tmp> -manifest-only`（无账密）成功；用当前 manifest id 对 2347771/2347773 下载文件成功；用历史 manifest id 复现 401。
- `uv run bump_download.py -config download.yaml -configs-dir configs -depotdir <tmp> -dry-run` 在命令行不含任何凭据时返回 0。
- `tests/test_bump_download.py` 用 `assertNotIn("-username"/"-password"/"-remember-password", command)` 锁死不回归。

## 适用范围

- 任何调用 DepotDownloader 拉取 Steam depot manifest/内容的脚本；判定依据是"该路径是否可能命中非当前 manifest"。
- 相关：issue #1130，PR #1131。
