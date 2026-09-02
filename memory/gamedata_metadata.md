---
title: gamedata_metadata
type: note
permalink: cs2-vibesignatures/gamedata-metadata
---

# gamedata per-entry change metadata

## Overview

每个 versioned gamedata 输出文件旁都会生成一个 `<file>.metadata.json`，记录每一个条目（symbol）相对上游的三种状态，供网页端做 diff 展示。diff 基准是 **上游原始文件 → 我们**（`DOWNLOAD_SOURCES` / `STATIC_SOURCES` 的内容 vs 生成后的最终文件）。

## 三种状态（per entry）

- `covered=false`：我们 gamesymbols 没有对应 symbol，条目保持上游原值（`updated` 恒为 false）。
- `covered=true, updated=false`：有对应 symbol，但快照值与上游值一致，未真正改写。
- `covered=true, updated=true`：有对应 symbol，且值被改写，附带 `changes[]`（每条含叶子 `path`、`before`、`after`、`line`）。

`line` 是**最终文件**里的行号；新增/删除的叶子用 `before: null` / `after: null` 表示。

## Schema

当前 companion 使用 schema v2：

```json
{
  "schema_version": 2,
  "gamever": "14176",
  "file": "swiftlys2/plugin_files/gamedata/cs2/core/signatures.jsonc",
  "summary": {"total": 63, "covered": 24, "updated": 16},
  "entries": [
    {"name": "CBaseEntity::DispatchSpawn", "covered": true, "covered_lines": [43, 44], "updated": true,
     "changes": [{"path": ["CBaseEntity::DispatchSpawn", "windows"], "before": "...", "after": "...", "line": 44}]},
    {"name": "SomeCoveredUnchanged", "covered": true, "covered_lines": [50], "updated": false},
    {"name": "UpstreamOnly", "covered": false, "covered_lines": [], "updated": false}
  ]
}
```

`covered_lines` 是最终文件内该 entry 所有标量叶子值的 1-based、升序、去重行号；uncovered 或最终文件中没有存活叶子的 entry 使用空数组。updated 行仍由 `changes[].line` 给出，前端以 updated 样式覆盖 covered 样式；删除叶子的 `line=null` 保持无行锚点。

## 实现
- `gamedata_metadata.py` - `write_file_metadata` / `compute_file_metadata`；按 JSON/JSONC/VDF/flat text 格式计算叶子 diff 与行号。
- `update_gamedata.py:generate_gamedata` - 在显式 release-local output root 中捕获 upstream baseline、更新 payload、canonicalize 后生成 companion。
- `gamedata_contract.py` - 将 `<output>.metadata.json` 纳入严格 `OUTPUT_PATHS` inventory 与 `gamedata_manifest_sha256`。
- `gamedata_candidate.py` - build/guard 绑定 snapshot/config/generator/payload/metadata bytes；不再提供 tracked publish/verify API。
- `release_bundle.py` - 将 payload/metadata 放入 exact archive allowlist 与 manifest，hosted verifier 独立复验。
## 覆盖分类规则（集中、复用现有谓词）

对每个叶子 `path`，取**第一个**经 `normalize_func_name_colons_to_underscore(seg, alias_to_name_map)` 后命中 `yaml_data` 的段作为条目名；命中即 `covered=true`。这与各 generator 做 name→symbol 匹配同源（`yaml_data` 以 `_` 形式为 key，`alias_to_name_map` 把 `::` 别名映射到 `_`）。未覆盖条目的名字用「最深 section 键之后的那一段」兜底；section 键集（**大小写敏感**）`{Signatures, Offsets, Patches, Signature, Offset, Addresses, VFuncs, VTables, Games, csgo}`——CounterStrikeSharp 的小写 `signatures`/`offsets` 是条目内字段组，刻意排除。文档级 `$schema` 字段不生成 entry。

## Release schema 与历史回填

- release manifest schema 4：metadata 引入前的历史 release；验证原始 `OUTPUT_PATHS`，不要求 companion。
- release manifest schema 5：每个原始输出必须有 companion，并将 payload 与 metadata 一起纳入 gamedata/tracked inventory hash。metadata 文档自身当前是 schema v2；release manifest 仍保持 schema 5。
- 历史版本只在能取得可靠 upstream baseline 时新增 companion，禁止伪造 diff。14175 及更早版本继续保持无 metadata 状态，网页允许浏览正文但禁用 Diff。
- `14176` 的 14 个可信 v1 companion 已通过只读取现有 companion + 最终 payload 的确定性 upgrader 升级到 v2；原有 `summary/changes/before/after/line` 与 payload 字节不变，只增加 `covered_lines` 并重算 release inventory hashes。

## 已知权衡

- 覆盖分类用 name 级成员关系，忽略签名段的 `library` 精确匹配（极端情况可能把「有 symbol 但 library 不匹配而实际跳过」的签名条目标记为 covered）；如需更精确可在 `gamedata_metadata.py` 补 library 校验。
- VDF 行号由 tokenizer 结构索引，对同名键靠结构层级消歧，正确性有单测 + 对 cs2kz 真实文件核对。
- 覆盖判定是只读启发式，不侵入 8 个 generator 的 `update()`。

## 验证
- `tests/test_gamedata_metadata.py`：三态分类、行号、flat/VDF diff、Plugify `VTables`/`$schema` 边界与写入。
- 契约回归：`tests/test_gamedata_candidate.py`、`tests/test_update_gamedata.py`、`tests/test_release_bundle.py`、release integration suite。
- 端到端使用由 `bin_artifacts` 构建的显式 candidate：`uv run update_gamedata.py -gamever <v> -snapshot <temp/candidate.yaml> -outputdir <temp/gamedata/v> -download_latest -strict`。