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

```json
{
  "schema_version": 1,
  "gamever": "14176",
  "file": "swiftlys2/plugin_files/gamedata/cs2/core/signatures.jsonc",
  "summary": {"total": 63, "covered": 24, "updated": 16},
  "entries": [
    {"name": "CBaseEntity::DispatchSpawn", "covered": true, "updated": true,
     "changes": [{"path": ["CBaseEntity::DispatchSpawn", "windows"], "before": "...", "after": "...", "line": 44}]},
    {"name": "SomeCoveredUnchanged", "covered": true, "updated": false},
    {"name": "UpstreamOnly", "covered": false, "updated": false}
  ]
}
```

## 实现

- `gamedata_metadata.py` - `write_file_metadata` / `compute_file_metadata`。按扩展名分派：
  - `.json` / `.jsonc`：结构叶子 diff + `gamedata_utils._build_jsonc_value_spans` 行号映射。
  - `.txt` VDF（cs2kz）：`vdf.loads` 结构 diff + `_vdf_leaf_lines`（tokenizer 行号索引）。
  - `.txt` 扁平 key=value（CS2FOW）：逐行正则对齐，所有条目 `covered=true`（静态模板整文件从快照重写）。
- `update_gamedata.py:generate_gamedata`：模块循环内 `update()` 前捕获 `before` 文本，`canonicalize_output_text` 后、`validate_output_tree` 前统一生成 metadata；strict 下失败即抛错，非 strict 仅告警。
- `gamedata_contract.py`：`metadata_companion_path`、`expected_inventory_paths`、`validate_output_tree` 均把 `<output>.metadata.json` 同伴纳入新输出预期，故 `gamedata_manifest_sha256` 自动覆盖 metadata，candidate build/guard/publish 与 release manifest 校验端到端一致。
- `release_workflow_lib/manifests.py`：release manifest schema 5 强制 metadata inventory；schema 4 保持 metadata 引入前的 OUTPUT_PATHS 契约，继续验证未回填的历史输出。

## 覆盖分类规则（集中、复用现有谓词）

对每个叶子 `path`，取**第一个**经 `normalize_func_name_colons_to_underscore(seg, alias_to_name_map)` 后命中 `yaml_data` 的段作为条目名；命中即 `covered=true`。这与各 generator 做 name→symbol 匹配同源（`yaml_data` 以 `_` 形式为 key，`alias_to_name_map` 把 `::` 别名映射到 `_`）。未覆盖条目的名字用「最深 section 键之后的那一段」兜底；section 键集（**大小写敏感**）`{Signatures, Offsets, Patches, Signature, Offset, Addresses, VFuncs, VTables, Games, csgo}`——CounterStrikeSharp 的小写 `signatures`/`offsets` 是条目内字段组，刻意排除。文档级 `$schema` 字段不生成 entry。

## Release schema 与历史回填

- schema 4：metadata 引入前的历史 release；验证原始 `OUTPUT_PATHS`，不要求 companion。
- schema 5：metadata release；每个原始输出必须有一个 companion，两个文件都纳入 gamedata/tracked inventory hash。
- 历史版本只在能取得可靠 upstream baseline 时迁移到 schema 5；禁止用 `before=after` 或当前无关 upstream 生成形式合法但语义失真的 metadata。
- `14176` 已用当前 upstream 与对应 snapshot 隔离重建，14 个最终 payload 与已跟踪文件逐字节一致后，真实回填 14 个 companion 并迁移 manifest 到 schema 5。更早版本保持 schema 4，作为可选迁移。

## 已知权衡

- 覆盖分类用 name 级成员关系，忽略签名段的 `library` 精确匹配（极端情况可能把「有 symbol 但 library 不匹配而实际跳过」的签名条目标记为 covered）；如需更精确可在 `gamedata_metadata.py` 补 library 校验。
- VDF 行号由 tokenizer 结构索引，对同名键靠结构层级消歧，正确性有单测 + 对 cs2kz 真实文件核对。
- 覆盖判定是只读启发式，不侵入 8 个 generator 的 `update()`。

## 验证

- `tests/test_gamedata_metadata.py`：三态分类、行号、flat/VDF diff、Plugify `VTables`/`$schema` 边界、写入、legacy inventory。
- 契约回归：`tests/test_gamedata_candidate.py` / `test_update_gamedata.py` / `test_release_workflow.py` / `test_release_gamedata_smoke.py`。
- 端到端：`uv run update_gamedata.py -gamever 14176 -snapshot gamesymbols/14176.yaml -download_latest -strict -outputdir <tmp>`（14 个输出各生成 1 个 `.metadata.json`）。
