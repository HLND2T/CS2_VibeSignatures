# preprocess_common_skill func_xrefs

## Summary
- `preprocess_common_skill` 只接受 `dict` 风格 `func_xrefs`
- 允许字段固定为：
  - `func_name`
  - `xref_strings`
  - `xref_gvs`
  - `xref_signatures`
  - `xref_funcs`
  - `exclude_funcs`
  - `exclude_strings`
  - `exclude_gvs`
  - `exclude_signatures`
- 正向源 `xref_strings` / `xref_gvs` / `xref_signatures` / `xref_funcs` 不能同时为空

## Contract
- 旧 tuple schema 不再支持，命中后直接视为非法配置
- `exclude_strings` 与 `exclude_gvs` 是全局排除集合：在正向交集后做差集
- `exclude_signatures` 只在剩余候选函数内部检查，命中即排除该候选函数
- `exclude_strings`、`exclude_gvs` 无命中时不视为失败，只视为空排除集

## Operational notes
- `xref_gvs` / `exclude_gvs` 依赖对应 YAML 的 `gv_va`
- `xref_funcs` / `exclude_funcs` 依赖对应 YAML 的 `func_va`
- `_can_probe_future_func_fast_path` 需要同时检查 func/gv 依赖 YAML 是否已存在
- `CCSPlayer_MovementServices_ProcessMovement` 使用 `CPlayer_MovementServices_s_pRunCommandPawn` 作为 gv xref 回退源
