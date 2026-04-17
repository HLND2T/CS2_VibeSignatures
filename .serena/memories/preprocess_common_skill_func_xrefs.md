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
- `xref_gvs` / `exclude_gvs` 中的每个元素既可以是 gv 符号名，也可以是显式 `0x...` 地址字面量

## Operational notes
- `xref_gvs` / `exclude_gvs` 为符号名时依赖对应 YAML 的 `gv_va`；为显式 `0x...` 地址时直接按 EA 查询 xref
- `xref_funcs` / `exclude_funcs` 依赖对应 YAML 的 `func_va`
- `_can_probe_future_func_fast_path` 仅检查真正依赖 YAML 的 func/gv 符号；显式 `0x...` 地址不会阻塞 fast-path
- 因此纯显式地址的 gv xref 配置即使没有 `new_binary_dir` 也可工作；但只要混入符号型 gv / func 依赖，仍需要对应 YAML 已存在
- `CCSPlayer_MovementServices_ProcessMovement` 使用 `CPlayer_MovementServices_s_pRunCommandPawn` 作为 gv xref 回退源
