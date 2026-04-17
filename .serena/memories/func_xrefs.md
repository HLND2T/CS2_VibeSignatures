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
- 规范化后的配置会传给 `preprocess_func_xrefs_via_mcp` 作为统一 func xref fallback

## Contract
- 旧 tuple schema 不再支持，命中后直接视为非法配置
- `xref_strings`、`xref_gvs`、`xref_signatures`、`xref_funcs` 是正向候选源，多个正向源之间取交集
- `exclude_strings` 与 `exclude_gvs` 是全局排除集合：在正向交集后做差集
- `exclude_signatures` 只在剩余候选函数内部检查，命中即排除该候选函数
- `exclude_strings`、`exclude_gvs` 无命中时不视为失败，只视为空排除集
- `xref_gvs` / `exclude_gvs` 中的每个元素既可以是 gv 符号名，也可以是显式 `0x...` 地址字面量

## Operational notes
- `xref_gvs` / `exclude_gvs` 为符号名时依赖对应 YAML 的 `gv_va`；为显式 `0x...` 地址时直接按 EA 查询 xref
- 显式地址字面量目前按 `0x` 前缀判定；示例：`xref_gvs: ["0x1805407C8"]`
- `xref_funcs` / `exclude_funcs` 依赖对应 YAML 的 `func_va`
- `_can_probe_future_func_fast_path` 仅检查真正依赖 YAML 的 func/gv 符号；显式 `0x...` 地址不会阻塞 fast-path
- 纯显式地址的 gv xref 配置即使没有 `new_binary_dir` 也可工作；但只要混入符号型 gv / func 依赖，仍需要对应 YAML 已存在
- `CCSPlayer_MovementServices_ProcessMovement` 使用 `CPlayer_MovementServices_s_pRunCommandPawn` 作为 gv xref 回退源

## Related memories
- `preprocess_common_skill_func_xrefs`：同一配置入口的较新摘要
- `preprocess_func_xrefs_via_mcp`：底层 xref 解析、候选集求交与排除逻辑
