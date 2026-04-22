# py_eval

## Overview
IDA MCP 的 `py_eval` 会通过类似 `exec(code, exec_globals, exec_locals)` 的双命名空间执行动态生成的 Python 脚本。生成脚本里定义的函数，其 global lookup 使用 `exec_globals`，不会自动看到写入 `exec_locals` 的顶层常量、导入模块或 helper 名称。

## Repeated Pitfall
- 如果 `py_eval` 脚本先定义顶层常量或导入模块，再定义 helper 函数，并在 helper 内引用这些名称，运行时可能报 `NameError`。
- 典型报错：`NameError: name 'SINGLE_MNEMS' is not defined`，即使脚本文本中已经在函数前定义了 `SINGLE_MNEMS`。
- 该问题不只影响常量，也会影响 `FLOAT_EPSILON`、`DOUBLE_EPSILON`、`MEM_OP_TYPES`、导入的模块名以及其他 helper。

## Correct Pattern
- 在所有顶层常量、导入依赖和 helper 函数定义完成后，真正调用 helper 或进入主逻辑前插入：

```python
globals().update(locals())
```

- 推荐位置：最后一个 helper 定义之后、`out = {}` / 主循环 / 主执行逻辑之前。
- 不要只修当前缺失名称；这是 `exec(..., globals, locals)` 作用域模型导致的系统性问题。

## Verification
- 为每个新增的大块 `py_eval` 生成脚本增加测试断言，检查生成的 code 中包含 `globals().update(locals())`。
- 对 float xref 过滤相关回归，当前定向命令为：

```bash
python -m unittest tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport.test_filter_func_addrs_by_float_xrefs_keeps_xref_matches_and_excludes_hits
python -m unittest tests.test_ida_analyze_util.TestFuncXrefsSignatureSupport tests.test_ida_preprocessor_scripts.TestFindCcsPlayerMovementServicesProcessMovement
```

## Related Files
- `ida_analyze_util.py` - 多处生成 `py_eval` 脚本，新增 helper/常量时必须遵守该桥接模式。
- `tests/test_ida_analyze_util.py` - 应覆盖生成脚本是否包含 `globals().update(locals())`。
