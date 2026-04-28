# ida_analyze_bin post_process 设计

日期：2026-04-28

状态：已确认，待实现计划

使用技能：`superpowers:brainstorming`

## 背景

`ida_analyze_bin.py` 当前按 module/platform 处理 IDA pipeline，主要流程是：

1. 读取 `config.yaml` 中 module 的 skills。
2. 根据 `expected_input` / `expected_output` / `skip_if_exists` 判定是否执行 skill。
3. 对待处理 skill 先运行 preprocessing，再在失败时回退到 Claude/Codex skill。
4. skill 和 vcall_finder 处理结束后退出 IDA。

现有 preprocessing 内部有函数和全局变量的即时 rename 逻辑，但它只覆盖 preprocessing 成功写出 yaml 的路径，无法覆盖以下场景：

- YAML 已存在导致 skill 被 skip。
- LLM fallback 生成了 yaml。
- 某些 skill 失败，但 module 内仍有其他有效 output yaml。
- 希望在 module 的所有 skills 完成后统一执行后处理。

## 目标

为 `ida_analyze_bin.py` pipeline 增加 module/platform 级 `post_process` 阶段。

默认 `post_process` 不做任何事，不改变现有行为。当命令行包含 `-rename` 时，post_process 遍历当前 module/platform 的每一个有效 expected output yaml，对 IDA 数据库执行 rename 和注释写入。

一个 module 的所有 skills 完成后，无论单个 skill 成功、失败或跳过，都要进入 post_process 判断。特别地，当 `-rename` 开启且该 module/platform 的所有 skill 都因为 expected output 已存在而被 skip 时，仍然要启动 IDA 并执行 post_process。

## 推荐方案

采用 pipeline 级 post_process 阶段，而不是把逻辑塞进 preprocessing 或拆成独立命令。

原因：

- 符合“所有 skills 完成后执行”的语义。
- 能覆盖已有 yaml、preprocess 生成 yaml、LLM fallback 生成 yaml、部分 skill 失败等多种来源。
- 能保持默认行为为空，降低对现有 pipeline 的影响。
- 与 `process_binary` 当前 module/platform 边界一致，易于统计和验证。

## 命令行与入口

`parse_args` 增加布尔参数：

```text
-rename
```

`main` 将 `args.rename` 传入 `process_binary`。

`process_binary` 增加参数：

```python
rename=False
```

当 `rename=False` 时，post_process 为空操作，现有 “所有输出已存在则不启动 IDA” 行为保持不变。

当 `rename=True` 时，如果当前 module/platform 存在至少一个有效 expected output yaml，即使没有待执行 skill，也要启动 IDA 并在退出前执行 post_process。

## 执行位置

post_process 放在 `process_binary` 的 IDA 生命周期内：

1. 构建当前 module/platform 的 skill 列表。
2. 判定待处理 skills 与已存在 expected outputs。
3. 若有待处理 skill、vcall_finder target，或 `-rename` 下存在有效 output yaml，则启动 IDA。
4. 顺序执行 skill pipeline。
5. 顺序执行 vcall_finder target。
6. 执行 post_process。
7. `quit_ida_gracefully`。

post_process 不作为某个 skill 的成功路径，不依赖单个 skill 的执行结果。

## YAML 收集规则

post_process 只遍历当前 module/platform 的 `expected_output`。

对每个 skill：

1. 使用现有 `expand_expected_paths(binary_dir, skill["expected_output"], platform)` 解析路径。
2. 只保留存在于硬盘上的文件。
3. 只处理可解析为 mapping 的 YAML。
4. 路径必须保持在当前 `binary_dir` 边界内，沿用已有路径安全约束。
5. 去重后按 skill 排序结果和 expected output 顺序稳定处理。

缺失文件、空文件、非 mapping YAML、字段不足或字段解析失败都跳过该文件或该动作，不阻断其他 yaml。

## YAML 动作分派

同一个 YAML 可以触发多个后处理动作。

### VTable rename

匹配字段：

```yaml
vtable_class: CEntFireOutputAutoCompletionFunctor
vtable_va: '0x1817617a8'
```

动作：

```text
0x1817617a8 -> CEntFireOutputAutoCompletionFunctor_vtable
```

### Function rename

匹配字段：

```yaml
func_name: CEntFireOutputAutoCompletionFunctor_FireOutput
func_va: '0x180c165c0'
```

普通函数和虚函数共用该规则。

动作：

```text
0x180c165c0 -> CEntFireOutputAutoCompletionFunctor_FireOutput
```

### Global variable rename

匹配字段：

```yaml
gv_name: CCSGameRules__sm_mapGcBanInformation
gv_va: '0x181eff6a8'
```

动作：

```text
0x181eff6a8 -> CCSGameRules__sm_mapGcBanInformation
```

### vfunc_sig comment

匹配字段：

```yaml
func_name: CCSPlayer_ItemServices_DropActivePlayerWeapon
vfunc_offset: '0xb8'
vfunc_sig: 48 FF A0 B8 00 00 00 C3
```

动作：

1. 定位 `vfunc_sig` 的唯一匹配地址。
2. 注释地址为 `match_start + vfunc_sig_disp`，未提供 `vfunc_sig_disp` 时使用 `0`。
3. 注释文本：

```text
0xB8 = 184LL = CCSPlayer_ItemServices_DropActivePlayerWeapon
```

### offset_sig comment

匹配字段：

```yaml
struct_name: CCheckTransmitInfo
member_name: m_nPlayerSlot
offset: '0x240'
offset_sig: 8B 8F ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B F0
offset_sig_disp: 0
```

动作：

1. 定位 `offset_sig` 的唯一匹配地址。
2. 注释地址为 `match_start + offset_sig_disp`，未提供 `offset_sig_disp` 时使用 `0`。
3. 注释文本：

```text
0x240 = 576LL = CCheckTransmitInfo::m_nPlayerSlot
```

## IDA rename 规则

函数 rename 优先使用 ida-pro-mcp `rename` tool 的 `batch.func`：

```python
{"batch": {"func": {"addr": "0x180c165c0", "name": "FunctionName"}}}
```

vtable 和 global variable rename 使用 `py_eval` 调用 `idc.set_name(ea, name, idc.SN_NOWARN)`。该方式与仓库现有 `_rename_gv_in_ida` 保持一致，也适合 vtable 这类 data 地址。

rename 是 best-effort 行为。单个地址 rename 失败时记录错误并继续处理后续动作。

## IDA comment 规则

comment 写入优先使用 ida-pro-mcp `set_comments` tool。参考接口位于：

```text
D:\ida-pro-mcp-fork\src\ida_pro_mcp\ida_mcp\api_modify.py
```

调用形态：

```python
{
    "items": [
        {
            "addr": "0x180a32c60",
            "comment": "0xB8 = 184LL = CCSPlayer_ItemServices_DropActivePlayerWeapon",
        }
    ]
}
```

`set_comments` 会同时尝试设置 disassembly comment 和 Hex-Rays decompiler comment。返回项带 `error` 时，记录该地址失败但继续处理。

如果 `set_comments` tool 不可用、调用级异常或 MCP 连接不可恢复，可以使用 `py_eval` fallback。fallback 只需保证 disassembly comment，不要求复刻 decompiler comment 逻辑。

签名定位必须严格：

- exactly one match：写注释。
- zero match：跳过并记录。
- multiple matches：跳过并记录。

这样避免把注释写到错误地址。

## 注释格式

十六进制 offset 使用大写数字：

```text
0xB8
0x240
```

十进制值固定追加 `LL`：

```text
184LL
576LL
```

完整格式：

```text
0xB8 = 184LL = CCSPlayer_ItemServices_DropActivePlayerWeapon
0x240 = 576LL = CCheckTransmitInfo::m_nPlayerSlot
```

地址字段与 offset 字段支持字符串十六进制或整数。解析失败时跳过该动作。

## 失败语义与统计

post_process 为 best-effort：

- 单个 yaml 解析失败不影响其他 yaml。
- 单个 rename 失败不影响其他动作。
- 单个 comment 失败不影响其他动作。
- 签名不唯一不写注释，不阻断后续处理。

只有以下情况计入 `fail_count += 1`：

- post_process 调用级异常导致整体无法执行。
- MCP 连接不可用且无法恢复。
- `-rename` 已启用，但 post_process 在进入核心流程前发生不可恢复错误。

skill 自身成功、失败、跳过的统计语义保持不变。

## 测试设计

主要补充 `tests/test_ida_analyze_bin.py`。

建议覆盖：

1. `parse_args`：默认 `rename=False`，传入 `-rename` 后为 True。
2. 默认空行为：`rename=False` 且所有 expected output 已存在时，不启动 IDA，不调用 post_process。
3. skip 后处理：`rename=True` 且所有 expected output 已存在时，仍启动 IDA，并调用 post_process。
4. YAML 动作收集：vtable、func、gv、vfunc_sig、offset_sig 都能生成对应 rename/comment 任务。
5. 同一 YAML 多动作：包含 `func_va` 和 `vfunc_sig` 时，同时生成函数 rename 与 vfunc comment。
6. best-effort：缺失文件、损坏 YAML、非 mapping YAML、字段不足、地址解析失败不会阻断有效 YAML。
7. comment API：优先调用 `set_comments`，返回单项 error 时继续。
8. post_process 整体失败：调用级异常计入一次 failure。

不要求真实启动 IDA 的集成测试。单元测试通过 mock `start_idalib_mcp`、`ensure_mcp_available`、MCP session 调用和 post_process helper 来验证 pipeline 行为。

## 非目标

本次不改变 YAML schema。

本次不把 post_process 拆成独立 CLI。

本次不改变现有 preprocessing 的即时 rename 行为；后续实现可按最小改动保留它们。若未来发现重复 rename 造成噪声，再单独设计去重或迁移。

本次不要求处理 `skip_if_exists` 中列出的额外 artifacts；只遍历当前 module/platform 的 expected output yaml。

## 实现注意事项

建议把实现拆成可测试 helper：

- 收集当前 module/platform 的 expected output yaml。
- 从 YAML mapping 生成 rename/comment action。
- 批量执行 function rename。
- 批量执行 data rename。
- 批量定位 signature comment address。
- 批量调用 `set_comments`。
- 在 `process_binary` 中接入 post_process 入口和 `-rename` 下的 IDA 启动条件。

尽量复用现有工具函数和现有路径解析逻辑，避免新增平行的路径解析规则。
