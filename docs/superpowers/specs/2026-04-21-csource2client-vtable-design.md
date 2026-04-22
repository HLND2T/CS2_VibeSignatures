# CSource2Client Linux vtable 未识别函数入口恢复设计

## 背景

当前 `ida_preprocessor_scripts/find-CSource2Client_vtable.py` 通过
`preprocess_common_skill` 间接调用 `ida_analyze_util.py` 中的
`preprocess_vtable_via_mcp`，而实际的 Linux vtable 收集逻辑位于
`_VTABLE_PY_EVAL_TEMPLATE`。

现有模板在扫描 vtable entry 时，若某个槽位指向 `.text` 段，但 IDA 尚未把该地址
识别为函数入口，就会在如下条件下提前停止：

- `idaapi.get_func(ptr_value)` 返回空；
- `ida_bytes.is_code(flags)` 也无法证明该地址已被识别为代码。

这会导致 Linux 下某些合法 vfunc entry 被截断。例如 `CSource2Client` 的
`0x424F8F0 -> 0x17537E0` 槽位实际落在 `.text` 段，但 IDA 把该地址显示为
`qword_17537E0`，从而使当前流程在该处停表，无法继续收集后续虚函数。

## 问题定义

对于 Linux vtable，如果某个 entry 指向可执行段中的未识别代码块，当前流程会把它
当成终止条件，而不是把它视为“需要先恢复函数定义的合法候选入口”。这会带来两个问题：

1. `vtable_entries` 缺失合法虚函数槽位；
2. 该槽位之后的所有 vfunc entries 都无法继续收集。

## 目标

本设计的目标是让 `preprocess_vtable_via_mcp` 能正确处理以下场景：

- 当 vtable entry 指向 `.text` 段中的地址时，优先尝试将其恢复为函数；
- 恢复成功后，把归一化后的真实函数起点写入 `vtable_entries`；
- 继续扫描后续 entry，而不是在首个未定义函数入口处停表。

## 非目标

本次设计不包括以下内容：

- 不修改 `find-CSource2Client_vtable.py` 的 skill 入口结构；
- 不改变 Windows vtable 查找路径；
- 不引入新的 YAML 字段；
- 不放宽“非函数数据不得进入 vtable_entries”的基本约束；
- 不对 vtable 元数据起始定位逻辑做重构，Linux 仍保持 `_ZTV... + 0x10` 和
  `_ZTI...` fallback 规则。

## 推荐方案

采用“在 `_VTABLE_PY_EVAL_TEMPLATE` 内部就地恢复未识别函数”的方案。

### 原因

- 当前 `preprocess_vtable_via_mcp` 已经假定 vtable 解析是一次性 `py_eval` 查询；
- 在模板内完成恢复与归一化，能避免多次 MCP 往返和重复读取；
- 恢复结果可以立即参与当前扫描循环，最容易保证“当前槽位恢复成功后继续向后收集”。

## 详细设计

### 1. 修改位置

唯一需要变更的核心逻辑位于 `ida_analyze_util.py` 的
`_VTABLE_PY_EVAL_TEMPLATE`。`find-CSource2Client_vtable.py` 继续作为薄封装，
无需感知该修复。

### 2. 现有停表条件中保留不变的部分

以下条件仍然维持现有行为：

- entry 值为 `0`：
  - Linux：保留现有逻辑，作为一个可写入的空槽位继续处理；
  - 非 Linux：视为终止；
- entry 值为全 `0xFF`：终止；
- entry 指向无效地址或不存在的 segment：终止；
- entry 指回 vtable 自身所在只读数据段：终止；
- entry 指向非可执行段：终止。

### 3. 可执行段 entry 的新处理逻辑

当 entry 指向可执行段时，按以下顺序处理：

1. 先调用 `idaapi.get_func(ptr_value)`；
2. 若已经存在函数：
   - 记录 `func.start_ea` 到 `vtable_entries`；
   - 继续扫描下一个槽位；
3. 若不存在函数：
   - 将该地址视为“未定义函数入口候选”；
   - 在模板内部尝试定义函数；
   - 重新读取覆盖该地址的函数对象；
   - 若成功得到函数，则记录其 `start_ea`；
   - 若仍失败，则在该槽位终止扫描。

### 4. 归一化规则

写入 `vtable_entries` 的值必须是归一化后的真实函数起点，而不是原始槽位值。

例如：

- 原始 entry 值：`0x17537E0`
- 若定义函数后覆盖函数起点为 `0x17537D5`，则写入 `0x17537d5`
- 若覆盖函数起点仍为 `0x17537E0`，则写入 `0x17537e0`

换言之，YAML 中写入的是“函数起点”，不是“槽位指针原值”。

### 5. 保守恢复策略

为了避免误把纯数据收入 vtable，本设计遵循以下保守原则：

- 仅对“来自 vtable entry 且目标位于可执行段”的地址尝试恢复；
- 仅当恢复后能读到 `idaapi.get_func(ptr_value)` 返回的覆盖函数时，才将其记入；
- 若恢复失败，则立即停表，不继续盲目跳过该槽位；
- 不因为地址落在 `.text` 就直接原样写入。

### 6. 对示例场景的预期行为

针对 `CSource2Client` 的 Linux vtable：

- 扫描到 `0x424F8F0` 时，entry 指向 `0x17537E0`；
- 当前模板不再直接停表；
- 模板尝试将 `0x17537E0` 恢复为函数；
- 成功后写入归一化函数起点；
- 扫描继续前进，收集 `0x424F8F8`、`0x424F900` 及其后的合法 vfunc entries。

## 数据流与接口影响

该改动不改变 `preprocess_vtable_via_mcp` 的 Python 接口，也不改变其返回结构：

- `vtable_class`
- `vtable_symbol`
- `vtable_va`
- `vtable_size`
- `vtable_numvfunc`
- `vtable_entries`

外层 `write_vtable_yaml` 和依赖 vtable YAML 的后续流程无需适配。

## 错误处理

若在恢复过程中出现任一情况，则当前槽位视为终止边界：

- 无法成功创建函数；
- 创建后仍无法读到覆盖该地址的函数；
- 创建出的函数不覆盖当前 entry 指向地址。

在 debug 模式下，应输出足够的信息，帮助判断是“恢复失败”还是“正常停表”。

## 风险与权衡

### 风险

- 某些异常编译产物中，`.text` 段可能包含并非真实函数入口的内容；
- 如果定义函数过于激进，可能把错误边界识别成函数。

### 控制手段

- 仅对 vtable entry 命中的可执行地址做恢复；
- 只有恢复成功并能读取到覆盖函数时才写入；
- 恢复失败仍停表，避免继续污染后续结果。

## 验证标准

### 定向验收

针对你提供的 `CSource2Client` Linux 样例，修复后应满足：

1. `0x424F8F0` 不再导致提前停表；
2. 对应 YAML entry 写入的是归一化后的函数起点；
3. `0x424F8F8`、`0x424F900` 等后续 entry 能继续出现在结果中；
4. `vtable_numvfunc` 相比当前实现增加。

### 回归要求

以下行为不应被破坏：

- 普通已识别函数 entry 的收集行为保持不变；
- Linux `0` 槽位处理行为保持不变；
- Windows vtable 路径行为保持不变；
- 非可执行段或回指只读数据段的 entry 仍然终止。

## 实施摘要

后续实现阶段应在 `_VTABLE_PY_EVAL_TEMPLATE` 中新增一个局部辅助流程，用于：

1. 对可执行段地址尝试读取现有函数；
2. 缺失时调用 IDA 的函数定义能力；
3. 将槽位值归一化为真实函数起点；
4. 仅在恢复成功时把 entry 计入结果。

该实现完成后，`preprocess_vtable_via_mcp` 将能够完整覆盖类似
`CSource2Client` 这类 Linux vtable 中“指向未识别函数入口”的特殊槽位。
