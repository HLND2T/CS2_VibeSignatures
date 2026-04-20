# 为 `IGameSystem_GamePostInit` 增加 slot-only dispatcher 预处理设计

## 背景

当前仓库已经有两类相关预处理能力：

- `ida_preprocessor_scripts/find-IGameSystem_LoopPostInitAllSystems.py`
  - 负责定位并生成 `IGameSystem_LoopPostInitAllSystems` 本体 YAML。
- `ida_preprocessor_scripts/_igamesystem_dispatch_common.py`
  - 负责另一类 IGameSystem dispatch 预处理，其识别模型依赖现有 callback wrapper / odd immediate 规则。

本次目标 `IGameSystem_GamePostInit` 的提取路径与现有 `_igamesystem_dispatch_common.py` 支持的模式不同：

- Windows 场景中，`IGameSystem_LoopPostInitAllSystems` 会调用一个很短的 wrapper，例如 `GameSystem_OnGamePostInit`，再由 wrapper 做 `jmp/call qword ptr [vtable + 0x28]`。
- Linux 场景中，`IGameSystem_LoopPostInitAllSystems` 则直接在循环体内执行 inline vcall，例如 `call qword ptr [rax+28h]`。

这两种形态的共同点是都能稳定推导出同一个 slot 信息：

- `vfunc_offset = 0x28`
- `vfunc_index = 5`
- `vtable_name = IGameSystem`

但它们并不适合直接复用现有 `_igamesystem_dispatch_common.py` 的识别逻辑。因此本次设计新增一个独立 helper，用于“从一个已知 dispatcher 的新生成 YAML 中提取 slot-only vfunc 信息”。

## 目标

- 新增 `ida_preprocessor_scripts/find-IGameSystem_GamePostInit.py`。
- 新增独立 helper，专门处理“从 dispatcher 中抽取 slot-only vfunc”这一模式。
- helper 同时支持：
  - Windows 的 wrapper vcall 形态
  - Linux 的 inline vcall 形态
- helper 支持多个 target，通过 `dispatch_rank` / `multi_order` 从唯一 slot entry 列表中做稳定映射。
- `find-IGameSystem_GamePostInit.py` 仅输出四个字段：
  - `func_name`
  - `vtable_name`
  - `vfunc_offset`
  - `vfunc_index`
- helper 只读取本轮已生成的 dispatcher YAML，不内置 `xref_strings` 搜索逻辑。
- 不修改 `ida_preprocessor_scripts/_igamesystem_dispatch_common.py`。

## 非目标

- 不把本次 helper 扩展成新的“大而全 dispatch 框架”。
- 不修改现有 `find-IGameSystem_LoopPostInitAllSystems.py` 的定位职责。
- 不在新 helper 内复用 `xref_strings` 搜索 dispatcher。
- 不依赖 `IGameSystem_vtable` YAML 来反查目标函数地址。
- 不为首版 helper 增加 rename 行为。
- 不在本次设计中实现更多与 `GamePostInit` 无关的 dispatcher 类型。

## 约束与输入假设

### 1. dispatcher 来源

新 helper 的 dispatcher 输入不是旧版本 YAML，也不是 IDA 当前命名结果，而是本轮已经生成到 `new_binary_dir` 中的 YAML 文件。

具体来说，调用方只提供：

- `dispatcher_yaml_stem`

helper 直接读取：

- `new_binary_dir/{dispatcher_yaml_stem}.{platform}.yaml`

并要求该 YAML 至少包含：

- `func_va`

若文件不存在、不可读或缺少 `func_va`，直接失败。

### 2. slot-only 输出

本次目标只需要 slot 元数据，不需要函数地址、函数大小、函数签名等额外字段。因此 helper 不应额外查询：

- `func_va`
- `func_size`
- `func_sig`
- `IGameSystem_vtable`

### 3. 跨平台一致性

虽然 Windows 和 Linux 的原始 callsite 数量可能不同，但最终输出应当以“去重后的唯一 slot entry 数量”为准，而不是原始 callsite 数量。

对 `IGameSystem_GamePostInit` 来说：

- Windows 可能出现两个 raw callsite，二者都映射到 `0x28`
- Linux 通常只有一个 raw callsite
- 去重后两边都应只剩 1 个 unique slot entry

## 方案对比

### 方案 A：新增专用但可多目标映射的 slot-dispatch helper

新增独立 helper，专门识别“从 dispatcher 中提取 slot-only vfunc 信息”这一模式，内部支持 Windows wrapper 与 Linux inline 两种形态，对外支持多个 target 的 rank/order 映射。

优点：

- 与现有 `_igamesystem_dispatch_common.py` 解耦，不污染既有语义。
- 精确覆盖本次问题，不需要为了兼容旧 helper 而妥协。
- 后续若再出现相同模式的 dispatcher，可直接复用。

缺点：

- 需要维护第二套 helper。

### 方案 B：把全部逻辑直接写进 `find-IGameSystem_GamePostInit.py`

优点：

- 实现最短。

缺点：

- 平台分支、去重、排序、映射逻辑都堆在单脚本里，可维护性差。
- 未来再有同类需求时容易复制粘贴。

### 方案 C：重新抽象一个覆盖更多模式的新 dispatch 框架

优点：

- 理论复用面最大。

缺点：

- 当前需求规模不足以支撑这一抽象。
- 过度设计风险高，且更容易误伤现有预处理路径。

## 结论

采用方案 A：新增独立的 slot-dispatch helper，并在 `find-IGameSystem_GamePostInit.py` 中以薄封装方式使用。

## 文件结构设计

新增两个文件：

- `ida_preprocessor_scripts/_igamesystem_slot_dispatch_common.py`
  - 新 helper，职责是从一个已知 dispatcher 的 YAML 中提取一个或多个 slot-only vfunc 信息。
- `ida_preprocessor_scripts/find-IGameSystem_GamePostInit.py`
  - 本次目标脚本，只声明 dispatcher 依赖与 target spec，并调用新 helper。

保持不变：

- `ida_preprocessor_scripts/find-IGameSystem_LoopPostInitAllSystems.py`
- `ida_preprocessor_scripts/_igamesystem_dispatch_common.py`

## Helper 接口设计

推荐新增入口：

```python
async def preprocess_igamesystem_slot_dispatch_skill(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    dispatcher_yaml_stem,
    target_specs,
    multi_order="index",
    expected_dispatch_count=None,
    debug=False,
):
    ...
```

### 参数说明

- `session`
  - 当前 IDA MCP 会话。
- `expected_outputs`
  - 当前 skill 对应的预期输出 YAML 路径列表。
- `new_binary_dir`
  - 当前模块、当前版本的 YAML 输出目录。
- `platform`
  - `windows` 或 `linux`。
- `dispatcher_yaml_stem`
  - 本轮已生成的 dispatcher YAML stem，例如 `IGameSystem_LoopPostInitAllSystems`。
- `target_specs`
  - 目标映射配置列表。
- `multi_order`
  - 当未显式提供 `dispatch_rank` 时，定义如何从 unique slot entry 列表中做多目标映射。
- `expected_dispatch_count`
  - 期望的“去重后 unique slot entry 数量”。
- `debug`
  - 是否输出调试日志。

### `target_specs` 结构

每个 target spec 为字典，至少包含：

- `target_name`
- `vtable_name`

可选字段：

- `dispatch_rank`

示例：

```python
TARGET_SPECS = [
    {
        "target_name": "IGameSystem_GamePostInit",
        "vtable_name": "IGameSystem",
        "dispatch_rank": 0,
    },
]
```

约束规则：

- `target_specs` 必须非空。
- 若任一条目提供 `dispatch_rank`，则所有条目都必须提供。
- `dispatch_rank` 必须是唯一的非负整数。
- `vtable_name` 不自动推断，必须由调用侧显式提供。

### 返回值

- 成功返回 `True`
- 任一关键步骤失败返回 `False`

helper 不向调用方暴露复杂对象；中间产物只在 helper 内部使用。

## 中间数据模型

helper 内部先收集 raw callsite，再归一化为 unique slot entry。

### raw callsite

raw callsite 用于描述“函数体中某一次原始虚调用命中”，至少包含：

- `source_ea`
- `source_kind`
- `vfunc_offset`
- `vfunc_index`

其中：

- `source_kind` 在 Windows 下通常为 `wrapper`
- `source_kind` 在 Linux 下通常为 `inline`

### unique slot entry

在对 raw callsite 按 `(vfunc_offset, vfunc_index)` 去重后，得到 unique slot entry 列表。映射逻辑只针对这个列表进行，不直接使用原始 callsite 列表。

## 调度脚本设计

`find-IGameSystem_GamePostInit.py` 只做薄封装，推荐声明：

```python
DISPATCHER_YAML_STEM = "IGameSystem_LoopPostInitAllSystems"

TARGET_SPECS = [
    {
        "target_name": "IGameSystem_GamePostInit",
        "vtable_name": "IGameSystem",
        "dispatch_rank": 0,
    },
]

EXPECTED_DISPATCH_COUNT = 1
```

然后直接调用新 helper。

这里的 `EXPECTED_DISPATCH_COUNT = 1` 表示：

- 基于去重后的 unique slot entry 数量做断言
- 不关心 Windows 原始 callsite 是否为 2
- 只关心最终唯一 slot 是否稳定为 1 个

## 提取算法设计

### 总体流程

1. 读取 `new_binary_dir/{dispatcher_yaml_stem}.{platform}.yaml`
2. 提取 `func_va`
3. 在 IDA 中打开 dispatcher 函数范围
4. 扫描 raw callsite
5. 将 raw callsite 归一化为 `{vfunc_offset, vfunc_index}`
6. 按 `(vfunc_offset, vfunc_index)` 去重
7. 对 unique slot entry 按稳定顺序排序
8. 根据 `dispatch_rank` 或 `multi_order` 映射到 `target_specs`
9. 按 slot-only 形式写出目标 YAML

### Windows 识别规则

Windows 下不要求 wrapper 已经拥有稳定名字，例如不要求 IDA 中一定叫 `GameSystem_OnGamePostInit`。helper 应通过函数结构识别：

1. 在 dispatcher 函数体中扫描近调用目标。
2. 对每个候选调用目标，检查其是否为“很短的 wrapper 函数”。
3. 进入 wrapper 后，要求能解析出唯一的最终虚调用形态：
   - `call qword ptr [reg+disp]`
   - 或 `jmp qword ptr [reg+disp]`
4. 将其中的 `disp` 作为 `vfunc_offset`。

推荐接受条件：

- `disp >= 0`
- `disp % 8 == 0`

若 wrapper 中无法唯一解析出上述形态，则该 raw callsite 视为无效。

### Linux 识别规则

Linux 下不复用 `_igamesystem_dispatch_common.py` 中的 odd immediate 规则，而是直接识别 inline vcall：

1. 在 dispatcher 函数体中扫描 `call` 指令。
2. 对候选 `call` 指令检查其操作数是否为形如：
   - `qword ptr [reg+disp]`
3. 进一步验证该 `reg` 来源于对象的 vtable 读取，例如前序存在类似：
   - `mov reg, [object_ptr]`
4. 取 `disp` 作为 `vfunc_offset`。

推荐接受条件同样为：

- `disp >= 0`
- `disp % 8 == 0`

### `vfunc_index` 计算

统一按以下规则计算：

```python
vfunc_index = vfunc_offset // 8
```

并要求：

```python
vfunc_offset % 8 == 0
```

否则直接失败。

## 去重、排序与映射

### 去重规则

先收集 raw callsite，再按以下键做去重：

```python
(vfunc_offset, vfunc_index)
```

对本次 `IGameSystem_GamePostInit`，预期行为为：

- Windows：两个 raw callsite 最终去重为一个 `0x28 / index 5`
- Linux：一个 raw callsite 保持为一个 `0x28 / index 5`

### 排序规则

对去重后的 unique slot entry，按如下键稳定排序：

```python
(vfunc_index, vfunc_offset)
```

如果需要在相同 slot 下保留额外稳定性，可在内部附带 `source_ea` 作为次级排序键，但排序语义应始终以 slot 信息为主。

### 映射规则

- 若所有条目都提供 `dispatch_rank`，则按排序后的 unique slot entry 列表，用 rank 精确映射。
- 若未提供 `dispatch_rank`，则按 `multi_order` 的顺序取前 `target_count` 项进行映射。

推荐约束：

- `expected_dispatch_count` 缺省时：
  - 若存在 `dispatch_rank`，默认值为 `max(dispatch_rank) + 1`
  - 否则默认值为 `len(target_specs)`
- `expected_dispatch_count` 校验对象是去重后的 unique slot entry 数量

## YAML 输出设计

helper 只写 slot-only YAML，对每个 target 输出：

```yaml
func_name: IGameSystem_GamePostInit
vtable_name: IGameSystem
vfunc_offset: 0x28
vfunc_index: 5
```

输出规则：

- 不写 `func_va`
- 不写 `func_rva`
- 不写 `func_size`
- 不写 `func_sig`

这样可以最大程度降低 helper 依赖，并与已有 slot-only 产物风格保持一致。

## 错误处理

### 直接失败的情况

以下情况任意一项发生时，helper 直接返回 `False`：

- dispatcher YAML 不存在
- dispatcher YAML 不可读
- dispatcher YAML 顶层不是字典
- dispatcher YAML 缺少 `func_va`
- 无法在 IDA 中得到 dispatcher 函数
- 未能识别任何有效 raw callsite
- Windows wrapper 无法解析为单一 `[reg+disp]` 虚调用
- Linux inline `call` 无法解析出合法 displacement
- `vfunc_offset < 0`
- `vfunc_offset % 8 != 0`
- `vfunc_index != vfunc_offset // 8`
- 去重后的 unique slot entry 数量与 `expected_dispatch_count` 不一致
- `dispatch_rank` 越界
- 无法为所有 target 完成映射
- 找不到对应的 `expected_output`
- YAML 写出失败

### 首版不做 best-effort 的事项

为了保持 helper 边界单一，以下事项首版不做：

- 不做 rename
- 不做 fallback xref 搜索
- 不做模糊匹配或“最像候选”的启发式选择

## 验证设计

本次设计的验证重点不是跑全量流程，而是确认 helper 的提取语义正确。

### Windows 验证目标

- 能从 `IGameSystem_LoopPostInitAllSystems` 中识别两个 raw callsite
- 两个 raw callsite 都能追到 wrapper 内的 `0x28`
- 去重后只剩 1 个 unique slot entry
- 最终输出：
  - `vfunc_offset = 0x28`
  - `vfunc_index = 5`

### Linux 验证目标

- 能从 `IGameSystem_LoopPostInitAllSystems` 中识别 inline `call [rax+28h]`
- 解析出 `vfunc_offset = 0x28`
- 去重后只剩 1 个 unique slot entry
- 最终输出：
  - `vfunc_offset = 0x28`
  - `vfunc_index = 5`

### 输出验证目标

`IGameSystem_GamePostInit` 的 YAML 仅包含四个字段：

- `func_name`
- `vtable_name`
- `vfunc_offset`
- `vfunc_index`

且 `vtable_name` 固定由 `target_specs` 提供，不由 helper 自动推断。

## 风险与权衡

### 1. Windows wrapper 识别过宽

若仅按“短函数 + 间接调用”判断 wrapper，可能引入误识别。

应对方式：

- 将识别范围限制在 dispatcher 函数直接调用到的候选函数上
- 要求 wrapper 内只出现唯一可解释的 `[reg+disp]` 虚调用形态

### 2. Linux inline vcall 识别过窄

若 Linux 编译器变体导致寄存器流与示例不同，可能出现漏识别。

应对方式：

- 首版只实现当前已知可靠模式
- 失败时返回 `False`，交给上层 Agent fallback
- 不在首版中引入过多启发式规则

### 3. 多目标能力先于实际需求

当前只落地 `IGameSystem_GamePostInit` 一个 target，但 helper 已支持多目标映射。

这是有意为之：

- 对外保持较小接口面
- 对内保留后续扩展位
- 避免未来出现第二个相同模式时再次重构 helper 形状

## 实施边界

本设计对应的实际改动范围应限制在：

- `ida_preprocessor_scripts/_igamesystem_slot_dispatch_common.py`
- `ida_preprocessor_scripts/find-IGameSystem_GamePostInit.py`

除非实现阶段发现真实阻塞，否则不应修改：

- `ida_preprocessor_scripts/_igamesystem_dispatch_common.py`
- `ida_preprocessor_scripts/find-IGameSystem_LoopPostInitAllSystems.py`
- `ida_analyze_util.py` 的通用预处理框架

## 最终结论

本次采用“新增独立 slot-dispatch helper + 薄封装目标脚本”的方案：

- 新 helper 只读取本轮新生成的 dispatcher YAML
- 新 helper 只负责从 dispatcher 中抽取去重后的 unique slot entry
- 新 helper 同时支持 Windows wrapper 与 Linux inline 两种识别路径
- 映射逻辑以 `dispatch_rank` / `multi_order` 为核心，面向多个 target
- `find-IGameSystem_GamePostInit.py` 只输出 slot-only YAML 四字段

该设计在复用价值、边界清晰度和实现复杂度之间取得了最合适的平衡，并且不会污染现有 `_igamesystem_dispatch_common.py` 的语义。
