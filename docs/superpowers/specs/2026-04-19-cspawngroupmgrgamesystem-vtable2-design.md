# `CSpawnGroupMgrGameSystem_vtable2` 与副虚表稳定定位设计

## 背景

当前 `find-CSpawnGroupMgrGameSystem_vtable` 通过 `preprocess_common_skill(...)` 调用 `preprocess_vtable_via_mcp(...)`，按类名 `CSpawnGroupMgrGameSystem` 解析 vtable，并输出 `CSpawnGroupMgrGameSystem_vtable.{platform}.yaml`。

现有公共实现默认只解析该类的第一张 vtable：

- Windows 优先尝试 `??_7CSpawnGroupMgrGameSystem@@6B@`
- Linux 优先尝试 `_ZTV24CSpawnGroupMgrGameSystem + 0x10`
- 两边都把第一次命中的 address point 当成目标 vtable

这对 `CSpawnGroupMgrGameSystem_DoesGameSystemReallocate` 不成立。该函数位于 `CSpawnGroupMgrGameSystem` 的副虚表，而不是主虚表，因此当前流程虽然能找到函数本身，却无法在 `CSpawnGroupMgrGameSystem_vtable.{platform}.yaml` 的 `vtable_entries` 中回填正确的 `vfunc_index` / `vfunc_offset`。

已知样本中：

- Windows 副虚表可由 `??_7CSpawnGroupMgrGameSystem@@6B@_0` 直接锚定
- Linux 副虚表对应的 address point 前一项 `offset-to-top` 为 `-8`

本次需要为 `CSpawnGroupMgrGameSystem` 新增独立的 `vtable2` 产物，并把副虚表定位能力沉淀为共享 helper，以便后续其他多重继承或多 address-point 类复用。

## 目标

- 新增 `CSpawnGroupMgrGameSystem_vtable2.{platform}.yaml` 产物。
- 让 `find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate` 明确绑定 `CSpawnGroupMgrGameSystem_vtable2`，不再依赖主虚表。
- 把“按序号 / 约束定位某一张虚表”的能力下沉为共享 helper，而不是把逻辑写死在单个 skill 脚本里。
- Linux 侧支持显式约束 `offset-to-top`，用于稳定筛选副虚表。
- 保持现有主虚表路径和既有 YAML schema 尽量不变，避免扩大改动面。

## 非目标

- 本次不把现有 `preprocess_vtable_via_mcp(...)` 直接改造成“任意 ordinal”通用入口。
- 本次不重构所有 `inherit_vfuncs` / `func_vtable_relations` 的语义模型。
- 本次不修改现有 vtable YAML 的字段集合与顺序。
- 本次不新增自动推断 `offset-to-top` 的通用高层配置语法到 `config.yaml`。
- 本次不执行全量测试、build 或无关重构。

## 方案比较

### 方案 A1：单脚本特判

只在 `find-CSpawnGroupMgrGameSystem_vtable2.py` 内实现一段专用 py_eval，直接返回副虚表 YAML。

优点：

- 代码最少
- 对公共层影响最小

缺点：

- 逻辑无法复用
- 后续如果再出现 `Foo_vtable2`、`Bar_vtable3`，会继续复制相同流程

### 方案 A2：新增共享 ordinal-vtable helper

新增一个专用 helper，负责按类名、候选别名、Linux `offset-to-top` 过滤条件和 ordinal 选择某一张 vtable，再由薄脚本生成具体产物。

优点：

- 保持本次仍是局部增量改动
- 副虚表定位能力可以复用
- 不扰动现有主路径的默认语义

缺点：

- 需要补一层新的共享接口
- 需要处理 `vtable_name` 到 YAML 文件名的兼容解析

### 方案 A3：直接扩展 `preprocess_vtable_via_mcp(...)`

为现有公共 helper 增加 `ordinal`、`expected_offset_to_top` 等参数，并让所有 vtable 查找路径都理解多张虚表。

优点：

- 长期最统一

缺点：

- 影响所有现有调用点
- 风险和测试面明显大于本次需求

## 选定方案

采用方案 A2：新增共享 ordinal-vtable helper，并由新 skill 脚本进行薄封装。

这是满足当前需求的最小充分方案。它既能稳定生成 `CSpawnGroupMgrGameSystem_vtable2`，又能为后续其他副虚表场景复用，不需要立即重构现有所有主虚表路径。

## 详细设计

### 1. 新增共享 helper

新增文件：

- `ida_preprocessor_scripts/_ordinal_vtable_common.py`

建议导出入口：

```python
async def preprocess_ordinal_vtable_via_mcp(
    session,
    class_name,
    ordinal,
    image_base,
    platform,
    debug=False,
    symbol_aliases=None,
    expected_offset_to_top=None,
):
    ...
```

参数语义：

- `class_name`：规范类名，如 `CSpawnGroupMgrGameSystem`
- `ordinal`：候选集合中的第几个目标，0 基
- `symbol_aliases`：显式优先候选符号列表，主要用于 Windows
- `expected_offset_to_top`：Linux 专用过滤条件，表示 address point 前一项的有符号 offset-to-top

返回值与现有 `preprocess_vtable_via_mcp(...)` 保持同构：

- `vtable_class`
- `vtable_symbol`
- `vtable_va`
- `vtable_rva`
- `vtable_size`
- `vtable_numvfunc`
- `vtable_entries`

该 helper 只负责查找与解析，不负责落盘 YAML。

### 2. 候选收集与选择规则

#### 2.1 Windows

Windows 侧候选收集顺序如下：

1. 优先检查 `symbol_aliases`
2. 若 alias 缺失或未命中，再收集该类全部相关 vftable / COL 候选
3. 对每个候选进行真实 vtable 验证
4. 过滤后按 address point 地址排序
5. 取 `ordinal` 指定项

建议优先支持的显式别名：

```text
??_7CSpawnGroupMgrGameSystem@@6B@_0
```

如果 alias 命中，仍然要执行一轮“像不像真实虚表”的验证，而不是直接信任符号存在。

#### 2.2 Linux

Linux 不采用“`_ZTV + 固定偏移`”方式定位副虚表，而采用 ABI 结构化规则：

1. 以 `_ZTI24CSpawnGroupMgrGameSystem` 为锚点
2. 枚举所有 `DataRefsTo(typeinfo)` 候选
3. 把 `ref - ptr_size` 解释为有符号 `offset-to-top`
4. 把 `ref + ptr_size` 视为该 address point 的起点
5. 仅保留能解析出有效 `vtable_entries` 的候选
6. 如果指定了 `expected_offset_to_top`，先按该值过滤
7. 过滤后按 address point 地址排序
8. 取 `ordinal` 指定项

本次 `CSpawnGroupMgrGameSystem_vtable2` 固定使用：

```text
expected_offset_to_top = -8
```

这样可以稳定命中副虚表，而不依赖具体版本中 `_ZTV` 内部布局长度。

### 3. 真实 vtable 验证规则

无论 Windows 还是 Linux，候选命中后都要经过统一验证：

- 从 address point 开始按指针宽度读取表项
- 连续项必须能落到可执行段中的代码地址
- 当遇到空指针、越界、回指到本段元数据、非可执行段或非代码地址时停止
- 只有至少解析出 1 个有效函数项的候选才算真实 vtable

生成的 `vtable_entries`、`vtable_size`、`vtable_numvfunc` 语义与现有主虚表 YAML 保持一致。

### 4. 新增 `find-CSpawnGroupMgrGameSystem_vtable2.py`

新增脚本：

- `ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_vtable2.py`

该脚本只做薄封装，不复写定位逻辑。

Windows 调用参数建议：

```python
symbol_aliases = ["??_7CSpawnGroupMgrGameSystem@@6B@_0"]
ordinal = 0
```

Linux 调用参数建议：

```python
expected_offset_to_top = -8
ordinal = 0
```

生成产物：

- `CSpawnGroupMgrGameSystem_vtable2.{platform}.yaml`

### 5. `CSpawnGroupMgrGameSystem_vtable2` 的 YAML 结构

新产物的 YAML schema 与现有 vtable YAML 完全一致，不新增字段：

- `vtable_class`
- `vtable_symbol`
- `vtable_va`
- `vtable_rva`
- `vtable_size`
- `vtable_numvfunc`
- `vtable_entries`

约束说明：

- 文件名区分主虚表与副虚表
- `vtable_class` 仍写真实类名 `CSpawnGroupMgrGameSystem`
- `expected_offset_to_top=-8` 只属于 helper 查找约束，不写入 YAML

这样可以避免修改 `VTABLE_YAML_ORDER` 和下游解析结构。

### 6. 修改 `find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.py`

当前脚本通过 xref signature 找到函数后，再借助：

```python
FUNC_VTABLE_RELATIONS = [
    ("CSpawnGroupMgrGameSystem_DoesGameSystemReallocate", "CSpawnGroupMgrGameSystem"),
]
```

让公共层到主虚表中反查 `vfunc_index` / `vfunc_offset`。这一步会失败，因为目标函数不在主虚表里。

本次改造后，应该让它显式绑定副虚表产物：

- 输出 `vtable_name` 改为 `CSpawnGroupMgrGameSystem_vtable2`
- 槽位回填只允许从 `CSpawnGroupMgrGameSystem_vtable2.{platform}.yaml` 读取
- 找不到则直接失败，不回退到主虚表

这里不应继续依赖旧的“类名自动拼 `_vtable`”语义。

### 7. 统一 `vtable_name` 到 YAML 路径的解析规则

当前共享逻辑中至少有以下路径默认采用：

```python
f"{vtable_name}_vtable.{platform}.yaml"
```

这意味着如果函数 YAML 里写：

```yaml
vtable_name: CSpawnGroupMgrGameSystem_vtable2
```

现有实现会错误解析为：

```text
CSpawnGroupMgrGameSystem_vtable2_vtable.{platform}.yaml
```

因此需要新增统一的 artifact stem 解析 helper。建议语义如下：

- 若 `vtable_name` 已经是 artifact stem，则直接使用：
  - 例如 `CSpawnGroupMgrGameSystem_vtable`
  - 例如 `CSpawnGroupMgrGameSystem_vtable2`
- 否则沿用旧行为，自动补 `_vtable`

建议受影响的路径至少包括：

- `preprocess_func_sig_via_mcp(...)` 内部 `_load_vtable_data(...)`
- `preprocess_index_based_vfunc_via_mcp(...)` 读取继承目标 vtable YAML 的路径
- 其他使用 `vtable_name` 推导 YAML 文件名的公共逻辑

这样既能兼容旧 YAML，又能支持新引入的 `*_vtable2` 产物。

### 8. `config.yaml` 变更

需要新增 skill 配置：

```yaml
- name: find-CSpawnGroupMgrGameSystem_vtable2
  expected_output:
    - CSpawnGroupMgrGameSystem_vtable2.{platform}.yaml
```

需要修改 `find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate` 的依赖：

- `expected_input` 从 `CSpawnGroupMgrGameSystem_vtable.{platform}.yaml`
- 调整为 `CSpawnGroupMgrGameSystem_vtable2.{platform}.yaml`

需要新增 symbol 配置：

```yaml
- name: CSpawnGroupMgrGameSystem_vtable2
  category: vtable
```

### 9. 下游兼容性

`find-IGameSystem_DoesGameSystemReallocate.py` 目前通过 `inherit_vfuncs` 读取：

- `../client/CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.{platform}.yaml`

它最终使用的是该函数 YAML 中的 `vfunc_index` / `vfunc_offset`，而不是硬编码主虚表。因此只要 `CSpawnGroupMgrGameSystem_DoesGameSystemReallocate` 改为绑定 `CSpawnGroupMgrGameSystem_vtable2`，该下游路径即可自然继承正确槽位，不需要另行引入主副虚表判断。

## 失败与回退策略

本次采用“失败即停”的保守策略，避免副虚表误判后污染 YAML。

### 1. `preprocess_ordinal_vtable_via_mcp(...)`

以下情况直接失败并返回 `None`：

- 候选集为空
- 提供了 `symbol_aliases` 但未命中任何可验证候选
- Linux 指定了 `expected_offset_to_top`，但过滤后无候选
- 过滤后候选数不足，`ordinal` 越界
- 命中的 address point 无法解析出有效 `vtable_entries`

### 2. `find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.py`

以下情况直接失败：

- xref signature 没有唯一命中目标函数
- 目标函数不在 `CSpawnGroupMgrGameSystem_vtable2` 的 `vtable_entries` 中
- `vtable_name` 无法解析到正确 YAML 文件

明确禁止以下回退：

- 从 `vtable2` 失败后静默切回主虚表
- 通过主虚表猜测副虚表槽位

## 调试输出建议

为了便于后续复用与排障，helper 的 debug 输出建议包含：

- 每个候选的 `vtable_symbol`
- 每个候选的 address point 地址
- Linux 候选的 `offset_to_top`
- 每个候选解析出的 `num_entries`
- 最终选择的是哪个候选，以及命中的原因：
  - alias 命中
  - `expected_offset_to_top` 过滤命中
  - ordinal 命中

## 验证设计

本次只做 Level 0 / Level 1 的定向验证，不默认跑 build 或全量测试。

建议新增或补充的测试点：

### 1. Windows alias 命中

- 给定 `??_7CSpawnGroupMgrGameSystem@@6B@_0`
- helper 能正确选择副虚表
- 返回的 `vtable_symbol`、`vtable_entries` 正确

### 2. Linux `offset-to-top` 过滤

- 给定多个 `_ZTI24CSpawnGroupMgrGameSystem` 引用候选
- `expected_offset_to_top=-8` 时仅保留副虚表
- `ordinal=0` 能稳定选中目标

### 3. `vtable_name` 路径解析

- 当 `vtable_name="CSpawnGroupMgrGameSystem"` 时仍解析到 `CSpawnGroupMgrGameSystem_vtable.{platform}.yaml`
- 当 `vtable_name="CSpawnGroupMgrGameSystem_vtable2"` 时解析到 `CSpawnGroupMgrGameSystem_vtable2.{platform}.yaml`
- 不应产生 `..._vtable2_vtable...` 路径

### 4. `DoesGameSystemReallocate` 绑定副虚表

- 生成的 YAML 中：
  - `vtable_name == CSpawnGroupMgrGameSystem_vtable2`
  - `vfunc_index` 与 `vfunc_offset` 来自副虚表
- 不允许从主虚表回填

### 5. 失败路径

- alias 不存在时返回失败
- Linux `expected_offset_to_top` 不匹配时返回失败
- 函数地址不在 `vtable2` 中时返回失败

## 影响范围

预计修改或新增的文件：

- `ida_preprocessor_scripts/_ordinal_vtable_common.py`
- `ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_vtable2.py`
- `ida_preprocessor_scripts/find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.py`
- `ida_analyze_util.py`
- `config.yaml`
- `tests/test_ida_analyze_util.py`
- `tests/test_ida_preprocessor_scripts.py`

## 实施顺序建议

1. 先实现 `vtable_name` 到 artifact stem 的统一解析 helper
2. 再实现 `_ordinal_vtable_common.py`
3. 新增 `find-CSpawnGroupMgrGameSystem_vtable2.py`
4. 修改 `find-CSpawnGroupMgrGameSystem_DoesGameSystemReallocate.py`
5. 更新 `config.yaml`
6. 补定向测试

## 风险与权衡

- 最大风险是 Linux 候选收集过宽，导致多个 typeinfo 引用都被当成可选 address point。通过 `expected_offset_to_top=-8` 和真实 vtable 验证可以显著降低风险。
- `vtable_name` 的路径解析是共享逻辑，改动虽然小，但影响范围广，必须以“旧语义完全兼容”为前提。
- 不把 `offset-to-top` 写入 YAML，意味着该约束不会自动被后续通用工具看到；但这正是本次的刻意取舍，因为它属于查找策略，不属于产物 schema。

## 结论

本次采用“新增共享 ordinal-vtable helper + 新增 `CSpawnGroupMgrGameSystem_vtable2` 产物 + 让 `DoesGameSystemReallocate` 显式绑定副虚表”的方案。

该方案可以稳定解决当前 `CSpawnGroupMgrGameSystem_DoesGameSystemReallocate` 不在主虚表中的问题，同时把副虚表定位能力沉淀为后续可复用的公共能力，并将改动范围控制在与本需求直接相关的预处理链路内。
