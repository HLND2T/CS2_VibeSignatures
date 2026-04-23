# 字符串最小长度统一配置与单次扫描复用设计

## 背景

当前仓库中的多个 IDA 预处理路径会通过 `idautils.Strings()` 枚举字符串，再基于精确匹配或子串匹配收集字符串地址与代码引用。现有实现直接使用 `idautils.Strings()` 的默认配置，而 Hex-Rays 文档说明其默认 setup 使用 `minlen=5`。这会导致长度为 4 字节的字符串无法被纳入枚举结果，从而影响依赖短字符串定位函数或引用的预处理逻辑。

同时，部分 `py_eval` 脚本在同一次远端执行中会针对多个目标字符串分别扫描整个字符串表。例如先扫描 `command_name`，再扫描 `help_string`。这类实现会重复遍历同一份字符串集合，增加不必要的开销，而且不同调用点之间的字符串 setup 逻辑目前并不统一。

本设计将字符串枚举行为统一下沉到共享 helper 中，既解决最小长度阈值问题，也顺手引入同一次 `py_eval` 内复用同一份 `Strings` 实例的微优化。

## 目标

- 将仓库内所有 `idautils.Strings()` 调用的默认最小字符串长度统一调整为 4。
- 支持通过环境变量 `CS2VIBE_STRING_MIN_LENGTH` 覆盖默认值。
- 在同一次 `py_eval` 中，如果存在多个目标字符串匹配需求，只扫描一次字符串表并复用结果。
- 保持现有匹配语义不变：
  - 精确匹配仍按完整字符串相等判断。
  - 子串匹配仍按包含关系判断。
  - 后续 `XrefsTo`、函数入口归一化、YAML 输出逻辑保持不变。

## 非目标

- 不引入新的命令行参数。
- 不做跨多次 `py_eval` 调用的字符串缓存。
- 不重构与字符串扫描无关的预处理流程。
- 不调整 IDA 字符串类型范围以外的搜索行为，除非现有代码已经显式依赖不同配置。

## 范围

本次设计覆盖以下已知调用点：

- `ida_analyze_util.py`
- `ida_preprocessor_scripts/find-CBaseFilter_InputTestActivator.py`
- `ida_preprocessor_scripts/_define_inputfunc.py`
- `ida_preprocessor_scripts/_registerconcommand.py`
- `ida_preprocessor_scripts/_register_event_listener_abstract.py`

其中：

- 所有调用点都需要统一接入新的最小长度配置。
- `_registerconcommand.py` 与 `_register_event_listener_abstract.py` 需要纳入“同一次 `py_eval` 单次扫描、多目标复用”的优化。
- 其他调用点若单次 `py_eval` 只查一个目标字符串，则只需要切换到统一 helper，不强制额外引入复杂索引结构。

## 设计概览

### 1. 统一最小长度配置

在 `ida_analyze_util.py` 中新增一个本地 helper，用于解析字符串最小长度配置。建议接口语义如下：

- 读取环境变量 `CS2VIBE_STRING_MIN_LENGTH`
- 未设置时返回默认值 `4`
- 解析失败时回退到 `4`
- 当值小于 `1` 时回退到 `4`

该 helper 只在本地 Python 侧执行，用于生成后续 `py_eval` 代码时注入稳定的整数值，避免把环境变量解析逻辑散落到多个远端脚本模板中。

### 2. 统一 `Strings` setup 代码生成

在 `ida_analyze_util.py` 中新增一个用于生成 `py_eval` 代码片段的 helper，统一负责：

- 创建 `idautils.Strings(default_setup=False)` 实例
- 调用一次 `setup(...)`
- 使用统一解析后的 `minlen`
- 保持与默认行为一致的其他关键参数

建议保持字符串类型为 C string，即使用与当前默认 setup 等价的 `strtypes=[ida_nalt.STRTYPE_C]`。除 `minlen` 外，不主动扩大字符串扫描语义，避免引入与现有结果不一致的副作用。

统一后的远端代码骨架应类似：

```python
import ida_nalt, idautils

strings = idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=resolved_minlen)
for item in strings:
    ...
```

这里的 `resolved_minlen` 由本地 helper 先解析，再作为常量写入对应的 `py_eval` 脚本。

### 3. 单次扫描复用策略

对于同一次 `py_eval` 中存在多个目标文本的场景，不再为每个目标文本分别遍历 `strings`，而是在一次扫描中建立索引，再按需取值。

建议支持两类复用模式：

- 精确匹配索引：`{text: [ea1, ea2, ...]}`
- 单次循环中的即时过滤：如果只有一个目标且无需复用，则允许在一次循环中直接判断

对于 `_registerconcommand.py` 和 `_register_event_listener_abstract.py`，推荐采用精确匹配索引模式，因为这两处天然是“若干目标文本 -> 匹配字符串地址集合”的问题，索引结构可以直接降低重复扫描成本，也更便于保留现有调试输出。

## 详细变更

### `ida_analyze_util.py`

新增共享 helper：

- 解析 `CS2VIBE_STRING_MIN_LENGTH`
- 生成统一的 `Strings` setup 代码片段

并将 `_collect_xref_func_starts_for_string()` 中原有的：

- `for s in idautils.Strings():`

替换为：

- 先初始化并 setup `Strings`
- 再基于统一配置后的字符串枚举器执行子串或精确匹配

这样 `_collect_xref_func_starts_for_string()` 自动具备 4 字节字符串可见性，且继续保留 `FULLMATCH:` 的语义。

### `find-CBaseFilter_InputTestActivator.py`

该文件的 Linux fallback 在一次 `py_eval` 中只搜索 `TestActivator` 一个目标字符串。这里无需引入额外索引结构，但应改为使用统一生成的 `Strings` setup 片段，确保 4 字节字符串阈值与全仓一致。

### `_define_inputfunc.py`

该文件在一次 `py_eval` 中仅对 `input_name` 做精确匹配。改动方式与上面类似：

- 统一接入新的 `Strings` setup 片段
- 不改后续 `xref`、段过滤、handler 解析逻辑

### `_registerconcommand.py`

该文件当前会分别扫描 `command_name` 与 `help_string`。改造后应：

- 先收集需要精确匹配的目标文本集合，过滤掉 `None` 或空字符串
- 一次遍历 `strings`
- 为命中的目标文本建立 `text -> [ea, ...]` 索引
- 再从索引中取出 `command_string_addrs` 与 `help_string_addrs`

这样可以确保：

- 同一次 `py_eval` 只创建一份 `Strings` 实例
- 只调用一次 `setup()`
- 只扫描一次字符串表

原有 debug 输出仍可保留，但其数据来源改为索引结果。

### `_register_event_listener_abstract.py`

当前该文件的 `_scan_exact_strings()` 结构适合改为“单次扫描返回索引”的模式，即：

- 构造目标文本集合
- 一次扫描建立命中索引
- 再使用 `anchor_event_name` 从索引读取结果

如果当前单次 `py_eval` 最终只消费一个文本，也仍应复用统一 `Strings` 初始化逻辑，为后续同类脚本提供一致模式。

## 错误处理与回退

- 当 `CS2VIBE_STRING_MIN_LENGTH` 缺失、为空、非整数、或小于 `1` 时，统一回退到 `4`
- 不因为环境变量非法值而抛异常中断分析流程
- 远端 `py_eval` 中仍保持现有的异常捕获与 JSON 序列化结果格式，不额外扩大失败面
- 若某调用点当前已有 debug 日志，则保留现有日志结构，必要时补充 `minlen` 或命中数量信息，但不要求新增大量日志

## 兼容性与性能

### 兼容性

- 4 字节字符串会从“不可见”变为“可见”，这是本次预期行为变更
- 对长度不小于 5 的字符串，匹配逻辑与结果应保持原有语义
- 由于未改变后续 `xref`、函数归一化、输出 YAML 结构，受影响范围应主要集中在“额外发现原本被漏掉的短字符串”

### 性能

- 单次 `setup()` 本身不是本次主要热点
- 真正的收益来自避免在同一次 `py_eval` 内重复扫描整个字符串表
- 本次设计不做跨调用缓存，避免引入失效策略、共享状态与额外复杂度

## 文档更新

建议在 `README.md` 中补充环境变量说明，至少覆盖：

- 新增环境变量 `CS2VIBE_STRING_MIN_LENGTH`
- 默认值为 `4`
- 非法值会回退到 `4`
- 作用范围为 IDA 预处理字符串枚举逻辑

## 验证方案

本次实现完成后，验证重点应为定向验证而非全量测试：

1. 代码层面确认所有 `idautils.Strings()` 调用点都已统一改造
2. 检查 `py_eval` 模板是否只在单次执行中创建一次 `Strings` 实例并调用一次 `setup()`
3. 检查多目标场景是否由“多次全量扫描”改为“一次扫描构建索引”
4. 检查环境变量默认值、非法值与显式覆盖值三种分支
5. 如需人工验证，可在含 4 字节字符串目标的样本上确认命中结果不再被漏掉

## 实施边界

本设计刻意保持为一次局部改动：

- 优先通过共享 helper 统一行为
- 不扩大到字符串缓存系统
- 不触碰与本需求无关的预处理架构

这样可以在较低风险下解决功能缺口，并为后续类似的字符串匹配脚本提供统一模式。
