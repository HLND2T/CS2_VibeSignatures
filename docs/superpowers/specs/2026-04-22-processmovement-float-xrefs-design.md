# `CCSPlayer_MovementServices_ProcessMovement` 浮点 xref 过滤设计

## 背景

当前 `CCSPlayer_MovementServices_ProcessMovement` 的 `func_xrefs` 回退依赖：

- `xref_gvs = ["CPlayer_MovementServices_s_pRunCommandPawn"]`
- `exclude_funcs = ["CPlayer_MovementServices_ForceButtons", "CPlayer_MovementServices_ForceButtonState"]`

在部分版本中，这组条件只能把候选函数收敛到两个地址，而不能唯一定位目标函数：

- `0x15fa950`
- `0x1602720`

现有 `preprocess_func_xrefs_via_mcp()` 只支持：

- 正向候选源：`xref_strings` / `xref_gvs` / `xref_signatures` / `xref_funcs`
- 排除条件：`exclude_funcs` / `exclude_strings` / `exclude_gvs` / `exclude_signatures`

因此即使脚本中已经声明：

```python
"xref_floats": ["64.0", "0.5"],
"exclude_floats": [],
```

核心归一化与过滤逻辑仍不会识别它们，导致无法利用函数内部访问的只读段浮点常量继续排除 `0x15fa950`。

目标是为 `func_xrefs` 增加一层“已形成 `common_funcs` 后的浮点常量精炼过滤”，使 `CCSPlayer_MovementServices_ProcessMovement` 最终只保留 `0x1602720`。

## 目标

- 为 `func_xrefs` 新增可选字段 `xref_floats` 与 `exclude_floats`
- 保持它们为“后置过滤条件”，不改变现有正向候选源模型
- 仅在已形成 `common_funcs` 后扫描候选函数内部访问的只读段标量浮点常量
- 支持同时识别 4 字节 IEEE754 `float` 与 8 字节 IEEE754 `double`
- 通过访问 `xmm` 的标量指令语义区分当前按 `float` 还是 `double` 读取
- 只支持标量指令，本次不处理 packed SIMD 常量
- 用固定容差比较浮点值：
  - `float`: `abs(actual - expected) < 1e-6`
  - `double`: `abs(actual - expected) < 1e-12`
- 在 `CCSPlayer_MovementServices_ProcessMovement` 的脚本与测试中接入这两个字段

## 非目标

- 本次不把 `xref_floats` / `exclude_floats` 视为独立正向候选源
- 本次不改变 `xref_strings` / `xref_gvs` / `xref_signatures` / `xref_funcs` 至少一个非空的约束
- 本次不支持 packed 指令，例如 `mulps` / `mulpd` / `movaps` / `movapd`
- 本次不支持从栈、堆、写时数据段或非只读段读取浮点常量
- 本次不引入每条规则自定义浮点容差
- 本次不尝试做更大范围的通用反汇编语义抽象或重构全部 `py_eval` 框架

## 方案比较

### 方案 A：仅按助记符后缀判定

做法：

- 扫描访问 `xmm` 且带内存操作数的指令
- 仅根据助记符后缀 `ss` / `sd` 决定读取 `float` / `double`

优点：

- 实现最直接
- 与 `mulss` / `mulsd` 这类典型案例天然匹配

缺点：

- 只靠后缀判定，边界说明不够完整
- 对“只读段 + 标量语义”的过滤表达不够明确

### 方案 B：仅按 IDA 操作数类型判定

做法：

- 主要依赖 IDA 解码出的操作数类型信息决定读取宽度

优点：

- 理论上更偏语义化

缺点：

- 更依赖 IDA 内部字段细节
- 测试桩更重
- 不如现有仓库中基于助记符和简单段名判断的 `py_eval` 风格稳定

### 方案 C：标量白名单加后缀判定

做法：

- 先限定“访问 `xmm`、包含内存操作数、目标位于 `.rdata` 或 `.rodata*`、且属于标量浮点指令”
- 再按 `ss` / `sd` 判定读取 `float` / `double`

优点：

- 语义边界最清晰
- 与当前 `common_funcs` 后置精炼模型最契合
- 能精确满足本次 Windows/Linux 示例
- 容易控制误判范围

缺点：

- 比纯后缀判定多一层筛选逻辑

## 选定方案

采用方案 C：标量白名单加后缀判定。

理由如下：

- 它能把“只处理候选函数内访问的只读段标量浮点常量”这一定义说清楚
- 它适合接入 `preprocess_func_xrefs_via_mcp()` 已有的“候选求交后再排除”的工作流
- 它可以在不扩大支持面的前提下，稳定覆盖当前 `ProcessMovement` 的识别需求

## 详细设计

### 1. 配置契约扩展

`preprocess_common_skill()` 中 `func_xrefs` 的允许字段新增：

- `xref_floats`
- `exclude_floats`

规则：

- 两个字段均为可选列表字段，元素以字符串形式声明，保持与现有脚本风格一致
- 归一化后仍以 `list[str]` 形式传入 `preprocess_func_xrefs_via_mcp()`
- 空列表合法
- 空字符串、非数值字符串或其他非法值直接视为配置错误并失败关闭

`xref_floats` / `exclude_floats` 的定位如下：

- 不属于正向候选源
- 不参与 `candidate_sets` 求交
- 仅作用于已形成的 `common_funcs`

因此，`func_xrefs` 仍保持现有约束：

- `xref_strings` / `xref_gvs` / `xref_signatures` / `xref_funcs` 至少一个非空

### 2. 过滤执行顺序

`preprocess_func_xrefs_via_mcp()` 的总体顺序保持不变：

1. 收集 `candidate_sets`
2. 求交得到 `common_funcs`
3. 应用现有排除条件：
   - `exclude_funcs`
   - `exclude_strings`
   - `exclude_gvs`
   - `exclude_signatures`
4. 应用新增浮点过滤：
   - `xref_floats`
   - `exclude_floats`
5. 检查 `common_funcs` 是否唯一

将浮点过滤放在现有排除条件之后的原因是：

- 先复用已有低成本排除条件收缩候选集合
- 再对剩余函数做指令级扫描，可以减少 IDA 侧工作量

语义定义：

- `xref_floats`：若某候选函数扫描到的只读段标量浮点常量中，没有任何一个匹配配置值，则排除
- `exclude_floats`：若某候选函数扫描到的只读段标量浮点常量中，任意一个匹配配置值，则排除
- 若同一函数同时命中二者，则以排除为准，`exclude_floats` 优先级更高

### 3. 新增内部 helper

新增一个内部 helper，用于对已形成的候选函数集合做浮点过滤。建议形式如下：

```python
async def _filter_func_addrs_by_float_xrefs_via_mcp(
    session,
    func_addrs,
    xref_floats,
    exclude_floats,
    debug=False,
):
    ...
```

职责：

- 接收当前 `common_funcs`
- 通过一次 `py_eval` 批量扫描这些函数
- 返回过滤后的函数地址集合
- 在失败场景下返回 `None`

这里不把逻辑继续塞进 `preprocess_func_xrefs_via_mcp()` 主体，是为了让：

- 主流程仍维持“候选收集 -> 排除 -> 唯一化”的结构清晰度
- 浮点扫描逻辑可独立测试
- 后续若其他脚本也需要同类过滤，可以直接复用

### 4. IDA 侧扫描规则

`py_eval` 内部按函数遍历指令，仅收集满足以下条件的引用：

- 指令至少有一个操作数涉及 `xmm`
- 指令至少有一个操作数为内存引用
- 内存目标地址可解析到 segment
- segment 名为 `.rdata` 或以 `.rodata` 开头
- 指令属于标量浮点场景

本次明确忽略：

- packed 指令
- 目标段不是只读数据段的引用
- 无法判定为 `float` / `double` 的其他 `xmm + mem` 指令

### 5. `float` / `double` 判定

类型判定采用“标量白名单加后缀判定”：

- 助记符以 `ss` 结尾，视为 scalar single，按 4 字节 `float` 读取
- 助记符以 `sd` 结尾，视为 scalar double，按 8 字节 `double` 读取
- 其他情况一律忽略，不参与匹配

这样可以覆盖：

- Windows 示例中的 `mulss xmm6, cs:dword_...`
- Linux 示例中的 `mulss xmm0, cs:dword_...`

同时满足用户要求：

- 若访问 `xmm` 的指令语义表明是 `float`，则按 `float` 读取
- 若指令语义表明是 `double`，则按 `double` 读取

### 6. 常量读取与比较

读取方式：

- `float`：读取 4 字节并使用 `struct.unpack("<f", raw4)`
- `double`：读取 8 字节并使用 `struct.unpack("<d", raw8)`

比较方式：

- 将规则中的每个 `xref_floats` / `exclude_floats` 元素先解析为 Python `float`
- `float` 常量比较使用 `1e-6`
- `double` 常量比较使用 `1e-12`

命中规则：

- 只要某个常量与某个配置值在对应容差内相等，即视为命中
- 若函数内没有扫描到任何命中的 `xref_floats`，则该函数被剔除
- 若函数内扫描到任意命中的 `exclude_floats`，则该函数被剔除

### 7. `py_eval` 返回结构

为了避免主进程重复扫描，`py_eval` 建议按函数返回结构化摘要，例如：

- 每个函数扫描到的常量列表
- 每个常量的地址、类型、值
- 是否命中 `xref_floats`
- 是否命中 `exclude_floats`

主进程只负责：

- 解析结果
- 根据命中位更新剩余候选函数集合
- 在 `debug=True` 时输出摘要日志

### 8. 调试日志

保留现有日志：

- `common_funcs before excludes`
- `common_funcs after excludes`

新增浮点阶段日志：

- `common_funcs before float filters`
- 每个候选函数扫描到的只读段标量常量摘要
- 因未命中 `xref_floats` 被排除的函数
- 因命中 `exclude_floats` 被排除的函数
- `common_funcs after float filters`

非 `debug` 模式不输出新增日志。

### 9. 错误处理

以下场景一律失败关闭：

- `xref_floats` / `exclude_floats` 字段类型非法
- 字段元素为空或无法解析成数值
- 浮点扫描 `py_eval` 调用失败
- `py_eval` 返回结构无法解析

失败关闭意味着：

- `preprocess_func_xrefs_via_mcp()` 返回 `None`
- `preprocess_common_skill()` 上层按“未能定位函数”处理

不允许在浮点过滤异常时静默退化为“忽略浮点条件继续运行”，以避免误定位。

### 10. 脚本接入

`ida_preprocessor_scripts/find-CCSPlayer_MovementServices_ProcessMovement.py` 中的 `FUNC_XREFS` 保持如下契约：

```python
{
    "func_name": "CCSPlayer_MovementServices_ProcessMovement",
    "xref_strings": [],
    "xref_gvs": ["CPlayer_MovementServices_s_pRunCommandPawn"],
    "xref_signatures": [],
    "xref_funcs": [],
    "xref_floats": ["64.0", "0.5"],
    "exclude_funcs": [
        "CPlayer_MovementServices_ForceButtons",
        "CPlayer_MovementServices_ForceButtonState",
    ],
    "exclude_strings": [],
    "exclude_gvs": [],
    "exclude_signatures": [],
    "exclude_floats": [],
}
```

这里的意图是：

- 先通过 `xref_gvs` 与 `exclude_funcs` 缩小到少量候选
- 再利用候选函数内部访问的标量只读段浮点常量，排除不含 `64.0` / `0.5` 的函数
- 最终只保留目标地址

## 测试设计

### 1. `tests/test_ida_analyze_util.py`

新增或更新以下测试：

- `preprocess_common_skill()` 接受并转发 `xref_floats` / `exclude_floats`
- 未知键校验仍然生效
- 非法浮点配置值会导致失败
- `preprocess_func_xrefs_via_mcp()` 中：
  - 命中 `xref_floats` 的候选函数保留
  - 未命中任何 `xref_floats` 的候选函数被排除
  - 命中 `exclude_floats` 的候选函数被排除
  - 同时命中正向与排除时，排除优先
  - 浮点扫描失败时整体返回 `None`

这些测试以 mock `py_eval` 结果为主，不引入真实 IDA 集成执行。

### 2. `tests/test_ida_preprocessor_scripts.py`

更新 `find-CCSPlayer_MovementServices_ProcessMovement` 的脚本转发测试，确保断言中包含：

- `xref_floats=["64.0", "0.5"]`
- `exclude_floats=[]`

### 3. 验证范围

本次只做定向单测与脚本转发测试，不扩展到更大范围的集成验证。

原因：

- 改动集中在 `func_xrefs` 配置归一化与候选过滤逻辑
- 已有测试风格本身就是以 mock MCP 返回值为主
- 在未必要运行真实 IDA 的前提下，可以更稳定地覆盖边界语义

## 风险与权衡

- 助记符与段名判断是有意收窄支持面，不追求覆盖全部 SSE/AVX 场景
- 只支持标量指令会遗漏某些潜在可用信号，但能显著降低误判和实现复杂度
- 失败关闭会让配置错误更早暴露，代价是首次接入时对测试覆盖要求更高

总体上，这一设计优先保证：

- 定位唯一性
- 规则语义清晰
- 对现有 `func_xrefs` 流程的最小侵入
