# `FUNC_XREFS` 全仓迁移为 `dict` 配置设计

日期：2026-04-16

## 背景

当前统一 `func_xrefs` 管线由 `ida_analyze_util.py` 消费，脚本侧通过 `FUNC_XREFS` 传入固定 6 元组：

`(func_name, xref_strings_list, xref_signatures_list, xref_funcs_list, exclude_funcs_list, exclude_strings_list)`

该协议在最初只有少量字段时尚可维护，但随着能力扩展，已经出现新的需求：

- 增加正向全局变量 xref 约束：`xref_gvs`
- 增加负向全局变量排除：`exclude_gvs`
- 增加负向字节签名过滤：`exclude_signatures`

如果继续沿用 tuple 位置参数，协议将膨胀为 9 元组，维护问题会迅速放大：

- 可读性差，调用点难以一眼看出每个列表的含义
- 所有新字段都依赖位置顺序，极易写错
- 多个字段同为 `list[str]`，顺序错位时很难被肉眼发现
- 校验与报错只能围绕“第几个参数”，不利于排查

因此本次设计决定只针对 `FUNC_XREFS` 这一类配置，全仓迁移为 `dict` 风格，并同步扩展 `xref_gvs`、`exclude_gvs`、`exclude_signatures` 能力。

## 目标

- 将全仓 `FUNC_XREFS`、`FUNC_XREFS_WINDOWS`、`FUNC_XREFS_LINUX` 统一迁移为 `list[dict]`
- 让 `preprocess_common_skill(..., func_xrefs=...)` 只接受 `dict`，不再兼容 tuple
- 新增 `xref_gvs`、`exclude_gvs`、`exclude_signatures` 三类约束
- 保持现有统一执行模型：先正向收敛，再负向排除，最后要求唯一
- 使未来继续扩展 `FUNC_XREFS` 字段时，不再受位置参数限制

## 非目标

- 不迁移其他 tuple 风格配置，如 `generate_yaml_desired_fields`、`func_vtable_relations`
- 不修改 `xref_strings`、`exclude_strings` 的字符串匹配语义
- 不引入正则匹配、权重排序、打分选优等更复杂的候选决策模型
- 不为某个单独脚本添加硬编码特判
- 不保留 tuple 兼容层

## 设计概览

统一后的 `FUNC_XREFS` 配置格式为：

```python
FUNC_XREFS = [
    {
        "func_name": "CCSPlayer_MovementServices_ProcessMovement",
        "xref_strings": [],
        "xref_gvs": ["CPlayer_MovementServices_s_pRunCommandPawn"],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]
```

其中：

- `xref_strings`、`xref_gvs`、`xref_signatures`、`xref_funcs` 是正向候选源
- `exclude_funcs`、`exclude_strings`、`exclude_gvs` 是全局负向排除源
- `exclude_signatures` 是局部负向过滤条件，只在正向收敛后的候选函数内部检查

执行模型调整为：

1. 收集所有正向候选集并求交
2. 对交集结果应用全局负向排除
3. 在剩余候选函数内部应用 `exclude_signatures`
4. 最终要求只剩 1 个函数

## 接口与契约

### `preprocess_common_skill`

`preprocess_common_skill(..., func_xrefs=...)` 中的 `func_xrefs` 条目必须全部满足以下 `dict` schema：

- `func_name`
- `xref_strings`
- `xref_gvs`
- `xref_signatures`
- `xref_funcs`
- `exclude_funcs`
- `exclude_strings`
- `exclude_gvs`
- `exclude_signatures`

约束如下：

- 每个条目必须是 `dict`
- 不允许未知字段，命中后直接报错
- `func_name` 必须是非空字符串
- 8 个列表字段允许省略，省略时按空列表处理
- 8 个列表字段若存在，必须为 `list` 或 `tuple`
- 8 个列表字段中的每个元素都必须是非空字符串
- `xref_strings`、`xref_gvs`、`xref_signatures`、`xref_funcs` 四者不能同时为空
- `exclude_funcs`、`exclude_strings`、`exclude_gvs`、`exclude_signatures` 可为空
- 同一批 `func_xrefs` 中不允许重复 `func_name`

内部标准化后的 `func_xrefs_map` 统一包含上述 9 个字段，值全部归一为 `list[str]`。

### `preprocess_func_xrefs_via_mcp`

接口扩展为接收：

- `xref_gvs`
- `exclude_gvs`
- `exclude_signatures`

并保留现有参数：

- `xref_strings`
- `xref_signatures`
- `xref_funcs`
- `exclude_funcs`
- `exclude_strings`
- `vtable_class`

## 字段语义

### 正向候选源

- `xref_strings`
  - 与现有语义一致
  - 通过字符串 xref 收集所属函数集合，参与求交

- `xref_gvs`
  - 读取对应当前版本 YAML 的 `gv_va`
  - 对该地址收集 xref 所属函数集合，参与求交

- `xref_signatures`
  - 与现有语义一致
  - 在全局搜索 signature 命中地址，再映射到所属函数集合，参与求交

- `xref_funcs`
  - 与现有语义一致
  - 读取依赖函数 YAML 中的 `func_va`，对该地址收集 xref 所属函数集合，参与求交

### 全局负向排除源

- `exclude_funcs`
  - 读取 YAML 中的 `func_va`
  - 在正向求交结束后，从候选函数集合中直接减去这些地址

- `exclude_strings`
  - 通过字符串 xref 收集所属函数集合并做并集
  - 在正向求交结束后，从候选函数集合中减去该并集
  - 如果某个排除字符串没有命中任何函数，不视为失败，只视为空排除集

- `exclude_gvs`
  - 读取 YAML 中的 `gv_va`
  - 对该地址收集 xref 所属函数集合并做并集
  - 在正向求交结束后，从候选函数集合中减去该并集
  - 如果某个排除全局变量没有命中任何函数，不视为失败，只视为空排除集

### 局部负向过滤

- `exclude_signatures`
  - 不进行全局搜索后反推函数集合
  - 只在正向求交并应用全局排除后的剩余候选函数内部检查
  - 若某个候选函数的函数范围内存在任一 `exclude_signature` 命中，则排除该候选函数
  - 若某个 `exclude_signature` 在某候选函数内没有命中，则该条件对该函数不产生影响

该语义与 `exclude_strings`、`exclude_gvs` 不同。后两者是“先收集全局排除函数集合再做差集”，而 `exclude_signatures` 是“候选函数内不得出现某字节模式”的局部过滤条件。

## 数据流与算法

### 正向阶段

候选集来源包括：

1. `vtable_class` 对应 vtable entries
2. `xref_strings`
3. `xref_gvs`
4. `xref_signatures`
5. `xref_funcs`

执行方式：

1. 先收集每一类正向来源对应的函数起始地址集合
2. 任一正向来源收集失败或产生空集合时，整体失败
3. 将全部正向集合做交集，得到 `common_funcs`

### 全局负向阶段

排除源包括：

1. `exclude_funcs`
2. `exclude_strings`
3. `exclude_gvs`

执行方式：

1. 分别收集每类排除源对应的函数地址集合
2. `exclude_funcs` 使用地址集合直接排除
3. `exclude_strings` 与 `exclude_gvs` 各自先做并集，再从 `common_funcs` 中减去
4. 某个 `exclude_string` 或 `exclude_gv` 无命中时，不直接失败

### 局部签名排除阶段

对经过全局排除后的每个候选函数：

1. 读取函数起始地址与函数结束边界
2. 仅在该函数范围内检查 `exclude_signatures`
3. 若任意一条 `exclude_signature` 在函数范围内命中，则移除该候选函数
4. 所有候选函数检查完成后，得到最终候选集

### 唯一性要求

- 最终候选集必须恰好为 1 个函数
- 若为 0 或大于 1，统一视为失败

## 依赖数据约束

### 依赖 YAML

以下字段依赖当前版本 YAML：

- `xref_funcs`
- `exclude_funcs`
- `xref_gvs`
- `exclude_gvs`

约束如下：

- `xref_funcs`、`exclude_funcs` 依赖的 YAML 必须能读取到合法 `func_va`
- `xref_gvs`、`exclude_gvs` 依赖的 YAML 必须能读取到合法 `gv_va`
- YAML 缺失、内容非映射、字段缺失、字段无法解析时，整体失败

### 函数边界

`exclude_signatures` 需要在候选函数范围内做局部检查，因此依赖：

- 能从候选 `func_va` 读取合法函数边界
- 能在函数范围内执行签名搜索或等价检查

若候选函数边界无法解析，则整体失败，不做猜测式退化处理。

## 错误处理

以下情况直接失败并返回 `False` 或 `None`：

- `func_xrefs` 条目不是 `dict`
- 存在未知字段
- `func_name` 非法
- 任一列表字段类型非法
- 任一列表字段中存在空字符串或非字符串元素
- 正向四类来源同时为空
- `xref_funcs`、`exclude_funcs` 依赖 YAML 缺失或 `func_va` 非法
- `xref_gvs`、`exclude_gvs` 依赖 YAML 缺失或 `gv_va` 非法
- `vtable_class` 对应 YAML 缺失或内容非法
- 正向任一来源收集失败或产生空集合
- `exclude_signatures` 局部检查所需函数边界无法解析
- 最终唯一性校验失败

以下情况不视为硬失败：

- 某个 `exclude_string` 没有命中任何函数
- 某个 `exclude_gv` 没有命中任何函数
- 某条 `exclude_signature` 在某候选函数内部没有命中

这些情况只意味着“该负向条件没有带来额外过滤效果”。

## 调试输出

在 `debug=True` 时建议增加以下输出：

- 每个 `FUNC_XREFS` 条目的标准化结果
- 每类正向候选源收集到的函数数量
- 正向求交前后的候选函数集合
- `exclude_funcs`、`exclude_strings`、`exclude_gvs` 的排除集合内容
- 应用全局负向排除前后的候选函数集合
- 每个候选函数内部 `exclude_signatures` 的命中情况
- 局部签名排除前后的候选函数集合
- 最终唯一化结果

## 迁移方案

本次为全仓 schema 升级，不保留旧 tuple 兼容层。

迁移动作包括：

1. 更新 `ida_analyze_util.py` 中 `func_xrefs` 的文档说明与输入校验
2. 更新 `preprocess_func_xrefs_via_mcp` 的参数签名与实现
3. 更新调用链，将 `xref_gvs`、`exclude_gvs`、`exclude_signatures` 透传到底层
4. 全量迁移 `ida_preprocessor_scripts/` 下所有 `FUNC_XREFS` 定义为 `dict`
5. 更新所有相关测试数据与断言，移除对 tuple schema 的依赖
6. 更新文档与 Serena memory 中对旧 tuple schema 的描述

## 测试与验证

本阶段只产出设计，不默认运行测试或构建。实现后建议至少做以下定向验证：

1. 静态迁移验证
   - 全仓搜索确认不再存在 tuple 风格 `FUNC_XREFS`
   - 确认所有 `FUNC_XREFS` 条目都含 `func_name`

2. 契约验证
   - 补充或更新单测，覆盖 `dict` schema 校验
   - 覆盖未知字段拒绝、旧 tuple 拒绝、空正向源拒绝

3. 行为验证
   - 覆盖 `xref_gvs` 正向求交
   - 覆盖 `exclude_gvs` 全局排除
   - 覆盖 `exclude_signatures` 仅在候选函数内部匹配的语义

4. 回归验证
   - 抽查若干现有 `func_xrefs` 脚本，确认迁移为 `dict` 后行为不变

## 风险与权衡

- 风险一：一次性全仓迁移后，任何遗漏的 tuple 都会立即失效
  - 缓解：实现前做全仓扫描，迁移后再做一次静态确认

- 风险二：`exclude_gvs` 与 `exclude_strings` 可能因为配置过宽而误排除真实目标
  - 缓解：保持“先正向求交再排除”的流程，尽量让负向条件只用于收敛而非主定位

- 风险三：`exclude_signatures` 若被误设计为全局搜索，会错误排除无关函数
  - 缓解：本设计明确限定其只在候选函数范围内检查，不允许退回全局语义

- 风险四：候选函数边界解析失败会阻断 `exclude_signatures`
  - 缓解：实现时复用已有函数基础信息读取能力，避免引入新的边界推断分支

## 实施边界

本设计只覆盖：

- `FUNC_XREFS` schema 从 tuple 迁移为 `dict`
- `xref_gvs`、`exclude_gvs`、`exclude_signatures` 三类能力接入统一管线
- 相关脚本、测试、文档与内存说明更新

本设计不覆盖：

- 其他 tuple 配置的统一迁移
- 更复杂的候选排序或启发式决策
- 运行时自动修复无效配置
