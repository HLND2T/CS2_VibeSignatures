# `config.yaml` `skip_if_exists` 跳过条件设计

## 背景

当前 `ida_analyze_bin.py` 对 skill 的调度主要依赖三类配置语义：

- `expected_output`：用于判断 skill 是否已经完成
- `expected_input`：用于判断 skill 运行前所需 artifact 是否齐全
- `prerequisite`：用于补充排序约束

这套模型可以表达“必须先产出某个 artifact，后续 skill 才能执行”，但还不能表达“某个中间 skill 不是必需的，只要另一个终态 artifact 已存在，就可以整体跳过它”。

`find-CEngineServiceMgr_DeactivateLoop` 就属于这种情况：

- 在部分 `libengine2.so` 版本中，`CEngineServiceMgr_DeactivateLoop` 可能被内联优化，独立函数不再存在
- 我们并不是必须拿到 `CEngineServiceMgr_DeactivateLoop.{platform}.yaml` 本身
- 真正需要的是 `ILoopType_DeallocateLoopMode.{platform}.yaml`
- 一旦后者已经存在，再继续执行 `find-CEngineServiceMgr_DeactivateLoop` 就没有必要

因此需要一类新的“可选跳过条件”，让某个 skill 在其自身 `expected_output` 尚不存在时，也能因为更高层 artifact 已就绪而被安全跳过。

## 目标

- 在 `config.yaml` 的 `modules[].skills[]` 下新增可选字段 `skip_if_exists`
- `skip_if_exists` 支持与 `expected_output` 相同的 artifact 模板形式，包括 `{platform}` 占位符
- 当 `skip_if_exists` 列表中的所有文件都存在时，当前 skill 直接跳过
- 跳过仅影响“是否执行该 skill”，不改变依赖排序、成功判定和最终产物语义
- 以最小改动支持如下配置：

```yaml
- name: find-CEngineServiceMgr_DeactivateLoop
  expected_output:
    - CEngineServiceMgr_DeactivateLoop.{platform}.yaml
  expected_input:
    - CEngineServiceMgr__MainLoop.{platform}.yaml
  skip_if_exists:
    - ILoopType_DeallocateLoopMode.{platform}.yaml
```

## 非目标

- 本次不把 `skip_if_exists` 扩展为通用依赖关系，不参与拓扑排序
- 本次不改造 `expected_input` / `expected_output` 的既有语义
- 本次不引入“任意一个存在即跳过”的 OR 语义；多文件场景采用 AND 语义，即必须全部存在才跳过
- 本次不修改 `update_gamedata.py`、`download.yaml` 或其他与 skill 调度无关的流程
- 本次不抽象新的高层配置系统或重构全部调度框架

## 方案比较

### 方案 A：新增通用 `skip_if_exists` 字段

做法：

- 在 `config.yaml` 中增加 `skip_if_exists`
- `parse_config()` 读取并传递该字段
- `process_binary()` 在预筛选阶段和执行前阶段都检查该字段
- 所有列出的 artifact 都存在时，跳过当前 skill

优点：

- 语义直接，对配置作者清晰
- 与当前 `expected_output` / `expected_input` 体系兼容
- 可复用于后续类似“中间 skill 可被终态 artifact 替代”的场景
- 改动范围集中在配置解析、调度与测试

缺点：

- 需要为新字段补充解析与测试覆盖
- 日志与跳过统计要新增一种原因分类

### 方案 B：移除 `prerequisite`，仅调整已有依赖

做法：

- 让 `find-ILoopType_DeallocateLoopMode` 只依赖 `CEngineServiceMgr__MainLoop`
- 不新增新字段，通过弱化 `find-CEngineServiceMgr_DeactivateLoop` 的存在意义来避免阻塞

优点：

- 配置改动最少

缺点：

- 不能表达“已有更高层 artifact 时跳过中间 skill”的明确语义
- 未来同类问题还会重复出现
- 会把本应属于调度器的语义压力转移给具体 skill 配置

### 方案 C：为该 skill 单独硬编码跳过逻辑

做法：

- 在 `ida_analyze_bin.py` 中针对 `find-CEngineServiceMgr_DeactivateLoop` 写死特殊判断

优点：

- 当前需求实现最快

缺点：

- 破坏调度器通用性
- 语义分散在代码里，不可配置
- 后续维护成本高

## 选定方案

采用方案 A：新增通用 `skip_if_exists` 字段。

理由如下：

- 它恰好表达本次需要的“终态 artifact 已存在时跳过中间 skill”的语义
- 只增加一个轻量配置字段，不需要改动现有依赖模型
- 可在不影响现有 skill 排序的前提下解决实际问题
- 对未来类似场景可直接复用，避免继续堆积特例逻辑

## 详细设计

### 1. 配置语义

在 `modules[].skills[]` 下新增可选字段：

- `skip_if_exists`：`list[string]`

规则：

- 支持 `{platform}` 占位符展开
- 与 `expected_output` 一样以当前模块 binary 目录为基准生成 artifact 路径
- 只有当列表非空且列表内所有文件都存在时，才判定当前 skill 可跳过
- 若字段缺失、为空列表或展开后列表为空，则视为“不启用该功能”

该字段是纯跳过条件，不表示：

- 当前 skill 已成功执行
- 当前 skill 的 `expected_output` 已存在
- 当前 skill 应该改变排序位置

### 2. 配置解析

`parse_config()` 为每个 skill 新增保留字段：

- `skip_if_exists`: `skill.get("skip_if_exists", []) or []`

这样后续调度阶段可以像读取 `expected_output`、`expected_input` 一样读取此字段。

### 3. 调度阶段的两次检查

`process_binary()` 中需要在两个阶段检查 `skip_if_exists`。

#### 阶段一：构建 `skills_to_process` 之前

当前逻辑会先检查：

- 平台是否匹配
- `expected_output` 是否已全部存在

本次新增：

- 若 `skip_if_exists` 全部存在，则直接：
  - 打印跳过日志
  - `skip_count += 1`
  - 不把该 skill 加入 `skills_to_process`

这样在开始 IDA 之前就能尽可能减少不必要的 skill 执行。

#### 阶段二：真正执行某个 skill 之前

即使预筛选时 `skip_if_exists` 尚未满足，也可能在本次运行中被前序 skill 刚刚生成。因此在遍历 `skills_to_process` 时，需要在现有“再次检查 `expected_output` 是否已存在”之前或相邻位置，重新检查一次 `skip_if_exists`。

若此时 `skip_if_exists` 已全部存在，则：

- 打印跳过日志
- `skip_count += 1`
- 直接 `continue`

这可以避免因为预先构建了任务列表而多跑一个已经没有必要执行的 skill。

### 4. 与拓扑排序、依赖和校验的关系

`skip_if_exists` 不参与拓扑排序：

- `topological_sort_skills()` 不读取该字段
- 不根据该字段推断新的依赖边
- 不改变现有 `expected_input` 与 `prerequisite` 的依赖语义

本次目标是“在既有排序结果上增加可选跳过”，而不是“用它建模新的依赖关系”。

因此，`find-ILoopType_DeallocateLoopMode` 当前通过 `prerequisite` 保持晚于 `find-CEngineServiceMgr_DeactivateLoop` 的排序关系，仍应保留。

### 5. 路径展开与错误处理

`skip_if_exists` 的路径展开沿用现有 `expand_expected_paths(...)`。

处理规则：

- 若占位符展开失败，按配置错误处理，当前 skill 记为失败
- 若展开成功但文件不全，不报错，只表示“跳过条件未满足”，继续走原流程
- 若字段缺失或为空，不影响现有行为

建议日志文案与 `expected_output` 跳过原因区分，例如：

- `Skipping skill: <name> (all skip_if_exists artifacts exist)`

以便和：

- `Skipping skill: <name> (all outputs exist)`

区分开来。

### 6. 本次配置落地

针对 engine 模块中的目标 skill，调整为：

- `find-CEngineServiceMgr_DeactivateLoop`
  - 保持：
    - `expected_output: [CEngineServiceMgr_DeactivateLoop.{platform}.yaml]`
    - `expected_input: [CEngineServiceMgr__MainLoop.{platform}.yaml]`
  - 新增：
    - `skip_if_exists: [ILoopType_DeallocateLoopMode.{platform}.yaml]`

- `find-ILoopType_DeallocateLoopMode`
  - 保持现状：
    - `expected_input: [CEngineServiceMgr__MainLoop.{platform}.yaml]`
    - `prerequisite: [find-CEngineServiceMgr_DeactivateLoop]`

这样可以保证：

- 若 `ILoopType_DeallocateLoopMode` 已存在，则 `find-CEngineServiceMgr_DeactivateLoop` 直接跳过
- 若其不存在，`find-CEngineServiceMgr_DeactivateLoop` 仍可正常尝试执行
- `find-ILoopType_DeallocateLoopMode` 的排序与运行条件不被破坏

## 数据流与行为结果

引入 `skip_if_exists` 后，单个 skill 的决策顺序变为：

1. 平台不匹配：跳过
2. `expected_output` 全部存在：跳过
3. `skip_if_exists` 全部存在：跳过
4. 否则进入后续执行流程
5. 执行前再次检查：
   - 若 `expected_output` 已存在：跳过
   - 若 `skip_if_exists` 已存在：跳过
6. 若仍未跳过，再继续做 `expected_input` 校验、预处理和 skill 执行

该顺序保证：

- 现有“已完成就跳过”逻辑优先级最高
- 新增“已有替代性终态 artifact 就跳过”逻辑次之
- 缺失 `skip_if_exists` 不会改变既有行为

## 测试设计

需要补充或调整单元测试，至少覆盖以下场景：

1. `parse_config()` 能正确读取 `skip_if_exists`
2. 当 `skip_if_exists` 全部存在且 `expected_output` 不存在时，skill 在预筛选阶段被跳过
3. 当 `skip_if_exists` 只存在部分文件时，skill 不应跳过
4. 当 `skip_if_exists` 在预筛选时不存在、但在执行前变为全部存在时，skill 在二次检查阶段被跳过
5. `skip_if_exists` 不应参与拓扑排序，也不应改变 `prerequisite` 的既有行为
6. 针对 `config.yaml` 的目标条目，确认新增字段后配置解析与执行路径符合预期

测试优先维持现有风格，尽量在已有 `tests/test_ida_analyze_bin.py` 中补充覆盖，而不是新增无关测试框架。

## 风险与权衡

主要风险：

- 若把 `skip_if_exists` 误用为依赖表达，可能产生“排序未变但行为被跳过”的误解
- 若日志文案不清晰，排查时难以区分是“已完成跳过”还是“替代 artifact 存在而跳过”

对应控制：

- 文档中明确 `skip_if_exists` 只是一种跳过条件，不是依赖条件
- 保持 `prerequisite` 和 `expected_input` 的语义不变
- 为跳过原因打印独立日志文案

## 验收标准

满足以下条件即可认为设计落地成功：

- `config.yaml` 可声明 `skip_if_exists`
- `ida_analyze_bin.py` 能按“全部存在才跳过”的语义处理该字段
- 该字段不影响现有拓扑排序和 `expected_input` 校验语义
- `find-CEngineServiceMgr_DeactivateLoop` 在 `ILoopType_DeallocateLoopMode.{platform}.yaml` 已存在时被稳定跳过
- 对应单元测试覆盖新增逻辑
