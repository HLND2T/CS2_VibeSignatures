# `ILoopType_DeallocateLoopMode` 多目标 LLM_DECOMPILE 与内联降级设计

## 背景

当前 `find-ILoopType_DeallocateLoopMode` 的 LLM fallback 只支持单条 `LLM_DECOMPILE` spec：

- `ida_preprocessor_scripts/find-ILoopType_DeallocateLoopMode.py` 只能引用 `references/engine/CEngineServiceMgr_DeactivateLoop.{platform}.yaml`
- `ida_analyze_util.py` 中 `_build_llm_decompile_specs_map(...)` 以 symbol name 为唯一 key，重复 symbol 会直接判定为 duplicated
- `_prepare_llm_decompile_request(...)` 只会读取一份 reference YAML，并只为一个 target function 准备当前版本的反汇编与伪代码
- `ida_preprocessor_scripts/prompt/call_llm_decompile.md` 的语义也是单 reference、单 target

这在旧版本中成立，因为 `CEngineServiceMgr_DeactivateLoop` 是独立函数，`ILoopType_DeallocateLoopMode` 可通过该函数中的 vcall 直接识别。

但在部分 `libengine2.so` 版本中，`CEngineServiceMgr_DeactivateLoop` 会被直接内联到 `CEngineServiceMgr__MainLoop` 中：

- 当前版本可能不存在独立的 `CEngineServiceMgr_DeactivateLoop`
- `find-CEngineServiceMgr_DeactivateLoop` 不应再假设一定产出 YAML
- `find-ILoopType_DeallocateLoopMode` 仍需要从 `CEngineServiceMgr__MainLoop` 中识别到 `ILoopType_DeallocateLoopMode` 的 vcall

同时，仅把 `find-ILoopType_DeallocateLoopMode` 的 `expected_input` 改成 `CEngineServiceMgr__MainLoop` 还不够。因为一旦排序不稳定，它仍可能在 `find-CEngineServiceMgr_DeactivateLoop` 之前执行，进而丢失本来可以利用的 `DeactivateLoop` 信息。

本次需要同时解决三个问题：

- `LLM_DECOMPILE` 支持同一 symbol 绑定多条 spec
- LLM prompt 同时注入 `CEngineServiceMgr_DeactivateLoop` 与 `CEngineServiceMgr__MainLoop` 的 reference/target 上下文
- `find-CEngineServiceMgr_DeactivateLoop` 允许“函数已内联、当前版本不存在”的合法缺失，同时保证 `find-ILoopType_DeallocateLoopMode` 仍排在其后执行

## 目标

- 允许 `find-ILoopType_DeallocateLoopMode` 以如下形式声明多条同名 `LLM_DECOMPILE` spec：

```python
LLM_DECOMPILE = [
    (
        "ILoopType_DeallocateLoopMode",
        "prompt/call_llm_decompile.md",
        "references/engine/CEngineServiceMgr_DeactivateLoop.{platform}.yaml",
    ),
    (
        "ILoopType_DeallocateLoopMode",
        "prompt/call_llm_decompile.md",
        "references/engine/CEngineServiceMgr__MainLoop.{platform}.yaml",
    ),
]
```

- 让 LLM fallback 在一次请求中同时看到两份 reference 上下文与可导出的当前版本 target 上下文。
- 当当前版本不存在独立 `CEngineServiceMgr_DeactivateLoop` 时，`find-CEngineServiceMgr_DeactivateLoop` 不计为失败。
- 保证 `find-ILoopType_DeallocateLoopMode` 在排序上仍位于 `find-CEngineServiceMgr_DeactivateLoop` 之后。
- 保持现有 LLM 输出 YAML schema 不变，仍复用 `found_vcall` / `found_call` / `found_funcptr` / `found_gv` / `found_struct_offset`。

## 非目标

- 本次不引入通用的 `optional expected_input` / `optional expected_output` 配置语法。
- 本次不修改 `update_gamedata.py` 的缺失 YAML 处理策略。
- 本次不重构全部 LLM fallback 调用点为完全新的高层接口。
- 本次不改变已有 symbol YAML schema、字段顺序或 `preprocess_common_skill(...)` 的核心产物装配流程。
- 本次不执行与该需求无关的测试、build 或重构。

## 方案比较

### 方案 A：局部双层依赖语义

做法：

- `find-ILoopType_DeallocateLoopMode` 的运行时硬依赖只保留 `CEngineServiceMgr__MainLoop.{platform}.yaml`
- 通过 `prerequisite` 强制它在排序上依赖 `find-CEngineServiceMgr_DeactivateLoop`
- `LLM_DECOMPILE` 支持同一 symbol 多条 spec，并在 LLM request 中聚合多 reference / 多 target
- `find-CEngineServiceMgr_DeactivateLoop` 返回“合法缺失”状态，而不是失败

优点：

- 改动范围集中
- 不需要引入全局 optional artifact 语义
- 同时满足“排序在后”和“当前版本可缺失”
- 与当前 `preprocess_common_skill(...)` 的批处理缓存逻辑兼容

缺点：

- 需要扩展 `ida_analyze_util.py` 中的 LLM request 结构
- 需要让预处理返回值从二态扩展为三态

### 方案 B：框架级 optional artifact

做法：

- 在 `config.yaml` 为 `expected_input` / `expected_output` 增加 optional 标记
- 调度、校验、skip/fail 统计都理解 optional artifact

优点：

- 语义更通用

缺点：

- 波及拓扑排序、输入校验、产物校验、日志与统计
- 风险和测试面明显大于当前需求

### 方案 C：新增中间统一产物

做法：

- 新增一个专门描述 “DeactivateLoop or inline site” 的 skill 和 YAML
- `find-ILoopType_DeallocateLoopMode` 只依赖该中间产物

优点：

- 语义单独封装

缺点：

- 多一层产物与维护成本
- 对当前问题属于过度设计

## 选定方案

采用方案 A：局部双层依赖语义。

这是满足当前需求的最小充分改造。它把“排序约束”和“运行时必需输入”拆开处理：

- 排序仍然显式晚于 `find-CEngineServiceMgr_DeactivateLoop`
- 执行时只要求 `CEngineServiceMgr__MainLoop` 一定存在
- 如果 `CEngineServiceMgr_DeactivateLoop` 当前版本仍存在，就纳入 LLM target 上下文
- 如果它已被内联，则合法跳过，不阻断 `ILoopType_DeallocateLoopMode` 的恢复流程

## 详细设计

### 1. `config.yaml` 依赖模型调整

修改 `find-ILoopType_DeallocateLoopMode` 的 skill 配置：

- `expected_input` 从：
  - `CEngineServiceMgr_DeactivateLoop.{platform}.yaml`
- 调整为：
  - `CEngineServiceMgr__MainLoop.{platform}.yaml`
- 新增：
  - `prerequisite: [find-CEngineServiceMgr_DeactivateLoop]`

语义拆分如下：

- `expected_input` 只表达“运行前必须存在的 artifact”
- `prerequisite` 只表达“排序必须晚于哪些 skill”

这样 `ida_analyze_bin.py` 在运行时不会因为 `CEngineServiceMgr_DeactivateLoop.{platform}.yaml` 缺失而在 expected_input 检查阶段直接失败，但 `topological_sort_skills(...)` 仍会将 `find-ILoopType_DeallocateLoopMode` 排到 `find-CEngineServiceMgr_DeactivateLoop` 之后。

### 2. `find-ILoopType_DeallocateLoopMode.py` 的多 spec 声明

该脚本的 `LLM_DECOMPILE` 改为两条同名 symbol spec，顺序固定如下：

1. `CEngineServiceMgr_DeactivateLoop.{platform}.yaml`
2. `CEngineServiceMgr__MainLoop.{platform}.yaml`

顺序固定的目的有两点：

- 当两者都可用时，优先把更直接、更小的 `DeactivateLoop` 上下文放在前面
- 当 `DeactivateLoop` 缺失时，后续逻辑只需要顺序跳过，不会影响 `MainLoop`

### 3. `LLM_DECOMPILE` spec 结构升级

`ida_analyze_util.py` 中 `_build_llm_decompile_specs_map(...)` 从当前：

- `symbol_name -> 单条 spec`

升级为：

- `symbol_name -> 有序 spec 列表`

新规则：

- 同一 symbol 允许重复出现
- 重复 symbol 不再视为错误
- 同一 symbol 下的多条 spec 必须都使用同一个 `prompt_path`
- 仍保留输入校验：`func_name`、`prompt_path`、`reference_yaml_path` 都必须为非空字符串

这样同一个 symbol 的多条 reference 可以被统一打包到一次 LLM request 中。

### 4. LLM request bundle 结构

`_prepare_llm_decompile_request(...)` 不再返回单 reference、单 target 请求，而是返回一个 bundle：

- `prompt_path`
- `prompt_template`
- `model`
- `client`
- `temperature`
- `effort`
- `api_key`
- `base_url`
- `fake_as`
- `reference_items`
- `target_func_names`

其中：

- `reference_items` 为有序列表，每一项来自一份 reference YAML，包含：
  - `reference_func_name`
  - `reference_disasm_code`
  - `reference_procedure`
- `target_func_names` 为有序列表，来自上述每条 reference YAML 的 `func_name`

每条 reference YAML 既定义“旧版本参考函数”，也定义“当前版本待导出 target function”。

### 5. 当前版本 target detail 的收集与降级

新增或调整 target detail 收集逻辑，使其支持：

- 针对同一 symbol 的多个 target function 逐个尝试导出
- 每个 target detail 包含：
  - `func_name`
  - `func_va`
  - `disasm_code`
  - `procedure`

具体规则：

1. 先按 spec 顺序逐个解析 target function name
2. 对每个 target：
   - 优先从当前版本已有 YAML 读取 `func_va`
   - 若无 YAML 或 YAML 中缺少 `func_va`，则回退到 name lookup
   - 若能定位函数地址，则导出 detail
   - 若确认当前版本没有该函数，则跳过该 target，不视为整个 symbol 的失败
3. 至少保留一个成功导出的 target detail 才允许发起 LLM 调用
4. 若所有 target 都无法导出，则 LLM fallback fail-closed

对 `ILoopType_DeallocateLoopMode` 而言，这意味着：

- `DeactivateLoop` 存在时，参与 target context
- `DeactivateLoop` 被内联时，仅丢弃该 target，继续使用 `MainLoop`
- 允许出现 `reference_blocks` 包含 `CEngineServiceMgr_DeactivateLoop` 与 `CEngineServiceMgr__MainLoop` 两块，但 `target_blocks` 只包含 `CEngineServiceMgr__MainLoop` 的情况；该缺失仅表示当前版本没有可导出的独立 `CEngineServiceMgr_DeactivateLoop`

### 6. Prompt 模板改造

`ida_preprocessor_scripts/prompt/call_llm_decompile.md` 改为支持多 reference / 多 target。

新模板不再使用单一占位符：

- `{disasm_for_reference}`
- `{procedure_for_reference}`
- `{disasm_code}`
- `{procedure}`

而是改为渲染两个预组装的多段文本：

- `reference_blocks`
- `target_blocks`

每个 reference block 至少包含：

- 函数名
- 反汇编
- 伪代码

每个 target block 至少包含：

- 函数名
- 反汇编
- 伪代码

Prompt 语义明确要求：

- 在所有 target functions 的并集中收集对 `{symbol_name_list}` 的引用
- 可以借助所有 reference functions 理解调用模式
- 输出格式仍然必须是当前约定的 YAML

### 7. `call_llm_decompile(...)` 的兼容策略

`call_llm_decompile(...)` 保持“一次调用、一次 YAML 输出”的现有模式，不改变返回值结构。

变化仅在输入层：

- 支持使用预渲染后的 `reference_blocks` / `target_blocks`
- 继续把 `symbol_name_list` 作为单次请求内需要识别的 symbol 集合

这样可以最大限度复用现有：

- `parse_llm_decompile_response(...)`
- `found_vcall` / `found_call` / `found_funcptr` / `found_gv` / `found_struct_offset` 的后续解析
- `preprocess_common_skill(...)` 中的直接 call / vcall / funcptr / gv / struct-member fallback

### 8. LLM request 缓存 key

缓存 key 从当前：

- `model + prompt_path + reference_yaml_path + temperature`

升级为：

- `model + prompt_path + 有序 reference_yaml_path 列表 + temperature`

原因：

- 同一 symbol 现在可能对应多份 reference
- 只有整组 spec 完全相同，才应复用同一次 LLM request

### 9. `find-CEngineServiceMgr_DeactivateLoop` 的合法缺失语义

当前调度链默认把“没有产出 expected_output”视为失败，这与“函数已被内联、当前版本不存在”不兼容。

本次将预处理返回语义从二态扩展为三态：

- `success`：成功生成 `CEngineServiceMgr_DeactivateLoop.{platform}.yaml`
- `absent_ok`：已明确确认当前版本不存在独立 `CEngineServiceMgr_DeactivateLoop`，这是合法缺失
- `failed`：其余情况，包括异常、歧义、脚本错误、无法证明 inline 缺失

实现方向：

- `find-CEngineServiceMgr_DeactivateLoop.py` 在预处理层优先通过 `CEngineServiceMgr__MainLoop` 判断：
  - 若存在对独立 `CEngineServiceMgr_DeactivateLoop` 的 direct call，则正常定位并产出 YAML
  - 若不存在 direct call，但在 `MainLoop` 中发现内联后的 `ILoopType_LoopDeactivate` / `ILoopType_DeallocateLoopMode` 序列，则判定为 `absent_ok`
  - 其他情况仍为 `failed`

`ida_skill_preprocessor.py` 与 `ida_analyze_bin.py` 对三态的处理：

- `success`：与当前相同
- `absent_ok`：
  - 不计入 `fail_count`
  - 不再继续 `run_skill(...)`
  - 以“合法缺失 / 已内联”形式打印日志
- `failed`：维持现有失败路径

### 10. `find-ILoopType_DeallocateLoopMode` 的执行时序

最终时序要求如下：

1. `find-CEngineServiceMgr__MainLoop`
2. `find-CEngineServiceMgr_DeactivateLoop`
3. `find-ILoopType_DeallocateLoopMode`

保证来源：

- `find-CEngineServiceMgr_DeactivateLoop` 的 `expected_input` 已依赖 `CEngineServiceMgr__MainLoop`
- `find-ILoopType_DeallocateLoopMode` 新增 `prerequisite: [find-CEngineServiceMgr_DeactivateLoop]`

这样可以保证：

- 如果 `DeactivateLoop` 能产出，`ILoopType_DeallocateLoopMode` 执行时一定能看到它
- 如果 `DeactivateLoop` 合法缺失，`ILoopType_DeallocateLoopMode` 仍然晚于它执行，从而能利用其“已判断 inline 缺失”的结果和 `MainLoop` 产物

## 错误处理与边界

- 同一 symbol 下若多条 spec 的 `prompt_path` 不一致，直接视为配置错误并 fail-closed。
- 某条 reference YAML 缺失、损坏或缺少 `func_name` 时，整个 symbol 的 bundle 视为无效并 fail-closed。
- 某个 target function 当前版本无法导出 detail 时，只跳过该 target，不直接失败整个 bundle。
- 所有 target 都不可用时，整个 symbol 的 LLM fallback 失败。
- `DeactivateLoop` 只有在能明确证明“当前版本不存在独立函数但已内联进 `MainLoop`”时，才能返回 `absent_ok`；不能因为普通定位失败就静默放过。

## 测试设计

### 1. `tests/test_ida_preprocessor_scripts.py`

- 更新 `find-ILoopType_DeallocateLoopMode` 对 `preprocess_common_skill(...)` 的转发断言：
  - `expected_input` 只依赖 `CEngineServiceMgr__MainLoop`
  - `llm_decompile_specs` 为两条同名 symbol spec，顺序固定
- 如有需要，为 `find-CEngineServiceMgr_DeactivateLoop` 新增测试，验证其脚本会向公共层传递合法缺失所需的配置或返回值

### 2. `tests/test_ida_analyze_util.py`

- 新增 `_build_llm_decompile_specs_map(...)` 用例：
  - 接受重复 symbol
  - 保留 spec 顺序
  - 拒绝同一 symbol 下不同 `prompt_path`
- 新增 `_prepare_llm_decompile_request(...)` 用例：
  - 能装配多份 reference
  - 能产出多 target function name 列表
  - cache key 会反映整组 reference path
- 新增 `preprocess_common_skill(...)` 用例：
  - 只有 `MainLoop` target 可导出时，仍能成功发起一次 LLM fallback 并生成 `ILoopType_DeallocateLoopMode`
  - `DeactivateLoop` 与 `MainLoop` 都可导出时，prompt 中包含两份 reference 与两份 target
  - 两个 target 都不可导出时，仍按失败处理

### 3. `tests/test_ida_analyze_bin.py`

- 验证 `prerequisite` 能保证 `find-ILoopType_DeallocateLoopMode` 排在 `find-CEngineServiceMgr_DeactivateLoop` 之后。
- 验证 `find-CEngineServiceMgr_DeactivateLoop` 返回 `absent_ok` 时：
  - 不计失败
  - 不触发 `run_skill(...)`
  - 后续 `find-ILoopType_DeallocateLoopMode` 仍继续执行

## 风险与权衡

- 多 reference / 多 target prompt 会增长上下文长度，但本场景只增加到两个函数，成本可控。
- 三态预处理返回值会影响调度层接口，因此必须把 `absent_ok` 限制在极少数可明确证明合法缺失的场景，避免被滥用成“软失败”。
- `find-ILoopType_DeallocateLoopMode` 仍依赖 `MainLoop` 作为硬输入，因此若 `MainLoop` 本身无法产出，整个恢复流程仍然失败。这是符合预期的，因为当前 inline 降级路径正是建立在 `MainLoop` 之上。

## 实施摘要

本次实现将分为四块：

1. 调整 `config.yaml` 中 `find-ILoopType_DeallocateLoopMode` 的依赖语义
2. 扩展 `ida_analyze_util.py` 的 LLM spec 聚合、request bundle、prompt 渲染与缓存 key
3. 为 `find-CEngineServiceMgr_DeactivateLoop` 增加合法缺失判定，并让调度层理解 `absent_ok`
4. 补齐覆盖多 spec 聚合、inline 降级与排序保证的测试

该方案在不引入全局 optional artifact 机制的前提下，满足：

- `DeactivateLoop` 可能不存在
- `ILoopType_DeallocateLoopMode` 仍可恢复
- 排序上依然晚于 `find-CEngineServiceMgr_DeactivateLoop`
