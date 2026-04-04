# 为 `ida_analyze_bin.py` 增加 `vcall_finder` 流程设计

## 背景

当前 `ida_analyze_bin.py` 负责按 `config.yaml` 中的 `modules -> skills` 顺序启动 IDA MCP、执行预处理与 Agent SKILL，并在 `bin/{gamever}/{module}` 下输出符号 YAML。

本次设计在不改变既有 `skills` 主流程的前提下，为脚本增加一个可选的附加分析链：

1. 当命令行传入 `-vcall_finder=...` 时，读取 `config.yaml` 中模块级 `vcall_finder` 配置。
2. 在每个模块/平台的既有 IDA 任务完成后，复用当前 IDA MCP 会话，定位指定对象并导出所有引用该对象的函数完整反汇编与伪代码。
3. 在全部模块/平台的 IDA 任务结束后，统一调用 OpenAI SDK 读取这些函数 YAML，并从 LLM 输出中提取目标对象的虚函数调用信息。
4. 将解析结果追加到对象级汇总 YAML 中，供后续人工检视或二次处理。

## 目标

- 为 `ida_analyze_bin.py` 新增参数 `-vcall_finder=g_pNetworkMessages`。
- 支持 `-vcall_finder=*` 与 `-vcall_finder=g_pNetworkMessages` 两类筛选方式。
- 仅处理 `config.yaml` 中模块已声明的 `vcall_finder` 对象。
- 导出目录按 `gamever` 隔离，避免不同版本中间产物互相覆盖。
- 在对象级汇总文件中以扁平列表形式保存 LLM 识别出的虚调用结果。
- OpenAI 配置兼容环境变量方式，并支持模型覆盖。

## 非目标

- 不自动枚举未在 `config.yaml` 中声明的对象名。
- 不新增模糊符号匹配、正则匹配或签名推断。
- 不为本次功能额外引入独立 CLI。
- 不引入强制刷新导出结果的额外参数。
- 不改变现有 `skills` 的拓扑排序、预处理、重试与摘要逻辑。

## 用户接口

### 新增命令行参数

- `-vcall_finder`
  - 未传入：禁用该功能。
  - `*`：处理模块中 `config.yaml` 已声明的全部对象。
  - `name1,name2`：仅处理同名对象，且对象必须存在于模块配置中。
- `-openai_model`
  - 可选，覆盖 OpenAI 使用的模型名。

### OpenAI 配置优先级

1. `-openai_model`
2. `OPENAI_API_MODEL`
3. 默认值 `gpt-4o`

OpenAI 鉴权与兼容基址沿用环境变量：

- `OPENAI_API_KEY`
- `OPENAI_API_BASE`（可选）

### `config.yaml` 配置

沿用模块级配置，不改格式：

```yaml
modules:
  - name: networksystem
    path_windows: game/bin/win64/networksystem.dll
    path_linux: game/bin/linuxsteamrt64/libnetworksystem.so

    vcall_finder:
      - g_pNetworkMessages
```

`parse_config()` 扩展后，每个模块对象除现有 `skills` 外，还应带有：

- `vcall_finder_objects: list[str]`

## 总体架构

采用“主脚本调度 + 独立 helper”方案。

### `ida_analyze_bin.py`

职责：

- 解析新参数 `-vcall_finder` 与 `-openai_model`
- 解析 `config.yaml` 中的模块级 `vcall_finder`
- 保持现有 `skills` 主流程不变
- 在每个模块/平台的 `skills` 执行完毕后，若命中 `-vcall_finder`，则调用 helper 执行当前二进制的引用函数导出
- 在所有模块/平台处理结束后，若启用了 `-vcall_finder`，则调用 helper 统一执行 OpenAI 聚合

### `ida_vcall_finder.py`

新增 helper 模块，职责分为两部分：

1. IDA 导出阶段
   - 基于 MCP `py_eval` 在当前二进制中定位对象
   - 枚举 `XrefsTo(object_ea)`，提取所属函数
   - 对每个唯一函数导出完整反汇编和完整伪代码 YAML
2. LLM 聚合阶段
   - 扫描 `vcall_finder/{gamever}/{object_name}` 下的单函数 YAML
   - 调用 OpenAI SDK
   - 解析 LLM YAML
   - 追加或更新对象级汇总 YAML

该拆分保证外部入口仍是 `ida_analyze_bin.py`，但将新功能的导出与聚合逻辑从主脚本中隔离。

## 执行时序

### 模块/平台级阶段

对每个命中的模块与平台：

1. 启动或复用 IDA MCP。
2. 按现有逻辑处理全部 `skills`。
3. 若当前模块在该平台命中 `-vcall_finder` 选择器，则在同一 IDA MCP 会话中执行对象引用函数导出。
4. 导出完成后按现有逻辑退出 IDA。

### IDA 启动判定修正

现有实现中，若某个模块/平台下全部 `skills` 的 `expected_output` 都已存在，会直接打印：

- `All skills already have yaml files, skipping IDA startup`

并跳过为该模块/平台启动 IDA。

本次设计要求在启用 `-vcall_finder` 时修正这条优化规则：

- 若当前模块/平台命中了 `vcall_finder` 对象，即使全部 `skills` 产物都已存在，也不得因为“`skills` 全部命中缓存”而跳过 IDA 启动。
- 换言之，模块/平台是否启动 IDA，必须同时考虑：
  - 是否仍有待处理的 `skills`
  - 是否仍需执行该模块/平台的 `vcall_finder`

推荐实现语义：

- `skills_to_process` 非空：启动 IDA
- `skills_to_process` 为空，但当前模块/平台存在命中的 `vcall_finder` 对象：仍然启动 IDA
- 仅当 `skills_to_process` 为空，且当前模块/平台没有需要执行的 `vcall_finder` 对象时，才允许整体跳过 IDA 启动

这条规则的目标是保证：

- `vcall_finder` 是与 `skills` 并列考虑的模块级任务
- 不会因为既有 `skills` 缓存命中而导致新增的 `vcall_finder` 流程完全不执行

### 全局收尾阶段

在所有模块/平台都完成后：

1. 若未启用 `-vcall_finder`，直接结束。
2. 若启用了 `-vcall_finder`，按对象逐个扫描 `vcall_finder/{gamever}/{object_name}/*/*/*.yaml`。
3. 对每个函数明细 YAML 调用 OpenAI。
4. 解析结果并更新 `vcall_finder/{gamever}/{object_name}.yaml`。

这样可以满足“先跑完 IDA 上所有任务，再做额外 OpenAI 动作”的要求。

## 输出结构

### 单函数明细 YAML

路径：

`vcall_finder/{gamever}/{object_name}/{module}/{platform}/{func_name}.yaml`

内容：

```yaml
object_name: g_pNetworkMessages
module: networksystem
platform: windows
func_name: sub_140123450
func_va: 0x12345678
disasm_code: |-
  这里输出函数的完整反汇编
procedure: |-
  这里输出函数的完整伪代码
```

说明：

- `module` 字段显式保存，避免聚合阶段依赖路径反推。
- `disasm_code` 与 `procedure` 使用 YAML literal block 存储。
- 若伪代码不可用，仍写入该明细文件，`procedure` 为空字符串。

### 对象级汇总 YAML

路径：

`vcall_finder/{gamever}/{object_name}.yaml`

结构：

```yaml
object_name: g_pNetworkMessages
results:
  - module: networksystem
    platform: windows
    func_name: sub_140123450
    func_va: 0x12345678
    found_vcall:
      - insn_va: 0x12345678
        insn_disasm: call    [rax+68h]
        vfunc_offset: 0x68
  - module: engine
    platform: linux
    func_name: sub_140223450
    func_va: 0x23456789
    found_vcall: []
```

说明：

- `results` 为扁平列表。
- 即使 LLM 未发现虚调用，也保留该函数项，并写入 `found_vcall: []`。
- 去重键为 `(module, platform, func_name, func_va)`。
- 若重复处理同一函数，更新已有记录的 `found_vcall`，而不是新增重复项。

## IDA 导出阶段设计

### 对象定位

对每个对象名执行精确符号查找：

- `ida_name.get_name_ea(BADADDR, object_name)`

若未找到：

- 记录为 `skip`
- 打印明确日志
- 不做模糊匹配或签名推断

### xref 收集

对象地址命中后：

- 枚举 `idautils.XrefsTo(object_ea, 0)`
- 取每个 `xref.frm`
- 通过 `ida_funcs.get_func(xref.frm)` 或 `idaapi.get_func(xref.frm)` 找所属函数
- 仅保留落在函数内的引用
- 以函数起始地址去重

### 函数导出

对每个唯一函数地址：

- 使用 `ida_funcs.get_func_name(func_ea)` 获取函数名
- 参考 `kphtools/ida/ida.py` 的导出方式生成完整反汇编
- 参考 `kphtools/ida/ida.py` 的反编译方式生成完整伪代码
- 写入单函数明细 YAML

导出的是整函数，而不是只包含引用附近的局部片段。

### 明细导出去重

- 单轮导出：按函数起始地址去重
- 跨多次运行：若明细 YAML 已存在，则默认跳过，不重复导出

注意：

- 即使单函数明细 YAML 已全部存在，也不应依赖“`skills` 全部已存在”这一条件跳过整个模块/平台的 IDA 启动。
- 是否允许对当前对象快速结束，应由 `vcall_finder` 自身逻辑判断，而不是复用 `skills` 的跳过条件。

### 导出阶段错误处理

- 对象不存在：`skip`
- 对象存在但无 xref：`skip`
- 单个函数无法取反汇编：该函数 `fail`，继续后续函数
- 单个函数无伪代码：写空 `procedure`，不视为整体失败
- MCP/IDA 会话整体失效：终止当前模块平台的 `vcall_finder`

## OpenAI 聚合阶段设计

### Prompt

固定使用下列模板：

```text
You are a reverse engineering expert. I have disassembly outputs and procedure code of the same function.

**Disassembly**

```c
{yaml.disasm_code}
```

**Procedure code**

```c
{yaml.procedure}
```

Please collect all virtual function calls for "{yaml.object_name}" and output those calls as YAML

Example:

```yaml
found_vcall: 
  - insn_va: 0x12345678
    insn_disasm: call    [rax+68h]
    vfunc_offset: 0x68
  - insn_va: 0x12345680
    insn_disasm: call    rax
    vfunc_offset: 0x80
```

If there are no virtual function calls for "{yaml.object_name}" found, output an empty YAML.
```

### SDK 调用方式

使用 OpenAI Python SDK：

- 客户端：`OpenAI(api_key=..., base_url=...)`
- 接口：`client.chat.completions.create(...)`
- `system`：`You are a reverse engineering expert.`
- `user`：填充后的 Prompt
- `temperature=0.1`

### 响应解析

解析规则参考 `kphtools/ida/generate_mapping.py`：

1. 优先提取 ```yaml ... ``` 代码块
2. 若无代码块，则直接把全文视为 YAML
3. 使用 `yaml.safe_load()` 解析
4. 统一规范化为：
   - `found_vcall: [...]`
   - 或 `found_vcall: []`

允许的“空结果”包括：

- 空字符串
- `{}` / `null`
- 缺失 `found_vcall`

这些情况都归一化为 `found_vcall: []`。

### 聚合阶段错误处理

- 单个明细 YAML 读取失败：记录错误并继续
- 单个 OpenAI 请求失败：记录错误并继续
- 单个响应 YAML 解析失败：不写入该函数结果，并打印调试信息片段
- 未配置 `OPENAI_API_KEY`：聚合阶段报错并返回失败

### 汇总文件更新语义

对每个明细函数，写入或更新以下记录：

- `module`
- `platform`
- `func_name`
- `func_va`
- `found_vcall`

更新策略：

- 已存在相同去重键：覆盖 `found_vcall`
- 不存在：追加新项

## 返回码与统计语义

- 原有 `skills` 失败：维持现有非零退出行为
- 启用了 `-vcall_finder` 且导出或聚合出现失败：最终也返回非零
- 对象不存在或无 xref：计为 `skip`，不视为整个流程失败

建议新增日志统计：

- 每个对象在每个模块/平台中找到的唯一函数数量
- 生成的明细 YAML 数量
- 聚合阶段扫描的文件数
- 成功解析与更新的记录数
- 跳过数与失败数

## 依赖与文档更新

### 代码文件

预计修改：

- `ida_analyze_bin.py`
- `pyproject.toml`
- `README_CN.md`

预计新增：

- `ida_vcall_finder.py`

### Python 依赖

在 `pyproject.toml` 中新增：

- `openai`

## 验证策略

本设计定义的最小验证范围如下：

### 静态验证

- 参数解析：
  - `-vcall_finder=*`
  - `-vcall_finder=g_pNetworkMessages`
  - `-openai_model`
- 配置筛选：
  - 仅处理模块配置中声明过的对象
- 路径组织：
  - 明细输出按 `vcall_finder/{gamever}/{object}/{module}/{platform}` 隔离
  - 汇总输出为 `vcall_finder/{gamever}/{object}.yaml`
- 汇总去重：
  - 相同 `(module, platform, func_name, func_va)` 不重复追加

### 运行验证

建议的真实 smoke 场景：

```bash
uv run ida_analyze_bin.py \
  -gamever=14141 \
  -modules=networksystem \
  -platform=windows \
  -vcall_finder=g_pNetworkMessages
```

预期验证点：

- 明细 YAML 正常生成
- 汇总 YAML 正常生成
- LLM 返回可解析
- 重跑时汇总项被更新而不是重复追加

## 实施边界

本设计控制在单个实现计划内完成，范围清晰：

- 新增一个 helper 模块
- 扩展主脚本参数与调度
- 新增 OpenAI 依赖
- 更新中文 README

不包含额外并行化、缓存层、刷新参数、外置 Prompt 文件或独立 CLI 的扩展工作。
