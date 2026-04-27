# CEntitySystem_RemoveEntity 预处理脚本设计

## 背景

仓库中已经存在 `find-SV_Kill_SmokeGrenade_CommandHandler.py`，可以通过 `RegisterConCommand` 注册信息定位 `SV_Kill_SmokeGrenade_CommandHandler`。

在 Windows 与 Linux 样本中，该 handler 的主体逻辑都非常集中：遍历 smoke grenade 链表，并在循环内直接调用 `CEntitySystem_RemoveEntity`。Windows 使用 `call imm`，Linux 样本也使用直接 `call imm`；同类优化场景还可能把最后一次调用变成尾调用 `jmp imm`。

因此，本次需要新增一个预处理脚本，从已知的 `SV_Kill_SmokeGrenade_CommandHandler` 函数体内定位唯一存在的直接分支目标，并将其作为 `CEntitySystem_RemoveEntity` 写出。与此同时，这类“从一个已知函数内抽取唯一直接 `call` / 尾调用 `jmp` 目标”的逻辑具有复用价值，应封装成独立工具类，供后续预处理脚本调用。

## 目标

- 新增共享模块 `ida_preprocessor_scripts/_direct_branch_target_common.py`
- 在共享模块中封装 `DirectBranchTargetLocator` 工具类
- 支持从指定源函数 YAML 读取 `func_va`
- 支持在源函数体内定位唯一直接 `call imm` 或直接 `jmp imm` 的目标函数
- 新增 `ida_preprocessor_scripts/find-CEntitySystem_RemoveEntity.py`
- 新增 `config.yaml` skill 配置，使 `find-CEntitySystem_RemoveEntity` 依赖 `SV_Kill_SmokeGrenade_CommandHandler.{platform}.yaml`
- 新增 `CEntitySystem_RemoveEntity` symbol metadata
- 输出 YAML 字段必须完全由调用脚本声明的 `GENERATE_YAML_DESIRED_FIELDS` 决定，公共工具类不得硬编码固定字段集合
- 成功时写出普通函数 YAML，失败时返回 `False` 交由上层 Agent 流程回退

## 非目标

- 本次不改造 `preprocess_common_skill`
- 本次不把间接调用、vtable 调用、寄存器跳转或内存操作数调用纳入定位范围
- 本次不根据参数寄存器模式识别 `g_pEntitySystem` 或待删除实体参数
- 本次不新增调试型扩展字段到最终 YAML
- 本次不运行完整构建或完整测试流程

## 方案比较

### 方案 1：新增直接分支目标公共工具类

新增 `_direct_branch_target_common.py`，把源 YAML 读取、IDA 函数扫描、唯一目标校验、目标函数信息查询、按字段契约写 YAML 等逻辑集中封装。具体 skill 脚本只声明源函数、目标函数和输出字段。

优点：

- 符合当前需求中的工具类要求
- 复用边界清晰，后续类似脚本不用复制 `py_eval` 与 YAML 写出逻辑
- 与 `_igamesystem_dispatch_common.py` 这类共享模块风格一致

缺点：

- 初次实现比单脚本略多一些结构代码

### 方案 2：只在 `find-CEntitySystem_RemoveEntity.py` 中写专用逻辑

优点：

- 实现路径最短

缺点：

- 后续类似需求会产生重复代码
- 唯一性校验、字段契约和错误处理容易漂移
- 不满足本次希望封装为工具类的要求

### 方案 3：扩展 `_registerconcommand.py`

优点：

- 可以少建一个公共模块

缺点：

- `_registerconcommand.py` 的职责是从控制台命令注册信息中提取 handler
- 本次问题是从已知函数内提取直接分支目标，职责不同
- 扩展进去会降低模块边界清晰度

## 选定方案

采用方案 1：新增直接分支目标公共工具类。

这是满足当前需求的最小充分方案，同时保留后续复用能力。

## 详细设计

### 1. 公共模块与工具类

新增模块：

- `ida_preprocessor_scripts/_direct_branch_target_common.py`

核心类：

```python
class DirectBranchTargetLocator:
    """Locate one direct call/jmp target inside a known source function."""
```

建议高层入口，以下只规定调用契约，具体实现步骤见后文定位流程：

```python
async def preprocess_direct_branch_target_skill(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    source_yaml_stem,
    target_name,
    generate_yaml_desired_fields,
    rename_to=None,
    allowed_mnemonics=("call", "jmp"),
    expected_target_count=1,
    debug=False,
):
    """Locate the direct branch target and write the requested YAML fields."""
```

接口约束：

- `source_yaml_stem` 指向已生成的源函数 YAML stem
- `target_name` 用于匹配输出文件名与最终 `func_name`
- `generate_yaml_desired_fields` 是输出字段契约的唯一来源
- `allowed_mnemonics` 默认只允许 `call` 与 `jmp`
- `expected_target_count` 本次固定使用 1，非 1 可先拒绝，避免提前泛化

### 2. 具体调用脚本

新增：

- `ida_preprocessor_scripts/find-CEntitySystem_RemoveEntity.py`

脚本只声明常量并调用公共入口：

```python
SOURCE_FUNCTION_NAME = "SV_Kill_SmokeGrenade_CommandHandler"
TARGET_FUNCTION_NAMES = [
    "CEntitySystem_RemoveEntity",
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CEntitySystem_RemoveEntity",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
        ],
    ),
]
```

`preprocess_skill` 调用 `preprocess_direct_branch_target_skill`，传入：

- `source_yaml_stem=SOURCE_FUNCTION_NAME`
- `target_name=TARGET_FUNCTION_NAMES[0]`
- `rename_to=TARGET_FUNCTION_NAMES[0]`
- `generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS`

### 3. 定位流程

公共工具类按以下顺序执行：

1. 从 `new_binary_dir/{source_yaml_stem}.{platform}.yaml` 读取源函数 YAML
2. 校验源 YAML 为 dict 且包含 `func_va`
3. 从 `expected_outputs` 中匹配唯一的 `{target_name}.{platform}.yaml`
4. 通过 `py_eval` 在 IDA 中解析源函数边界
5. 遍历 `idautils.Heads(func.start_ea, func.end_ea)`
6. 仅处理 mnemonic 在 `allowed_mnemonics` 中的指令
7. 使用 `idautils.CodeRefsFrom(ea, False)` 解析直接代码引用
8. 将目标地址归一到所属 IDA function start
9. 对目标函数 start 去重
10. 要求去重后的目标函数数量等于 `expected_target_count`
11. 查询目标函数 `func_va` 与 `func_size`
12. 根据 `GENERATE_YAML_DESIRED_FIELDS` 构造 payload
13. 写出目标 YAML
14. best-effort rename 目标函数

### 4. 直接分支判定

接受：

- `call imm`
- 直接尾调用 `jmp imm`

不接受：

- `call rax`
- `jmp rax`
- `call [reg+disp]`
- `jmp [reg+disp]`
- vtable dispatch
- thunk 链的跨函数递归展开

判定方式以 IDA 代码引用为准，而不是只看文本操作数。若某条 `call` 或 `jmp` 没有直接代码引用，则不计入候选。

### 5. YAML 字段生成

公共工具类必须先解析 `generate_yaml_desired_fields`，只允许为当前 `target_name` 生成声明过的字段。

字段来源：

- `func_name`：`target_name`
- `func_va`：IDA 查询到的目标函数 start
- `func_rva`：`func_va - image_base`
- `func_size`：IDA function boundary
- `func_sig`：仅当 `GENERATE_YAML_DESIRED_FIELDS` 为当前目标声明该字段时，调用 `preprocess_gen_func_sig_via_mcp` 生成

如果声明了工具类无法提供的字段，应返回 `False` 并在 `debug=True` 时打印原因。公共工具类不得因为自己默认习惯而额外写出未声明字段。

### 6. `config.yaml` 接入

新增 skill 配置，位置放在 `find-SV_Kill_SmokeGrenade_CommandHandler` 附近：

```yaml
- name: find-CEntitySystem_RemoveEntity
  expected_output:
    - CEntitySystem_RemoveEntity.{platform}.yaml
  expected_input:
    - SV_Kill_SmokeGrenade_CommandHandler.{platform}.yaml
```

新增 symbol metadata：

```yaml
- name: CEntitySystem_RemoveEntity
  category: func
  alias:
    - CEntitySystem::RemoveEntity
```

### 7. 错误处理

以下情况返回 `False`：

- `PyYAML` 不可用
- 源 YAML 缺失或格式不正确
- 源 YAML 缺少 `func_va`
- 目标输出路径不唯一
- `generate_yaml_desired_fields` 未包含当前 `target_name`
- 源函数边界无法在 IDA 中解析
- 直接 `call` / `jmp` 目标去重后数量不是 1
- 目标函数边界无法解析
- 请求了 `func_sig` 但签名生成失败
- 请求了未知字段

所有异常都应被公共入口收敛为 `False`，保持预处理失败后可回退。

## 验证方式

不主动运行完整构建或测试。

实施后应做定向验证：

- `python -m py_compile ida_preprocessor_scripts/_direct_branch_target_common.py ida_preprocessor_scripts/find-CEntitySystem_RemoveEntity.py`
- 静态检查 `config.yaml` 中新增 skill 的 `expected_input`、`expected_output` 与 symbol metadata 名称一致

真实 IDA MCP 验证需要在有 IDA 会话的环境中触发对应预处理流程，预期结果是：

- `SV_Kill_SmokeGrenade_CommandHandler` 内唯一直接分支目标被解析为 `CEntitySystem_RemoveEntity`
- 写出 `CEntitySystem_RemoveEntity.{platform}.yaml`
- YAML 字段只包含 `GENERATE_YAML_DESIRED_FIELDS` 声明的字段

## 风险与权衡

- 如果未来 `SV_Kill_SmokeGrenade_CommandHandler` 内新增其他直接 `call` 或直接 `jmp`，本脚本会失败。这是有意的 fail-fast 设计，避免误判。
- 如果目标函数通过 thunk 间接跳转，本次不会递归展开 thunk。这样可以保持工具类语义简单，并避免误跨到不相关函数。
- `func_sig` 生成依赖现有 `preprocess_gen_func_sig_via_mcp`，若目标函数过短或签名不唯一，预处理会失败并回退。

## 实施边界

本次实施只触及：

- `ida_preprocessor_scripts/_direct_branch_target_common.py`
- `ida_preprocessor_scripts/find-CEntitySystem_RemoveEntity.py`
- `config.yaml`

不修改其他预处理脚本，不修改已有公共 helper 的行为。
