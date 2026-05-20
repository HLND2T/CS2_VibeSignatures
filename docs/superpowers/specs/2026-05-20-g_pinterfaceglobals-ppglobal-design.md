# g_pInterfaceGlobals ppGlobal 预处理设计

## 背景

现有 `find-g_pInterfaceGlobals` 只定位 `g_pInterfaceGlobals` 表本身，并生成 `g_pInterfaceGlobals.{platform}.yaml`。IDA 中该表实际由连续的 16 字节 entry 组成：

```text
entry + 0x0: interface_name_ptr
entry + 0x8: pp_global_ptr
```

每个 `interface_name_ptr` 指向稳定的接口版本字符串，例如 `VApplication001`；对应的 `pp_global_ptr` 是该接口全局变量指针的地址，例如 `g_pVApplication`。但实际 IDB 中 `pp_global_ptr` 不一定已经被重命名，因此不能把 IDA 名称作为定位依据。

## 目标

- 新增 `find-g_pInterfaceGlobals_ppGlobal` 预处理脚本。
- 从 `g_pInterfaceGlobals` 表程序化定位 `g_pVApplication`、`g_pVEngineCvar` 等 `g_pXXXX` 全局变量指针。
- 为每个目标输出最小 GV YAML 字段：
  - `gv_name`
  - `gv_va`
  - `gv_rva`
- 在 `config.yaml` 中为 `client`、`server`、`engine` 注册新 skill。
- 在 `client`、`server`、`engine` 的 symbols 中注册这些 `g_pXXXX`，类别为 `gv`。
- 强制要求三个模块的 `g_pInterfaceGlobals` entries 覆盖对应平台预期集合；允许实际表中存在额外 entries，且不为额外项生成 YAML。

## 非目标

- 不为这些 `g_pXXXX` 生成 `gv_sig`、`gv_sig_va`、`gv_inst_*` 字段。
- 不依赖或信任 `pp_global_ptr` 当前 IDA 名称。
- 不针对 `client`、`server`、`engine` 维护不同 expected list；只允许 Windows `.dll` 与 Linux `.so` 存在平台尾项差异。
- 不调整 `find-g_pInterfaceGlobals` 的现有定位逻辑。
- 不修改下游 gamedata 生成逻辑。

## 方案比较

### 方案 1：以 interface_name 集合为强约束

脚本维护一份 `EXPECTED_ENTRIES = [(interface_name, gv_name), ...]`。运行时读取 `g_pInterfaceGlobals` 表中的实际 entries，按 `interface_name` 建立映射，并要求当前平台预期的每个 `interface_name` 都存在。通过校验后，用同一 entry 的 `pp_global_ptr` 地址生成对应 `gv_name` 的 YAML；实际表中多出的 entries 忽略。

优点：

- 不依赖 IDB 中 `pp_global_ptr` 是否已重命名。
- 强校验能及时发现表结构或接口列表变化。
- 三个模块使用同一份规则，行为一致；平台差异只由 `platform` 决定。

缺点：

- CS2 接口列表发生合法变化时，需要显式更新 expected list。

### 方案 2：只按 interface_name 前缀匹配

脚本扫描表项后要求 expected entries 按顺序出现在实际 entries 前缀中，不要求总数量完全一致。

优点：

- 对新增接口更宽容。

缺点：

- 无法处理合法的顺序调整。

### 方案 3：按 pp_global_ptr IDA 名称匹配

直接读取 `pp_global_ptr` 处的 IDA 名称并按 `g_pXXXX` 生成 YAML。

优点：

- 实现简单。

缺点：

- 实际 IDB 中该地址不一定被重命名，定位依据不可靠。
- 与已确认约束冲突。

## 选定方案

采用方案 1：以 `interface_name` 序列为强约束。

`interface_name_ptr` 是唯一可信 key。`pp_global_ptr` 只作为同一 entry 中待输出 GV 的地址来源；其 IDA 名称不参与定位和校验。Windows `.dll` 预期包含最后两项 `("NavSystem001", "g_pNavSystem")` 与 `("NavGameTest001", "g_pNavGameTest")`；当前 Linux `.so` 预期最后一项为 `("Vrad3_001", "g_pRAD3")`，不强制 `NavSystem001` 或 `NavGameTest001`。

## 详细设计

### 1. 新增预处理脚本

新增文件：

```text
ida_preprocessor_scripts/find-g_pInterfaceGlobals_ppGlobal.py
```

脚本入口仍使用现有约定：

```python
async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map,
    new_binary_dir, platform, image_base, llm_config=None, debug=False,
):
```

脚本内部维护 Windows 完整列表，并由平台派生实际 expected list：

```python
EXPECTED_ENTRIES = [
    ("VApplication001", "g_pVApplication"),
    ("VEngineCvar007", "g_pVEngineCvar"),
    ...
]
WINDOWS_EXPECTED_ENTRIES = EXPECTED_ENTRIES
LINUX_EXPECTED_ENTRIES = EXPECTED_ENTRIES[:-2]
```

### 2. 输入来源

脚本读取当前模块目录下：

```text
g_pInterfaceGlobals.{platform}.yaml
```

并解析其中的 `gv_va`。该文件由现有 `find-g_pInterfaceGlobals` 生成，新 skill 在 `config.yaml` 中声明 `expected_input` 依赖它。

如果输入 YAML 缺失、`gv_va` 缺失或地址不可解析，脚本返回 `False`。

### 3. IDA 侧扫描

通过 MCP `py_eval` 在 IDA 内完成表项扫描：

1. 从 `g_pInterfaceGlobals.gv_va` 开始。
2. 每 16 字节读取一个 entry。
3. `entry + 0x0` 读取 `interface_name_ptr`。
4. `entry + 0x8` 读取 `pp_global_ptr`。
5. 对 `interface_name_ptr` 读取 C 字符串。
6. 遇到空 `interface_name_ptr` 或空 `pp_global_ptr` 时停止。
7. 设置合理上限，例如 `len(EXPECTED_ENTRIES) + 1` 或固定最大值，避免异常情况下无限扫描。

扫描结果结构：

```python
[
    {
        "index": 0,
        "entry_va": "0x...",
        "interface_name": "VApplication001",
        "interface_name_va": "0x...",
        "pp_global_va": "0x...",
    },
]
```

### 4. 预期集合强校验规则

实际 entries 必须覆盖当前平台 expected entries 的完整集合：

- 每个 expected `interface_name` 都必须能在实际 entries 中找到。
- 每个 expected `interface_name` 对应 entry 的 `pp_global_ptr` 必须是有效地址。
- expected `interface_name` 在实际 entries 中重复出现时返回失败，避免地址歧义。
- 实际表中的额外 entries 不参与 GV YAML 输出。
- 实际 entries 的顺序不参与校验。

不校验 `pp_global_ptr` 当前 IDA 名称，因为该名称不可靠。

任一不一致时脚本返回 `False`，并在 debug 模式输出：

- missing expected interface names
- duplicated expected interface name
- expected interface name
- invalid `pp_global_ptr`

### 5. YAML 输出

只有在全量校验通过后，脚本才批量写出 YAML，避免半成品污染输出目录。

每个 entry 按 expected 映射生成：

```yaml
gv_name: g_pVApplication
gv_va: '0x...'
gv_rva: '0x...'
```

其中：

- `gv_name` 来自 `EXPECTED_ENTRIES` 的第二列。
- `gv_va` 为同一 entry 的 `pp_global_ptr` 地址。
- `gv_rva = gv_va - image_base`。

写入使用现有 `ida_analyze_util.write_gv_yaml`，保持 GV YAML 的 key 顺序和格式一致。

### 6. 可选 IDB 重命名

校验和写 YAML 成功后，可尝试调用 `idc.set_name(pp_global_ptr, gv_name, idc.SN_NOWARN)`，提升后续 IDB 可读性。

该重命名不能作为定位依据。若重命名失败，只在 debug 模式记录，不影响已经完成的 YAML 输出。

### 7. config.yaml 注册

在 `client`、`server`、`engine` 三个模块的 `find-g_pInterfaceGlobals` 后新增。公共 `expected_output` 只包含 Windows/Linux 共有项，Windows 专有的 `g_pNavSystem` 与 `g_pNavGameTest` 通过 `expected_output_windows` 注册：

```yaml
- name: find-g_pInterfaceGlobals_ppGlobal
  expected_output:
    - g_pVApplication.{platform}.yaml
    - g_pVEngineCvar.{platform}.yaml
    # ...
  expected_output_windows:
    - g_pNavSystem.{platform}.yaml
    - g_pNavGameTest.{platform}.yaml
  expected_input:
    - g_pInterfaceGlobals.{platform}.yaml
```

并在三个模块的 `symbols` 中新增这些目标：

```yaml
- name: g_pVApplication
  category: gv
- name: g_pVEngineCvar
  category: gv
- name: g_pNavGameTest
  category: gv
  platform: windows
```

如某个 symbol 已存在于同一模块，则不重复注册。

### 8. Expected entries 初始集合

初始集合来自用户提供的 `g_pInterfaceGlobals` 表。实现时应完整转写为 `(interface_name, gv_name)` 列表，并保持顺序。

前几项示例：

```python
("VApplication001", "g_pVApplication")
("VEngineCvar007", "g_pVEngineCvar")
("VStringTokenSystem001", "g_pVStringTokenSystem")
("TestScriptMgr001", "g_pTestScriptMgr")
("VProcessUtils002", "g_pProcessUtils")
```

该列表是 `client`、`server`、`engine` 的共同预期。任一模块缺少对应平台的 expected interface，都应视为失败。

## 错误处理

- 输入 `g_pInterfaceGlobals` YAML 不存在：返回 `False`。
- `gv_va` 无法解析：返回 `False`。
- IDA 读取 entry 失败：返回 `False`。
- 缺少当前平台 expected interface：返回 `False`。
- expected interface 重复出现：返回 `False`。
- expected interface 对应的 `pp_global_ptr` 无效：返回 `False`。
- 输出路径不在 `expected_outputs` 中或 expected output 缺失：返回 `False`。
- YAML 写入异常：返回 `False`。

## 验证方式

本需求不要求默认执行测试或 build。实现完成后可做定向验证：

1. 脚本可被 Python import。
2. `config.yaml` 可被 PyYAML 解析。
3. `client`、`server`、`engine` 都注册了 `find-g_pInterfaceGlobals_ppGlobal`。
4. 三个模块的新 skill 都依赖 `g_pInterfaceGlobals.{platform}.yaml`。
5. 三个模块都注册了 expected entries 对应的 `category: gv` symbols。
6. 可用单元测试 mock MCP `py_eval`，覆盖：
   - 完全匹配时写出全部 YAML。
   - 实际表多出 entry 时成功，且只写出 expected entries 对应 YAML。
   - 顺序调整时成功，并按 `interface_name` 绑定 `pp_global_ptr`。
   - 缺少 entry 时失败。
   - expected interface 被替换为未知 interface 时失败。
   - `pp_global_ptr` 没有 IDA 名称时仍成功。

## 交付边界

本次交付包含：

- 新增预处理脚本。
- 更新 `config.yaml`。
- 如有必要，新增轻量单元测试覆盖强校验逻辑。

不包含：

- 运行完整 IDA 分析。
- 运行完整 build。
- 修改 downstream dist 输出。
