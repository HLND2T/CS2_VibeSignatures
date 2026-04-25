# JSONC 原文注释与排版保留设计

## 背景

`update_gamedata.py` 会聚合 YAML 签名数据，并委派 `dist/*/gamedata.py` 更新各插件的 gamedata 文件。当前 JSONC 文件通过 `gamedata_utils.py` 中的 `load_jsonc()` 读取：先移除注释，再用 `json.loads()` 解析。写回时 `save_jsonc()` 直接执行 `json.dump(data, indent=4)`，因此会丢失原始 JSONC 中的注释、空行、部分排版细节和可能存在的局部格式差异。

用户期望更新 JSONC 时尽量逐字保留原始排版、空行和注释位置，只替换实际发生变化的 value。

## 目标

- 保留 JSONC 文件原文中的注释、空行、缩进、键顺序和未变更片段。
- 对已有字段只替换具体 value 的文本范围，不整体重排文件。
- 覆盖当前 JSONC gamedata 更新路径，包括 SwiftlyS2、Plugify、ModSharp、CS2Surf 等使用 `load_jsonc()` / `save_jsonc()` 的模块。
- 保持现有模块调用方式尽量稳定，避免每个 `dist/*/gamedata.py` 重写保存逻辑。
- 在无法安全做原文替换时给出明确降级路径，避免静默写坏 JSONC。

## 非目标

- 不在本设计中重构 `update_gamedata.py` 的模块发现、下载或统计流程。
- 不改变 YAML 到目标 gamedata 的业务映射规则。
- 不追求支持任意 JSONC 大规模结构编辑的完美格式保留。
- 不为了保留注释引入重量级依赖，除非后续实现验证内置方案不可维护。

## 现状与问题

当前共享函数位于 `gamedata_utils.py`：

- `strip_jsonc_comments()` 能在保留字符串内容的前提下移除 `//` 与 `/* */` 注释。
- `load_jsonc()` 读取文件、剥离注释并返回普通 Python dict。
- `save_jsonc()` 的 `original_content` 参数目前未实际使用，最终直接格式化输出干净 JSON。

这意味着所有依赖 `save_jsonc()` 的 JSONC 模块都会在第一次更新后丢失注释和原始布局。

## 推荐方案

采用“JSONC token 扫描 + key path 到 value span 映射 + 原文切片替换”的方式。

核心思路：

1. 读取 JSONC 原文。
2. 用轻量 tokenizer 跳过注释和字符串内部的伪注释，识别对象、数组、字符串 key、冒号、逗号和 primitive value。
3. 建立从 JSON path 到原文 value 范围的映射，例如：
   - `("CEntityInstance::AcceptInput", "windows") -> (start, end)`
   - `("csgo", "Signatures", "Foo", "win64") -> (start, end)`
4. 保存前比较原始 parsed data 与更新后的 data，只收集发生变化的叶子节点。
5. 对每个变化节点，用 `json.dumps(new_value, ensure_ascii=False)` 生成新的 value 文本，并替换原文对应范围。
6. 从文件末尾向前应用替换，避免前一次替换影响后续 span。

该方案不重新生成整个 JSONC 文件，因此能够最大程度保留注释、空行、缩进、键顺序和未修改字段的原始文本。

## 组件设计

### `load_jsonc_with_source()`

新增共享读取入口，返回解析结果和原文上下文：

- `data`: 注释剥离后的 JSON 数据。
- `source`: 原始 JSONC 文本。
- `spans`: JSON path 到 value 原文范围的映射。

为减少调用点改动，现有 `load_jsonc()` 可继续返回 `data`，新增接口供保留注释保存路径使用。

### JSONC tokenizer

新增内部 tokenizer，负责扫描原文并输出足够解析 value span 的 token。它需要正确处理：

- 双引号字符串与转义字符。
- 字符串中的 `//`、`/*`、`*/` 不作为注释。
- 单行注释、块注释和空白。
- object、array、string、number、boolean、null。

本 tokenizer 不需要构建完整 AST，只需要在递归解析时记录每个 value 的起止偏移。

### `save_jsonc_preserving_format()`

新增共享保存入口，输入文件路径、更新后的数据和原始上下文：

- 计算原数据与新数据的叶子差异。
- 对已有 path 执行原文 value 替换。
- 如果遇到新增 key、删除 key、类型从容器变成标量或无法定位 span，则进入降级策略。
- 写回时保持原文件换行风格，默认不改变文件末尾换行。

### `save_jsonc()`

现有 `save_jsonc()` 保持兼容，但内部优先尝试保留格式：

- 如果调用方提供 `original_content` 或 future context，则走保留格式路径。
- 如果无法获取原文上下文，则保留当前 `json.dump()` 行为。

更稳妥的实现方式是先更新调用点，让 JSONC 模块使用 `load_jsonc_with_source()` 和 `save_jsonc_preserving_format()`，待验证稳定后再考虑把 `save_jsonc()` 默认行为切换为保留格式。

## 数据流

以 SwiftlyS2 signatures 为例：

1. `_update_signatures()` 读取 `signatures.jsonc`。
2. 共享读取函数同时得到 `signatures` 数据和原文 span context。
3. 现有循环继续根据 YAML 更新 `entry[platform]`。
4. 保存函数比较原始 `signatures` 与更新后的 `signatures`。
5. 只替换发生变化的 `"windows"` / `"linux"` 字符串 value。
6. 文件中注释、空行、对象顺序和未变更字段保持原样。

Plugify 和 CS2Surf 的嵌套路径更深，但同样通过 JSON path 定位到具体平台字段，例如 `("csgo", "Signatures", name, "win64")`。

## 降级策略

为避免错误保留导致 JSONC 损坏，保存逻辑需要显式处理无法安全替换的情况：

- 如果所有变化都是已有叶子 value 的替换，则执行原文切片替换。
- 如果发现新增 key 或删除 key，默认回退到当前 `json.dump()` 行为，并打印 warning。
- 如果 path 无法定位到原文 span，回退到当前 `json.dump()` 行为，并打印 warning。
- 如果替换后无法重新解析为等价 JSON 数据，中止写入并抛出异常，保留原文件不变。

当前 gamedata 更新逻辑主要替换既有 signatures、offsets、vfunc index 和 struct offset，因此常规路径应能命中安全替换，不需要频繁降级。

## 错误处理

- tokenizer 遇到非法 JSONC 结构时抛出带文件路径和偏移位置的异常。
- 保存前对变更 path 做去重和排序，避免重复替换同一 value span。
- 替换后重新用现有 `load_jsonc` 解析临时文本，并与目标数据比较，确认写回结果语义一致。
- 仅在完整校验通过后写回文件，避免部分写入。

## 测试策略

建议增加针对 `gamedata_utils.py` 的单元测试，不需要依赖真实 gamedata 全量数据：

- 保留文件头注释、对象前注释、行尾注释和块注释。
- 保留空行、缩进、键顺序和未变更字段的原文。
- 正确替换字符串、整数、布尔值和 null。
- 正确处理字符串内部包含 `//` 或 `/* */` 的内容。
- 嵌套对象路径替换覆盖 SwiftlyS2 与 Plugify 风格。
- 新增 key 触发明确降级或异常路径。
- 替换后重新解析结果与目标数据一致。

针对 `dist/*/gamedata.py` 的验证可以使用小型临时 JSONC fixture，避免直接改动真实 dist 文件。

## 实施边界

优先改动共享工具与少量 JSONC 调用点：

- `gamedata_utils.py`
- `dist/swiftlys2/gamedata.py`
- `dist/plugify-plugin-s2sdk/gamedata.py`
- `dist/modsharp-public/gamedata.py`
- `dist/cs2surf/gamedata.py`

不触碰 VDF、纯 JSON、下载逻辑、配置结构和签名转换规则。

## 风险与权衡

- 自研 tokenizer 需要覆盖 JSONC 边界情况，但实现范围可控，且能满足“尽量逐字保留”的要求。
- 第一次实现建议只支持已有叶子 value 替换，避免新增对象成员时格式插入复杂化。
- 若上游 JSONC 格式极不规范，保留格式路径可能降级到普通 JSON 输出；这比错误写入更安全。
- 将 `save_jsonc()` 默认切换为保留格式前，应先通过 fixture 验证所有 JSONC 模块。

## 验收标准

- 更新已有 JSONC value 后，原文件注释仍存在。
- 未变更片段与原文逐字一致。
- 变更片段仅限对应 value 文本。
- 替换后的 JSONC 能被现有加载逻辑解析。
- SwiftlyS2、Plugify、ModSharp、CS2Surf 的 JSONC 更新路径可以复用同一套保存机制。
