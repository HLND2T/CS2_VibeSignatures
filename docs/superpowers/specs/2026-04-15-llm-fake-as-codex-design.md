# `-llm_fake_as=codex` 传输切换与 effort 统一设计

## 背景

当前仓库中的 LLM 文本调用链主要有两条：

- `ida_llm_utils.py:72` 的 `call_llm_text(...)`
- `ida_analyze_util.py:1785` 的 `call_llm_decompile(...)`

两条链路当前都依赖 OpenAI Python SDK 的 `chat.completions.create(...)`。

这带来两个问题：

1. 无法在指定场景下强制改为 `POST {base_url}/v1/responses`
2. 无法稳定构造接近 Codex CLI 风格的请求头与 SSE 请求形态

目标请求形态为：

```http
POST {BASEURL}/v1/responses
Authorization: Bearer sk-XXXX
Content-Type: application/json
Accept: text/event-stream
Accept-Encoding: identity
User-Agent: codex_cli_rs/0.80.0 (Windows 15.7.2; x86_64) Terminal
Originator: codex_cli_rs
Host: <base_url host>

{"input":[{"content":"Who are you?","role":"user"}],"model":"gpt-5.4","reasoning":{"effort":"high"},"stream":true}
```

同时，用户要求把推理强度从“隐式固定 high”升级为统一可配置参数，并让 SDK 路径与 `codex` 伪装路径共享同一套入口：

- `-llm_effort=` 对应环境变量 `CS2VIBE_LLM_EFFORT=`
- `-llm_fake_as=` 对应环境变量 `CS2VIBE_LLM_FAKE_AS=`
- `-llm_temperature=` 对应环境变量 `CS2VIBE_LLM_TEMPERATURE=`

其中 `-llm_temperature` 的环境变量 fallback 已经存在，本次设计要求继续沿用现有行为。

## 问题定义

当前问题不在单一函数，而在公共 LLM 传输层缺少“可切换的协议后端”：

1. `call_llm_text(...)` 固定绑定 `chat.completions.create(...)`
2. `call_llm_decompile(...)` 通过 `call_llm_text(...)` 间接固定在 `/chat/completions`
3. 仓库当前没有 `-llm_fake_as` 参数，也没有统一的 `llm_effort` 参数
4. `temperature` 虽已存在统一配置，但 `reasoning` 仍未成为一等配置项，也缺少统一默认值

结果是：

- 无法按需强制切换到 `/responses`
- 无法在保留现有调用方的前提下复用统一的文本提取接口
- SDK 路径与 fake-as 路径的参数语义不一致

## 目标

- 为公共 LLM 调用链增加 `-llm_fake_as=codex` 传输切换能力
- 当 `-llm_fake_as=codex` 时，绕过 OpenAI SDK 的 `chat.completions`，直接用 `httpx` 手写 `/v1/responses` SSE 请求
- 新增 `-llm_effort`，并让 SDK 路径与 `codex` 路径都受其控制
- 当 `-llm_effort` 与 `CS2VIBE_LLM_EFFORT` 都未设置时，统一默认使用 `medium`
- 保持 `call_llm_text(...)` 的返回值仍为纯文本字符串，尽量不改上层业务逻辑
- 让 `temperature` 是否发送仅由 `-llm_temperature` 是否显式设置决定
- 增加对应环境变量 fallback，并保持 CLI 优先于环境变量

## 非目标

- 不追求完全复刻 Codex CLI 的全部内部头字段与行为
- 不消除 OpenAI SDK 默认路径上的 SDK 特有 header
- 不重写 `call_llm_decompile(...)` 的业务解析逻辑
- 不改动已有 prompt 模板内容
- 不引入新的第三方依赖，优先复用仓库已存在的 `httpx`
- 不在本次设计中扩展更多 fake-as 类型，当前仅定义 `codex`

## 方案比较

### 方案 A：继续使用 OpenAI SDK，仅覆盖 headers

保留 `client.chat.completions.create(...)` 或 `client.responses.create(...)`，通过 `default_headers` / `extra_headers` 尽量把请求伪装成 Codex。

优点：

- 实现量较小
- 能复用 SDK 现有解析逻辑

缺点：

- SDK 仍会附带 `x-stainless-*` 等额外 headers
- 对 SSE 细节与请求头控制不彻底
- 很难满足“强制按指定格式发送”的要求

### 方案 B：仅为 `responses.create(...)` 建一个 SDK 分支

默认继续走 `chat.completions`，`-llm_fake_as=codex` 时改为 `client.responses.create(stream=True)`。

优点：

- 比方案 A 更接近目标 body 结构
- 仍保留 SDK 的类型与流封装

缺点：

- 请求头仍然受 SDK 限制
- 仍无法彻底控制 Accept、Accept-Encoding、User-Agent 与 Host
- 仍然不是“明确绕过 SDK 的 codex transport”

### 方案 C：新增独立 `codex_http` transport

默认路径继续使用 OpenAI SDK；当 `-llm_fake_as=codex` 时，改由 `httpx` 直接发送 `/responses` SSE 请求，并手动解析事件流，最后仍返回纯文本。

优点：

- 对 URL、headers、body 和流读取拥有完全控制权
- 最符合“强制按指定格式发送”的要求
- 能把 transport 差异收敛到公共 helper，不污染上层业务逻辑

缺点：

- 需要自己实现 SSE 解析与异常处理
- 改动面高于纯 SDK 分支

## 选定方案

采用方案 C。

原因如下：

- 用户明确要求“强制按照指定格式发送 API 请求”
- 仅依赖 SDK 无法彻底移除 SDK 自带 header 和默认行为
- 当前仓库已依赖 `httpx`，实现独立 transport 的边际成本可控
- 上层业务只依赖“输入消息 -> 输出纯文本”，适合在公共 helper 中吸收 transport 差异

## 详细设计

### 1. 参数入口与环境变量

在 `ida_analyze_bin.py` 中补齐并统一以下参数入口：

- `-llm_fake_as=`
  - fallback: `CS2VIBE_LLM_FAKE_AS`
  - 允许值：空值、`codex`
- `-llm_effort=`
  - fallback: `CS2VIBE_LLM_EFFORT`
  - 允许值：`none`、`minimal`、`low`、`medium`、`high`、`xhigh`
- `-llm_temperature=`
  - fallback: `CS2VIBE_LLM_TEMPERATURE`
  - 保持现有实现与校验逻辑

优先级统一为：

1. CLI 参数
2. 环境变量
3. 默认值 `medium`

最终统一写入 `llm_config`，供后续 helper 使用。

其中 `effort` 的最终解析优先级为：

1. CLI `-llm_effort`
2. 环境变量 `CS2VIBE_LLM_EFFORT`
3. 默认值 `medium`

### 2. 公共传输抽象

`ida_llm_utils.py` 保持为公共 LLM 调用入口，但内部增加 transport 分流。

建议保留当前函数职责并新增辅助函数：

- `create_openai_client(...)`
  - 继续服务默认 SDK 路径
- `normalize_optional_temperature(...)`
  - 保持现有行为
- 新增 `normalize_optional_effort(...)`
  - 校验并归一化 `none|minimal|low|medium|high|xhigh`
- 新增 `_call_llm_text_via_codex_http(...)`
  - 专门负责 `/responses` SSE 请求与文本提取
- `call_llm_text(...)`
  - 继续作为统一入口
  - 内部根据 `fake_as` 选择 SDK 或 `codex_http`

设计原则：

- 上层只感知“文本调用”，不感知 transport 细节
- SDK 路径与 `codex_http` 路径共享同一套参数语义
- 两条路径都返回纯文本字符串

### 3. SDK 路径行为

当 `fake_as` 未设置时，`call_llm_text(...)` 保持 SDK 路径。

请求映射如下：

- 调用接口：`client.chat.completions.create(...)`
- 基础字段：
  - `model`
  - `messages`
- 可选字段：
  - `temperature`：仅当 `-llm_temperature` 被显式设置时发送
  - `reasoning_effort`：总是发送最终解析值；未显式设置时默认发送 `medium`

等价语义为：

```python
client.chat.completions.create(
    model=model,
    messages=messages,
    temperature=temperature_if_set,
    reasoning_effort=resolved_effort,
)
```

这意味着 SDK 版也不再把 effort 硬编码在调用方，而是统一由 `-llm_effort` / 环境变量 / 默认值 `medium` 控制。

### 4. `codex_http` 路径行为

当 `fake_as == "codex"` 时，`call_llm_text(...)` 改走 `_call_llm_text_via_codex_http(...)`。

#### 4.1 URL 规则

- 使用传入的 `base_url`
- helper 内部统一拼成：`{base_url.rstrip('/')}/responses`
- 约定调用方传入的 `base_url` 已是 `/v1` 根路径，例如：
  - `http://127.0.0.1:8080/v1`
  - `https://api.example.com/v1`

#### 4.2 Headers 规则

固定发送：

```http
Authorization: Bearer <api_key>
Content-Type: application/json
Accept: text/event-stream
Accept-Encoding: identity
User-Agent: codex_cli_rs/0.80.0 (Windows 15.7.2; x86_64) Terminal
Originator: codex_cli_rs
Host: <base_url host>
```

说明：

- `Host` 默认从 `base_url` 解析得到，不额外引入 override 配置
- 不额外伪造与业务无关的其他头字段
- 不复用 OpenAI SDK client，以避免 SDK 自动附加 header

#### 4.3 Body 映射

`messages` 将被转换为 `/responses` 的 `input` 结构。

本次设计采用最小充分映射：

- 默认仅发送用户可见文本到 `input`
- `model` 直接透传
- `stream` 固定为 `true`
- `temperature` 仅当显式设置时发送
- `reasoning` 总是发送最终解析值；未显式设置时默认发送 `{"effort":"medium"}`

目标 body 形态：

```json
{
  "input": [
    {
      "role": "user",
      "content": "..."
    }
  ],
  "model": "gpt-5.4",
  "reasoning": {
    "effort": "medium"
  },
  "temperature": 0.1,
  "stream": true
}
```

其中：

- 若 `temperature` 未设置，则省略 `temperature`
- 若 `effort` 未显式设置，则仍发送默认值 `reasoning: {"effort": "medium"}`

#### 4.4 `messages -> input` 转换

为了尽量不改变现有上层 prompt 构造方式，建议在 helper 内完成转换。

转换策略：

- 从 `messages` 中抽取 `role == "user"` 的消息内容
- 将多个 user 消息以双换行拼接为单一文本
- 转换成：

```json
[
  {
    "role": "user",
    "content": "拼接后的文本"
  }
]
```

说明：

- 当前不把 `system` 角色单独映射为 `instructions`
- 当前不保留多条 message 的逐条结构
- 这样能最大程度贴近用户要求的报文样式，并降低兼容复杂度

若后续发现某些 prompt 强依赖 system/user 分离，再在后续迭代中增加 `instructions` 映射。

### 5. SSE 响应解析

`codex_http` 路径需要自行解析 `text/event-stream`。

解析目标不是保留完整事件序列，而是提取最终可用文本并返回给现有上层逻辑。

建议规则：

1. 逐行读取 SSE 事件
2. 仅处理 `data:` 行
3. 遇到 `[DONE]` 时结束
4. 对 JSON payload 做容错解析
5. 兼容常见文本增量字段，按顺序累积文本
6. 返回最终拼接后的字符串

设计要求：

- helper 对不同事件类型做宽松兼容
- 上层只拿到最终文本，不直接依赖流事件 schema
- 若最终没有提取到任何文本，则视为失败

### 6. 异常处理

`codex_http` 路径将失败分为三类：

#### 6.1 网络失败

包括：

- 连接失败
- 超时
- 非 2xx 状态码
- 中途断流

处理要求：

- 抛出包含状态码与响应片段的异常
- `debug=True` 时打印请求 URL、headers 摘要与响应片段

#### 6.2 协议失败

包括：

- 返回内容不是 `text/event-stream`
- SSE 数据行无法按预期分帧
- 事件流提前结束且无合法内容

处理要求：

- 抛出“非法 SSE 响应”类错误
- 调试日志输出响应头与原始片段

#### 6.3 内容失败

包括：

- 请求成功但未提取到任何文本
- 事件 JSON 结构合法但不含可消费文本字段

处理要求：

- 抛出“空响应内容”错误
- 避免把空字符串静默当成成功

### 7. `call_llm_decompile(...)` 兼容性

`ida_analyze_util.py:1785` 的 `call_llm_decompile(...)` 不应自行引入 transport 分支。

它只需要：

- 从 `llm_config` 接收 `fake_as`
- 从 `llm_config` 接收 `effort`
- 继续调用统一的 `call_llm_text(...)`

这样可以保证：

- `call_llm_decompile(...)` 的业务语义不变
- `parse_llm_decompile_response(...)` 不受 transport 差异影响
- 其他未来复用 `call_llm_text(...)` 的链路也可自动获得 `codex` transport 能力

### 8. Debug 输出

在 `debug=True` 时，两条路径都应输出关键请求摘要，便于对比：

- 路径类型：`openai_sdk` 或 `codex_http`
- `model`
- `fake_as`
- `temperature`
- `effort`
- 目标 URL
- 请求 body 预览

`codex_http` 路径还应额外输出：

- SSE 响应头
- 提取到的原始事件片段预览
- 最终汇总文本

## 兼容性与风险

### 兼容性

- 未设置 `-llm_fake_as` 时，行为与当前版本保持兼容
- 未设置 `-llm_effort` 时，统一默认使用 `medium`
- `-llm_temperature` 的既有行为保持不变
- 上层调用方无需改为处理 stream 对象，仍然拿到文本字符串

### 风险

- `/responses` 事件 schema 在不同兼容服务上可能存在差异
- `messages -> input` 的最小映射可能弱化部分 system prompt 语义
- 如果某些 provider 依赖严格的 Host 或其他额外头，后续可能还需补 provider-specific 兼容逻辑

### 风险控制

- 仅在 `-llm_fake_as=codex` 时启用新路径
- 保留默认 SDK 路径作为稳定回退
- 使用本地 fake server 做报文级定向验证
- 先实现最小充分映射，不提前引入复杂 schema 抽象

## 验证方案

本次设计的验证以定向单测和 fake server 抓包为主，不要求真实联网调用第三方 API。

### 1. 参数解析验证

验证以下优先级与合法性：

- `-llm_fake_as` 与 `CS2VIBE_LLM_FAKE_AS`
- `-llm_effort` 与 `CS2VIBE_LLM_EFFORT`
- `-llm_temperature` 与 `CS2VIBE_LLM_TEMPERATURE`
- 非法 `fake_as` / `effort` 的报错路径

### 2. SDK 路径验证

验证 `call_llm_text(...)` 在默认路径下：

- 继续调用 `chat.completions.create(...)`
- `temperature` 仅在显式设置时发送
- `reasoning_effort` 在未显式设置时默认发送 `medium`

### 3. `codex_http` 路径验证

使用本地 HTTP 假服务抓包，验证：

- 请求 URL 为 `/v1/responses`
- headers 包含预期的 `Accept`、`Accept-Encoding`、`User-Agent`、`Originator`
- body 使用 `input/model/stream` 结构
- 未显式设置 `effort` 时仍发送 `reasoning.effort=medium`
- `temperature` 与 `reasoning.effort` 的发送条件正确

### 4. SSE 解析验证

覆盖：

- 正常返回单段文本
- 正常返回多段增量文本
- 空事件流
- 非 JSON `data:` 行
- 非 `text/event-stream` 响应
- 非 2xx 响应

### 5. 回归验证

至少补一条 `call_llm_decompile(...)` 的回归测试，确认：

- 上层仍拿到纯文本
- transport 切换不会破坏现有解析入口

## 实施边界

本次实现应限制在与 LLM 传输相关的最小必要范围：

- `ida_analyze_bin.py`
- `ida_llm_utils.py`
- `ida_analyze_util.py`
- 对应参数解析与 helper 单测

除非实现时发现真实耦合点，否则不扩散到无关 preprocessor 脚本与 prompt 文件。

## 结论

本设计通过新增 `-llm_fake_as=codex` 与 `-llm_effort`，把“推理参数语义”与“传输协议选择”统一收敛到公共 helper 层：

- 默认路径继续使用 OpenAI SDK
- `codex` 路径使用 `httpx` 手写 `/responses` SSE 请求
- `temperature` 与 `effort` 由统一 CLI / 环境变量控制
- 上层业务继续消费纯文本结果

这是一种最小充分、可验证、可回退的实现方向，既满足用户对报文形态的控制要求，也尽量减少对现有业务逻辑的扰动。
