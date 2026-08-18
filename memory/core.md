---
title: core
type: note
permalink: cs2-vibesignatures/core
---

# Core

- 项目全景、责任边界、架构管线与关键文件：见 [[project_overview]]。
- `ida_analyze_bin.py` 主入口、CLI 参数、环境变量与依赖推断：见 [[ida_analyze_bin]]。
- 预处理工作流、skill 生命周期、Agent fallback 与 LLM_DECOMPILE 契约：见 [[ida_skill_preprocessor]]。
- LLM 辅助符号恢复的内部实现、请求组装/批处理/重试与归一化：见 [[llm_decompile]]。
- LLM_DECOMPILE reference YAML 的生成入口、MCP/identity 门禁与四字段 schema：见 [[generate_reference_yaml]]。
- config YAML 结构、module/skill 声明与 platform 约定：见 [[config_yaml]]。
- 符号输出 YAML（func/vfunc/gv/struct）schema 与唯一性约束：见 [[symbol_yaml]]。
