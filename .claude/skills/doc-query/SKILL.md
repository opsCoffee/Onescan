---
name: doc-query
description: MCP 工具使用指南和文档查询策略，包括 deepwiki（GitHub 开源项目文档）、context7（技术文档和 API 参考）、playwright/chrome-devtools（在线文档交互）、sequential thinking（复杂问题分析）工具说明。禁止使用 PowerShell/Bash 查询文档，优先使用 MCP 工具，支持多源交叉验证。适用于查询文档、API 参考、分析复杂问题、技术调研时使用。
---

# 查询文档

1. 必须使用已有的 MCP 工具查询文档，禁止使用 PowerShell 或 Bash 命令查询
2. 必要时，可以使用多个 MCP 交叉查询和验证，确保查询结果的准确性

## MCP 工具说明

### 文档查询工具

1. **deepwiki** - 查询 GitHub 开源项目的文档和代码库
   - 适用场景：查询开源项目的 README、Wiki、代码示例
   - 示例：查询 Burp Montoya API 的使用方法

2. **context7** - 查询技术文档和 API 参考
   - 适用场景：查询库的 API 文档、使用指南
   - 示例：查询特定版本的 API 接口定义

3. **playwright / chrome-devtools** - 打开和交互网页内容
   - 适用场景：访问在线文档、官方网站
   - 示例：查看 PortSwigger 官方文档

### 分析思考工具

4. **sequential thinking** - 进行复杂问题的结构化分析和思考
   - 适用场景：需要多步骤推理、问题分解、方案评估时
   - 建议：在执行复杂分析任务时优先使用此工具
   - 示例：分析架构设计、评估技术方案、调试复杂问题

## 使用原则

- 优先使用 MCP 工具而非命令行工具
- 对于关键信息，使用多个来源交叉验证
- 使用 sequential thinking 进行复杂问题的分析