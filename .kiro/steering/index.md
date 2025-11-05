---
inclusion: always
---

# Claude Skills 索引

本项目已迁移到 Claude Skills 架构，所有开发指南现在作为按需调用的技能提供。这种架构显著减少了上下文 token 使用量（>50%），提高了响应速度和相关性。

## 技能调用机制

技能会根据对话内容**自动激活**，无需手动指定。Kiro 会分析您的问题并加载相关技能。

### 自动激活示例

- 讨论 Java 代码 → 自动加载 `coding-style`
- 编写测试 → 自动加载 `testing`
- 执行 Git 操作 → 自动加载 `git-standards`
- 查询文档 → 自动加载 `doc-query`
- 处理异常 → 自动加载 `error-handling`

## 可用技能列表

### 1. coding-style
**Java 8 代码风格规范**
- 命名约定（成员变量 m 前缀、静态变量 s 前缀、常量 UPPER_SNAKE_CASE）
- 格式化标准（4 空格缩进、K&R 大括号风格）
- Lambda 表达式和 Stream API 使用指南
- 异常处理、资源管理

**使用时机**：编写或审查 Java 代码、讨论代码规范、进行代码格式化、使用 Java 8 特性

### 2. testing
**Maven 测试策略和 JUnit 最佳实践**
- 测试原则（核心功能、最小化、快速反馈）
- 验证次数限制（最多 2 次尝试）
- 测试数据要求（禁止 mock、使用真实数据）
- AAA 模式、测试命名规范、@Before/@After 使用

**使用时机**：编写单元测试、集成测试、调试测试失败、讨论测试策略

### 3. error-handling
**Java 异常处理最佳实践**
- 检查型/非检查型异常分类
- 参数验证、配置加载
- try-with-resources 资源管理
- 错误恢复策略（默认值、降级、重试）
- UI 错误显示、日志记录

**使用时机**：处理异常、编写错误处理代码、调试错误、设计容错机制

### 4. git-standards
**Git 命令规范和最佳实践**
- 查看命令必须使用 --no-pager 避免交互模式
- Windows 环境下使用 -F 参数提交（通过 fsWrite 创建 commit.log）
- Conventional Commits 格式（必须中文、禁止 AI 标识）
- 分支管理（--no-ff 合并）、Git 别名使用

**使用时机**：执行 Git 命令、提交代码、合并分支、查看历史、处理 Git 操作

### 5. doc-query
**MCP 工具使用指南和文档查询策略**
- deepwiki（GitHub 开源项目文档）
- context7（技术文档和 API 参考）
- playwright/chrome-devtools（在线文档交互）
- sequential thinking（复杂问题分析）

**使用时机**：查询文档、API 参考、分析复杂问题、技术调研

### 6. product
**OneScan 产品概览**
- 核心功能（递归扫描、指纹识别、动态变量、数据收集）
- 目标用户（安全研究人员、渗透测试人员）
- 当前版本 2.2.0

**使用时机**：讨论产品功能、能力、用户需求

### 7. structure
**项目结构和目录布局**
- 根目录布局、单模块结构（src/）
- 包组织（burp.common.*、burp.onescan.*）
- 关键架构组件（BurpExtender、FpManager、CollectManager）
- 命名约定（m 前缀、s 前缀）

**使用时机**：导航代码库、理解架构、定位文件

### 8. tech
**技术栈和构建系统约束**
- Java 17（JDK 17）编译目标
- 仅使用 Maven（禁止 Gradle）
- 专用 Montoya API（禁止旧版 Burp Extender API）
- Windows 平台（cmd 兼容命令）
- Maven 单模块结构、核心依赖

**使用时机**：设置构建、管理依赖、确保 Java 17 兼容性

## 技能使用指南

### 查看可用技能
询问"有哪些可用的技能？"或"列出所有技能"即可查看此索引。

### 技能自动加载
技能会根据对话内容自动加载，您无需手动指定。系统会智能识别相关技能。

### 性能优势
- **减少上下文使用**：只加载相关技能，而非全部规则
- **提高响应速度**：更少的 token 处理
- **增强相关性**：只获取当前任务所需的指导

## 技能位置

所有技能位于 `.claude/skills/` 目录：
```
.claude/skills/
├── coding-style/SKILL.md
├── testing/SKILL.md
├── error-handling/SKILL.md
├── git-standards/SKILL.md
├── doc-query/SKILL.md
├── product/SKILL.md
├── structure/SKILL.md
└── tech/SKILL.md
```

## 迁移说明

原 `.kiro/steering/` 目录中的规则文件已迁移到 Claude Skills 架构。如果您需要查看原始文件，它们已备份到 `.kiro/steering/backup_before_migration/` 目录。

---

**注意**：此索引文件始终加载，以便您随时了解可用的技能。具体技能内容仅在需要时按需加载。
