# OneScan 项目优化任务

> **说明**: 代码评审规范和标准已移至 `.claude/skills/code-review/SKILL.md`  
> 工作流程和输出格式请参考 `.claude/skills/code-review/references/` 目录

## 当前状态

- **项目版本**: 2.2.0
- **评审状态**: 待开始
- **当前阶段**: 阶段 0 - 项目评审与分析
- **总进度**: 0/0 (0%)

## 任务清单

### 阶段 0：项目评审与分析

**目标**: 完成项目代码质量评审，生成详细的问题清单和优化计划

- [ ] **[REVIEW-001]** 项目结构分析
  - 分析整体架构和模块划分
  - 识别核心功能模块和依赖关系
  - 评估代码组织的合理性

- [ ] **[REVIEW-002]** 代码质量评审
  - 运行静态代码分析工具（SpotBugs、PMD、Checkstyle）
  - 识别代码中的潜在问题（安全、性能、逻辑等）
  - 按严重程度对问题进行分类和优先级排序

- [ ] **[REVIEW-003]** 技术债务评估
  - 识别重复代码和可重构的部分
  - 评估代码复杂度和可维护性
  - 识别过大的文件和函数

- [ ] **[REVIEW-004]** 生成评审报告
  - 创建 `.agent/analysis_report.md`（参考 `.claude/skills/code-review/references/output-patterns.md`）
  - 创建 `.agent/task_status.json`
  - 更新本文件包含具体的任务清单

---

### 后续阶段

完成阶段 0 后，将根据评审结果生成具体的优化任务，按优先级组织为：

- **阶段 1**: P0 级别问题修复（严重）
- **阶段 2**: P1 级别问题修复（高）
- **阶段 3**: P2 级别问题修复（中）
- **阶段 4**: P3 级别问题优化（低）

## 快速参考

- 📋 **评审规范**: `.claude/skills/code-review/SKILL.md`
- 🔄 **工作流程**: `.claude/skills/code-review/references/workflows.md`
- 📊 **输出格式**: `.claude/skills/code-review/references/output-patterns.md`
- 🔧 **Burp API**: `.claude/skills/code-review/references/burp-api-guide.md`
- 🐍 **任务管理**: `.agent/task_status_manager.py`
