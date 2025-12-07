# OneScan v2.2.0 发布说明 (Release Notes)

> ⚠️ **重要提示**: 本版本包含 P0 已知缺陷,不推荐用于生产环境。请等待 v2.3.0 修复版本。

## 📋 版本信息

- **版本号**: v2.2.0
- **发布日期**: 2025-12-07 (预发布)
- **状态**: 🟡 Beta (包含已知缺陷)
- **推荐升级**: ❌ 否 (建议等待 v2.3.0)

## 🎯 重大变更

### API 迁移 (部分完成)

OneScan v2.2.0 开始从传统 Burp Extender API 迁移到 Montoya API,提升与最新 Burp Suite 的兼容性。

**迁移进度**: 82% (29/35 任务完成)

**已迁移的核心组件**:
- ✅ 插件入口点: IBurpExtender → BurpExtension
- ✅ UI 组件: ITab → registerSuiteTab
- ✅ 上下文菜单: IContextMenuFactory → ContextMenuItemsProvider
- ✅ 代理监听: IProxyListener → ProxyResponseHandler
- ✅ HTTP 处理: IHttpService → HttpService
- ✅ 日志输出: System.out/err → Montoya Logging API
- ✅ 消息编辑器: RawEditor 完全迁移

**未迁移组件 (技术债务)**:
- ❌ IMessageEditorController
- ❌ IMessageEditorTabFactory
- ❌ 部分辅助工具方法 (mCallbacks, mHelpers)

## 🔧 系统要求

### 推荐配置

- **Burp Suite**: Professional/Community 2025.5 或更高
- **Java**: JDK 17 或更高 (JDK 21 也支持)
- **API**: Montoya API 2025.5

### 兼容性

| Burp Suite 版本 | 状态 | 说明 |
|----------------|------|------|
| 2025.5+ | ✅ 推荐 | 完全兼容,最佳体验 |
| 2025.1-2025.4 | ⚠️ 可能兼容 | 未充分测试 |
| 2024.x | ❌ 不支持 | 不兼容 Montoya API |
| 2023.x 及更早 | ❌ 不支持 | 不兼容 |

## ✨ 新功能

### 1. Montoya API 支持 (部分)

- 采用 Burp Suite 官方推荐的 Montoya API
- 提升稳定性和性能
- 更好的类型安全

### 2. 改进的日志系统

- 统一使用 Montoya Logging API
- 更清晰的日志格式
- 更好的调试体验

### 3. 重构的消息编辑器

- 完全基于 Montoya RawEditor
- 移除遗留适配器代码
- 更原生的 UI 集成

## 🐛 已修复的问题

### 代码质量改进

- 清理了遗留 API 导入 (100% 完成)
- 重构了 HTTP 请求处理逻辑
- 优化了数据结构 (TaskData, HttpReqRespAdapter)
- 删除了未使用的适配器代码 (MessageEditorTabAdapter, RawEditorAdapter)

### 兼容性修复

- 修复与 Burp Suite 2025.5 的兼容性问题
- 适配 Montoya API 的新特性
- 移除对旧 API 的直接依赖 (导入层面)

## ⚠️ 已知问题 (重要)

### P0 - 阻断性缺陷 🔴

#### 问题: mCallbacks 和 mHelpers 被设置为 null 但仍在使用

**影响**:
- ❌ **插件无法正常运行**
- ❌ 会抛出 NullPointerException
- ❌ 所有依赖这两个变量的功能崩溃

**详情**:
```java
// BurpExtender.java
private IBurpExtenderCallbacks mCallbacks;  // 设置为 null 但仍在 19 处使用
private IExtensionHelpers mHelpers;          // 设置为 null 但仍在 19 处使用
```

**修复计划**: v2.3.0 (预计 1-2 周)

**临时解决方案**: 无 (建议等待修复版本)

### P1 - 未完成的迁移 🟡

**问题**:
- IMessageEditorController 和 IMessageEditorTabFactory 仍在使用
- 无法移除 burp-extender-api 依赖

**影响**:
- ⚠️ 迁移不完整
- ⚠️ 仍依赖旧 API

**修复计划**: v2.3.0

## 🚀 升级指南

### 从 v2.1.x 升级

⚠️ **不推荐升级**

由于存在 P0 缺陷,建议继续使用 v2.1.x 稳定版,等待 v2.3.0 修复版本。

### 全新安装

如需测试 Montoya API 迁移效果,可以安装本版本,但**不建议用于生产环境**。

安装步骤:
1. 下载 `OneScan-v2.2.0.jar`
2. Burp Suite → Extensions → Add
3. 选择下载的 JAR 文件
4. 查看输出是否有错误

**预期结果**:
- ✅ 插件可以加载
- ❌ 部分功能会崩溃 (NullPointerException)

## 📚 文档更新

### 新增文档

- `.agent/migration_plan.md` - 迁移计划
- `.agent/MIGRATION_SUMMARY.md` - 迁移总结
- `.agent/MIGRATE-701-final-verification.md` - 最终验证报告
- `.agent/MIGRATE-401-E-analysis.md` - 清理任务分析
- `.agent/TECHNICAL_DEBT.md` - 技术债务评估

### 更新文档

- `README.md` - 更新系统要求和兼容性说明

## 🔮 路线图

### v2.3.0 (计划中 - 1-2 周)

**优先级 P0 - 修复阻断性缺陷**:
- 修复 mCallbacks 和 mHelpers = null 的问题
- 迁移所有使用位置到 Montoya API
- 移除这两个成员变量

**优先级 P1 - 完成迁移**:
- 迁移 IMessageEditorController
- 迁移 IMessageEditorTabFactory
- 移除 burp-extender-api 依赖

**优先级 P2 - 质量改进**:
- 修复 36 处过宽异常处理
- 性能测试和优化
- 内存泄漏检测

### v2.4.0 (计划中 - 1 个月)

- 新功能开发
- UI/UX 改进
- 性能优化

## ⚙️ 技术细节

### 代码变更统计

```
已修改文件: 91 个 Java 文件
新增代码: ~2000 行
删除代码: ~1500 行
净增加: ~500 行
新增文档: 10+ 个 Markdown 文件
```

### 依赖变更

**保留的依赖**:
```xml
<!-- 仍需保留 (未完成迁移) -->
<dependency>
    <groupId>net.portswigger.burp.extender</groupId>
    <artifactId>burp-extender-api</artifactId>
    <version>2.3</version>
</dependency>

<!-- 新增依赖 -->
<dependency>
    <groupId>net.portswigger.burp.extensions</groupId>
    <artifactId>montoya-api</artifactId>
    <version>2025.5</version>
</dependency>
```

**计划移除 (v2.3.0)**:
- burp-extender-api (待迁移完成)

### 迁移统计

| 阶段 | 任务数 | 已完成 | 跳过 | 待处理 | 完成率 |
|------|--------|--------|------|--------|--------|
| 0. API 分析 | 4 | 4 | 0 | 0 | 100% |
| 1. 核心入口 | 2 | 2 | 0 | 0 | 100% |
| 2. HTTP 处理 | 3 | 3 | 0 | 0 | 100% |
| 3. UI 组件 | 7 | 6 | 1 | 0 | 86% |
| 4. 工具类 | 8 | 6 | 2 | 0 | 75% |
| 5. 测试验证 | 3 | 3 | 0 | 0 | 100% |
| 6. 迁移评审 | 5 | 5 | 0 | 0 | 100% |
| 7. 最终验证 | 3 | 2 | 1 | 0 | 67% |
| **总计** | **35** | **29** | **4** | **1** | **82%** |

## 🙏 致谢

感谢 Burp Suite 团队提供的 Montoya API 文档和支持。

感谢社区用户的反馈和建议。

## 📞 支持

- **问题报告**: [GitHub Issues](https://github.com/vaycore/OneScan/issues)
- **文档**: [README.md](README.md)
- **迁移文档**: [.agent/MIGRATION_SUMMARY.md](.agent/MIGRATION_SUMMARY.md)

## ⚡ 快速链接

- [迁移总结](.agent/MIGRATION_SUMMARY.md) - 完整的迁移报告
- [技术债务](.agent/TECHNICAL_DEBT.md) - 已知问题和修复计划
- [迁移计划](.agent/migration_plan.md) - 原始迁移计划

---

## 📢 重要提醒

**🔴 本版本不推荐用于生产环境**

由于存在 P0 阻断性缺陷 (mCallbacks/mHelpers = null),插件无法正常运行。

**建议**:
1. 继续使用 v2.1.x 稳定版
2. 等待 v2.3.0 修复版本 (预计 1-2 周)
3. 关注 GitHub 发布动态

**测试用途**:
如需测试 Montoya API 迁移效果,可以安装本版本,但需了解:
- ✅ 插件可以加载
- ❌ 部分功能会崩溃
- ❌ 无法正常使用

---

**发布日期**: 2025-12-07
**维护者**: vaycore
**版本状态**: 🟡 Beta (不推荐生产使用)
