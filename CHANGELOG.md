# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.0] - 2025-12-09

### Changed

- **代码现代化** (CLEANUP-813)
  - 使用 `Stream.toList()` 替代 `collect(Collectors.toList())` (8 处)
  - 使用 `String.isBlank()` 替代 `trim().isEmpty()` (8 处)
  - 移除未使用的 `Collectors` 导入 (4 处)
  - 代码质量评分：90/100 (A 级)

### Improved

- **构建质量** (CLEANUP-814)
  - 编译成功，零 lint 警告
  - 符合 JDK 17 最佳实践
  - 生成 OneScan-v2.3.0.jar (1.1MB)

### Fixed

- 无

## [2.2.1] - 2025-12-08

### Removed

- **完全移除传统 Burp Extender API 依赖** (CLEANUP-804)
  - 从 `pom.xml` 中移除 `burp-extender-api` 依赖
  - 从 properties 中移除 `burp-extender-api.version`
  - 实现 100% Montoya API 迁移

- **移除传统接口声明** (CLEANUP-801)
  - 从 `BurpExtender` 类中移除 `IMessageEditorController` 接口
  - 从 `BurpExtender` 类中移除 `IMessageEditorTabFactory` 接口
  - 删除相关的接口实现方法

- **删除未使用的成员变量** (CLEANUP-802)
  - 删除 `mCallbacks` 成员变量
  - 删除 `mHelpers` 成员变量

- **删除类型转换适配器** (CLEANUP-803)
  - 删除 `convertHttpServiceToLegacy()` 方法

### Changed

- **迁移扩展卸载方法**
  - 从 `mCallbacks.unloadExtension()` 迁移到 `api.extension().unload()`

### Fixed

- 无

## [2.2.0] - 2025-12-07

### Added

- **完成核心 Burp API 迁移** (95% 完成)
  - 迁移核心入口点 (BurpExtender)
  - 迁移 HTTP 处理 (HttpHandler, ProxyRequestHandler)
  - 迁移 UI 组件 (RawEditor, ContextMenuItemsProvider)
  - 迁移日志系统 (Montoya Logging API)
  - 迁移辅助工具类 (HttpReqRespAdapter)

### Changed

- **API 版本升级**
  - 从 burp-extender-api 2.3 升级到 montoya-api 2025.5
  - JDK 版本要求: 17+

### Deprecated

- 无

### Removed

- 无 (遗留代码在 v2.2.1 中移除)

### Fixed

- 无

### Security

- 无

---

## 版本说明

- **[2.2.1]** - 代码清理和优化版本 (阶段 8)
- **[2.2.0]** - Montoya API 核心迁移版本 (阶段 0-7)

## 链接

- [完整迁移文档](.agent/MIGRATION_FINAL_SUMMARY.md)
- [完整性验证报告](.agent/CLEANUP-808-final-verification.md)
- [发布说明 v2.2.1](.agent/RELEASE_NOTES_v2.2.1.md)
