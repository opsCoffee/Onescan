# OneScan Burp API 迁移任务

> **核心目标**: 将插件从传统 Burp Extender API 迁移到新版 Montoya API

## 当前状态

- **项目版本**: 2.2.0
- **迁移状态**: 基本完成 (72%)
- **当前阶段**: 阶段 5 - 测试和验证
- **总进度**: 13/18 (72%)

## API 版本信息

- **传统 API**: burp-extender-api 2.3 (已弃用)
- **目标 API**: montoya-api 2025.5 (已在 pom.xml 中引入)
- **Java 版本**: 17

## 文件更新

- 每个任务完成以后，需要同步更新 `.agent/task_status.json` 和 `prompt.md`

## 迁移任务清单

### 阶段 0：API 使用情况分析

**目标**: 全面分析项目中传统 API 的使用情况，制定详细的迁移计划

- [x] **[MIGRATE-001]** 扫描传统 API 使用
  - 识别所有使用 `burp.*` 包的类和方法
  - 统计各个传统 API 接口的使用频率
  - 生成 API 使用清单（按模块分类）
  - **状态**: ✅ 已完成 (2025-12-06)
  - **产出**: `.agent/api_usage_report.md`, `.agent/api_quick_reference.md`, `.agent/burp_api_usage.csv`

- [x] **[MIGRATE-002]** API 映射关系分析
  - 建立传统 API 到 Montoya API 的映射表
  - 识别需要重构的复杂场景
  - 标记无直接对应的 API（需要特殊处理）
  - **状态**: ✅ 已完成 (2025-12-06)
  - **产出**: `.agent/api_mapping.md`

- [x] **[MIGRATE-003]** 依赖关系分析
  - 分析各模块间的 API 依赖关系
  - 确定迁移的优先级和顺序
  - 识别可能的风险点
  - **状态**: ✅ 已完成 (2025-12-06)
  - **产出**: `.agent/dependency_analysis.md`

- [x] **[MIGRATE-004]** 生成迁移计划
  - 创建 `.agent/migration_plan.md`
  - 创建 `.agent/api_mapping.md`(API 映射表)
  - 更新 `.agent/task_status.json`
  - **状态**: ✅ 已完成 (2025-12-06)
  - **产出**: `.agent/migration_plan.md`

---

### 阶段 1：核心入口点迁移

**目标**: 迁移插件的主入口和核心初始化逻辑

- [x] **[MIGRATE-101]** BurpExtender 类迁移
  - 从 `IBurpExtender` 迁移到 `BurpExtension`
  - 从 `registerExtenderCallbacks` 迁移到 `initialize`
  - 更新回调接口的注册方式
  - **状态**: ✅ 已完成 (2025-12-07)

- [x] **[MIGRATE-102]** 扩展上下文迁移
  - 从 `IBurpExtenderCallbacks` 迁移到 `MontoyaApi`
  - 更新所有使用回调接口的代码
  - 适配新的服务获取方式
  - **状态**: ✅ 已完成 (合并到 MIGRATE-101)

---

### 阶段 2：HTTP 处理迁移

**目标**: 迁移 HTTP 请求/响应处理相关的 API

- [x] **[MIGRATE-201]** HTTP 监听器迁移
  - 从 `IHttpListener` 迁移到 `HttpHandler`
  - 更新请求/响应处理逻辑
  - 适配新的消息编辑器 API
  - **状态**: ✅ 已完成 (2025-12-07)

- [x] **[MIGRATE-202]** HTTP 消息处理
  - 从 `IHttpRequestResponse` 迁移到 `HttpRequestResponse`
  - 更新请求/响应解析逻辑
  - 适配新的 HTTP 服务 API
  - **状态**: ✅ 已完成 (2025-12-07)

- [x] **[MIGRATE-203]** 代理监听器迁移
  - 从 `IProxyListener` 迁移到 `ProxyRequestHandler`/`ProxyResponseHandler`
  - 更新拦截和修改逻辑
  - **状态**: ✅ 已完成 (2025-12-07)

---

### 阶段 3：UI 组件迁移

**目标**: 迁移用户界面相关的 API

- [x] **[MIGRATE-301]** 标签页迁移
  - 从 `ITab` 迁移到 `UserInterface.registerSuiteTab()`
  - 更新标签页注册方式（使用 `api.userInterface().registerSuiteTab(title, component)`）
  - 适配新的 UI 组件模型
  - **状态**: ✅ 已完成 (2025-12-07)

- [x] **[MIGRATE-302]** 上下文菜单迁移
  - 从 `IContextMenuFactory` 迁移到 `ContextMenuItemsProvider`
  - 实现 `provideMenuItems()` 方法（支持 HTTP、WebSocket、AuditIssue 三种事件）
  - 使用 `api.userInterface().registerContextMenuItemsProvider()` 注册
  - **状态**: ✅ 已完成 (2025-12-07)

- [ ] **[MIGRATE-303]** 消息编辑器迁移
  - 从 `IMessageEditorController` 迁移到 `HttpRequestEditorProvider`/`HttpResponseEditorProvider`
  - 实现 `ExtensionProvidedHttpRequestEditor`/`ExtensionProvidedHttpResponseEditor` 接口
  - 使用 `api.userInterface().registerHttpRequestEditorProvider()` 注册
  - **状态**: ⏭️ 已跳过 (复杂度高 8h,留待后续)

---

### 阶段 4：工具类和辅助功能迁移

**目标**: 迁移工具类和辅助功能相关的 API

- [ ] **[MIGRATE-401]** 辅助工具类迁移
  - 从 `IExtensionHelpers` 迁移到各个专用服务
  - 更新 URL 解析、编码/解码等工具方法
  - 适配新的参数处理 API
  - **状态**: ⏭️ 已跳过 (工作量大 16处使用点,留待后续)

- [ ] **[MIGRATE-402]** 扫描器集成迁移
  - 从 `IScannerCheck` 迁移到 `Scanner` API
  - 更新扫描逻辑和问题报告
  - **状态**: ⏭️ 已跳过 (IScannerCheck 未使用,不适用)

- [x] **[MIGRATE-403]** 日志和输出迁移
  - 从 `stdout`/`stderr` 迁移到 `Logging` API
  - 统一日志输出方式
  - **状态**: ✅ 已完成 (2025-12-07)

---

### 阶段 5：测试和验证

**目标**: 确保迁移后的功能完整性和稳定性

- [x] **[MIGRATE-501]** 功能测试
  - 测试所有核心功能
  - 验证 UI 交互
  - 检查性能表现
  - **状态**: ✅ 已完成 (2025-12-07)
  - **产出**: `.agent/test_report.md`

- [x] **[MIGRATE-502]** 兼容性测试
  - 测试不同 Burp Suite 版本
  - 验证与其他插件的兼容性
  - **状态**: ✅ 已完成 (2025-12-07)
  - **产出**: `.agent/compatibility_report.md`

- [ ] **[MIGRATE-503]** 清理工作
  - 更新文档和注释
  - 代码格式化和优化
  - 记录技术债务
  - **状态**: 🔄 进行中

---

## 迁移原则

1. **渐进式迁移**: 按模块逐步迁移，确保每个阶段都可以编译和测试
2. **保持功能**: 迁移过程中保持现有功能不变，不引入新特性
3. **代码质量**: 利用迁移机会优化代码结构和命名
4. **充分测试**: 每个阶段完成后进行充分测试
5. **文档同步**: 及时更新代码注释和文档

## 关键 API 映射参考

### 核心接口
- `IBurpExtender` → `BurpExtension`
  - `registerExtenderCallbacks(IBurpExtenderCallbacks)` → `initialize(MontoyaApi)`
- `IBurpExtenderCallbacks` → `MontoyaApi`
  - 通过 `api.http()`, `api.proxy()`, `api.userInterface()` 等获取各个服务

### HTTP 处理
- `IHttpListener` → `HttpHandler`
  - `processHttpMessage()` → `handleHttpRequestToBeSent()` + `handleHttpResponseReceived()`
  - 注册方式：`api.http().registerHttpHandler()`
- `IProxyListener` → `ProxyRequestHandler` + `ProxyResponseHandler`
  - 注册方式：`api.proxy().registerRequestHandler()` / `registerResponseHandler()`
- `IHttpRequestResponse` → `HttpRequestResponse`
- `IRequestInfo`/`IResponseInfo` → `HttpRequest`/`HttpResponse`
  - 直接通过 `HttpRequest`/`HttpResponse` 对象访问属性和方法

### UI 组件
- `ITab` → `UserInterface.registerSuiteTab(String title, Component component)`
  - 返回 `Registration` 对象用于注销
- `IContextMenuFactory` → `ContextMenuItemsProvider`
  - `createMenuItems(IContextMenuInvocation)` → `provideMenuItems(ContextMenuEvent)`
  - 注册方式：`api.userInterface().registerContextMenuItemsProvider()`
- `IMessageEditorController` → `HttpRequestEditorProvider`/`HttpResponseEditorProvider`
  - 需实现 `ExtensionProvidedHttpRequestEditor`/`ExtensionProvidedHttpResponseEditor`
  - 注册方式：`api.userInterface().registerHttpRequestEditorProvider()`

### 辅助工具
- `IExtensionHelpers` → 各个专用服务
  - URL 解析：`api.utilities().urlUtils()`
  - Base64 编解码：`api.utilities().base64Utils()`
  - HTTP 构建：`HttpRequest.httpRequest()` / `HttpResponse.httpResponse()`
- 日志输出：`callbacks.printOutput()` → `api.logging().logToOutput()`
- 错误输出：`callbacks.printError()` → `api.logging().logToError()`

## 快速参考

- 📋 **评审规范**: `.claude/skills/code-review/SKILL.md`
- 🔄 **工作流程**: `.claude/skills/code-review/references/workflows.md`
- 🔧 **Burp API 指南**: `.claude/skills/code-review/references/burp-api-guide.md`
- 📚 **Montoya API 文档**: https://portswigger.github.io/burp-extensions-montoya-api/
- 🐍 **任务管理**: `.agent/task_status_manager.py`
