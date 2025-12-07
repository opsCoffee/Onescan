# OneScan Burp API 迁移任务

> **核心目标**: 将插件从传统 Burp Extender API 迁移到新版 Montoya API

## 当前状态

- **项目版本**: 2.2.0
- **迁移状态**: 全面完成阶段
- **当前阶段**: 阶段 7 - 完成剩余技术债务
- **总进度**: 15/28 (54%) - 核心功能已迁移，剩余技术债务待完成

## API 版本信息

- **传统 API**: burp-extender-api 2.3 (已弃用)
- **目标 API**: montoya-api 2025.5 (已在 pom.xml 中引入)
- **Java 版本**: 17

## 文件更新

- 每个任务完成以后，需要同步更新 `.agent/task_status.json` 和 `prompt.md`

## 迁移任务清单

### 阶段 0：API 使用情况分析

**目标**: 全面分析项目中传统 API 的使用情况，制定详细的迁移计划

- [ ] **[MIGRATE-001]** 扫描传统 API 使用
  - 识别所有使用 `burp.*` 包的类和方法
  - 统计各个传统 API 接口的使用频率
  - 生成 API 使用清单（按模块分类）
  - **状态**: ✅ 已完成 (2025-12-06)
  - **产出**: `.agent/api_usage_report.md`, `.agent/api_quick_reference.md`, `.agent/burp_api_usage.csv`

- [ ] **[MIGRATE-002]** API 映射关系分析
  - 建立传统 API 到 Montoya API 的映射表
  - 识别需要重构的复杂场景
  - 标记无直接对应的 API（需要特殊处理）
  - **状态**: ✅ 已完成 (2025-12-06)
  - **产出**: `.agent/api_mapping.md`

- [ ] **[MIGRATE-003]** 依赖关系分析
  - 分析各模块间的 API 依赖关系
  - 确定迁移的优先级和顺序
  - 识别可能的风险点
  - **状态**: ✅ 已完成 (2025-12-06)
  - **产出**: `.agent/dependency_analysis.md`

- [ ] **[MIGRATE-004]** 生成迁移计划
  - 创建 `.agent/migration_plan.md`
  - 创建 `.agent/api_mapping.md`(API 映射表)
  - 更新 `.agent/task_status.json`
  - **状态**: ✅ 已完成 (2025-12-06)
  - **产出**: `.agent/migration_plan.md`

---

### 阶段 1：核心入口点迁移

**目标**: 迁移插件的主入口和核心初始化逻辑

- [ ] **[MIGRATE-101]** BurpExtender 类迁移
  - 从 `IBurpExtender` 迁移到 `BurpExtension`
  - 从 `registerExtenderCallbacks` 迁移到 `initialize`
  - 更新回调接口的注册方式
  - **状态**: ✅ 已完成 (2025-12-07)

- [ ] **[MIGRATE-102]** 扩展上下文迁移
  - 从 `IBurpExtenderCallbacks` 迁移到 `MontoyaApi`
  - 更新所有使用回调接口的代码
  - 适配新的服务获取方式
  - **状态**: ✅ 已完成 (合并到 MIGRATE-101)

---

### 阶段 2：HTTP 处理迁移

**目标**: 迁移 HTTP 请求/响应处理相关的 API

- [ ] **[MIGRATE-201]** HTTP 监听器迁移
  - 从 `IHttpListener` 迁移到 `HttpHandler`
  - 更新请求/响应处理逻辑
  - 适配新的消息编辑器 API
  - **状态**: ✅ 已完成 (2025-12-07)

- [ ] **[MIGRATE-202]** HTTP 消息处理
  - 从 `IHttpRequestResponse` 迁移到 `HttpRequestResponse`
  - 更新请求/响应解析逻辑
  - 适配新的 HTTP 服务 API
  - **状态**: ✅ 已完成 (2025-12-07)

- [ ] **[MIGRATE-203]** 代理监听器迁移
  - 从 `IProxyListener` 迁移到 `ProxyRequestHandler`/`ProxyResponseHandler`
  - 更新拦截和修改逻辑
  - **状态**: ✅ 已完成 (2025-12-07)

---

### 阶段 3：UI 组件迁移

**目标**: 迁移用户界面相关的 API

- [ ] **[MIGRATE-301]** 标签页迁移
  - 从 `ITab` 迁移到 `UserInterface.registerSuiteTab()`
  - 更新标签页注册方式（使用 `api.userInterface().registerSuiteTab(title, component)`）
  - 适配新的 UI 组件模型
  - **状态**: ✅ 已完成 (2025-12-07)

- [ ] **[MIGRATE-302]** 上下文菜单迁移
  - 从 `IContextMenuFactory` 迁移到 `ContextMenuItemsProvider`
  - 实现 `provideMenuItems()` 方法（支持 HTTP、WebSocket、AuditIssue 三种事件）
  - 使用 `api.userInterface().registerContextMenuItemsProvider()` 注册
  - **状态**: ✅ 已完成 (2025-12-07)

- [ ] **[MIGRATE-303]** 消息编辑器迁移（已拆分为子任务，见阶段 7）
  - 从 `IMessageEditorController` 迁移到 `HttpRequestEditorProvider`/`HttpResponseEditorProvider`
  - 实现 `ExtensionProvidedHttpRequestEditor`/`ExtensionProvidedHttpResponseEditor` 接口
  - 使用 `api.userInterface().registerHttpRequestEditorProvider()` 注册
  - **状态**: 🔄 已拆分（见 MIGRATE-303-A 到 MIGRATE-303-D）
  - **预计总工作量**: 8 小时

---

### 阶段 4：工具类和辅助功能迁移

**目标**: 迁移工具类和辅助功能相关的 API

- [ ] **[MIGRATE-401]** 辅助工具类迁移（已拆分为子任务，见阶段 7）
  - 从 `IExtensionHelpers` 迁移到各个专用服务
  - 更新 URL 解析、编码/解码等工具方法
  - 适配新的参数处理 API
  - **状态**: 🔄 已拆分（见 MIGRATE-401-A 到 MIGRATE-401-E）
  - **预计总工作量**: 16 小时

- [ ] **[MIGRATE-402]** 扫描器集成迁移
  - 从 `IScannerCheck` 迁移到 `Scanner` API
  - 更新扫描逻辑和问题报告
  - **状态**: ✅ 不适用（项目未使用 IScannerCheck 接口）

- [ ] **[MIGRATE-403]** 日志和输出迁移
  - 从 `stdout`/`stderr` 迁移到 `Logging` API
  - 统一日志输出方式
  - **状态**: ✅ 已完成 (2025-12-07)

---

### 阶段 5：测试和验证

**目标**: 确保迁移后的功能完整性和稳定性

- [ ] **[MIGRATE-501]** 功能测试
  - 测试所有核心功能
  - 验证 UI 交互
  - 检查性能表现
  - **状态**: ✅ 已完成 (2025-12-07)
  - **产出**: `.agent/test_report.md`

- [ ] **[MIGRATE-502]** 兼容性测试
  - 测试不同 Burp Suite 版本
  - 验证与其他插件的兼容性
  - **状态**: ✅ 已完成 (2025-12-07)
  - **产出**: `.agent/compatibility_report.md`

- [ ] **[MIGRATE-503]** 清理工作
  - 更新文档和注释
  - 代码格式化和优化
  - 记录技术债务
  - **状态**: ✅ 已完成 (2025-12-07)

---

### 阶段 6：迁移验证与评审

**目标**: 全面检查迁移完成情况，评审代码质量，确保无遗漏

- [ ] **[MIGRATE-601]** 迁移完整性检查
  - 扫描所有源代码文件，确认无残留的传统 API 引用
  - 检查所有 `burp.*` 包的导入语句是否已清理
  - 验证所有已迁移的类是否正确使用 Montoya API
  - 生成迁移完整性报告
  - **预计工作量**: 2-3 小时
  - **状态**: ✅ 已完成 (2025-12-07)
  - **产出**: `.agent/MIGRATE-601-integrity-report.md`
  - **结论**: 核心迁移完成 90%，剩余为已知技术债务

- [ ] **[MIGRATE-602]** 代码质量评审
  - 评审已迁移代码的质量和规范性
  - 检查异常处理是否完善
  - 验证日志输出是否统一使用 Montoya Logging API
  - 检查资源管理和内存泄漏风险
  - 评估代码可维护性和可读性
  - **预计工作量**: 3-4 小时
  - **状态**: 🔄 进行中

- [ ] **[MIGRATE-603]** API 使用规范性检查
  - 验证 Montoya API 的使用是否符合最佳实践
  - 检查是否有不推荐的 API 使用方式
  - 确认线程安全性和并发处理
  - 验证 UI 组件的注册和注销是否正确
  - **预计工作量**: 2-3 小时
  - **状态**: 🔄 进行中

- [ ] **[MIGRATE-604]** 技术债务评估
  - 整理跳过的迁移任务（MIGRATE-303, MIGRATE-401）
  - 评估技术债务的影响和优先级
  - 制定后续优化计划
  - 更新 `.agent/TECHNICAL_DEBT.md`
  - **预计工作量**: 1-2 小时
  - **状态**: 🔄 进行中

- [ ] **[MIGRATE-605]** 文档完整性检查
  - 检查代码注释是否完整和准确
  - 验证 README.md 是否需要更新
  - 确认迁移相关文档的完整性
  - 生成最终迁移总结报告
  - **预计工作量**: 1-2 小时
  - **状态**: 🔄 进行中

---

### 阶段 7：完成剩余技术债务

**目标**: 完成所有跳过的迁移任务，实现 100% Montoya API 迁移

#### 子阶段 7.1：消息编辑器迁移 (MIGRATE-303 拆分)

- [ ] **[MIGRATE-303-A]** 分析现有消息编辑器使用情况
  - 分析 `RawEditorAdapter.java` 的实现和使用场景
  - 识别所有依赖 `IMessageEditor` 的组件
  - 分析 `OneScanInfoTab` 的 UI 结构和数据流
  - 制定详细的重构方案
  - **预计工作量**: 1.5 小时
  - **状态**: ⏳ 待开始
  - **产出**: `.agent/MIGRATE-303-A-analysis.md`

- [ ] **[MIGRATE-303-B]** 重构 OneScanInfoTab 使用 Montoya RawEditor
  - 移除 `IMessageEditorTab` 接口实现
  - 直接使用 Montoya `RawEditor` API
  - 更新 UI 组件的数据绑定逻辑
  - 测试 UI 交互功能
  - **预计工作量**: 3 小时
  - **状态**: ⏳ 待开始
  - **依赖**: MIGRATE-303-A

- [ ] **[MIGRATE-303-C]** 更新 BurpExtender 中的编辑器引用
  - 将 `mRequestTextEditor` 和 `mResponseTextEditor` 类型改为 `RawEditor`
  - 移除 `RawEditorAdapter` 的使用
  - 更新所有相关的方法调用
  - **预计工作量**: 2 小时
  - **状态**: ⏳ 待开始
  - **依赖**: MIGRATE-303-B

- [ ] **[MIGRATE-303-D]** 清理和测试
  - 删除 `RawEditorAdapter.java` 文件
  - 移除 `IMessageEditor` 相关导入
  - 完整测试消息编辑器功能
  - 更新相关文档和注释
  - **预计工作量**: 1.5 小时
  - **状态**: ⏳ 待开始
  - **依赖**: MIGRATE-303-C
  - **产出**: `.agent/MIGRATE-303-completion-report.md`

---

#### 子阶段 7.2：辅助工具类迁移 (MIGRATE-401 拆分)

- [ ] **[MIGRATE-401-A]** IHttpService 迁移分析和规划
  - 统计 `IHttpService` 的所有使用位置（27 处）
  - 分析每个使用场景的迁移策略
  - 确定迁移到 `HttpService` 的具体方案
  - 识别需要重构的复杂场景
  - **预计工作量**: 2 小时
  - **状态**: ⏳ 待开始
  - **产出**: `.agent/MIGRATE-401-A-analysis.md`

- [ ] **[MIGRATE-401-B]** 重构 HttpReqRespAdapter
  - 将 `IHttpRequestResponse` 接口改为内部接口或移除
  - 将 `IHttpService` 替换为 Montoya `HttpService`
  - 更新适配器的构造方法和工厂方法
  - 保持与现有代码的兼容性
  - **预计工作量**: 3 小时
  - **状态**: ⏳ 待开始
  - **依赖**: MIGRATE-401-A

- [ ] **[MIGRATE-401-C]** 更新 BurpExtender 中的 IHttpService 使用
  - 批量替换 `IHttpService` 为 `HttpService`
  - 更新所有工具方法的参数和返回值类型
  - 修复类型转换和方法调用
  - 分批测试每个修改的方法
  - **预计工作量**: 4 小时
  - **状态**: ⏳ 待开始
  - **依赖**: MIGRATE-401-B

- [ ] **[MIGRATE-401-D]** 更新核心数据结构
  - 重构 `TaskData` 类，移除 `IHttpRequestResponse` 依赖
  - 更新 `TaskPool` 和相关扫描引擎代码
  - 使用 Montoya 原生类型或自定义数据类
  - 确保扫描功能完整性
  - **预计工作量**: 5 小时
  - **状态**: ⏳ 待开始
  - **依赖**: MIGRATE-401-C
  - **风险**: 高（涉及核心扫描引擎）

- [ ] **[MIGRATE-401-E]** 清理和验证
  - 删除 `HttpReqRespAdapter.java`（如果不再需要）
  - 移除所有 `IHttpRequestResponse` 和 `IHttpService` 导入
  - 从 `pom.xml` 移除 `burp-extender-api` 依赖
  - 完整回归测试所有功能
  - **预计工作量**: 2 小时
  - **状态**: ⏳ 待开始
  - **依赖**: MIGRATE-401-D
  - **产出**: `.agent/MIGRATE-401-completion-report.md`

---

#### 子阶段 7.3：最终验证和文档

- [ ] **[MIGRATE-701]** 完整性最终验证
  - 重新扫描所有源代码，确认零传统 API 引用
  - 验证 `pom.xml` 已移除 `burp-extender-api`
  - 确认所有代码使用 Montoya API
  - 生成最终迁移报告
  - **预计工作量**: 1 小时
  - **状态**: ⏳ 待开始
  - **依赖**: MIGRATE-303-D, MIGRATE-401-E
  - **产出**: `.agent/MIGRATE-701-final-report.md`

- [ ] **[MIGRATE-702]** 性能和稳定性测试
  - 压力测试扫描引擎
  - 内存泄漏检测
  - 并发场景测试
  - 长时间运行稳定性测试
  - **预计工作量**: 2 小时
  - **状态**: ⏳ 待开始
  - **依赖**: MIGRATE-701

- [ ] **[MIGRATE-703]** 文档更新和发布准备
  - 更新 README.md（API 版本、兼容性说明）
  - 更新代码注释和 JavaDoc
  - 编写迁移完成总结报告
  - 准备发布说明（Release Notes）
  - **预计工作量**: 2 小时
  - **状态**: ⏳ 待开始
  - **依赖**: MIGRATE-702
  - **产出**: `.agent/migration_final_summary.md`

---

## 迁移原则

1. **渐进式迁移**: 按模块逐步迁移，确保每个阶段都可以编译和测试
2. **保持功能**: 迁移过程中保持现有功能不变，不引入新特性
3. **代码质量**: 利用迁移机会优化代码结构和命名
4. **充分测试**: 每个阶段完成后进行充分测试
5. **文档同步**: 及时更新代码注释和文档

## 任务进度统计

### 总体进度
- **总任务数**: 28 个
- **已完成**: 15 个 (54%)
- **进行中**: 4 个 (14%)
- **待开始**: 9 个 (32%)

### 按阶段统计
- **阶段 0** (分析): 4/4 ✅ 100%
- **阶段 1** (入口): 2/2 ✅ 100%
- **阶段 2** (HTTP): 3/3 ✅ 100%
- **阶段 3** (UI): 2/3 ⚠️ 67% (MIGRATE-303 已拆分)
- **阶段 4** (工具): 2/3 ⚠️ 67% (MIGRATE-401 已拆分)
- **阶段 5** (测试): 3/3 ✅ 100%
- **阶段 6** (评审): 1/5 🔄 20%
- **阶段 7** (债务): 0/13 ⏳ 0%

### 关键里程碑
- ✅ 核心框架迁移完成 (2025-12-07)
- ✅ 基础功能验证通过 (2025-12-07)
- 🔄 代码质量评审中
- ⏳ 技术债务清理待开始
- ⏳ 100% 迁移目标待完成

---

## 评审检查清单

### 代码层面
- [ ] 核心入口点使用 Montoya API ✅
- [ ] HTTP 处理使用 Montoya API ✅
- [ ] 日志统一使用 `api.logging()` ✅
- [ ] 无残留的 `burp.*` 包导入 ⚠️ (2 个适配器待处理)
- [ ] UI 组件完全使用 Montoya API ⚠️ (MIGRATE-303 待完成)
- [ ] 数据模型完全使用 Montoya API ⚠️ (MIGRATE-401 待完成)
- [ ] 异常处理完善 🔄 (评审中)
- [ ] 线程安全性验证 🔄 (评审中)

### 功能层面
- [ ] 核心扫描功能正常 ✅
- [ ] UI 交互响应正确 ✅
- [ ] 上下文菜单可用 ✅
- [ ] 代理拦截工作正常 ✅
- [ ] 配置持久化正常 ✅
- [ ] 性能测试 ⏳ (MIGRATE-702)
- [ ] 稳定性测试 ⏳ (MIGRATE-702)

### 文档层面
- [ ] 迁移计划文档 ✅
- [ ] API 映射文档 ✅
- [ ] 完整性检查报告 ✅
- [ ] 代码注释完整准确 🔄 (MIGRATE-605)
- [ ] README.md 更新 ⏳ (MIGRATE-703)
- [ ] 技术债务记录 🔄 (MIGRATE-604)
- [ ] 迁移总结报告 ⏳ (MIGRATE-703)

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

## 执行建议

### 优先级排序

**P0 - 立即执行** (完成阶段 6 评审):
1. MIGRATE-602: 代码质量评审
2. MIGRATE-603: API 使用规范性检查
3. MIGRATE-604: 技术债务评估
4. MIGRATE-605: 文档完整性检查

**P1 - 高优先级** (消息编辑器迁移):
1. MIGRATE-303-A: 分析现有使用情况
2. MIGRATE-303-B: 重构 OneScanInfoTab
3. MIGRATE-303-C: 更新 BurpExtender 引用
4. MIGRATE-303-D: 清理和测试

**P2 - 中优先级** (辅助工具类迁移 - 低风险部分):
1. MIGRATE-401-A: IHttpService 迁移分析
2. MIGRATE-401-B: 重构 HttpReqRespAdapter
3. MIGRATE-401-C: 更新 BurpExtender 使用

**P3 - 高风险任务** (核心引擎重构):
1. MIGRATE-401-D: 更新核心数据结构
2. MIGRATE-401-E: 清理和验证

**P4 - 最终验证**:
1. MIGRATE-701: 完整性最终验证
2. MIGRATE-702: 性能和稳定性测试
3. MIGRATE-703: 文档更新和发布准备

### 执行策略

**短期目标** (本周):
- 完成阶段 6 的所有评审任务
- 完成 MIGRATE-303 消息编辑器迁移
- 预计工作量: 12-15 小时

**中期目标** (下周):
- 完成 MIGRATE-401-A 到 MIGRATE-401-C
- 预计工作量: 9 小时

**长期目标** (两周后):
- 完成 MIGRATE-401-D 核心引擎重构（高风险）
- 完成最终验证和文档
- 预计工作量: 10 小时

**总预计工作量**: 31-34 小时

### 风险管理

**高风险任务**:
- MIGRATE-401-D (核心数据结构重构)
  - 风险: 可能影响扫描引擎稳定性
  - 缓解: 充分的单元测试和回归测试
  - 建议: 创建独立分支进行开发

**中风险任务**:
- MIGRATE-303-B (OneScanInfoTab 重构)
  - 风险: UI 交互可能出现问题
  - 缓解: 详细的 UI 测试
  
**低风险任务**:
- 所有评审和分析任务
- 文档更新任务

---

## 快速参考

- 📋 **评审规范**: `.claude/skills/code-review/SKILL.md`
- 🔄 **工作流程**: `.claude/skills/code-review/references/workflows.md`
- 🔧 **Burp API 指南**: `.claude/skills/code-review/references/burp-api-guide.md`
- 📚 **Montoya API 文档**: https://portswigger.github.io/burp-extensions-montoya-api/
- 🐍 **任务管理**: `.agent/task_status_manager.py`
- 📊 **完整性报告**: `.agent/MIGRATE-601-integrity-report.md`
- 📝 **技术债务**: `.agent/TECHNICAL_DEBT.md`
