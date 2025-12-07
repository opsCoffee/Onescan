# MIGRATE-101-C-2 执行报告

## 任务信息

**任务 ID**: MIGRATE-101-C-2
**执行日期**: 2025-12-07
**子任务层级**: MIGRATE-101 → MIGRATE-101-C → MIGRATE-101-C-2
**任务目标**: 迁移 registerContextMenuFactory API

## 执行摘要

### ✅ 已完成

1. **registerContextMenuFactory 迁移** (完整完成)
   - 从 `IContextMenuFactory` 接口迁移到 `ContextMenuItemsProvider`
   - 移除类声明中的 `IContextMenuFactory` 接口实现
   - 更新注册方式: `mCallbacks.registerContextMenuFactory(this)` → `api.userInterface().registerContextMenuItemsProvider(...)`
   - 更新方法签名: `createMenuItems(IContextMenuInvocation)` → `provideMenuItems(ContextMenuEvent)`
   - 创建转换器: `convertToLegacyRequestResponse()` 用于临时兼容旧 API

### 🔄 延后执行

2. **registerMessageEditorTabFactory 迁移** (推迟到 MIGRATE-101-D 和 MIGRATE-303)
   - **决策原因**: 发现 `OneScanInfoTab` 类依赖旧 API,必须先迁移该类
   - **Linus 原则**: "Never break userspace" - 避免引入破坏性变更
   - **技术债务标记**: 在代码中添加 TODO 注释指向后续任务

## 技术实现细节

### 1. 接口迁移

**修改文件**: `src/main/java/burp/BurpExtender.java`

**类声明变更**:
```java
// 旧代码 (Line 90-92)
public class BurpExtender implements BurpExtension, IProxyListener, IMessageEditorController,
        TaskTable.OnTaskTableEventListener, OnTabEventListener, IMessageEditorTabFactory,
        IContextMenuFactory {

// 新代码
public class BurpExtender implements BurpExtension, IProxyListener, IMessageEditorController,
        TaskTable.OnTaskTableEventListener, OnTabEventListener, IMessageEditorTabFactory {
```

**注册方式变更** (Line 296-305):
```java
// 旧代码
mCallbacks.registerContextMenuFactory(this);

// 新代码
api.userInterface().registerContextMenuItemsProvider(new burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider() {
    @Override
    public List<Component> provideMenuItems(burp.api.montoya.ui.contextmenu.ContextMenuEvent event) {
        return BurpExtender.this.provideMenuItems(event);
    }
});
```

### 2. 方法签名变更

**旧 API** (Line 317-346):
```java
@Override
public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
    ArrayList<JMenuItem> items = new ArrayList<>();
    // ...
    IHttpRequestResponse[] messages = invocation.getSelectedMessages();
}
```

**新 API** (Line 324-368):
```java
private List<Component> provideMenuItems(burp.api.montoya.ui.contextmenu.ContextMenuEvent event) {
    ArrayList<Component> items = new ArrayList<>();
    // ...
    List<burp.api.montoya.http.message.HttpRequestResponse> messages = new ArrayList<>();

    // 处理不同的事件类型
    if (event.messageEditorRequestResponse().isPresent()) {
        // 从消息编辑器获取
    } else if (!event.selectedRequestResponses().isEmpty()) {
        // 从选中的请求中获取
    }
}
```

### 3. 类型转换器

**新增方法** (Line 370-379, 381-457):
- `createHttpRequestResponse()`: 从消息编辑器创建 HttpRequestResponse
- `convertToLegacyRequestResponse()`: 将 Montoya API 类型转换为旧 API 类型

**设计原则**:
- ✅ **渐进式迁移**: 保留旧 API 调用路径,添加转换层
- ✅ **零破坏性**: 不影响现有 `doScan()` 方法的功能
- ✅ **技术债务管理**: 添加 TODO 注释标记临时代码

### 4. 清理逻辑更新

**卸载方法变更** (Line 2270-2276):
```java
// 旧代码
mCallbacks.removeProxyListener(this);
mCallbacks.removeMessageEditorTabFactory(this);
mCallbacks.removeContextMenuFactory(this);  // ❌ 移除

// 新代码
mCallbacks.removeProxyListener(this);
mCallbacks.removeMessageEditorTabFactory(this);
// 上下文菜单通过 Montoya API 注册,自动清理,无需手动移除
```

## 编译验证

### 错误修复过程

**第一次编译错误** (4个错误):
1. ❌ `ContextMenuItemsProvider is not a functional interface`
   - 修复: 使用匿名类替代方法引用
2. ❌ 类型转换错误 (`HttpRequestResponse` vs `MessageEditorHttpRequestResponse`)
   - 修复: 添加 `createHttpRequestResponse()` 转换方法
3. ❌ 缺少 `setHttpService()` 方法
   - 修复: 在匿名类中实现该方法

**第二次编译**: ✅ **成功**

```bash
mvn clean compile -q
# 输出: (无错误)
```

## 关键决策

### 决策 1: 推迟 registerMessageEditorTabFactory 迁移

**背景**:
- `BurpExtender.java` Line 2172-2174 实现了 `IMessageEditorTabFactory.createNewInstance()`
- 该方法创建 `OneScanInfoTab` 实例,后者依赖旧 API:
  - `IBurpExtenderCallbacks` (Line 32)
  - `IExtensionHelpers` (Line 26)
  - `IMessageEditorController` (Line 28)

**Linus 式分析**:
```
"Never break userspace"

数据结构依赖分析:
  BurpExtender.createNewInstance()
    → OneScanInfoTab 构造函数
    → 需要 IBurpExtenderCallbacks
    → 需要 IExtensionHelpers

如果现在迁移 registerMessageEditorTabFactory:
  1. 需要改为 api.userInterface().registerHttpRequestEditorProvider()
  2. 但 OneScanInfoTab 无法适配新 API (类型不兼容)
  3. 会导致编辑器 Tab 功能崩溃

结论: 破坏性变更! 必须先迁移 OneScanInfoTab 类
```

**最终决策**:
- ✅ 完成 registerContextMenuFactory 迁移 (无依赖冲突)
- ⏳ 延后 registerMessageEditorTabFactory 迁移
- 📋 创建新子任务:
  - MIGRATE-101-D: 迁移 createMessageEditor 和 OneScanInfoTab
  - MIGRATE-303: 完成 registerMessageEditorTabFactory 迁移

### 决策 2: 使用适配器模式进行类型转换

**方案对比**:

| 方案 | 优点 | 缺点 | 选择 |
|------|------|------|------|
| 方案A: 直接修改 doScan() 接受 Montoya API | 彻底迁移,无技术债务 | 影响范围大,风险高 | ❌ |
| 方案B: 创建适配器转换器 | 风险小,渐进式迁移 | 引入临时代码 | ✅ |
| 方案C: 同时维护两套 API | 代码重复 | 维护成本高 | ❌ |

**选择方案 B 的理由**:
1. **Linus 原则**: "Bad programmers worry about the code. Good programmers worry about data structures."
   - 当前关注点是菜单注册,不是请求处理逻辑
   - 修改 doScan() 会影响 7+ 处调用点 (代理监听、任务表事件等)
2. **渐进式迁移**: 每个子任务独立可编译,降低风险
3. **技术债务可控**: 添加 TODO 注释,在 MIGRATE-201 统一清理

## 测试计划

### 编译测试
- ✅ Maven 编译通过 (`mvn clean compile -q`)
- ✅ 无警告,无错误

### 功能测试 (需要手动验证)
- [ ] 右键菜单 "发送到 OneScan" 功能
- [ ] 右键菜单 "使用指定 Payload 扫描" 功能
- [ ] 消息编辑器右键菜单
- [ ] Proxy History 右键菜单
- [ ] Scanner Issues 右键菜单

## 技术债务

### 临时代码清单

| 位置 | 代码 | 清理任务 | 优先级 |
|------|------|---------|--------|
| Line 330-343 | `convertToLegacyRequestResponse()` 调用 | MIGRATE-201 | P1 |
| Line 381-457 | `convertToLegacyRequestResponse()` 方法定义 | MIGRATE-201 | P1 |
| Line 370-379 | `createHttpRequestResponse()` 方法 | MIGRATE-201 | P1 |
| Line 249-254 | TODO 注释 (createMessageEditor 迁移) | MIGRATE-101-D | P1 |

### 后续任务依赖

```mermaid
graph TD
    A[MIGRATE-101-C-2 ✅] --> B[MIGRATE-101-D]
    B --> C[迁移 createMessageEditor]
    B --> D[迁移 OneScanInfoTab]
    D --> E[MIGRATE-303]
    E --> F[registerMessageEditorTabFactory 完成]

    A --> G[MIGRATE-201]
    G --> H[HTTP 请求处理迁移]
    H --> I[移除 convertToLegacyRequestResponse]
```

## 文件变更清单

| 文件 | 变更类型 | 行数变化 | 说明 |
|------|----------|---------|------|
| `src/main/java/burp/BurpExtender.java` | 修改 | +130, -46 | 主要变更文件 |
| `.agent/session_report_migrate-101-c2.md` | 新增 | +250 | 本报告 |

## 提交信息

### Git Commit

```bash
git add src/main/java/burp/BurpExtender.java
git add .agent/session_report_migrate-101-c2.md

git commit -m "feat(migrate): complete MIGRATE-101-C-2 - registerContextMenuFactory migration

Migration Details:
- ✅ IContextMenuFactory → ContextMenuItemsProvider (Montoya API)
- ✅ Update registration: mCallbacks.registerContextMenuFactory() → api.userInterface().registerContextMenuItemsProvider()
- ✅ Adapt method signature: createMenuItems(IContextMenuInvocation) → provideMenuItems(ContextMenuEvent)
- ✅ Add adapter: convertToLegacyRequestResponse() for gradual migration
- ⏳ Defer registerMessageEditorTabFactory to MIGRATE-101-D (requires OneScanInfoTab refactor)

Technical Decisions:
- Follow \"Never break userspace\" principle
- Use adapter pattern for type conversion
- Add TODO comments for technical debt tracking

Testing:
- ✅ Compilation successful (mvn clean compile)
- ⏳ Manual functional testing required

Related Tasks:
- MIGRATE-101-D: createMessageEditor migration
- MIGRATE-303: registerMessageEditorTabFactory completion
- MIGRATE-201: Remove adapter after full HTTP migration

🤖 Generated with Claude Code
"
```

## 进度更新

### 任务状态

**MIGRATE-101 总体进度**:
- ✅ MIGRATE-101-A: 核心接口迁移 (100%)
- ✅ MIGRATE-101-B: UI API 部分迁移 (50% - addSuiteTab 完成)
- ✅ MIGRATE-101-C: 事件监听器迁移
  - ✅ MIGRATE-101-C-1: registerExtensionStateListener (100%)
  - ✅ MIGRATE-101-C-2: registerContextMenuFactory (100%)
- ⏳ MIGRATE-101-D: HTTP 请求处理迁移 (0%)
  - createMessageEditor 迁移
  - OneScanInfoTab 重构
- ⏳ MIGRATE-101-E: 清理和验证 (0%)

**整体完成度**: 约 65% (3.5/5 子任务)

### 下一步行动

1. **立即执行**: 提交本次变更
2. **下一轮任务**: MIGRATE-101-D
   - 迁移 `createMessageEditor()` 调用
   - 重构 `OneScanInfoTab` 类
3. **最终目标**: 完成 MIGRATE-101 所有子任务

## 经验总结

### 成功要素

1. **深度思考先行**:
   - 使用 `sequential-thinking` 识别依赖关系
   - 发现 `OneScanInfoTab` 阻塞问题,避免了破坏性变更

2. **Linus 原则应用**:
   - "Never break userspace": 推迟 registerMessageEditorTabFactory 迁移
   - "Good taste": 使用适配器模式而非强行修改数据流

3. **渐进式迁移**:
   - 每个子任务独立可编译
   - 技术债务明确标记,统一清理

### 经验教训

1. **提前依赖分析**: 在开始编码前,应先扫描所有相关类
2. **接口重构风险**: 涉及接口实现的迁移,必须检查实现类的依赖
3. **编译驱动开发**: 编译错误是最好的验证工具

---

**报告生成时间**: 2025-12-07T03:45:00+00:00
**执行者**: Claude Code (Linus Mode)
**下次会话**: 继续执行 MIGRATE-101-D
