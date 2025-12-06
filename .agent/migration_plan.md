# OneScan - Burp API 迁移执行计划

**生成日期:** 2025-12-06
**项目版本:** 2.2.0
**迁移目标:** 从 Burp Extender API 迁移到 Montoya API
**预计工时:** 46-48 小时

---

## 执行摘要

基于 API 使用情况分析、映射关系分析和依赖关系分析,本迁移计划采用**三层渐进式架构**,确保每个阶段完成后都能编译和运行。核心原则:**Never break userspace** - 每次提交后 `mvn compile` 必须成功,插件加载不能报错。

**关键发现:**
- **代码规模:** 2246 行核心代码依赖传统 API
- **主要接口:** 12 个传统 API 接口需要迁移
- **热点调用:** 100+ 处 API 调用位置
- **最大风险:** BurpExtender 主类是单点依赖

**迁移策略:**
```
Layer 0 (基础设施) → Layer 1 (独立模块) → Layer 2 (核心逻辑)
      串行执行              可部分并行              串行执行
      8 小时                6-8 小时                20 小时
```

---

## 一、迁移架构总览

### 1.1 三层架构设计

```
┌─────────────────────────────────────────────────┐
│ Layer 0: 基础设施层 (Infrastructure)             │
│ ┌─────────────────────────────────────────────┐ │
│ │ BurpExtender 主类                            │ │
│ │ - IBurpExtender → BurpExtension             │ │
│ │ - IBurpExtenderCallbacks → MontoyaApi       │ │
│ └─────────────────────────────────────────────┘ │
│ 提供全局 MontoyaApi 实例                         │
└─────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────┐
│ Layer 1: 独立模块层 (Independent)                │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│ │UI 组件   │ │工具类    │ │日志输出  │         │
│ │ITab      │ │Helpers   │ │stdout    │         │
│ └──────────┘ └──────────┘ └──────────┘         │
│ ┌──────────┐                                    │
│ │上下文菜单│ (依赖 UI 组件)                      │
│ └──────────┘                                    │
└─────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────┐
│ Layer 2: 核心逻辑层 (Core Logic)                 │
│ ┌─────────────────────────────────────────────┐ │
│ │ HTTP 处理 (doScan 核心逻辑)                  │ │
│ │ - IProxyListener → ProxyResponseHandler     │ │
│ │ - IHttpRequestResponse → HttpRequestResponse│ │
│ └─────────────────────────────────────────────┘ │
│ ┌─────────────────────────────────────────────┐ │
│ │ 消息编辑器 (OneScanInfoTab)                  │ │
│ │ - IMessageEditorTab → HttpResponseEditor    │ │
│ └─────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

### 1.2 关键约束

1. **每层独立验证:** 每层迁移完成后必须通过 `mvn compile` 和插件加载测试
2. **Git 分支隔离:** 每层在独立分支进行,合并前验证通过
3. **向后兼容:** 迁移过程中保持功能不变,不引入新特性
4. **可回滚:** 任何失败都能回滚到前一稳定状态

---

## 二、详细任务清单

### 阶段 0: API 使用情况分析 (已完成 ✅)

| 任务 ID | 任务名称 | 状态 | 完成时间 | 产出物 |
|---------|---------|------|---------|--------|
| MIGRATE-001 | 扫描传统 API 使用 | ✅ 完成 | 2025-12-06 | `.agent/api_usage_report.md` |
| MIGRATE-002 | API 映射关系分析 | ✅ 完成 | 2025-12-06 | `.agent/api_mapping.md` |
| MIGRATE-003 | 依赖关系分析 | ✅ 完成 | 2025-12-06 | `.agent/dependency_analysis.md` |
| MIGRATE-004 | 生成迁移计划 | 🔄 进行中 | 2025-12-06 | `.agent/migration_plan.md` (本文档) |

---

### 阶段 1: 基础设施层迁移 (Layer 0)

**目标:** 建立 Montoya API 基础,所有模块依赖的根基础设施

**Git 分支:** `migrate-layer0`

**验证标准:** `mvn compile` 成功 + 插件加载无报错 + 扩展名称显示正确

#### MIGRATE-101: BurpExtender 类迁移

**难度:** 🟡 Medium
**预计工时:** 4 小时
**依赖:** 无
**影响范围:** 全局

**迁移内容:**
```java
// 传统 API
public class BurpExtender implements IBurpExtender {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // ...
    }
}

// Montoya API
public class BurpExtender implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        // ...
    }
}
```

**关键步骤:**
1. 修改类声明: `implements IBurpExtender` → `implements BurpExtension`
2. 重命名方法: `registerExtenderCallbacks()` → `initialize()`
3. 修改参数类型: `IBurpExtenderCallbacks callbacks` → `MontoyaApi api`
4. 保存 `api` 实例为成员变量: `this.api = api;`

**验证清单:**
- [ ] 编译成功
- [ ] 插件加载成功
- [ ] `initialize()` 方法被调用

---

#### MIGRATE-102: 扩展上下文迁移

**难度:** 🟡 Medium
**预计工时:** 4 小时
**依赖:** MIGRATE-101
**影响范围:** 全局

**迁移内容:** 更新所有 `callbacks.xxx()` 调用为 `api.xxx()`

| 传统 API | Montoya API | 位置 |
|---------|------------|------|
| `callbacks.setExtensionName("OneScan")` | `api.extension().setName("OneScan")` | BurpExtender:234 |
| `callbacks.getStdout()` | `api.logging().logToOutput()` | BurpExtender:236 |
| `callbacks.getStderr()` | `api.logging().logToError()` | BurpExtender:236 |
| `callbacks.getHelpers()` | `api.utilities()` | BurpExtender:227 |
| `callbacks.addSuiteTab(this)` | `api.userInterface().registerSuiteTab()` | BurpExtender:280 |
| `callbacks.createMessageEditor()` | `api.userInterface().createHttpRequestEditor()` | BurpExtender:282-283 |
| `callbacks.registerProxyListener(this)` | `api.proxy().registerResponseHandler()` | BurpExtender:290 |
| `callbacks.registerContextMenuFactory(this)` | `api.userInterface().registerContextMenuItemsProvider()` | BurpExtender:292 |
| `callbacks.registerExtensionStateListener(this)` | `api.extension().registerUnloadingHandler()` | BurpExtender:246 |
| `callbacks.makeHttpRequest()` | `api.http().sendRequest()` | BurpExtender:1110 |
| `callbacks.sendToRepeater()` | `api.repeater().sendToRepeater()` | BurpExtender:2018 |
| `callbacks.unloadExtension()` | `api.extension().unload()` | BurpExtender:2070 |

**关键步骤:**
1. 使用 IDE 的 "Find Usages" 功能找到所有 `callbacks` 调用
2. 逐个替换为对应的 Montoya API 调用
3. 保存所有返回的 `Registration` 对象用于清理

**验证清单:**
- [ ] 编译成功
- [ ] 插件名称显示为 "OneScan"
- [ ] 无 `callbacks` 引用残留 (使用 `grep -r "callbacks\." src/`)

---

### 阶段 2: 独立模块层迁移 (Layer 1)

**目标:** 迁移相对独立的功能模块,这些模块可以部分并行处理

**Git 分支:** `migrate-layer1` (基于 `migrate-layer0`)

**验证标准:** 所有 UI 功能正常 + 工具方法可用 + 日志输出正常

#### MIGRATE-301: 标签页迁移

**难度:** 🟢 Low
**预计工时:** 6 小时
**依赖:** MIGRATE-102
**影响范围:** 模块级 (UI)
**可并行任务:** MIGRATE-401, MIGRATE-403

**迁移内容:**
```java
// 传统 API
public class BurpExtender implements ITab {
    @Override
    public String getTabCaption() {
        return "OneScan";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}
callbacks.addSuiteTab(this);

// Montoya API
api.userInterface().registerSuiteTab("OneScan", mainPanel);
```

**关键步骤:**
1. 移除 `implements ITab` 声明
2. 删除 `getTabCaption()` 和 `getUiComponent()` 方法
3. 修改注册调用: `callbacks.addSuiteTab(this)` → `api.userInterface().registerSuiteTab("OneScan", mainPanel)`

**验证清单:**
- [ ] 编译成功
- [ ] "OneScan" 标签页显示
- [ ] 标签页内容正常

---

#### MIGRATE-401: 辅助工具类迁移

**难度:** 🟡 Medium
**预计工时:** 6 小时
**依赖:** MIGRATE-102
**影响范围:** 全局 (30+ 处调用)
**可并行任务:** MIGRATE-301, MIGRATE-403

**迁移内容:** 替换 `IExtensionHelpers` 的所有调用

| 传统 API | Montoya API | 影响位置 |
|---------|------------|---------|
| `helpers.analyzeRequest(byte[])` | `HttpRequest.httpRequest(ByteArray)` | 10+ 处 |
| `helpers.analyzeResponse(byte[])` | `HttpResponse.httpResponse(ByteArray)` | 8+ 处 |
| `helpers.stringToBytes(String)` | `ByteArray.byteArray(String)` | 8+ 处 |
| `helpers.bytesToString(byte[])` | `ByteArray.toString()` | 1 处 |

**关键步骤:**
1. 删除 `IExtensionHelpers helpers = callbacks.getHelpers();` 初始化
2. 替换所有 `helpers.analyzeRequest()` 调用
3. 替换所有 `helpers.analyzeResponse()` 调用
4. 替换所有字符串/字节数组转换调用
5. 同步更新 OneScanInfoTab.java 中的调用

**验证清单:**
- [ ] 编译成功
- [ ] HTTP 请求解析正常
- [ ] HTTP 响应解析正常
- [ ] 字符串转换功能正常
- [ ] 无 `helpers.` 引用残留

---

#### MIGRATE-403: 日志和输出迁移

**难度:** 🟢 Low
**预计工时:** 2 小时
**依赖:** MIGRATE-102
**影响范围:** 全局
**可并行任务:** MIGRATE-301, MIGRATE-401

**迁移内容:**
```java
// 传统 API
PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
stdout.println("OneScan loaded");
stderr.println("Error occurred");

// Montoya API
api.logging().logToOutput("OneScan loaded");
api.logging().logToError("Error occurred");
```

**关键步骤:**
1. 删除 `PrintWriter stdout/stderr` 成员变量
2. 替换所有 `stdout.println()` 为 `api.logging().logToOutput()`
3. 替换所有 `stderr.println()` 为 `api.logging().logToError()`

**验证清单:**
- [ ] 编译成功
- [ ] 控制台日志正常输出
- [ ] 错误日志正常输出

---

#### MIGRATE-302: 上下文菜单迁移

**难度:** 🟡 Medium
**预计工时:** 6 小时
**依赖:** MIGRATE-301
**影响范围:** 模块级 (UI)

**迁移内容:**
```java
// 传统 API
public class BurpExtender implements IContextMenuFactory {
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        // ...
    }
}

// Montoya API
public class MyContextMenuProvider implements ContextMenuItemsProvider {
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> messages = event.selectedRequestResponses();
        // ...
    }
}
api.userInterface().registerContextMenuItemsProvider(new MyContextMenuProvider());
```

**关键步骤:**
1. 创建新的 `MyContextMenuProvider` 类实现 `ContextMenuItemsProvider`
2. 迁移 `createMenuItems()` 逻辑到 `provideMenuItems()`
3. 修改数组访问为 List 访问
4. 更新注册方式

**验证清单:**
- [ ] 编译成功
- [ ] 右键菜单 "发送到插件" 显示
- [ ] 菜单点击功能正常
- [ ] Payload 动态菜单显示

---

### 阶段 3: 核心逻辑层迁移 (Layer 2)

**目标:** 迁移核心业务逻辑,完成最复杂的 API 适配

**Git 分支:** `migrate-layer2` (基于 `migrate-layer1`)

**验证标准:** 核心扫描功能正常 + 消息编辑器正常

#### MIGRATE-201: HTTP 监听器迁移

**难度:** 🟡 Medium
**预计工时:** 6 小时
**依赖:** MIGRATE-102
**影响范围:** 模块级 (HTTP 处理)

**迁移内容:**
```java
// 传统 API
public class BurpExtender implements IProxyListener {
    @Override
    public void processProxyMessage(boolean messageIsRequest,
                                    IInterceptedProxyMessage message) {
        if (!messageIsRequest) {
            doScan(message.getMessageInfo());
        }
    }
}

// Montoya API
public class MyProxyResponseHandler implements ProxyResponseHandler {
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(
            InterceptedResponse interceptedResponse) {
        doScan(interceptedResponse.messageReference());
        return ProxyResponseReceivedAction.continueWith(
            interceptedResponse.response());
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(
            InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(
            interceptedResponse.response());
    }
}
```

**关键步骤:**
1. 创建新的 `MyProxyResponseHandler` 类
2. 实现 `handleResponseReceived()` 和 `handleResponseToBeSent()` 方法
3. 迁移 `processProxyMessage()` 的响应处理逻辑
4. 更新注册方式

**验证清单:**
- [ ] 编译成功
- [ ] 代理监听器捕获响应
- [ ] doScan 方法被正确调用
- [ ] 代理流量正常通过

---

#### MIGRATE-202: HTTP 消息处理

**难度:** 🟡 Medium
**预计工时:** 6 小时
**依赖:** MIGRATE-201
**影响范围:** 模块级 (HTTP 处理)

**迁移内容:** 替换所有 `IHttpRequestResponse` 使用

| 传统 API | Montoya API |
|---------|------------|
| `byte[] request = requestResponse.getRequest()` | `HttpRequest request = requestResponse.request()` |
| `byte[] response = requestResponse.getResponse()` | `HttpResponse response = requestResponse.response()` |
| `IHttpService service = requestResponse.getHttpService()` | `HttpService service = requestResponse.httpService()` |
| `requestResponse.setRequest(bytes)` | 使用 Builder 创建新实例 |
| `requestResponse.setResponse(bytes)` | 使用 Builder 创建新实例 |

**关键步骤:**
1. 替换 doScan 方法中的 `IHttpRequestResponse` 参数类型
2. 更新所有 `getRequest()`/`getResponse()` 调用
3. 更新 `IRequestInfo`/`IResponseInfo` 解析逻辑
4. 更新 HttpReqRespAdapter 类 (如果保留)

**验证清单:**
- [ ] 编译成功
- [ ] HTTP 请求解析正常
- [ ] HTTP 响应解析正常
- [ ] 扫描逻辑正常执行

---

#### MIGRATE-203: 代理监听器清理 (可选)

**难度:** 🟢 Low
**预计工时:** 4 小时
**依赖:** MIGRATE-202
**影响范围:** 模块级

**迁移内容:** 移除代理监听器注册/注销相关的传统 API 调用

**验证清单:**
- [ ] 编译成功
- [ ] 代理监听功能正常

---

#### MIGRATE-303: 消息编辑器迁移

**难度:** 🔴 High
**预计工时:** 8 小时
**依赖:** MIGRATE-302, MIGRATE-401
**影响范围:** 模块级 (UI)

**迁移内容:**
```java
// 传统 API
public class BurpExtender implements IMessageEditorTabFactory {
    @Override
    public IMessageEditorTab createNewInstance(
            IMessageEditorController controller, boolean editable) {
        return new OneScanInfoTab(callbacks, controller, editable);
    }
}

public class OneScanInfoTab implements IMessageEditorTab {
    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        // ...
    }
}

// Montoya API
public class MyResponseEditorProvider implements HttpResponseEditorProvider {
    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(
            EditorCreationContext creationContext) {
        return new OneScanInfoEditor(api);
    }
}

public class OneScanInfoEditor implements ExtensionProvidedHttpResponseEditor {
    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        // ...
    }
}
```

**关键步骤:**
1. 创建新的 `MyResponseEditorProvider` 类
2. 重构 `OneScanInfoTab` 为 `OneScanInfoEditor`
3. 替换 `IMessageEditorTab` 接口为 `ExtensionProvidedHttpResponseEditor`
4. 更新方法签名和逻辑
5. 更新注册方式

**验证清单:**
- [ ] 编译成功
- [ ] "OneScan Info" 标签页显示
- [ ] 标签页内容正确显示
- [ ] 仅对响应启用

---

### 阶段 4: 测试和验证 (Layer 3)

**目标:** 全面测试迁移结果,确保功能完整性

**Git 分支:** `migrate-layer2` → `main`

#### MIGRATE-501: 功能测试

**难度:** 🟡 Medium
**预计工时:** 6 小时
**依赖:** MIGRATE-403
**产出物:** `.agent/test_report.md`

**测试清单:**
- [ ] 插件加载/卸载
- [ ] 主标签页 UI
- [ ] 代理监听和扫描
- [ ] 右键菜单
- [ ] OneScan Info 标签页
- [ ] 发送到 Repeater
- [ ] 日志输出

---

#### MIGRATE-502: 兼容性测试

**难度:** 🟡 Medium
**预计工时:** 4 小时
**依赖:** MIGRATE-501
**产出物:** `.agent/compatibility_report.md`

**测试清单:**
- [ ] Burp Suite 2023.1+
- [ ] Burp Suite Professional
- [ ] Burp Suite Community Edition

---

#### MIGRATE-503: 清理工作

**难度:** 🟢 Low
**预计工时:** 2 小时
**依赖:** MIGRATE-502

**清理清单:**
- [ ] 移除 pom.xml 中的 burp-extender-api 依赖
- [ ] 删除未使用的适配器类
- [ ] 更新代码注释
- [ ] 运行代码格式化

---

## 三、风险管理

### 3.1 高风险点和缓解措施

| 风险 | 影响 | 概率 | 缓解措施 |
|-----|------|------|---------|
| BurpExtender 主类迁移失败 | 全局崩溃 | 低 | 在独立分支操作,逐步迁移每个 callbacks 调用 |
| IExtensionHelpers 密集使用 (30+处) | 大量代码需修改 | 中 | 使用 IDE "Find Usages",创建临时适配器 |
| OneScanInfoTab 架构变化 | 消息编辑器失效 | 中 | 保持业务逻辑不变,仅修改接口层 |
| 代理监听器拆分 | 流量拦截逻辑重构 | 低 | OneScan 仅处理响应,逻辑简单 |
| 不可变对象适应 | HTTP 消息修改代码重写 | 低 | 使用 Builder 模式,避免直接操作字节数组 |

### 3.2 回滚策略

如果某阶段迁移失败:

1. **Git 分支策略:**
   - 每阶段在独立分支进行
   - 失败时回滚到前一稳定分支
   - 分支命名: `migrate-layer0`, `migrate-layer1`, `migrate-layer2`

2. **验证失败处理:**
   - 编译失败: 立即回滚最后一次修改
   - 功能失败: 检查日志,定位问题,修复后重新验证
   - 无法修复: 回滚整个阶段,重新规划

---

## 四、执行时间表

### 4.1 预计时间分配

| 阶段 | 任务数 | 串行工时 | 并行工时 (实际) | 关键产出 |
|-----|-------|---------|----------------|---------|
| 阶段 0 (分析) | 4 | 已完成 | 已完成 | 本文档 |
| 阶段 1 (基础设施) | 2 | 8 小时 | 8 小时 | MontoyaApi 就绪 |
| 阶段 2 (独立模块) | 4 | 20 小时 | 6-8 小时 | UI + 工具类就绪 |
| 阶段 3 (核心逻辑) | 4 | 24 小时 | 20 小时 | 核心功能就绪 |
| 阶段 4 (测试清理) | 3 | 12 小时 | 12 小时 | 迁移完成 |
| **总计** | **17** | **64 小时** | **46-48 小时** | **Montoya 版本** |

### 4.2 里程碑

| 里程碑 | 完成标志 | 验证方式 | 目标日期 |
|-------|---------|---------|---------|
| 分析完成 | MIGRATE-004 完成 | 本文档生成 | 2025-12-06 |
| 基础设施就绪 | MIGRATE-102 完成 | `mvn compile` + 插件加载 | 2025-12-07 |
| UI 层可用 | MIGRATE-302 完成 | 标签页显示 + 菜单可点击 | 2025-12-09 |
| 核心功能就绪 | MIGRATE-202 完成 | doScan 正常扫描 | 2025-12-11 |
| 全部迁移完成 | MIGRATE-503 完成 | pom.xml 移除传统 API | 2025-12-15 |

---

## 五、验证和测试

### 5.1 每阶段验证清单

**阶段 1 验证 (Layer 0):**
```bash
# 1. 编译检查
mvn clean compile

# 2. 插件加载检查
java -jar burpsuite_pro.jar
# 手动加载插件,查看控制台输出

# 3. 基础功能检查
- 插件名称显示为 "OneScan"
- 扩展卸载处理器注册成功
- 无错误日志
```

**阶段 2 验证 (Layer 1):**
```bash
# 1. 编译检查
mvn clean compile

# 2. UI 功能检查
- "OneScan" 标签页显示
- 右键菜单 "发送到插件" 出现
- 控制台日志正常输出

# 3. 工具类检查
- HTTP 请求解析正常
- 字符串/字节数组转换正常
```

**阶段 3 验证 (Layer 2):**
```bash
# 1. 编译检查
mvn clean compile

# 2. 核心功能检查
- 代理监听器捕获流量
- doScan 方法正常执行
- OneScan Info 标签页显示内容

# 3. 集成测试
- 使用真实流量测试扫描功能
- 验证与 Repeater 的集成
```

### 5.2 测试用例 (MIGRATE-501)

| 测试场景 | 操作步骤 | 预期结果 |
|---------|---------|---------|
| 插件加载 | 启动 Burp,加载插件 | 无错误,显示 "OneScan" 标签页 |
| 代理扫描 | 开启代理,访问测试站点 | 捕获响应并执行扫描 |
| 右键菜单 | 在 Proxy History 中右键 | 显示 "发送到插件" 菜单 |
| 消息编辑器 | 查看响应的 OneScan Info 标签 | 显示解析后的信息 |
| 发送到 Repeater | 点击菜单项 | 请求发送到 Repeater |
| 插件卸载 | 卸载插件 | 清理所有资源,无错误 |

---

## 六、快速参考

### 6.1 关键 API 映射速查表

| 我要做什么 | 传统 API | Montoya API |
|----------|---------|------------|
| 注册插件 | `implements IBurpExtender`<br>`registerExtenderCallbacks()` | `implements BurpExtension`<br>`initialize()` |
| 获取辅助工具 | `callbacks.getHelpers()` | `api.utilities()` |
| 解析 HTTP 请求 | `helpers.analyzeRequest(bytes)` | `HttpRequest.httpRequest(bytes)` |
| 解析 HTTP 响应 | `helpers.analyzeResponse(bytes)` | `HttpResponse.httpResponse(bytes)` |
| 发起 HTTP 请求 | `callbacks.makeHttpRequest(service, request)` | `api.http().sendRequest(request)` |
| 添加主标签页 | `callbacks.addSuiteTab(this)` | `api.userInterface().registerSuiteTab(title, component)` |
| 注册代理监听 | `callbacks.registerProxyListener(this)` | `api.proxy().registerResponseHandler(handler)` |
| 输出日志 | `callbacks.getStdout().println()` | `api.logging().logToOutput()` |

### 6.2 常见陷阱

❌ **不要混用传统 API 和 Montoya API**
❌ **不要直接修改不可变对象**
❌ **不要忘记返回操作指令 (ProxyResponseReceivedAction)**
✅ **使用 Builder 模式构建 HTTP 消息**
✅ **使用强类型对象替代字节数组**
✅ **保存 Registration 对象用于清理**

---

## 七、下一步行动

### 7.1 立即执行

1. ✅ 创建 `.agent/migration_plan.md` (本文档)
2. ⏳ 更新 `.agent/task_status.json` 标记 MIGRATE-004 完成
3. ⏳ 更新 `prompt.md` 勾选 MIGRATE-004
4. ⏳ 提交 Git commit: `feat(migrate): 完成 MIGRATE-004 迁移计划生成`
5. ⏳ 创建 Git 分支: `git checkout -b migrate-layer0`
6. ⏳ 开始 MIGRATE-101: BurpExtender 类迁移

### 7.2 优先级排序

1. ⭐⭐⭐⭐⭐ MIGRATE-101/102 (基础设施,必须最先)
2. ⭐⭐⭐⭐ MIGRATE-401 (工具类,影响范围大)
3. ⭐⭐⭐⭐ MIGRATE-201/202 (HTTP 处理,核心功能)
4. ⭐⭐⭐ MIGRATE-301/302 (UI 组件,用户体验)
5. ⭐⭐⭐ MIGRATE-303 (消息编辑器,复杂但非必需)
6. ⭐⭐ MIGRATE-403 (日志输出,简单)

### 7.3 可选降级策略

- 如果时间紧张,MIGRATE-303 (OneScan Info 标签页) 可以暂时跳过
- 如果遇到技术难题,可以先迁移其他任务,积累经验后再回头处理
- 如果某个任务多次失败,可以跳过,在 task_status.json 中标记为 `skipped`

---

## 附录 A: 文件清单

**输入文件:**
- `.agent/api_usage_report.md` - API 使用情况分析
- `.agent/api_mapping.md` - API 映射关系
- `.agent/dependency_analysis.md` - 依赖关系分析

**输出文件:**
- `.agent/migration_plan.md` - 本文档
- `.agent/task_status.json` - 任务状态跟踪
- `prompt.md` - 任务清单 (人类可读)

**参考文件:**
- `.agent/api_quick_reference.md` - API 快速参考
- `.agent/burp_api_usage.csv` - API 使用统计
- `.agent/scan_summary.txt` - 扫描摘要

---

## 附录 B: 参考资料

- **Montoya API 官方文档:** https://portswigger.github.io/burp-extensions-montoya-api/
- **Montoya API 示例:** https://github.com/portswigger/burp-extensions-montoya-api-examples
- **Java 17 文档:** https://docs.oracle.com/en/java/javase/17/
- **Burp Suite 文档:** https://portswigger.net/burp/documentation

---

**文档版本:** 1.0
**最后更新:** 2025-12-06
**作者:** Claude (AI Agent)
**下一步:** 开始 MIGRATE-101 (BurpExtender 类迁移)
