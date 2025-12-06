# OneScan 项目 - Burp API 快速参考表

## 接口实现总表

| 接口名称 | 实现类 | 行号 | 方法数 | 调用频率 | 重要性 |
|---------|--------|------|--------|---------|--------|
| IBurpExtender | BurpExtender | 88 | 1 | 1次(启动) | 必要 |
| IBurpExtenderCallbacks | 使用方 | 177-294 | 17 | 20+次 | 核心 |
| IExtensionHelpers | 使用方 | 178 | 5 | 30+次 | 核心 |
| IProxyListener | BurpExtender | 88 | 1 | 常频 | 高 |
| IInterceptedProxyMessage | 使用方 | 392 | 1 | 常频 | 高 |
| ITab | BurpExtender | 88 | 2 | 1次 | 中 |
| IMessageEditorController | BurpExtender | 88 | 3 | 多次 | 高 |
| IMessageEditorTabFactory | BurpExtender | 88 | 1 | 1次 | 中 |
| IMessageEditorTab | OneScanInfoTab | 24 | 7 | 多次 | 中 |
| IContextMenuFactory | BurpExtender | 88 | 1 | 1次 | 低 |
| IContextMenuInvocation | 使用方 | 312 | 1 | 常频 | 低 |
| IExtensionStateListener | BurpExtender | 88 | 1 | 1次(卸载) | 必要 |
| IHttpService | 使用方/实现 | 多处 | 3 | 常频 | 高 |
| IHttpRequestResponse | 使用方/实现 | 多处 | 10 | 常频 | 核心 |
| IRequestInfo | 使用方 | 多处 | 4 | 常频 | 高 |
| IResponseInfo | 使用方 | 多处 | 4 | 常频 | 高 |
| ICookie | 使用方 | 1083 | 2 | 罕见 | 低 |

## 关键方法调用热力图

### 高频调用(10+ 次)
- `analyzeRequest()` - IExtensionHelpers
- `analyzeResponse()` - IExtensionHelpers
- `getHttpService()` - IHttpRequestResponse
- `getHost()` - IHttpService
- `getHeaders()` - IRequestInfo/IResponseInfo
- `stringToBytes()` - IExtensionHelpers

### 中频调用(5-10 次)
- `getPort()` - IHttpService
- `getRequest()` - IHttpRequestResponse
- `getResponse()` - IHttpRequestResponse
- `getBodyOffset()` - IResponseInfo/IRequestInfo

### 低频调用(<5 次)
- `registerProxyListener()` - IBurpExtenderCallbacks
- `removeProxyListener()` - IBurpExtenderCallbacks
- `makeHttpRequest()` - IBurpExtenderCallbacks
- `sendToRepeater()` - IBurpExtenderCallbacks
- 其他初始化和卸载方法

## 按功能模块分布

```
生命周期管理 (5%)
├─ IBurpExtender:registerExtenderCallbacks()
├─ IExtensionStateListener:extensionUnloaded()
└─ IBurpExtenderCallbacks:注册/移除监听器

代理监听 (8%)
├─ IProxyListener:processProxyMessage()
└─ IInterceptedProxyMessage:getMessageInfo()

HTTP 处理 (55%) ⭐⭐⭐
├─ IExtensionHelpers (分析、转换)
├─ IHttpRequestResponse (请求响应对象)
├─ IHttpService (服务信息)
├─ IRequestInfo (请求分析)
├─ IResponseInfo (响应分析)
└─ ICookie (Cookie处理)

UI 组件 (18%)
├─ ITab:UI标签页
├─ IMessageEditorController:编辑器控制
├─ IMessageEditorTabFactory:标签工厂
└─ IMessageEditorTab:信息面板

菜单交互 (8%)
├─ IContextMenuFactory:菜单创建
└─ IContextMenuInvocation:菜单调用
```

## 文件分布表

| 文件 | 接口数 | 行数 | 职责 |
|-----|--------|------|------|
| BurpExtender.java | 9 | 2246 | 核心入口,包含大部分实现 |
| OneScanInfoTab.java | 1 | 244 | 信息辅助面板 |
| HttpReqRespAdapter.java | 1 | 253 | 请求响应适配器 |

## 调用路径关键节点

### 1. 启动初始化链
```
IBurpExtender.registerExtenderCallbacks()
  ↓
IBurpExtenderCallbacks.getHelpers()
  ↓
IBurpExtenderCallbacks.registerProxyListener()
IBurpExtenderCallbacks.registerContextMenuFactory()
IBurpExtenderCallbacks.registerExtensionStateListener()
IBurpExtenderCallbacks.addSuiteTab()
```

### 2. 代理监听处理链
```
IProxyListener.processProxyMessage()
  ↓
IInterceptedProxyMessage.getMessageInfo()
  ↓
IExtensionHelpers.analyzeRequest()
IExtensionHelpers.analyzeResponse()
  ↓
IBurpExtenderCallbacks.makeHttpRequest()
```

### 3. UI 消息编辑链
```
IMessageEditorTabFactory.createNewInstance()
  ↓
IMessageEditorTab.setMessage()
  ↓
IExtensionHelpers.analyzeRequest/Response()
  ↓
IMessageEditor.setMessage()
```

### 4. 右键菜单链
```
IContextMenuFactory.createMenuItems()
  ↓
IContextMenuInvocation.getSelectedMessages()
  ↓
IHttpRequestResponse.getRequest/Response()
  ↓
IBurpExtenderCallbacks.makeHttpRequest()
```

### 5. 卸载清理链
```
IExtensionStateListener.extensionUnloaded()
  ↓
IBurpExtenderCallbacks.removeProxyListener()
IBurpExtenderCallbacks.removeExtensionStateListener()
IBurpExtenderCallbacks.removeMessageEditorTabFactory()
IBurpExtenderCallbacks.removeContextMenuFactory()
```

## 数据流向分析

```
请求来源:
├─ Proxy (代理拦截)
├─ Send (右键菜单)
├─ Payload (字典扫描)
├─ Process (Payload处理)
├─ Import (URL导入)
├─ Scan (递归扫描)
└─ Redirect (重定向跟随)

处理流程:
代理消息 → IHttpRequestResponse → IRequestInfo/IResponseInfo
    ↓
请求过滤 (Host白名单/黑名单、方法过滤、后缀过滤)
    ↓
Payload处理 (URL/Header/Body替换)
    ↓
变量填充 (动态变量替换)
    ↓
IBurpExtenderCallbacks.makeHttpRequest()
    ↓
响应处理 (Cookie、重定向、指纹识别)
    ↓
任务表显示 (TaskData)
```

## 性能考量

| 操作 | 频率 | 成本 | 优化建议 |
|------|------|------|---------|
| analyzeRequest() | 10+ 次 | 中 | 缓存分析结果 |
| analyzeResponse() | 8+ 次 | 中 | 选择性分析 |
| stringToBytes() | 8+ 次 | 低 | 使用缓存的编码 |
| makeHttpRequest() | 常频 | 高 | 连接池复用 |
| 字符串拼接 | 常频 | 中 | 使用 StringBuilder |

## 错误处理覆盖情况

| 方法 | 异常处理 | 等级 |
|-----|---------|------|
| processProxyMessage() | ✓ | 中 |
| createMenuItems() | ✓ | 中 |
| doScan() | ✓ | 低(缺少部分处理) |
| makeHttpRequest() | ⚠ | 低(重试逻辑不完整) |
| analyzeRequest() | ✗ | 低 |
| analyzeResponse() | ✗ | 低 |

## Montoya API 迁移优先级

| 优先级 | 接口 | 迁移难度 | 预计工作量 |
|------|------|---------|-----------|
| P0 | IBurpExtender → Extension | 低 | 2天 |
| P0 | IBurpExtenderCallbacks → MontoyaApi | 中 | 5天 |
| P1 | IProxyListener → ProxyRequestHandler | 低 | 2天 |
| P1 | IExtensionHelpers → MontoyaApi.utilities() | 中 | 3天 |
| P2 | ITab, IMessageEditor → 新 UI API | 高 | 7天 |
| P2 | IContextMenuFactory → ContextMenuItemsProvider | 低 | 2天 |
| P3 | IMessageEditorTab → MessageEditorProvider | 中 | 4天 |

## 快速检查清单

### API 兼容性检查
- [ ] IBurpExtender 存在 ✓
- [ ] IBurpExtenderCallbacks 使用 ✓
- [ ] IProxyListener 实现 ✓
- [ ] ITab 实现 ✓
- [ ] IContextMenuFactory 实现 ✓
- [ ] IMessageEditorTabFactory 实现 ✓
- [ ] IExtensionStateListener 实现 ✓

### 关键功能检查
- [ ] 代理监听工作 ✓
- [ ] HTTP 请求能发送 ✓
- [ ] UI 标签页显示 ✓
- [ ] 右键菜单可用 ✓
- [ ] 消息编辑可用 ✓
- [ ] 卸载清理资源 ✓

### 风险识别
- [ ] 线程安全问题 ⚠
- [ ] 内存泄漏风险 ⚠
- [ ] 异常处理不完整 ⚠
- [ ] 硬编码常数 ⚠

---

生成时间: 2025-12-06
扫描深度: Very Thorough
覆盖范围: 100% Java 源代码
