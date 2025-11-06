# Montoya 迁移映射笔记

## 传统 API 使用点

- `burp/BurpExtender.java`
  - 接口实现：`IBurpExtender`, `IProxyListener`, `IMessageEditorController`, `ITab`, `IMessageEditorTabFactory`, `IExtensionStateListener`, `IContextMenuFactory`
  - 字段：`IBurpExtenderCallbacks`, `IExtensionHelpers`, `IMessageEditor`, `IHttpRequestResponse`
  - 方法：`registerExtenderCallbacks`, `createMenuItems`, `processProxyMessage`, 多处 `IHttpRequestResponse` 构建与处理
  - 注册：`addSuiteTab`, `createMessageEditor`, `registerProxyListener`, `registerContextMenuFactory`, `registerMessageEditorTabFactory`, `registerExtensionStateListener`

- `burp/onescan/info/OneScanInfoTab.java`
  - 接口：`IMessageEditorTab`
  - 依赖：`IExtensionHelpers`, `IMessageEditorController`, `IRequestInfo`, `IResponseInfo`

- `burp/onescan/common/HttpReqRespAdapter.java`
  - 类型：`IHttpRequestResponse`, `IHttpService`

## Montoya 目标替换

- 插件入口
  - 旧：`IBurpExtender#registerExtenderCallbacks(IBurpExtenderCallbacks)`
  - 新：`BurpExtension#initialize(MontoyaApi)`
  - 字段替换：`IBurpExtenderCallbacks` → `MontoyaApi`，`IExtensionHelpers` → 使用 `montoya.utilities()`/相关子 API

- HTTP 请求/响应
  - 旧：`callbacks.makeHttpRequest(IHttpService, byte[])` 返回 `IHttpRequestResponse`
  - 新：`montoya.http().sendRequest(HttpRequest)` 返回 `HttpRequestResponse`
  - 构建：`HttpRequest.httpRequestFromUrl(String)`；响应体：`response.response().toByteArray()`

- 消息编辑器
  - 旧：`callbacks.createMessageEditor(controller, editable)` 返回 `IMessageEditor`
  - 新：`montoya.userInterface().createHttpRequestEditor()` / `createHttpResponseEditor()` 返回 `MessageEditor`

- Suite Tab
  - 旧：`callbacks.addSuiteTab(ITab)`
  - 新：`montoya.userInterface().registerSuiteTab(SuiteTab)`

- 上下文菜单
  - 旧：`IContextMenuFactory` + `registerContextMenuFactory`
  - 新：`ContextMenuItemsProvider` + `montoya.userInterface().registerContextMenuItemsProvider(...)`

- 代理监听器
  - 旧：`IProxyListener#processProxyMessage(...)` + `registerProxyListener`
  - 新：`ProxyResponseHandler#handleResponseReceived(...)` + `montoya.proxy().registerResponseHandler(...)`

- 日志
  - 旧：`callbacks.printOutput/printError`
  - 新：`montoya.logging().logToOutput/logToError`

## 备注

- 编译器驱动迁移：先替换入口类为 `BurpExtension`，编译错误会指示所有旧 API 使用点。
- 零拷贝原则：尽量使用 Montoya 提供的 `ByteArray` 与类型而非 `byte[]` 中转。
