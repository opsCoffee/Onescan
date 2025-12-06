# OneScan 项目 - Burp API 迁移映射表

**生成日期:** 2025-12-06
**项目:** OneScan
**目标:** 从传统 Burp Extender API 迁移到 Montoya API

---

## 执行摘要

本文档提供传统 Burp Extender API 到 Montoya API 的完整映射关系。基于 OneScan 项目的实际使用情况（见 `.agent/api_usage_report.md`），我们识别了 12 个需要迁移的传统接口，并为每个接口提供了对应的 Montoya API 替代方案。

**迁移复杂度评估:**
- **直接映射 (Low):** 5 个接口 - 简单的 1:1 替换
- **需要适配 (Medium):** 5 个接口 - 需要重构但逻辑相似
- **需要重构 (High):** 2 个接口 - API 模型变化较大

---

## 一、核心接口映射

### 1.1 IBurpExtender → BurpExtension

**迁移难度:** 🟢 Low

| 传统 API | Montoya API | 变化说明 |
|---------|------------|---------|
| `interface IBurpExtender` | `interface BurpExtension` | 接口重命名 |
| `void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)` | `void initialize(MontoyaApi api)` | 方法重命名，参数类型变化 |

**迁移示例:**

```java
// 传统 API
public class BurpExtender implements IBurpExtender {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("OneScan");
        // 初始化代码...
    }
}

// Montoya API
public class BurpExtender implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("OneScan");
        // 初始化代码...
    }
}
```

**关键差异:**
- 不再需要保存 `callbacks` 实例，直接使用 `MontoyaApi`
- `MontoyaApi` 提供模块化的服务访问方式（如 `api.http()`, `api.proxy()` 等）

---

### 1.2 IBurpExtenderCallbacks → MontoyaApi

**迁移难度:** 🟡 Medium

| 传统 API 方法 | Montoya API 等价物 | 调用位置 |
|-------------|------------------|---------|
| `getHelpers()` | `api.utilities()` | 全局 |
| `setExtensionName(String)` | `api.extension().setName(String)` | 初始化 |
| `getStdout()` | `api.logging().logToOutput(String)` | 日志 |
| `getStderr()` | `api.logging().logToError(String)` | 错误日志 |
| `registerMessageEditorTabFactory()` | `api.userInterface().registerHttpRequestEditorProvider()` | UI 注册 |
| `registerExtensionStateListener()` | `api.extension().registerUnloadingHandler()` | 生命周期 |
| `addSuiteTab()` | `api.userInterface().registerSuiteTab()` | UI 注册 |
| `createMessageEditor()` | `api.userInterface().createHttpRequestEditor()` | UI 创建 |
| `registerProxyListener()` | `api.proxy().registerRequestHandler()`<br>`api.proxy().registerResponseHandler()` | 代理监听 |
| `registerContextMenuFactory()` | `api.userInterface().registerContextMenuItemsProvider()` | 菜单注册 |
| `makeHttpRequest()` | `api.http().sendRequest()` | HTTP 请求 |
| `sendToRepeater()` | `api.repeater().sendToRepeater()` | 工具集成 |
| `unloadExtension()` | `api.extension().unload()` | 生命周期 |

**迁移示例:**

```java
// 传统 API - 注册代理监听器
callbacks.registerProxyListener(this);

// Montoya API - 分别注册请求和响应处理器
api.proxy().registerRequestHandler(new MyProxyRequestHandler(api));
api.proxy().registerResponseHandler(new MyProxyResponseHandler(api));
```

**关键差异:**
- Montoya API 采用模块化设计，通过 `api.xxx()` 访问不同服务
- 部分回调接口需要拆分（如代理监听器分为请求和响应两个处理器）
- 输出流方式改为直接调用日志方法

---

## 二、代理和 HTTP 处理

### 2.1 IProxyListener → ProxyRequestHandler + ProxyResponseHandler

**迁移难度:** 🟡 Medium

| 传统 API | Montoya API | 说明 |
|---------|------------|------|
| `IProxyListener` | `ProxyRequestHandler` + `ProxyResponseHandler` | 拆分为两个独立接口 |
| `void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message)` | `ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest)`<br>`ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse)` | 分别处理请求和响应 |

**迁移示例:**

```java
// 传统 API
public class BurpExtender implements IProxyListener {
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (!messageIsRequest) {  // 仅处理响应
            IHttpRequestResponse requestResponse = message.getMessageInfo();
            doScan(requestResponse);
        }
    }
}

// Montoya API
public class MyProxyResponseHandler implements ProxyResponseHandler {
    private final MontoyaApi api;

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        HttpRequestResponse requestResponse = interceptedResponse.messageReference();
        doScan(requestResponse);

        // 返回操作指令
        return ProxyResponseReceivedAction.continueWith(interceptedResponse.response());
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse.response());
    }
}
```

**关键差异:**
- 传统 API 使用 `boolean` 参数区分请求/响应，Montoya API 使用独立接口
- Montoya API 需要返回操作指令（继续/拦截/丢弃）
- 每个处理器有两个阶段：`Received` 和 `ToBeSent`

**注册方式对比:**

```java
// 传统 API
callbacks.registerProxyListener(this);

// Montoya API
api.proxy().registerResponseHandler(new MyProxyResponseHandler(api));
```

---

### 2.2 IHttpRequestResponse → HttpRequestResponse

**迁移难度:** 🟢 Low

| 传统 API 方法 | Montoya API 等价物 | 说明 |
|-------------|------------------|------|
| `byte[] getRequest()` | `HttpRequest request()` | 返回类型从 `byte[]` 改为 `HttpRequest` 对象 |
| `byte[] getResponse()` | `HttpResponse response()` | 返回类型从 `byte[]` 改为 `HttpResponse` 对象 |
| `IHttpService getHttpService()` | `HttpService httpService()` | 返回类型从接口改为类 |
| `void setRequest(byte[])` | 不支持直接修改 | 需要创建新的 `HttpRequestResponse` |
| `void setResponse(byte[])` | 不支持直接修改 | 需要创建新的 `HttpRequestResponse` |
| `String getComment()` | `String comment()` | 方法重命名 |
| `void setComment(String)` | `HttpRequestResponse withComment(String)` | 改为不可变对象，返回新实例 |
| `String getHighlight()` | `HighlightColor highlightColor()` | 返回类型变化 |
| `void setHighlight(String)` | `HttpRequestResponse withHighlightColor(HighlightColor)` | 改为不可变对象 |

**迁移示例:**

```java
// 传统 API
byte[] request = requestResponse.getRequest();
byte[] response = requestResponse.getResponse();
IHttpService service = requestResponse.getHttpService();

// Montoya API
HttpRequest request = requestResponse.request();
HttpResponse response = requestResponse.response();
HttpService service = requestResponse.httpService();
```

**关键差异:**
- Montoya API 使用强类型对象替代字节数组
- 采用不可变对象模式，修改需要创建新实例
- 方法命名遵循 JavaBeans 规范（去掉 `get` 前缀）

---

### 2.3 IExtensionHelpers → 多个专用服务

**迁移难度:** 🟡 Medium

| 传统 API 方法 | Montoya API 等价物 | 服务模块 |
|-------------|------------------|---------|
| `analyzeRequest(byte[])` | `HttpRequest.httpRequest(ByteArray)` | `api.http()` |
| `analyzeRequest(IHttpService, byte[])` | `HttpRequest.httpRequest(String)` | `api.http()` |
| `analyzeResponse(byte[])` | `HttpResponse.httpResponse(ByteArray)` | `api.http()` |
| `stringToBytes(String)` | `ByteArray.byteArray(String)` | `burp.api.montoya.core.ByteArray` |
| `bytesToString(byte[])` | `ByteArray.toString()` | `burp.api.montoya.core.ByteArray` |
| `urlEncode(String)` | `api.utilities().urlUtils().encode(String)` | `api.utilities()` |
| `urlDecode(String)` | `api.utilities().urlUtils().decode(String)` | `api.utilities()` |
| `base64Encode(byte[])` | `api.utilities().base64Utils().encodeToString(ByteArray)` | `api.utilities()` |
| `base64Decode(String)` | `api.utilities().base64Utils().decode(String)` | `api.utilities()` |

**迁移示例:**

```java
// 传统 API
IExtensionHelpers helpers = callbacks.getHelpers();
IRequestInfo requestInfo = helpers.analyzeRequest(request);
String method = requestInfo.getMethod();
List<String> headers = requestInfo.getHeaders();

// Montoya API
HttpRequest httpRequest = HttpRequest.httpRequest(ByteArray.byteArray(request));
String method = httpRequest.method();
List<HttpHeader> headers = httpRequest.headers();
```

**关键差异:**
- 传统 API 的 `IExtensionHelpers` 是一个大而全的工具类
- Montoya API 将功能拆分到多个专用服务：`Utilities`, `UrlUtils`, `Base64Utils` 等
- HTTP 请求/响应解析改为直接使用 `HttpRequest`/`HttpResponse` 静态工厂方法

---

### 2.4 IRequestInfo / IResponseInfo → HttpRequest / HttpResponse

**迁移难度:** 🟢 Low

| 传统 API (IRequestInfo) | Montoya API (HttpRequest) | 说明 |
|----------------------|-------------------------|------|
| `String getMethod()` | `String method()` | 方法重命名 |
| `List<String> getHeaders()` | `List<HttpHeader> headers()` | 返回类型变化 |
| `URL getUrl()` | `String url()` | 返回类型变化 |
| `int getBodyOffset()` | `int bodyOffset()` | 方法重命名 |
| `List<IParameter> getParameters()` | `List<ParsedHttpParameter> parameters()` | 返回类型变化 |

| 传统 API (IResponseInfo) | Montoya API (HttpResponse) | 说明 |
|------------------------|--------------------------|------|
| `short getStatusCode()` | `short statusCode()` | 方法重命名 |
| `List<String> getHeaders()` | `List<HttpHeader> headers()` | 返回类型变化 |
| `int getBodyOffset()` | `int bodyOffset()` | 方法重命名 |
| `List<ICookie> getCookies()` | `List<Cookie> cookies()` | 返回类型变化 |

**迁移示例:**

```java
// 传统 API
IRequestInfo requestInfo = helpers.analyzeRequest(request);
String method = requestInfo.getMethod();
URL url = requestInfo.getUrl();
List<String> headers = requestInfo.getHeaders();

// Montoya API
HttpRequest httpRequest = HttpRequest.httpRequest(request);
String method = httpRequest.method();
String url = httpRequest.url();
List<HttpHeader> headers = httpRequest.headers();
```

---

### 2.5 IHttpService → HttpService

**迁移难度:** 🟢 Low

| 传统 API 方法 | Montoya API 等价物 | 说明 |
|-------------|------------------|------|
| `String getHost()` | `String host()` | 方法重命名 |
| `int getPort()` | `int port()` | 方法重命名 |
| `String getProtocol()` | `boolean secure()` | 返回类型变化，`https` 对应 `true` |

**迁移示例:**

```java
// 传统 API
IHttpService service = requestResponse.getHttpService();
String host = service.getHost();
int port = service.getPort();
String protocol = service.getProtocol();  // "http" 或 "https"

// Montoya API
HttpService service = requestResponse.httpService();
String host = service.host();
int port = service.port();
boolean isSecure = service.secure();  // true 表示 https
```

---

## 三、用户界面组件

### 3.1 ITab → UserInterface.registerSuiteTab()

**迁移难度:** 🟢 Low

| 传统 API | Montoya API | 说明 |
|---------|------------|------|
| `interface ITab` | 不需要接口 | 直接注册组件 |
| `String getTabCaption()` | 参数化到注册方法 | 标题作为参数传递 |
| `Component getUiComponent()` | 参数化到注册方法 | 组件作为参数传递 |

**迁移示例:**

```java
// 传统 API
public class BurpExtender implements IBurpExtender, ITab {
    private JPanel mainPanel;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        mainPanel = new JPanel();
        callbacks.addSuiteTab(this);
    }

    @Override
    public String getTabCaption() {
        return "OneScan";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}

// Montoya API
public class BurpExtender implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        JPanel mainPanel = new JPanel();
        api.userInterface().registerSuiteTab("OneScan", mainPanel);
    }
}
```

**关键差异:**
- 不再需要实现 `ITab` 接口
- 标题和组件直接作为参数传递给注册方法
- 更简洁的 API 设计

---

### 3.2 IContextMenuFactory → ContextMenuItemsProvider

**迁移难度:** 🟡 Medium

| 传统 API | Montoya API | 说明 |
|---------|------------|------|
| `interface IContextMenuFactory` | `interface ContextMenuItemsProvider` | 接口重命名 |
| `List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)` | `List<Component> provideMenuItems(ContextMenuEvent event)` | 方法重命名，参数类型变化 |

**迁移示例:**

```java
// 传统 API
public class BurpExtender implements IContextMenuFactory {
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();

        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages != null && messages.length > 0) {
            JMenuItem item = new JMenuItem("发送到插件");
            item.addActionListener(e -> doScan(messages[0]));
            menuItems.add(item);
        }

        return menuItems;
    }
}

// Montoya API
public class MyContextMenuProvider implements ContextMenuItemsProvider {
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        List<HttpRequestResponse> messages = event.selectedRequestResponses();
        if (!messages.isEmpty()) {
            JMenuItem item = new JMenuItem("发送到插件");
            item.addActionListener(e -> doScan(messages.get(0)));
            menuItems.add(item);
        }

        return menuItems;
    }
}
```

**注册方式对比:**

```java
// 传统 API
callbacks.registerContextMenuFactory(this);

// Montoya API
api.userInterface().registerContextMenuItemsProvider(new MyContextMenuProvider());
```

**关键差异:**
- `IContextMenuInvocation` 改为 `ContextMenuEvent`
- `getSelectedMessages()` 改为 `selectedRequestResponses()`，返回类型从数组改为 `List`
- Montoya API 还支持 WebSocket 和 AuditIssue 的上下文菜单（通过方法重载）

---

### 3.3 IMessageEditorTabFactory + IMessageEditorTab → HttpRequestEditorProvider + HttpResponseEditorProvider

**迁移难度:** 🔴 High

**传统 API 架构:**
- `IMessageEditorTabFactory` - 工厂接口，创建编辑器标签实例
- `IMessageEditorTab` - 标签接口，提供编辑器功能
- `IMessageEditorController` - 控制器接口，提供数据访问

**Montoya API 架构:**
- `HttpRequestEditorProvider` - 请求编辑器提供者
- `HttpResponseEditorProvider` - 响应编辑器提供者
- `ExtensionProvidedHttpRequestEditor` - 请求编辑器实现
- `ExtensionProvidedHttpResponseEditor` - 响应编辑器实现

**映射关系:**

| 传统 API | Montoya API | 说明 |
|---------|------------|------|
| `IMessageEditorTabFactory.createNewInstance()` | `HttpResponseEditorProvider.provideHttpResponseEditor()` | 工厂方法重命名 |
| `IMessageEditorTab.getTabCaption()` | `ExtensionProvidedHttpResponseEditor.caption()` | 方法重命名 |
| `IMessageEditorTab.getUiComponent()` | `ExtensionProvidedHttpResponseEditor.uiComponent()` | 方法重命名 |
| `IMessageEditorTab.isEnabled()` | `ExtensionProvidedHttpResponseEditor.isEnabledFor()` | 方法重命名，参数变化 |
| `IMessageEditorTab.setMessage()` | `ExtensionProvidedHttpResponseEditor.setRequestResponse()` | 方法重命名 |
| `IMessageEditorTab.getMessage()` | `ExtensionProvidedHttpResponseEditor.getResponse()` | 方法重命名 |
| `IMessageEditorTab.isModified()` | `ExtensionProvidedHttpResponseEditor.isModified()` | 保持一致 |
| `IMessageEditorTab.getSelectedData()` | `ExtensionProvidedHttpResponseEditor.selectedData()` | 返回类型变化 |

**迁移示例 (OneScanInfoTab):**

```java
// 传统 API
public class BurpExtender implements IMessageEditorTabFactory {
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new OneScanInfoTab(callbacks, controller, editable);
    }
}

public class OneScanInfoTab implements IMessageEditorTab {
    private IMessageEditorController controller;
    private JTextArea textArea;

    @Override
    public String getTabCaption() {
        return "OneScan Info";
    }

    @Override
    public Component getUiComponent() {
        return textArea;
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return !isRequest;  // 仅对响应启用
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        if (!isRequest) {
            IResponseInfo responseInfo = helpers.analyzeResponse(content);
            textArea.setText(buildInfoText(responseInfo));
        }
    }
}

// Montoya API
public class MyResponseEditorProvider implements HttpResponseEditorProvider {
    private final MontoyaApi api;

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
        return new OneScanInfoEditor(api);
    }
}

public class OneScanInfoEditor implements ExtensionProvidedHttpResponseEditor {
    private final MontoyaApi api;
    private final JTextArea textArea;
    private HttpRequestResponse requestResponse;

    @Override
    public String caption() {
        return "OneScan Info";
    }

    @Override
    public Component uiComponent() {
        return textArea;
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        return requestResponse.response() != null;
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
        if (requestResponse.response() != null) {
            HttpResponse response = requestResponse.response();
            textArea.setText(buildInfoText(response));
        }
    }

    @Override
    public HttpResponse getResponse() {
        return requestResponse != null ? requestResponse.response() : null;
    }

    @Override
    public Selection selectedData() {
        // 返回选中的文本范围
        return null;
    }

    @Override
    public boolean isModified() {
        return false;
    }
}
```

**注册方式对比:**

```java
// 传统 API
callbacks.registerMessageEditorTabFactory(this);

// Montoya API
api.userInterface().registerHttpResponseEditorProvider(new MyResponseEditorProvider(api));
```

**关键差异:**
1. **拆分接口**: 传统 API 使用一个工厂接口 + 一个标签接口，Montoya API 分为请求编辑器和响应编辑器两套独立接口
2. **去除 Controller**: 传统 API 需要 `IMessageEditorController` 提供数据，Montoya API 直接通过 `setRequestResponse()` 传递完整数据
3. **类型安全**: 传统 API 使用 `byte[]` + `boolean isRequest`，Montoya API 使用强类型 `HttpRequest`/`HttpResponse`
4. **isEnabled 参数变化**: 传统 API 传递 `byte[] + boolean`，Montoya API 传递完整的 `HttpRequestResponse` 对象

---

### 3.4 IMessageEditorController → 不需要单独接口

**迁移难度:** 🟢 Low

| 传统 API | Montoya API | 说明 |
|---------|------------|------|
| `IMessageEditorController` | 不需要单独接口 | 数据通过 `setRequestResponse()` 传递 |
| `IHttpService getHttpService()` | 包含在 `HttpRequestResponse` 中 | - |
| `byte[] getRequest()` | `HttpRequestResponse.request()` | - |
| `byte[] getResponse()` | `HttpRequestResponse.response()` | - |

**关键差异:**
- 传统 API 需要实现 `IMessageEditorController` 接口来为编辑器提供数据
- Montoya API 直接将完整的 `HttpRequestResponse` 对象传递给编辑器，无需单独的控制器接口

---

## 四、扩展状态管理

### 4.1 IExtensionStateListener → Extension.registerUnloadingHandler()

**迁移难度:** 🟢 Low

| 传统 API | Montoya API | 说明 |
|---------|------------|------|
| `interface IExtensionStateListener` | `interface ExtensionUnloadingHandler` | 接口重命名 |
| `void extensionUnloaded()` | `void extensionUnloaded()` | 方法名保持一致 |

**迁移示例:**

```java
// 传统 API
public class BurpExtender implements IExtensionStateListener {
    @Override
    public void extensionUnloaded() {
        // 清理资源
        callbacks.removeProxyListener(this);
        callbacks.removeContextMenuFactory(this);
        // ...
    }
}

callbacks.registerExtensionStateListener(this);

// Montoya API
api.extension().registerUnloadingHandler(() -> {
    // 清理资源
    // 注意：Montoya API 的注册会返回 Registration 对象，可以通过 deregister() 取消注册
    // 但大多数情况下，插件卸载时 Burp 会自动清理所有注册
});
```

**关键差异:**
- Montoya API 支持使用 Lambda 表达式注册卸载处理器
- Montoya API 的所有注册方法返回 `Registration` 对象，可以手动取消注册

---

## 五、复杂场景映射

### 5.1 发起 HTTP 请求

**传统 API:**

```java
IHttpService service = requestResponse.getHttpService();
byte[] request = requestResponse.getRequest();

byte[] response = callbacks.makeHttpRequest(service, request);
```

**Montoya API:**

```java
HttpRequest request = requestResponse.request();

HttpRequestResponse response = api.http().sendRequest(request);
```

**关键差异:**
- 传统 API 需要分别传递 `IHttpService` 和 `byte[]`
- Montoya API 的 `HttpRequest` 对象已包含所有必要信息
- Montoya API 返回完整的 `HttpRequestResponse`，而不仅仅是响应字节数组

---

### 5.2 发送到 Repeater

**传统 API:**

```java
IHttpService service = requestResponse.getHttpService();
byte[] request = requestResponse.getRequest();
boolean useHttps = "https".equals(service.getProtocol());

callbacks.sendToRepeater(
    service.getHost(),
    service.getPort(),
    useHttps,
    request,
    "OneScan Tab"
);
```

**Montoya API:**

```java
api.repeater().sendToRepeater(
    requestResponse.request(),
    "OneScan Tab"
);
```

**关键差异:**
- Montoya API 大幅简化 API，不再需要单独传递主机、端口、协议
- `HttpRequest` 对象已包含所有必要信息

---

### 5.3 创建消息编辑器

**传统 API:**

```java
IMessageEditor requestEditor = callbacks.createMessageEditor(this, true);
IMessageEditor responseEditor = callbacks.createMessageEditor(this, false);

// 后续使用
requestEditor.setMessage(request, true);
responseEditor.setMessage(response, false);
```

**Montoya API:**

```java
HttpRequestEditor requestEditor = api.userInterface().createHttpRequestEditor();
HttpResponseEditor responseEditor = api.userInterface().createHttpResponseEditor();

// 后续使用
requestEditor.setRequest(HttpRequest.httpRequest(request));
responseEditor.setResponse(HttpResponse.httpResponse(response));
```

**关键差异:**
- Montoya API 分别创建请求编辑器和响应编辑器，类型安全
- 不再需要传递 `IMessageEditorController`
- 不再使用 `boolean` 参数区分请求/响应

---

### 5.4 构建 HTTP 请求

**传统 API:**

```java
IExtensionHelpers helpers = callbacks.getHelpers();

List<String> headers = new ArrayList<>();
headers.add("GET / HTTP/1.1");
headers.add("Host: example.com");
headers.add("User-Agent: OneScan");

byte[] request = helpers.buildHttpMessage(headers, null);
```

**Montoya API:**

```java
HttpRequest request = HttpRequest.httpRequest()
    .withService(HttpService.httpService("example.com", 443, true))
    .withPath("/")
    .withMethod("GET")
    .withHeader("User-Agent", "OneScan");
```

**关键差异:**
- Montoya API 使用 Builder 模式，更流畅的 API 设计
- 不再需要手工拼接 HTTP 首行和头部
- 类型安全，编译时错误检查

---

## 六、无直接对应的 API（需要特殊处理）

### 6.1 IParameter - 参数处理

**传统 API:**
```java
IRequestInfo requestInfo = helpers.analyzeRequest(request);
List<IParameter> parameters = requestInfo.getParameters();

for (IParameter param : parameters) {
    String name = param.getName();
    String value = param.getValue();
    byte type = param.getType();  // GET, POST, COOKIE, etc.
}
```

**Montoya API:**
```java
HttpRequest httpRequest = HttpRequest.httpRequest(request);
List<ParsedHttpParameter> parameters = httpRequest.parameters();

for (ParsedHttpParameter param : parameters) {
    String name = param.name();
    String value = param.value();
    HttpParameterType type = param.type();  // URL, BODY, COOKIE
}
```

**关键差异:**
- 参数类型从 `byte` 改为枚举 `HttpParameterType`
- 方法名遵循 JavaBeans 规范

---

### 6.2 IScannerCheck - 扫描器集成

**状态:** OneScan 项目未使用，暂不映射

**传统 API:** `IScannerCheck`
**Montoya API:** `Scanner.registerScanCheck()`

---

### 6.3 ICookie - Cookie 处理

**传统 API:**
```java
IResponseInfo responseInfo = helpers.analyzeResponse(response);
List<ICookie> cookies = responseInfo.getCookies();

for (ICookie cookie : cookies) {
    String name = cookie.getName();
    String value = cookie.getValue();
}
```

**Montoya API:**
```java
HttpResponse httpResponse = HttpResponse.httpResponse(response);
List<Cookie> cookies = httpResponse.cookies();

for (Cookie cookie : cookies) {
    String name = cookie.name();
    String value = cookie.value();
}
```

**关键差异:**
- 方法名遵循 JavaBeans 规范
- Montoya API 的 `Cookie` 对象提供更多属性（如 domain, path, expiry 等）

---

## 七、迁移优先级建议

基于 OneScan 项目的实际使用情况和 API 依赖关系，建议按以下顺序迁移：

### 阶段 0: API 分析（已完成）
- ✅ MIGRATE-001: 扫描传统 API 使用
- 🔄 MIGRATE-002: API 映射关系分析（当前任务）
- ⏳ MIGRATE-003: 依赖关系分析
- ⏳ MIGRATE-004: 生成迁移计划

### 阶段 1: 核心入口点迁移
1. **MIGRATE-101: BurpExtender 类迁移**
   - `IBurpExtender` → `BurpExtension`
   - `registerExtenderCallbacks()` → `initialize()`
   - **难度:** Low
   - **依赖:** 无
   - **影响:** 全局

2. **MIGRATE-102: 扩展上下文迁移**
   - `IBurpExtenderCallbacks` → `MontoyaApi`
   - 更新所有 `callbacks.xxx()` 调用为 `api.xxx()`
   - **难度:** Medium
   - **依赖:** MIGRATE-101
   - **影响:** 全局

### 阶段 2: HTTP 处理迁移
3. **MIGRATE-201: HTTP 监听器迁移**
   - `IProxyListener` → `ProxyRequestHandler + ProxyResponseHandler`
   - **难度:** Medium
   - **依赖:** MIGRATE-102
   - **影响:** 模块级

4. **MIGRATE-202: HTTP 消息处理**
   - `IHttpRequestResponse` → `HttpRequestResponse`
   - `IExtensionHelpers` → `Utilities` + `HttpRequest/Response`
   - **难度:** Medium
   - **依赖:** MIGRATE-201
   - **影响:** 模块级

### 阶段 3: UI 组件迁移
5. **MIGRATE-301: 标签页迁移**
   - `ITab` → `registerSuiteTab()`
   - **难度:** Low
   - **依赖:** MIGRATE-102
   - **影响:** 模块级

6. **MIGRATE-302: 上下文菜单迁移**
   - `IContextMenuFactory` → `ContextMenuItemsProvider`
   - **难度:** Medium
   - **依赖:** MIGRATE-301
   - **影响:** 模块级

7. **MIGRATE-303: 消息编辑器迁移**
   - `IMessageEditorTabFactory + IMessageEditorTab` → `HttpResponseEditorProvider`
   - **难度:** High
   - **依赖:** MIGRATE-302
   - **影响:** 模块级

### 阶段 4: 辅助功能迁移
8. **MIGRATE-401: 辅助工具类迁移**
   - `IExtensionHelpers` → 各个专用服务
   - **难度:** Medium
   - **依赖:** MIGRATE-102
   - **影响:** 全局

9. **MIGRATE-403: 日志和输出迁移**
   - `stdout/stderr` → `Logging` API
   - **难度:** Low
   - **依赖:** MIGRATE-102
   - **影响:** 全局

---

## 八、迁移风险点

### 8.1 不可变对象模式

**风险:** Montoya API 大量使用不可变对象，修改需要创建新实例

**影响范围:**
- `HttpRequest`
- `HttpResponse`
- `HttpRequestResponse`

**缓解措施:**
- 使用 Builder 模式或 `with*()` 方法创建修改后的副本
- 避免直接修改字节数组，使用高级 API

### 8.2 代理监听器拆分

**风险:** 传统 API 的 `IProxyListener` 使用一个方法处理请求和响应，Montoya API 拆分为两个独立接口

**影响范围:**
- BurpExtender.java:383-395

**缓解措施:**
- OneScan 项目仅处理响应，迁移到 `ProxyResponseHandler` 即可
- 如果未来需要处理请求，再注册 `ProxyRequestHandler`

### 8.3 消息编辑器架构变化

**风险:** `IMessageEditorTab` 迁移到 `ExtensionProvidedHttpResponseEditor` 涉及架构重构

**影响范围:**
- OneScanInfoTab.java (整个文件)

**缓解措施:**
- 保持业务逻辑不变，仅修改接口适配层
- 使用适配器模式过渡（可选）

### 8.4 线程安全

**风险:** Montoya API 的一些对象可能不是线程安全的

**影响范围:**
- UI 组件更新
- 并发 HTTP 请求

**缓解措施:**
- UI 更新使用 `SwingUtilities.invokeLater()`
- HTTP 请求处理使用 Montoya API 的线程池

---

## 九、常见陷阱和最佳实践

### 9.1 避免的陷阱

❌ **不要混用传统 API 和 Montoya API**
```java
// 错误示例
public class BurpExtender implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        // 不要这样做！
        IBurpExtenderCallbacks callbacks = ...; // 无法获取
    }
}
```

❌ **不要直接修改不可变对象**
```java
// 错误示例
HttpRequest request = ...;
request.setHeader("X-Custom", "value");  // 编译错误！

// 正确做法
HttpRequest modifiedRequest = request.withHeader("X-Custom", "value");
```

❌ **不要忘记返回操作指令**
```java
// 错误示例
public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
    doScan(response.messageReference());
    // 忘记返回！编译错误
}

// 正确做法
public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
    doScan(response.messageReference());
    return ProxyResponseReceivedAction.continueWith(response.response());
}
```

### 9.2 最佳实践

✅ **使用 Builder 模式构建 HTTP 消息**
```java
HttpRequest request = HttpRequest.httpRequest()
    .withService(HttpService.httpService("example.com", 443, true))
    .withPath("/api/v1/users")
    .withMethod("POST")
    .withHeader("Content-Type", "application/json")
    .withBody("{\"name\":\"test\"}");
```

✅ **使用强类型对象替代字节数组**
```java
// 好的做法
HttpResponse response = requestResponse.response();
short statusCode = response.statusCode();
List<HttpHeader> headers = response.headers();

// 避免
byte[] responseBytes = requestResponse.getResponse();  // 传统 API
```

✅ **保存 Registration 对象用于清理**
```java
private Registration proxyRegistration;

public void initialize(MontoyaApi api) {
    proxyRegistration = api.proxy().registerResponseHandler(new MyHandler(api));
}

public void cleanup() {
    if (proxyRegistration != null) {
        proxyRegistration.deregister();
    }
}
```

---

## 十、总结

### 10.1 迁移统计

| 接口类型 | 传统 API 数量 | Montoya API 数量 | 迁移难度 |
|---------|------------|----------------|---------|
| 核心入口 | 2 | 2 | Low |
| HTTP 处理 | 6 | 5 | Medium |
| UI 组件 | 4 | 3 | Medium-High |
| 辅助工具 | 3 | 多个专用服务 | Medium |
| 总计 | 15 | ~20 | - |

### 10.2 关键发现

1. **API 设计哲学变化:**
   - 传统 API: 大而全的接口，使用原始类型（`byte[]`, `boolean`）
   - Montoya API: 模块化设计，强类型对象，不可变对象模式

2. **最大改进:**
   - 类型安全：减少运行时错误
   - API 简化：减少样板代码
   - 模块化：更清晰的职责划分

3. **最大挑战:**
   - 消息编辑器架构重构（`IMessageEditorTab` → `ExtensionProvidedHttpResponseEditor`）
   - 代理监听器拆分（`IProxyListener` → 两个独立接口）
   - 不可变对象适应（需要使用 Builder 模式）

4. **迁移成本评估:**
   - **总体难度:** 中等
   - **预计工时:** 60-80 小时
   - **风险等级:** 中低（API 设计良好，文档完善）

---

## 附录 A: 快速参考表

| 我要做什么 | 传统 API | Montoya API |
|----------|---------|------------|
| 注册插件 | `implements IBurpExtender`<br>`registerExtenderCallbacks()` | `implements BurpExtension`<br>`initialize()` |
| 获取辅助工具 | `callbacks.getHelpers()` | `api.utilities()` |
| 解析 HTTP 请求 | `helpers.analyzeRequest(bytes)` | `HttpRequest.httpRequest(bytes)` |
| 解析 HTTP 响应 | `helpers.analyzeResponse(bytes)` | `HttpResponse.httpResponse(bytes)` |
| 发起 HTTP 请求 | `callbacks.makeHttpRequest(service, request)` | `api.http().sendRequest(request)` |
| 发送到 Repeater | `callbacks.sendToRepeater(host, port, useHttps, request, tab)` | `api.repeater().sendToRepeater(request, tab)` |
| 添加主标签页 | `callbacks.addSuiteTab(this)`<br>`implements ITab` | `api.userInterface().registerSuiteTab(title, component)` |
| 注册右键菜单 | `callbacks.registerContextMenuFactory(this)`<br>`implements IContextMenuFactory` | `api.userInterface().registerContextMenuItemsProvider(provider)` |
| 注册代理监听 | `callbacks.registerProxyListener(this)`<br>`implements IProxyListener` | `api.proxy().registerResponseHandler(handler)` |
| 创建消息编辑器 | `callbacks.createMessageEditor(controller, editable)` | `api.userInterface().createHttpResponseEditor()` |
| 输出日志 | `callbacks.getStdout().println()` | `api.logging().logToOutput()` |
| 输出错误 | `callbacks.getStderr().println()` | `api.logging().logToError()` |
| 设置插件名称 | `callbacks.setExtensionName()` | `api.extension().setName()` |
| 卸载处理 | `callbacks.registerExtensionStateListener(this)` | `api.extension().registerUnloadingHandler()` |

---

## 附录 B: 参考资料

- **Montoya API 官方文档:** https://portswigger.github.io/burp-extensions-montoya-api/
- **Montoya API 示例:** https://github.com/portswigger/burp-extensions-montoya-api-examples
- **OneScan API 使用报告:** `.agent/api_usage_report.md`
- **OneScan API 快速参考:** `.agent/api_quick_reference.md`

---

**文档版本:** 1.0
**最后更新:** 2025-12-06
**作者:** Claude (AI Agent)
