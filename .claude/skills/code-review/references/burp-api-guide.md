# Burp Suite API 使用指南

## API 版本

OneScan 项目使用两个 Burp Suite API：

- **Burp Extender API 2.3** - 传统 API
- **Montoya API 2025.5** - 新版 API（推荐）

## Montoya API 核心概念

### 1. 扩展初始化

```java
@BurpExtension
public class BurpExtender implements BurpExtension {
    
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("OneScan");
        
        // 注册 HTTP 处理器
        api.http().registerHttpHandler(new MyHttpHandler());
        
        // 注册 UI 组件
        api.userInterface().registerSuiteTab("OneScan", mainPanel);
        
        // 注册上下文菜单
        api.userInterface().registerContextMenuItemsProvider(
            new MyContextMenuProvider()
        );
    }
}
```

### 2. HTTP 请求处理

```java
public class MyHttpHandler implements HttpHandler {
    
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(
            HttpRequestToBeSent requestToBeSent) {
        
        // 获取请求信息
        String url = requestToBeSent.url();
        String method = requestToBeSent.method();
        List<HttpHeader> headers = requestToBeSent.headers();
        ByteArray body = requestToBeSent.body();
        
        // 修改请求
        HttpRequest modifiedRequest = requestToBeSent
            .withAddedHeader("X-Custom-Header", "value")
            .withBody("new body");
        
        // 继续发送修改后的请求
        return RequestToBeSentAction.continueWith(modifiedRequest);
        
        // 或者丢弃请求
        // return RequestToBeSentAction.drop();
    }
    
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(
            HttpResponseReceived responseReceived) {
        
        // 获取响应信息
        int statusCode = responseReceived.statusCode();
        List<HttpHeader> headers = responseReceived.headers();
        ByteArray body = responseReceived.body();
        
        // 分析响应
        analyzeResponse(responseReceived);
        
        // 继续处理响应
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}
```

### 3. 发送自定义请求

```java
// 构建请求
HttpRequest request = HttpRequest.httpRequest()
    .withService(HttpService.httpService("example.com", 443, true))
    .withPath("/api/endpoint")
    .withMethod("POST")
    .withAddedHeader("Content-Type", "application/json")
    .withBody("{\"key\":\"value\"}");

// 发送请求
HttpRequestResponse response = api.http().sendRequest(request);

// 处理响应
if (response.response() != null) {
    int statusCode = response.response().statusCode();
    String body = response.response().bodyToString();
}
```

### 4. UI 组件

```java
// 创建主面板
JPanel mainPanel = new JPanel(new BorderLayout());

// 注册为 Suite Tab
api.userInterface().registerSuiteTab("OneScan", mainPanel);

// 创建上下文菜单
api.userInterface().registerContextMenuItemsProvider(
    new ContextMenuItemsProvider() {
        @Override
        public List<Component> provideMenuItems(
                ContextMenuEvent event) {
            
            JMenuItem menuItem = new JMenuItem("Send to OneScan");
            menuItem.addActionListener(e -> {
                // 处理菜单点击
                List<HttpRequestResponse> items = 
                    event.messageEditorRequestResponse()
                        .map(Collections::singletonList)
                        .orElse(event.selectedRequestResponses());
                
                processItems(items);
            });
            
            return Collections.singletonList(menuItem);
        }
    }
);
```

### 5. 日志记录

```java
// 不同级别的日志
api.logging().logToOutput("Info message");
api.logging().logToError("Error message");

// 带异常的日志
try {
    // ...
} catch (Exception e) {
    api.logging().logToError("Operation failed: " + e.getMessage());
    api.logging().logToError(e);
}
```

### 6. 持久化数据

```java
// 保存扩展设置
api.persistence().extensionData().setString("config_key", "value");

// 读取扩展设置
String value = api.persistence().extensionData().getString("config_key");

// 保存项目级别数据
api.persistence().projectData().setString("project_key", "value");
```

## 线程安全注意事项

### UI 线程

```java
// ❌ 错误：在非 UI 线程更新 UI
new Thread(() -> {
    label.setText("Updated");  // 可能导致问题
}).start();

// ✅ 正确：使用 SwingUtilities
new Thread(() -> {
    SwingUtilities.invokeLater(() -> {
        label.setText("Updated");
    });
}).start();
```

### HTTP 处理器

```java
// HTTP 处理器在 Burp 的线程池中执行
// 必须确保线程安全

public class MyHttpHandler implements HttpHandler {
    
    // ❌ 错误：不安全的共享状态
    private List<String> results = new ArrayList<>();
    
    // ✅ 正确：使用并发集合
    private final List<String> results = new CopyOnWriteArrayList<>();
    
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(
            HttpRequestToBeSent request) {
        
        // 安全地添加结果
        results.add(request.url());
        
        return RequestToBeSentAction.continueWith(request);
    }
}
```

## 性能优化

### 1. 避免阻塞 HTTP 处理器

```java
// ❌ 错误：在处理器中执行耗时操作
@Override
public RequestToBeSentAction handleHttpRequestToBeSent(
        HttpRequestToBeSent request) {
    
    // 这会阻塞 Burp 的请求处理
    performExpensiveOperation(request);
    
    return RequestToBeSentAction.continueWith(request);
}

// ✅ 正确：异步处理
private final ExecutorService executor = Executors.newFixedThreadPool(4);

@Override
public RequestToBeSentAction handleHttpRequestToBeSent(
        HttpRequestToBeSent request) {
    
    // 异步处理，不阻塞
    executor.submit(() -> performExpensiveOperation(request));
    
    return RequestToBeSentAction.continueWith(request);
}
```

### 2. 批量处理

```java
// ❌ 错误：逐个发送请求
for (String url : urls) {
    HttpRequest request = buildRequest(url);
    api.http().sendRequest(request);
}

// ✅ 正确：使用线程池批量处理
ExecutorService executor = Executors.newFixedThreadPool(10);
List<Future<HttpRequestResponse>> futures = new ArrayList<>();

for (String url : urls) {
    Future<HttpRequestResponse> future = executor.submit(() -> {
        HttpRequest request = buildRequest(url);
        return api.http().sendRequest(request);
    });
    futures.add(future);
}

// 等待所有请求完成
for (Future<HttpRequestResponse> future : futures) {
    HttpRequestResponse response = future.get();
    processResponse(response);
}

executor.shutdown();
```

### 3. 缓存优化

```java
// 使用 LRU 缓存避免重复处理
private final Map<String, Result> cache = 
    Collections.synchronizedMap(new LinkedHashMap<String, Result>(
        100, 0.75f, true) {
        
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Result> eldest) {
            return size() > 100;  // 最多缓存 100 个
        }
    });

public Result process(String key) {
    Result cached = cache.get(key);
    if (cached != null) {
        return cached;
    }
    
    Result result = expensiveOperation(key);
    cache.put(key, result);
    return result;
}
```

## 常见问题

### 1. 扩展加载失败

**问题**: 扩展无法加载或加载后立即卸载

**可能原因**:
- 依赖库缺失或版本不兼容
- 初始化代码抛出异常
- 类加载器问题

**解决方案**:
```java
@Override
public void initialize(MontoyaApi api) {
    try {
        // 初始化代码
        initializeExtension(api);
        
        api.logging().logToOutput("OneScan loaded successfully");
    } catch (Exception e) {
        api.logging().logToError("Failed to initialize: " + e.getMessage());
        api.logging().logToError(e);
        // 不要重新抛出异常，否则扩展会被卸载
    }
}
```

### 2. UI 更新不生效

**问题**: 在后台线程更新 UI 组件，但界面没有变化

**解决方案**:
```java
// 始终在 EDT 线程更新 UI
SwingUtilities.invokeLater(() -> {
    tableModel.fireTableDataChanged();
    label.setText("Updated");
});
```

### 3. 内存泄漏

**问题**: 长时间运行后内存占用持续增长

**常见原因**:
- 缓存无限增长
- 监听器未注销
- 线程未正确关闭

**解决方案**:
```java
// 1. 限制缓存大小
private final Map<String, Result> cache = 
    new LRUCache<>(1000);  // 最多 1000 个

// 2. 注销监听器
@Override
public void extensionUnloaded() {
    // 清理资源
    executor.shutdown();
    cache.clear();
    // 注销监听器
}

// 3. 使用弱引用
private final Map<String, WeakReference<Result>> cache = 
    new ConcurrentHashMap<>();
```

## 最佳实践

1. **错误处理**: 始终捕获并记录异常
2. **线程安全**: 使用并发集合和同步机制
3. **资源管理**: 正确关闭线程池和连接
4. **性能优化**: 避免阻塞操作，使用异步处理
5. **日志记录**: 记录关键操作和错误信息
6. **UI 更新**: 使用 SwingUtilities.invokeLater
7. **内存管理**: 限制缓存大小，及时释放资源
