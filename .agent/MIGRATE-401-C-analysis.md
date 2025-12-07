# MIGRATE-401-C 迁移分析

## 任务目标

批量替换 `IHttpService` 为 `HttpService`,移除所有 `convertHttpServiceToLegacy()` 调用,将剩余的旧 API 迁移到 Montoya API。

## 当前状态分析

### 1. mHelpers 使用情况 (13处)

#### 1.1 analyzeRequest() - 5处

| 行号 | 代码 | 上下文 | 迁移策略 |
|------|------|--------|----------|
| 691 | `mHelpers.analyzeRequest(requestBytes)` | ProxyResponseHandler | 使用 `HttpRequest.httpRequest(ByteArray.byteArray(requestBytes))` |
| 1027 | `mHelpers.analyzeRequest(convertHttpServiceToLegacy(service), request)` | runEnableAndMergeTask | 使用 `HttpRequest.httpRequest(ByteArray.byteArray(request))` |
| 1280 | `mHelpers.analyzeRequest(reqResp.getRequest())` | handleFollowRedirect | 已有 Montoya API `montoyaReqResp.request()`,直接使用 |
| 1919 | `mHelpers.analyzeRequest(convertHttpServiceToLegacy(service), requestBytes)` | buildTaskData | 使用 `HttpRequest.httpRequest(ByteArray.byteArray(requestBytes))` |
| 2017 | `mHelpers.analyzeRequest(httpReqResp.getRequest())` | prepareBasicVariables | 使用 `httpReqResp.request()` (已是 Montoya 类型) |

**迁移要点**:
- `IRequestInfo` → `HttpRequest`
- `info.getMethod()` → `request.method()`
- `info.getUrl()` → `request.url()`
- `info.getHeaders()` → `request.headers()`
- `info.getBodyOffset()` → `request.bodyOffset()`

#### 1.2 analyzeResponse() - 3处

| 行号 | 代码 | 上下文 | 迁移策略 |
|------|------|--------|----------|
| 1265 | `mHelpers.analyzeResponse(reqResp.getResponse())` | handleFollowRedirect | 使用 `HttpResponse.httpResponse(ByteArray.byteArray(reqResp.getResponse()))` |
| 2030 | `mHelpers.analyzeResponse(respBytes)` | prepareBasicVariables | 使用 `HttpResponse.httpResponse(ByteArray.byteArray(respBytes))` |
| 2274 | `mCallbacks.getHelpers().analyzeResponse(respBytes)` | getStatusCodeByResponse | 使用 `HttpResponse.httpResponse(ByteArray.byteArray(respBytes))` |

**迁移要点**:
- `IResponseInfo` → `HttpResponse`
- `info.getStatusCode()` → `response.statusCode()`
- `info.getHeaders()` → `response.headers()`
- `info.getBodyOffset()` → `response.bodyOffset()`

#### 1.3 stringToBytes() / bytesToString() - 5处

| 行号 | 代码 | 迁移方案 |
|------|------|----------|
| 1562 | `mHelpers.stringToBytes(processedRequest)` | `processedRequest.getBytes(StandardCharsets.UTF_8)` |
| 1925 | `mHelpers.bytesToString(requestBytes)` | `new String(requestBytes, StandardCharsets.UTF_8)` |
| 1974 | `mHelpers.stringToBytes(newRequest)` | `newRequest.getBytes(StandardCharsets.UTF_8)` |
| 2191 | `mHelpers.stringToBytes(L.get("message_editor_loading"))` | `L.get("message_editor_loading").getBytes(StandardCharsets.UTF_8)` |
| 2229 | `mHelpers.stringToBytes(hint)` | `hint.getBytes(StandardCharsets.UTF_8)` |
| 2233 | `mHelpers.stringToBytes(hint)` | `hint.getBytes(StandardCharsets.UTF_8)` |

### 2. mCallbacks 使用情况 (5处)

| 行号 | 代码 | 迁移方案 |
|------|------|----------|
| 1354 | `mCallbacks.makeHttpRequest(convertHttpServiceToLegacy(service), reqRawBytes)` | `api.http().sendRequest(HttpRequest.httpRequest(service, ByteArray.byteArray(reqRawBytes)))` |
| 2257 | `mCallbacks.sendToRepeater(host, port, useHttps, reqBytes, null)` | `api.repeater().sendToRepeater(host, port, useHttps, ByteArray.byteArray(reqBytes))` |
| 2274 | `mCallbacks.getHelpers().analyzeResponse(respBytes)` | 同 mHelpers.analyzeResponse() |
| 2309 | `mCallbacks.unloadExtension()` | **保留** - 生命周期方法,无对应 Montoya API |
| 2438 | `mCallbacks.removeMessageEditorTabFactory(this)` | **删除** - MIGRATE-303-D 已移除 MessageEditorTabFactory |

### 3. convertHttpServiceToLegacy() 调用 (6处)

所有调用点都将在上述迁移中被移除:
- Line 1027: runEnableAndMergeTask
- Line 1287: handleFollowRedirect
- Line 1292: handleFollowRedirect
- Line 1354: doMakeHttpRequest
- Line 1919: buildTaskData
- Line 2156: getHttpService (IMessageEditorController)

### 4. 方法定义

- Line 469-486: `convertHttpServiceToLegacy()` 方法 - **删除**

## 迁移策略

### 阶段1: 字符串转换 (低风险)
替换所有 `stringToBytes()` / `bytesToString()` 为标准 Java API。

### 阶段2: 请求/响应分析 (中等风险)
替换所有 `analyzeRequest()` / `analyzeResponse()` 为 Montoya API。

### 阶段3: HTTP 请求 (高风险)
替换 `makeHttpRequest()` 为 `api.http().sendRequest()`。

### 阶段4: 清理 (低风险)
- 移除 `convertHttpServiceToLegacy()` 方法
- 移除 `mCallbacks.removeMessageEditorTabFactory()` 调用
- 删除不再使用的导入

## 风险评估

### 高风险点

1. **makeHttpRequest() 迁移** (Line 1354)
   - 旧API: 返回 `IHttpRequestResponse`
   - 新API: `sendRequest()` 返回 `HttpRequestResponse`
   - 影响: `doMakeHttpRequest()` 方法的返回值类型
   - 缓解: 已有 `HttpReqRespAdapter` 适配器

2. **IRequestInfo/IResponseInfo 属性差异**
   - 可能存在方法名不一致的情况
   - 需要逐个验证替换的正确性

### 中等风险点

1. **getHttpService() 返回值** (Line 2156)
   - IMessageEditorController 接口要求返回 `burp.IHttpService`
   - 但此接口已标记为 TODO,可能需要保留转换逻辑

### 低风险点

1. 字符串编码转换 - Montoya API 默认使用 UTF-8,与旧 API 一致
2. ByteArray 包装 - Montoya API 提供 `ByteArray.byteArray()` 工厂方法

## 验证计划

1. **编译验证**: `mvn compile`
2. **方法级验证**: 每修改一个方法,立即编译检查
3. **类型检查**: 确认所有 Legacy API 类型已移除
4. **TODO 标记**: 确认所有 MIGRATE-401-C 标记已清除

## 预期成果

- ✅ 移除所有 mHelpers.analyzeRequest/Response 调用 (8处)
- ✅ 移除所有 mHelpers.stringToBytes/bytesToString 调用 (5处)
- ✅ 移除 mCallbacks.makeHttpRequest 调用 (1处)
- ✅ 移除 mCallbacks.sendToRepeater 调用 (1处)
- ✅ 移除 mCallbacks.getHelpers() 调用 (1处)
- ✅ 删除 convertHttpServiceToLegacy() 方法定义
- ✅ 移除所有 TODO: MIGRATE-401-C 标记 (6处)
- ✅ 编译通过
