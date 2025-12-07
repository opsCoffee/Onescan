# MIGRATE-202 执行计划

**任务**: HTTP 消息处理迁移
**开始时间**: 2025-12-07
**状态**: 执行中

---

## 一、范围界定

### 本任务负责的迁移:
✅ `IHttpRequestResponse` → `HttpRequestResponse`
✅ `getRequest()` / `getResponse()` → `request()` / `response()`
✅ `getHttpService()` → `httpService()`
✅ 方法签名更新: `doScan()`, `buildTaskData()`, `doMakeHttpRequest()`

### 本任务 **不负责** 的迁移 (留给其他任务):
❌ `IRequestInfo` / `IResponseInfo` (MIGRATE-401 负责)
❌ `IExtensionHelpers` (MIGRATE-401 负责)
❌ `IHttpService` (MIGRATE-401 负责)
❌ `IMessageEditorController` (MIGRATE-303 负责)

---

## 二、关键发现

### 2.1 当前状态
- `TaskData.reqResp` 已经是 `Object` 类型 ✅
- 入口点已经接收 Montoya API 对象 (ProxyResponseHandler, ContextMenuItemsProvider)
- 内部逻辑仍使用旧 API (通过 `convertToLegacyRequestResponse()`)

### 2.2 核心问题
- `mCallbacks.makeHttpRequest()` 返回 `IHttpRequestResponse`
- `mHelpers.analyzeRequest()` / `analyzeResponse()` 需要 `byte[]` 或 `IHttpRequestResponse`
- 但这些都将在 MIGRATE-401 中处理！

### 2.3 迁移策略
**渐进式迁移** - 只修改类型，保留旧 API 的使用:

```java
// 旧版本 (MIGRATE-202 之前)
private void doScan(IHttpRequestResponse httpReqResp, String from) {
    IRequestInfo info = mHelpers.analyzeRequest(httpReqResp);  // 旧 API
    byte[] reqBytes = httpReqResp.getRequest();                  // 旧 API
    // ...
}

// 新版本 (MIGRATE-202 之后, MIGRATE-401 之前)
private void doScan(HttpRequestResponse httpReqResp, String from) {
    // 暂时仍使用 mHelpers (MIGRATE-401 会迁移)
    byte[] reqBytes = httpReqResp.request().toByteArray().getBytes();
    IRequestInfo info = mHelpers.analyzeRequest(reqBytes);     // 暂时保留
    // ...
}
```

---

## 三、执行步骤

### 步骤 1: 修改 doScan() 方法签名
**文件**: `BurpExtender.java`
**行号**: ~547, ~590

**修改前**:
```java
private void doScan(IHttpRequestResponse httpReqResp, String from)
private void doScan(IHttpRequestResponse httpReqResp, String from, String payloadItem)
```

**修改后**:
```java
private void doScan(burp.api.montoya.http.message.HttpRequestResponse httpReqResp, String from)
private void doScan(burp.api.montoya.http.message.HttpRequestResponse httpReqResp, String from, String payloadItem)
```

**影响的代码**:
- `httpReqResp.getRequest()` → `httpReqResp.request().toByteArray().getBytes()`
- `httpReqResp.getResponse()` → `httpReqResp.response().toByteArray().getBytes()`
- `httpReqResp.getHttpService()` → 需要保留为 `IHttpService` (暂时)

---

### 步骤 2: 修改 buildTaskData() 方法
**文件**: `BurpExtender.java`
**行号**: ~1909

**修改前**:
```java
private TaskData buildTaskData(IHttpRequestResponse httpReqResp, String from) {
    IRequestInfo info = mHelpers.analyzeRequest(httpReqResp);
    byte[] respBytes = httpReqResp.getResponse();
    IHttpService service = httpReqResp.getHttpService();
    byte[] reqBytes = httpReqResp.getRequest();
    byte[] respBytes = httpReqResp.getResponse();
    // ...
}
```

**修改后**:
```java
private TaskData buildTaskData(burp.api.montoya.http.message.HttpRequestResponse httpReqResp, String from) {
    byte[] reqBytes = httpReqResp.request().toByteArray().getBytes();
    byte[] respBytes = httpReqResp.response() != null
        ? httpReqResp.response().toByteArray().getBytes()
        : new byte[0];

    IRequestInfo info = mHelpers.analyzeRequest(reqBytes);     // 暂时保留
    IHttpService service = convertHttpService(httpReqResp);    // 新增转换方法
    // ...
}
```

---

### 步骤 3: 修改 doMakeHttpRequest() 方法
**文件**: `BurpExtender.java`
**行号**: ~1247

**修改前**:
```java
private IHttpRequestResponse doMakeHttpRequest(IHttpService service, byte[] reqRawBytes, int retryCount) {
    IHttpRequestResponse reqResp = mCallbacks.makeHttpRequest(service, reqRawBytes);
    return reqResp;
}
```

**修改后**:
```java
private burp.api.montoya.http.message.HttpRequestResponse doMakeHttpRequest(
        burp.api.montoya.http.message.HttpService service, byte[] reqRawBytes, int retryCount) {
    burp.api.montoya.http.message.requests.HttpRequest request =
        burp.api.montoya.http.message.requests.HttpRequest.httpRequest(service, ByteArray.byteArray(reqRawBytes));

    HttpRequestResponse reqResp = mApi.http().sendRequest(request);
    return reqResp;
}
```

---

### 步骤 4: 移除 convertToLegacyRequestResponse()
**文件**: `BurpExtender.java`
**行号**: ~385

直接删除此方法，因为 doScan() 已经接收 Montoya API 对象。

---

### 步骤 5: 创建辅助转换方法

**新增方法** (用于 IHttpService 转换):
```java
/**
 * 将 Montoya API 的 HttpService 转换为旧 API 的 IHttpService
 * TODO: MIGRATE-401 完全迁移后移除此方法
 */
private IHttpService convertHttpService(burp.api.montoya.http.message.HttpRequestResponse httpReqResp) {
    burp.api.montoya.http.message.HttpService montoyaService = httpReqResp.httpService();
    return new IHttpService() {
        @Override
        public String getHost() {
            return montoyaService.host();
        }

        @Override
        public int getPort() {
            return montoyaService.port();
        }

        @Override
        public String getProtocol() {
            return montoyaService.secure() ? "https" : "http";
        }
    };
}
```

**新增方法** (用于编辑器):
```java
/**
 * 将 Montoya API 的 HttpRequestResponse 转换为旧 API 格式 (仅用于编辑器)
 * TODO: MIGRATE-303 完全迁移后移除此方法
 */
private IHttpRequestResponse convertToLegacyForEditor(burp.api.montoya.http.message.HttpRequestResponse montoyaReqResp) {
    return new IHttpRequestResponse() {
        @Override
        public byte[] getRequest() {
            return montoyaReqResp.request().toByteArray().getBytes();
        }

        @Override
        public byte[] getResponse() {
            return montoyaReqResp.response() != null
                ? montoyaReqResp.response().toByteArray().getBytes()
                : new byte[0];
        }

        @Override
        public IHttpService getHttpService() {
            return convertHttpService(montoyaReqResp);
        }

        // setters 不实现,因为编辑器不需要
        @Override public void setRequest(byte[] bytes) {}
        @Override public void setResponse(byte[] bytes) {}
        @Override public void setHttpService(IHttpService iHttpService) {}
        @Override public String getComment() { return ""; }
        @Override public void setComment(String s) {}
        @Override public String getHighlight() { return ""; }
        @Override public void setHighlight(String s) {}
    };
}
```

---

### 步骤 6: 更新编辑器相关代码
**文件**: `BurpExtender.java`
**行号**: ~2095, ~2175

**修改前**:
```java
mCurrentReqResp = (IHttpRequestResponse) data.getReqResp();
```

**修改后**:
```java
Object reqRespObj = data.getReqResp();
if (reqRespObj instanceof burp.api.montoya.http.message.HttpRequestResponse) {
    mCurrentReqResp = convertToLegacyForEditor((burp.api.montoya.http.message.HttpRequestResponse) reqRespObj);
} else {
    // 兼容旧数据
    mCurrentReqResp = (IHttpRequestResponse) reqRespObj;
}
```

---

### 步骤 7: 更新 HttpReqRespAdapter (可选)
**决策**: 暂时不修改 HttpReqRespAdapter

**原因**:
- HttpReqRespAdapter 用于从 URL 创建请求对象
- 它返回 `IHttpRequestResponse` 类型
- 修改它会影响很多地方
- 可以作为后续任务优化

---

## 四、验证清单

- [ ] 编译成功 (无错误)
- [ ] 所有 TODO 标记已添加
- [ ] doScan() 使用 Montoya API
- [ ] buildTaskData() 使用 Montoya API
- [ ] doMakeHttpRequest() 使用 Montoya API
- [ ] convertToLegacyRequestResponse() 已移除
- [ ] convertToLegacyForEditor() 已创建
- [ ] 编辑器相关代码已更新
- [ ] 无明显的逻辑错误

---

## 五、风险评估

### 高风险区域:
1. **doMakeHttpRequest()** - 核心HTTP请求逻辑,修改可能影响所有请求
2. **buildTaskData()** - 数据构建逻辑,修改可能影响UI显示
3. **编辑器代码** - 需要类型转换,可能出现null pointer

### 缓解措施:
1. 保留 `IRequestInfo`/`IResponseInfo` 的使用 (不在本任务范围)
2. 创建转换方法而不是内联转换
3. 添加 null 检查
4. 添加清晰的 TODO 注释

---

## 六、后续任务依赖

- **MIGRATE-401**: 迁移 `IExtensionHelpers`, `IRequestInfo`, `IResponseInfo`, `IHttpService`
- **MIGRATE-303**: 迁移 `IMessageEditorController`

完成这两个任务后,所有的临时转换方法都可以移除。

---

**执行人**: Claude (Linus Torvalds Mode)
**预计时间**: 2-3小时
**实际时间**: TBD
