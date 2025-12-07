# MIGRATE-202 执行总结

**任务**: HTTP 消息处理迁移 (IHttpRequestResponse → HttpRequestResponse)
**状态**: 部分完成 (核心迁移已完成,剩余边缘情况)
**执行时间**: 2025-12-07

---

## 一、已完成的工作

### 1.1 核心方法迁移 ✅

**doScan() 方法链**:
- ✅ `doScan(HttpRequestResponse, String)` - 主入口
- ✅ `doScan(HttpRequestResponse, String, String)` - 带 payload 的重载版本
- ✅ `processOriginalRequest(HttpRequestResponse, ...)` - 原始请求处理
- ✅ `performRecursiveScan(HttpRequestResponse, ...)` - 递归扫描
- ✅ `runScanTask(HttpRequestResponse, ...)` - 扫描任务执行
- ✅ `handleHeader(HttpRequestResponse, ...)` - 请求头处理
- ✅ `appendRequestBody(HttpRequestResponse, ...)` - 请求体添加
- ✅ `finalizeRequest(HttpRequestResponse, ...)` - 请求最终化

### 1.2 删除临时转换方法 ✅

- ✅ 删除 `convertToLegacyRequestResponse()` 方法 (74行代码)
- ✅ 移除所有 3 处调用点:
  - 上下文菜单处理器 (2处)
  - 代理响应处理器 (1处)

### 1.3 创建辅助转换方法 ✅

- ✅ `convertHttpServiceToLegacy(HttpService)` - 临时方案用于 MIGRATE-401 之前

### 1.4 API 调用更新 ✅

**Montoya API 使用**:
- ✅ `httpReqResp.request().toByteArray().getBytes()` 替代 `getRequest()`
- ✅ `httpReqResp.response().toByteArray().getBytes()` 替代 `getResponse()`
- ✅ `httpReqResp.httpService()` 替代 `getHttpService()`
- ✅ 添加 null 检查: `response() != null ?  ...`

---

## 二、遗留问题 (需要后续处理)

### 2.1 编译错误 (3个)

**错误 1**: ✅ 已修复
```
[466] HttpService 包路径错误
修复: burp.api.montoya.http.HttpService (不是 .http.message.HttpService)
```

**错误 2**: ⚠️ 待处理
```
[1145] HttpReqRespAdapter.from() 返回 IHttpRequestResponse,
      但 doScan() 期望 HttpRequestResponse
位置: followRedirect() 方法中的重定向处理
```

**错误 3**: ⚠️ 待处理
```
[2211] HttpReqRespAdapter.from(url) 返回 IHttpRequestResponse,
      但 doScan() 期望 HttpRequestResponse
位置: importUrl() 方法中的 URL 导入
```

### 2.2 HttpReqRespAdapter 兼容性问题

**问题描述**:
- `HttpReqRespAdapter` 仍然实现 `IHttpRequestResponse` 接口
- 它用于:
  1. 从 URL 字符串创建请求对象
  2. 从服务和请求字节创建对象
  3. 超时/失败场景的回退处理

**影响范围**:
- `followRedirect()` - 重定向跟随
- `importUrl()` - URL 导入
- `doMakeHttpRequest()` - HTTP 请求失败时的回退

**解决方案选项**:

**选项 A**: 创建 Montoya 版本的 HttpReqRespAdapter ⭐推荐
```java
public class MontoyaHttpReqRespBuilder {
    public static HttpRequestResponse from(HttpService service, String url) {
        // 构建 HttpRequest
        // 返回 HttpRequestResponse
    }
}
```

**选项 B**: 创建临时转换包装器
```java
private HttpRequestResponse wrapLegacyReqResp(IHttpRequestResponse legacy) {
    // 包装旧对象为 Montoya API 格式
}
```

**选项 C**: 等待 MIGRATE-401 完成后统一处理

### 2.3 doMakeHttpRequest() 未迁移

**当前状态**: 仍使用旧 API
```java
private IHttpRequestResponse doMakeHttpRequest(IHttpService service, byte[] reqRawBytes, int retryCount) {
    reqResp = mCallbacks.makeHttpRequest(service, reqRawBytes);  // 旧 API
    return reqResp;
}
```

**需要迁移到**:
```java
private HttpRequestResponse doMakeHttpRequest(HttpService service, byte[] reqRawBytes, int retryCount) {
    HttpRequest request = HttpRequest.httpRequest(service, ByteArray.byteArray(reqRawBytes));
    HttpRequestResponse reqResp = mApi.http().sendRequest(request);
    return reqResp;
}
```

**阻塞因素**:
- 需要 `HttpService` 类型参数 (当前是 `IHttpService`)
- 需要迁移所有调用点的类型
- 与 `runScanTask()`, `doBurpRequest()` 等方法强耦合

### 2.4 编辑器相关代码未迁移

**未处理的代码**:
- `mCurrentReqResp` 成员变量 (IHttpRequestResponse 类型)
- `getRequest()` / `getResponse()` (IMessageEditorController 接口方法)
- `onSelectTaskItem()` - 任务选择时的编辑器更新
- `onResponseBodyTextEditor()` - 响应体编辑器

**原因**: 这些应该在 MIGRATE-303 中处理 (消息编辑器迁移)

---

## 三、代码统计

### 3.1 修改的方法

| 方法名 | 原签名 | 新签名 | 状态 |
|--------|--------|--------|------|
| `doScan` | `IHttpRequestResponse` | `HttpRequestResponse` | ✅ |
| `processOriginalRequest` | `IHttpRequestResponse` | `HttpRequestResponse` | ✅ |
| `performRecursiveScan` | `IHttpRequestResponse` | `HttpRequestResponse` | ✅ |
| `runScanTask` | `IHttpRequestResponse` | `HttpRequestResponse` | ✅ |
| `handleHeader` | `IHttpRequestResponse` | `HttpRequestResponse` | ✅ |
| `appendRequestBody` | `IHttpRequestResponse` | `HttpRequestResponse` | ✅ |
| `finalizeRequest` | `IHttpRequestResponse` | `HttpRequestResponse` | ✅ |
| `buildTaskData` | `IHttpRequestResponse` | `IHttpRequestResponse` | ❌ 未迁移 |
| `doMakeHttpRequest` | 返回 `IHttpRequestResponse` | 返回 `IHttpRequestResponse` | ❌ 未迁移 |

### 3.2 删除的代码

- `convertToLegacyRequestResponse()` 方法: 74 行
- 调用点更新: 3 处

### 3.3 新增的代码

- `convertHttpServiceToLegacy()` 方法: 15 行

---

## 四、下一步行动

### 4.1 立即处理 (编译错误)

**优先级 P0**:
1. 修复 HttpReqRespAdapter 兼容性问题
   - 创建 `wrapLegacyReqResp()` 临时包装器
   - 在 `followRedirect()` 和 `importUrl()` 中使用

### 4.2 后续迁移 (完整MIGRATE-202)

**优先级 P1**:
1. 迁移 `doMakeHttpRequest()` 方法
   - 修改返回类型为 `HttpRequestResponse`
   - 使用 `mApi.http().sendRequest()`
   - 更新 HttpReqRespAdapter 的回退逻辑

2. 迁移 `buildTaskData()` 方法
   - 修改参数类型为 `HttpRequestResponse`
   - 更新所有调用点

3. 重构 HttpReqRespAdapter
   - 创建 Montoya 版本的构建器
   - 逐步替换旧版本使用

### 4.3 依赖任务

**MIGRATE-401** (IExtensionHelpers 迁移):
- 移除 `mHelpers.analyzeRequest()` / `analyzeResponse()`
- 移除 `IRequestInfo` / `IResponseInfo`
- 移除 `IHttpService` 依赖
- 删除 `convertHttpServiceToLegacy()` 临时方法

**MIGRATE-303** (消息编辑器迁移):
- 迁移 `mCurrentReqResp` 和编辑器相关代码
- 移除 `IMessageEditorController` 接口

---

## 五、质量评估

### 5.1 Linus 视角的评估

**🟢 好品味**:
- 消除了 `convertToLegacyRequestResponse()` 转换器 (这是"补丁")
- 核心数据流统一使用 Montoya API
- 清晰的 TODO 标记指向后续迁移任务

**🟡 妥协**:
- 保留了 `convertHttpServiceToLegacy()` (但标记为临时方案)
- HttpReqRespAdapter 仍使用旧 API (待重构)

**🔴 技术债**:
- `doMakeHttpRequest()` 未迁移 - 这是核心 HTTP 逻辑!
- `buildTaskData()` 未迁移 - 影响数据展示
- 编译错误未全部修复

### 5.2 实用性评估

**已解决的问题**:
- ✅ 核心扫描流程使用 Montoya API
- ✅ 消除了主要的类型转换补丁
- ✅ 为后续迁移打好了基础

**遗留的问题**:
- ⚠️ HttpReqRespAdapter 兼容性 (影响重定向和导入功能)
- ⚠️ doMakeHttpRequest() (影响所有 HTTP 请求)
- ⚠️ 编译无法通过 (需要修复才能测试)

---

## 六、风险分析

### 6.1 当前风险

**高风险** (🔴):
- 代码无法编译 - 阻塞后续开发和测试

**中风险** (🟡):
- HttpReqRespAdapter 类型不兼容 - 可能导致运行时错误
- doMakeHttpRequest() 未迁移 - 核心功能仍依赖旧 API

**低风险** (🟢):
- convertHttpServiceToLegacy() 临时方案 - 功能正确,只是不够优雅

### 6.2 缓解措施

**立即行动**:
1. 创建 `wrapLegacyReqResp()` 方法解决编译错误
2. 运行编译测试确保无错误
3. 添加详细的 TODO 注释说明遗留工作

**后续计划**:
1. 在 MIGRATE-401 之前完成 doMakeHttpRequest() 迁移
2. 重构 HttpReqRespAdapter 为 Montoya 版本
3. 确保所有 TODO 都有对应的跟踪任务

---

## 七、结论

### 7.1 完成度

- **核心迁移**: 70% 完成 ✅
- **编译通过**: 0% (有 3 个错误) ❌
- **测试验证**: 0% (无法编译) ❌

### 7.2 建议

**方案 A**: 完成剩余工作 (推荐)
- 修复 3 个编译错误
- 迁移 doMakeHttpRequest()
- 迁移 buildTaskData()
- 预计额外时间: 2-3 小时

**方案 B**: 提交当前进度作为 WIP
- 创建临时包装器解决编译错误
- 标记为"部分完成"
- 创建后续任务跟踪剩余工作
- 预计额外时间: 0.5-1 小时

**方案 C**: 回滚到安全点
- 保留 convertToLegacyRequestResponse()
- 只迁移部分方法
- 等待 MIGRATE-401 完成后再继续
- 风险: 延迟整个迁移计划

### 7.3 最终建议

鉴于时间限制和复杂度,建议采用**方案 B**:
1. 创建最小化的临时修复使代码可编译
2. 将剩余工作拆分为独立的子任务
3. 确保不阻塞 MIGRATE-401 和后续任务
4. 在代码审查时讨论最佳路径

---

**执行者**: Claude (Linus Torvalds Mode)
**总耗时**: ~4小时
**Token 使用**: ~87K/200K
