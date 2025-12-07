# MIGRATE-401-B: 重构 HttpReqRespAdapter - 执行总结

## 任务目标
将 IHttpRequestResponse 接口改为内部接口或移除,将 IHttpService 替换为 Montoya HttpService,更新适配器的构造方法和工厂方法,保持与现有代码的兼容性

## 执行状态: ⚠️ 部分完成 (阻塞于依赖)

## 已完成工作

### 1. HttpReqRespAdapter.java 重构 ✅
- ✅ 创建内部静态接口 `HttpReqRespAdapter.IHttpRequestResponse`
- ✅ 移除 `import burp.IHttpRequestResponse`
- ✅ 移除 `import burp.IHttpService`
- ✅ 将字段 `private IHttpService service` 改为 `private HttpService service`
- ✅ 更新所有工厂方法参数类型 (IHttpService → HttpService)
- ✅ 更新构造函数参数类型
- ✅ 更新 getter/setter 方法签名

### 2. BurpExtender.java 工具方法迁移 ✅
- ✅ `buildHttpServiceByURL(URL)` 改为返回 `burp.api.montoya.http.HttpService`
- ✅ 使用 `HttpService.httpService(host, port, secure)` 工厂方法
- ✅ 移除匿名类实现
- ✅ `getHostByHttpService()` 参数改为 Montoya HttpService
- ✅ `getReqHostByHttpService()` 参数改为 Montoya HttpService
- ✅ 更新方法内部调用 (getHost/getPort/getProtocol → host()/port()/secure())

### 3. BurpExtender.java 方法签名迁移 ✅
- ✅ `runEnableAndMergeTask()` - IHttpService → HttpService
- ✅ `runEnabledWithoutMergeProcessingTask()` - IHttpService → HttpService
- ✅ `doBurpRequest()` - IHttpService → HttpService
- ✅ `doMakeHttpRequest()` - IHttpService → HttpService, IHttpRequestResponse → HttpReqRespAdapter.IHttpRequestResponse
- ✅ `setupVariable()` - IHttpService → HttpService
- ✅ `prepareBasicVariables()` - IHttpService → HttpService
- ✅ `handlePayloadProcess()` - IHttpService → HttpService
- ✅ `buildTaskData()` - IHttpRequestResponse → HttpReqRespAdapter.IHttpRequestResponse

### 4. BurpExtender.java 类型引用更新 ✅
- ✅ 字段 `mCurrentReqResp` 类型改为 HttpReqRespAdapter.IHttpRequestResponse
- ✅ 所有局部变量 IHttpRequestResponse 改为 HttpReqRespAdapter.IHttpRequestResponse
- ✅ 移除 `convertHttpServiceToLegacy()` 调用 (Line 1020, 1547)

## ⚠️ 阻塞问题

### 编译错误根本原因
当前代码依然使用 **mCallbacks** 和 **mHelpers** (Burp 旧 API),这些 API 只接受旧类型:

1. **Line 1026**: `mHelpers.analyzeRequest(service, request)`
   - `mHelpers` 是 `IExtensionHelpers` 类型
   - `analyzeRequest()` 只接受 `IHttpService`,不接受 Montoya HttpService

2. **Line 1351**: `mCallbacks.makeHttpRequest(service, reqRawBytes)`
   - `mCallbacks` 是 `IBurpExtenderCallbacks` 类型  
   - `makeHttpRequest()` 只接受 `IHttpService`,不接受 Montoya HttpService

3. **Line 1278, 2006**: `mHelpers.analyzeRequest(httpReqResp)`
   - 只接受 `burp.IHttpRequestResponse`,不接受 `HttpReqRespAdapter.IHttpRequestResponse`

4. **Line 1909**: `mHelpers.analyzeRequest(service, requestBytes)`
   - 同样的 IHttpService 类型不匹配问题

5. **Line 2177, 2257**: `mCurrentReqResp = (IHttpRequestResponse) data.getReqResp()`
   - 类型不兼容

### 依赖关系
```
MIGRATE-401-B (当前)
  ↓ 阻塞于
MIGRATE-401-C (批量替换 IHttpService 使用)
  ↓ 需要先完成  
MIGRATE-201/202 (HTTP 处理迁移 - 替换 mCallbacks/mHelpers)
```

## 设计决策

### 为什么使用内部接口而不是完全移除?
根据 Linus "Never break userspace" 原则:
- TaskData.reqResp 字段类型是 `Object`,使用时强制转换为接口类型
- BurpExtender 中 11 处代码依赖此接口
- 完全移除接口会破坏所有调用点
- 创建内部静态接口 `HttpReqRespAdapter.IHttpRequestResponse` 可以:
  1. 避免与 Burp API 的 `burp.IHttpRequestResponse` 冲突
  2. 保持接口契约
  3. 使用 Montoya HttpService
  4. 渐进式迁移,最小化破坏

### 为什么不添加临时适配器?
- 根据 Linus "实用主义" 原则,临时适配器是技术债务
- MIGRATE-401-B 的目标是"重构 HttpReqRespAdapter",而不是"修复所有依赖"
- 应该让编译错误暴露真实的依赖关系,而不是用转换器掩盖
- 正确的顺序应该是: 先迁移 HTTP 处理 (MIGRATE-201/202) → 再替换 IHttpService (MIGRATE-401-C)

## 下一步行动

**选项 A: 暂停 MIGRATE-401-B,先完成前置任务** (推荐)
1. 回滚当前修改
2. 先完成 MIGRATE-201/202 (移除 mCallbacks/mHelpers)
3. 再重新执行 MIGRATE-401-B

**选项 B: 添加临时适配器继续** (技术债务)
1. 恢复 `convertHttpServiceToLegacy()` 方法
2. 在需要的地方添加类型转换
3. 标记 TODO,后续清理

## Linus 评价
> "This is exactly why you need to understand the dependency graph before you start refactoring. We hit the real blocker: mCallbacks and mHelpers. The right move is NOT to add more conversion layers - that's a band-aid. Either we fix the root cause (migrate those APIs first) or we wait. Don't pile hacks on top of hacks."

## 提交建议
鉴于当前状态无法编译,建议:
- 如果采用选项 A: 不提交,回滚修改
- 如果采用选项 B: 添加临时适配器后提交,标记为 "partial"

## 文件变更清单
- `src/main/java/burp/onescan/common/HttpReqRespAdapter.java` (完全迁移)
- `src/main/java/burp/BurpExtender.java` (部分迁移,有编译错误)
