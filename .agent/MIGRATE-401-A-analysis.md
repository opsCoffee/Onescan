# MIGRATE-401-A: IHttpService 迁移分析和规划

## 执行摘要

**任务**: 统计 IHttpService 的所有使用位置,分析每个使用场景的迁移策略
**扫描日期**: 2025-12-07
**扫描结果**: 33 处引用 (包括导入、注释、方法签名、实例化等)

## 1. 使用统计

### 1.1 文件级别分布

| 文件 | 引用次数 | 类型 |
|------|---------|------|
| `burp/onescan/common/HttpReqRespAdapter.java` | 8 | 适配器类 (核心) |
| `burp/BurpExtender.java` | 25 | 插件主类 |

### 1.2 使用场景分类

#### HttpReqRespAdapter.java (8 处)

| 行号 | 类型 | 代码 | 复杂度 |
|------|------|------|--------|
| 5 | import | `import burp.IHttpService;` | 简单 |
| 22 | 字段 | `private IHttpService service;` | **核心** |
| 37 | 方法调用 | `IHttpService service = BurpExtender.buildHttpServiceByURL(u);` | 简单 |
| 46 | 参数 | `public static HttpReqRespAdapter from(IHttpService service, ...)` | 简单 |
| 83 | 参数 | `public static HttpReqRespAdapter from(IHttpService service, byte[] requestBytes)` | 简单 |
| 171 | 参数 | `private HttpReqRespAdapter(IHttpService service, byte[] requestBytes)` | 简单 |
| 244 | 返回值 | `public IHttpService getHttpService()` | **接口方法** |
| 249 | 参数 | `public void setHttpService(IHttpService iHttpService)` | **接口方法** |

#### BurpExtender.java (25 处)

| 行号 | 类型 | 代码 | 复杂度 |
|------|------|------|--------|
| 466 | 注释 | `将 Montoya API 的 HttpService 转换为旧 API 的 IHttpService` | 文档 |
| 469 | 方法签名 | `private IHttpService convertHttpServiceToLegacy(...)` | **转换工具** |
| 470 | 匿名类 | `return new IHttpService() { ... }` | 简单 |
| 541 | 参数 | `IHttpService service, String urlOrPqf, ...` | 简单 |
| 1019 | 注释 | `TODO: MIGRATE-401 - 将 IHttpService 迁移到 HttpService` | 标记 |
| 1020 | 赋值 | `IHttpService service = convertHttpServiceToLegacy(...)` | 简单 |
| 1094 | 参数 | `private void runEnableAndMergeTask(IHttpService service, ...)` | 简单 |
| 1128 | 参数 | `private void runEnabledWithoutMergeProcessingTask(IHttpService service, ...)` | 简单 |
| 1155 | 参数 | `private void doBurpRequest(IHttpService service, ...)` | 简单 |
| 1285 | 赋值 | `IHttpService service = reqResp.getHttpService();` | 简单 |
| 1290 | 赋值 | `IHttpService service = buildHttpServiceByURL(redirectUrl);` | 简单 |
| 1344 | 参数 | `private IHttpRequestResponse doMakeHttpRequest(IHttpService service, ...)` | 简单 |
| 1546 | 注释 | `TODO: MIGRATE-401 - 将 IHttpService 迁移到 HttpService` | 标记 |
| 1547 | 赋值 | `IHttpService service = convertHttpServiceToLegacy(...)` | 简单 |
| 1614 | 参数 | `private String setupVariable(IHttpService service, ...)` | 简单 |
| 1654 | 参数 | `private VariableContext prepareBasicVariables(IHttpService service, ...)` | 简单 |
| 1907 | 参数 | `private byte[] handlePayloadProcess(IHttpService service, ...)` | 简单 |
| 2012 | 赋值 | `IHttpService service = httpReqResp.getHttpService();` | 简单 |
| 2047 | 注释 | `通过 IHttpService 实例，获取请求的 Host 地址` | 文档 |
| 2049 | 参数注释 | `@param service IHttpService 实例` | 文档 |
| 2052 | 参数 | `private String getReqHostByHttpService(IHttpService service)` | **工具方法** |
| 2063 | 注释 | `通过 IHttpService 实例，获取请求的 Host 值` | 文档 |
| 2067 | 参数 | `public static String getHostByHttpService(IHttpService service)` | **工具方法** |
| 2080 | 注释 | `通过 URL 实例，构建 IHttpService 实例` | 文档 |
| 2084 | 返回值 | `public static IHttpService buildHttpServiceByURL(URL url)` | **工厂方法** |
| 2088 | 匿名类 | `return new IHttpService() { ... }` | 简单 |
| 2158 | 返回值 | `public IHttpService getHttpService()` | **接口方法** |

## 2. 迁移策略分析

### 2.1 核心模块: HttpReqRespAdapter.java

**难度**: 🔴 High
**影响**: 全局 (实现 IHttpRequestResponse 接口)

#### 问题分析

1. **接口依赖**: HttpReqRespAdapter 实现 `IHttpRequestResponse` 接口
   - `getHttpService()` 返回 `IHttpService`
   - `setHttpService(IHttpService)` 接受 `IHttpService`

2. **数据存储**: `private IHttpService service;` 字段
   - 所有工厂方法都需要 IHttpService 参数
   - 构造函数需要 IHttpService 参数

3. **使用者**: 大量代码依赖 `HttpReqRespAdapter` (如 TaskData、TaskPool 等)

#### 迁移方案

**方案 A: 重构为内部接口 (推荐)**
```java
// 步骤 1: 定义内部接口 (避免冲突)
interface IHttpRequestResponse {
    byte[] getRequest();
    void setRequest(byte[] bytes);
    byte[] getResponse();
    void setResponse(byte[] bytes);
    String getComment();
    void setComment(String s);
    String getHighlight();
    void setHighlight(String s);
    burp.api.montoya.http.HttpService getHttpService();  // ← 改为 Montoya 类型
    void setHttpService(burp.api.montoya.http.HttpService httpService);
}

// 步骤 2: HttpReqRespAdapter 实现新接口
public class HttpReqRespAdapter implements IHttpRequestResponse {
    private burp.api.montoya.http.HttpService service;  // ← 改为 Montoya 类型
    ...
}

// 步骤 3: 更新工厂方法
public static HttpReqRespAdapter from(burp.api.montoya.http.HttpService service, byte[] requestBytes) {
    return new HttpReqRespAdapter(service, requestBytes);
}
```

**方案 B: 完全移除接口 (最彻底)**
```java
// 移除 IHttpRequestResponse 接口,成为独立数据类
public class HttpReqRespAdapter {
    private burp.api.montoya.http.HttpService service;
    // 保留所有 getter/setter 但不实现接口
}
```

**推荐**: 方案 A (分阶段迁移,风险较低)

### 2.2 核心模块: BurpExtender.java 工具方法

**难度**: 🟡 Medium
**影响**: 模块级

#### 需要迁移的工具方法

| 方法 | 当前签名 | 目标签名 | 难度 |
|------|----------|----------|------|
| `buildHttpServiceByURL` | `IHttpService buildHttpServiceByURL(URL)` | `HttpService buildHttpServiceByURL(URL)` | 简单 |
| `getHostByHttpService` | `String getHostByHttpService(IHttpService)` | `String getHostByHttpService(HttpService)` | 简单 |
| `getReqHostByHttpService` | `String getReqHostByHttpService(IHttpService)` | `String getReqHostByHttpService(HttpService)` | 简单 |

#### 迁移方案

```java
// 原实现:
public static IHttpService buildHttpServiceByURL(URL url) {
    return new IHttpService() {
        @Override public String getHost() { return url.getHost(); }
        @Override public int getPort() { return getPort(url); }
        @Override public String getProtocol() { return url.getProtocol(); }
    };
}

// 新实现:
public static burp.api.montoya.http.HttpService buildHttpServiceByURL(URL url) {
    return burp.api.montoya.http.HttpService.httpService(
        url.getHost(),
        url.getPort() == -1 ? (url.getProtocol().equals("https") ? 443 : 80) : url.getPort(),
        url.getProtocol().equals("https")
    );
}
```

### 2.3 转换工具: convertHttpServiceToLegacy

**难度**: 🟢 Easy
**影响**: 临时适配 (最终应删除)

#### 当前使用场景

- Line 1020: 从 Montoya HttpRequestResponse 获取 HttpService 后转换
- Line 1547: 从 ContextMenuEvent 获取 HttpService 后转换

#### 迁移方案

**阶段 1**: 保留此方法,用于渐进式迁移
**阶段 2**: 将调用处改为直接使用 Montoya HttpService
**阶段 3**: 删除此方法

### 2.4 方法参数迁移

**难度**: 🟢 Easy
**影响**: 局部

#### 需要迁移的方法 (12 个)

| 方法 | 参数位置 | 迁移策略 |
|------|----------|----------|
| `runEnableAndMergeTask` | 第 1 个参数 | 改为 `HttpService` |
| `runEnabledWithoutMergeProcessingTask` | 第 1 个参数 | 改为 `HttpService` |
| `doBurpRequest` | 第 1 个参数 | 改为 `HttpService` |
| `doMakeHttpRequest` | 第 1 个参数 | 改为 `HttpService` |
| `setupVariable` | 第 1 个参数 | 改为 `HttpService` |
| `prepareBasicVariables` | 第 1 个参数 | 改为 `HttpService` |
| `handlePayloadProcess` | 第 1 个参数 | 改为 `HttpService` |

**迁移策略**: 批量替换,一次性修改所有方法签名和调用处

## 3. 复杂场景识别

### 3.1 高复杂度场景

#### 场景 1: HttpReqRespAdapter 接口实现
- **问题**: IHttpRequestResponse 接口强制要求 `IHttpService getHttpService()`
- **影响**: 全局 (所有使用 HttpReqRespAdapter 的代码)
- **方案**: 定义内部接口,避免与 Burp 旧 API 冲突

#### 场景 2: TaskData 类依赖
- **问题**: TaskData 存储 `IHttpRequestResponse` 对象
- **影响**: 扫描引擎核心数据结构
- **方案**: 在 MIGRATE-401-D 中处理

### 3.2 中等复杂度场景

#### 场景 3: buildHttpServiceByURL 匿名类
- **问题**: 当前使用匿名类实现 IHttpService 接口
- **影响**: 多处调用 (37, 1290, 2084 行)
- **方案**: 改为 `HttpService.httpService()` 静态工厂方法

### 3.3 低复杂度场景

#### 场景 4: 局部变量赋值
- **问题**: 多处局部变量使用 IHttpService 类型
- **影响**: 局部代码
- **方案**: 直接批量替换类型

## 4. 迁移顺序建议

### 阶段 1: 工具方法迁移 (MIGRATE-401-B)
1. 重构 HttpReqRespAdapter 接口定义
2. 更新 HttpReqRespAdapter 内部实现
3. 迁移 buildHttpServiceByURL
4. 迁移 getHostByHttpService
5. 迁移 getReqHostByHttpService

### 阶段 2: 方法参数迁移 (MIGRATE-401-C)
1. 批量替换所有方法参数类型
2. 更新方法调用处的类型转换
3. 移除 convertHttpServiceToLegacy 调用

### 阶段 3: 核心数据结构迁移 (MIGRATE-401-D)
1. 重构 TaskData 类
2. 更新 TaskPool 和扫描引擎
3. 测试扫描功能完整性

### 阶段 4: 清理工作 (MIGRATE-401-E)
1. 删除 convertHttpServiceToLegacy 方法
2. 移除所有 IHttpService 导入
3. 更新文档和注释

## 5. 风险评估

| 风险 | 等级 | 影响范围 | 缓解措施 |
|------|------|----------|----------|
| 接口不兼容 | 🔴 High | HttpReqRespAdapter | 使用内部接口隔离 |
| 类型转换错误 | 🟡 Medium | 多处调用 | 分批测试,逐步迁移 |
| 扫描功能中断 | 🔴 High | 核心业务 | MIGRATE-401-D 单独处理 |
| 编译失败 | 🟢 Low | 全局 | 先改接口,再改实现 |

## 6. 预估工时

| 任务 | 工时 | 难度 |
|------|------|------|
| MIGRATE-401-A (分析) | 2h | Medium |
| MIGRATE-401-B (适配器重构) | 3h | High |
| MIGRATE-401-C (方法参数迁移) | 4h | Medium |
| MIGRATE-401-D (核心数据结构) | 5h | High |
| MIGRATE-401-E (清理验证) | 2h | Low |
| **总计** | **16h** | - |

## 7. 结论

**总引用数**: 33 处
**核心文件**: 2 个
**高复杂度场景**: 2 个
**推荐策略**: 渐进式迁移 (4 阶段)
**关键难点**: HttpReqRespAdapter 接口重构

**Linus 评价**:
> "This is a classic case of interface dependency. The right approach is NOT to hack around it with converters - that's a band-aid. We need to cleanly separate the internal interface from the Burp API. Good data structures, good code."

**下一步行动**: 开始执行 MIGRATE-401-B (适配器重构)
