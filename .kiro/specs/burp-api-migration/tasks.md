# Burp API 迁移任务列表

## 概述

本文档基于 requirements.md 和 design.md，将迁移工作分解为可执行的具体任务。

**总工期**: 2-3 周
**核心原则**: 简单直接、编译器驱动、零拷贝、快速迁移

---

## 阶段 1: API 直接替换 (第 1 周)

### 1.1 准备工作 (1 天)

#### Task 1.1.1: 创建迁移分支
- [-] 创建新分支 `feat/migrate-to-montoya-api`
- [ ] 确保当前代码已提交
- [ ] 备份当前版本 JAR 文件

```bash
git checkout -b feat/migrate-to-montoya-api
git push -u origin feat/migrate-to-montoya-api
```

**验收**: 分支创建成功，可以开始开发

---

#### Task 1.1.2: 分析现有 API 调用
- [ ] 搜索所有传统 API 使用位置
- [ ] 创建 API 映射表
- [ ] 阅读 Montoya API 文档

```bash
# 搜索传统 API 调用
grep -r "IBurpExtenderCallbacks" src/
grep -r "IHttpRequestResponse" src/
grep -r "IMessageEditor" src/
grep -r "IContextMenuFactory" src/
grep -r "IProxyListener" src/
```

**输出**: API 映射表（记录在 migration-notes.md）

**验收**: 清楚了解所有需要替换的 API 调用点

---

### 1.2 插件入口重构 (1 天)

#### Task 1.2.1: 修改 BurpExtender 类
- [ ] 删除 `IBurpExtender` 接口实现
- [ ] 实现 `BurpExtension` 接口
- [ ] 修改 `registerExtenderCallbacks` 为 `initialize`
- [ ] 替换 `IBurpExtenderCallbacks` 为 `MontoyaApi`

**文件**: `src/main/java/burp/BurpExtender.java`

```java
// 删除
public class BurpExtender implements IBurpExtender, IProxyListener, ... {
    private IBurpExtenderCallbacks callbacks;
    
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }
}

// 替换为
public class BurpExtender implements BurpExtension {
    private MontoyaApi montoya;
    
    public void initialize(MontoyaApi montoya) {
        this.montoya = montoya;
    }
}
```

**验收**: 代码编译通过，插件入口使用 Montoya API

---

#### Task 1.2.2: 更新组件初始化
- [ ] 修改 ScanEngine 构造函数接收 MontoyaApi
- [ ] 修改 FingerprintManager 构造函数接收 MontoyaApi
- [ ] 修改 CollectManager 构造函数接收 MontoyaApi
- [ ] 更新所有组件的初始化代码

**验收**: 所有核心组件使用 Montoya API 初始化

---

### 1.3 HTTP 请求处理重构 (2 天)

#### Task 1.3.1: 替换 HTTP 请求方法
- [ ] 定位所有 `callbacks.makeHttpRequest()` 调用
- [ ] 替换为 `montoya.http().sendRequest()`
- [ ] 更新请求构建代码使用 `HttpRequest.httpRequestFromUrl()`
- [ ] 更新响应处理代码使用 Montoya 类型

**文件**: `src/main/java/burp/onescan/scanner/ScanEngine.java`

```java
// 删除
IHttpRequestResponse response = callbacks.makeHttpRequest(service, request);
byte[] responseBytes = response.getResponse();

// 替换为
HttpRequest request = HttpRequest.httpRequestFromUrl(url)
    .withAddedHeader("User-Agent", "OneScan/2.3.0");
HttpRequestResponse response = montoya.http().sendRequest(request);
ByteArray responseBytes = response.response().toByteArray();
```

**验收**: 所有 HTTP 请求使用 Montoya API，编译通过

---

#### Task 1.3.2: 更新请求构建逻辑
- [ ] 替换 `IHttpService` 为 `HttpService`
- [ ] 更新 URL 构建逻辑
- [ ] 更新 Header 添加逻辑
- [ ] 更新 Body 设置逻辑

**验收**: 请求构建代码使用 Montoya 类型

---

#### Task 1.3.3: 更新响应解析逻辑
- [ ] 替换 `IHttpRequestResponse` 为 `HttpRequestResponse`
- [ ] 更新响应状态码获取
- [ ] 更新响应 Header 解析
- [ ] 更新响应 Body 提取

**验收**: 响应解析代码使用 Montoya 类型

---

### 1.4 UI 组件重构 (1 天)

#### Task 1.4.1: 更新消息编辑器
- [ ] 定位所有 `callbacks.createMessageEditor()` 调用
- [ ] 替换为 `montoya.userInterface().createHttpRequestEditor()`
- [ ] 更新编辑器的消息设置方法
- [ ] 更新编辑器的消息获取方法

**文件**: `src/main/java/burp/onescan/ui/MessageEditorPanel.java`

```java
// 删除
IMessageEditor editor = callbacks.createMessageEditor(controller, editable);

// 替换为
MessageEditor requestEditor = montoya.userInterface().createHttpRequestEditor();
MessageEditor responseEditor = montoya.userInterface().createHttpResponseEditor();
```

**验收**: UI 组件使用 Montoya 消息编辑器

---

#### Task 1.4.2: 更新 Suite Tab 注册
- [ ] 替换 `callbacks.addSuiteTab()` 为 `montoya.userInterface().registerSuiteTab()`
- [ ] 更新 Tab 组件的接口实现

**验收**: OneScan Tab 正确注册到 Burp Suite

---

#### Task 1.4.3: 更新上下文菜单
- [ ] 替换 `IContextMenuFactory` 为 `ContextMenuItemsProvider`
- [ ] 更新菜单项创建逻辑
- [ ] 更新菜单项点击处理

**验收**: 右键菜单功能正常

---

### 1.5 代理监听器重构 (1 天)

#### Task 1.5.1: 替换代理监听器接口
- [ ] 删除 `IProxyListener` 接口实现
- [ ] 实现 `ProxyResponseHandler` 接口
- [ ] 更新 `processProxyMessage` 为 `handleResponseReceived`
- [ ] 更新返回值为 `ProxyResponseReceivedAction`

**文件**: `src/main/java/burp/onescan/proxy/OneScanProxyHandler.java`

```java
// 删除
public class OneScanProxyHandler implements IProxyListener {
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        // ...
    }
}

// 替换为
public class OneScanProxyHandler implements ProxyResponseHandler {
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        // ...
        return ProxyResponseReceivedAction.continueWith(response);
    }
}
```

**验收**: 代理监听器使用 Montoya API

---

#### Task 1.5.2: 更新监听器注册
- [ ] 替换 `callbacks.registerProxyListener()` 为 `montoya.proxy().registerResponseHandler()`

**验收**: 代理监听器正确注册

---

### 1.6 配置兼容性实现 (1 天)

#### Task 1.6.1: 实现配置版本管理
- [ ] 在 Config 类添加 version 字段
- [ ] 实现版本检测逻辑
- [ ] 实现自动升级逻辑
- [ ] 实现配置备份逻辑

**文件**: `src/main/java/burp/common/config/Config.java`

```java
private static final String CURRENT_VERSION = "2.3.0";
private String version;

public static Config load(MontoyaApi montoya) throws IOException {
    // 读取配置
    Map<String, Object> data = readYaml(configPath);
    String fileVersion = (String) data.get("version");
    
    // 版本兼容处理
    if (fileVersion == null || fileVersion.startsWith("2.2.")) {
        // 备份旧配置
        Files.copy(configPath, backupPath);
        // 升级配置
        return upgradeFromV2_2(data, montoya);
    }
    
    return parseConfig(data);
}
```

**验收**: 能够加载 v2.2.0 配置文件并自动升级

---

#### Task 1.6.2: 实现降级兼容
- [ ] 实现宽容模式解析
- [ ] 处理未知配置项
- [ ] 提供清晰的错误提示

**验收**: v2.3.0 配置可以被 v2.2.0 读取（或提供清晰提示）

---

### 1.7 日志和错误处理 (1 天)

#### Task 1.7.1: 更新日志调用
- [ ] 替换 `callbacks.printOutput()` 为 `montoya.logging().logToOutput()`
- [ ] 替换 `callbacks.printError()` 为 `montoya.logging().logToError()`

**验收**: 日志输出使用 Montoya API

---

#### Task 1.7.2: 保持错误恢复能力
- [ ] 确认网络超时处理逻辑不变
- [ ] 确认正则匹配失败处理逻辑不变
- [ ] 确认配置加载失败处理逻辑不变

**验收**: 错误恢复行为与 v2.2.0 一致

---

## 阶段 2: 测试和修复 (第 2-3 周)

### 2.1 单元测试 (2 天)

#### Task 2.1.1: 修复现有单元测试
- [ ] 运行 `mvn test`
- [ ] 修复编译错误
- [ ] 修复 API 签名变化导致的失败
- [ ] 确保所有单元测试通过

**验收**: `mvn test` 全部通过

---

#### Task 2.1.2: 添加字符编码测试
- [ ] 测试中文 URL 处理
- [ ] 测试中文 Header 处理
- [ ] 测试中文 Body 处理

**文件**: `src/test/java/burp/onescan/CharacterEncodingTest.java`

```java
@Test
public void testChineseCharacterHandling() {
    String url = "http://testsite.com/管理员/";
    HttpRequest request = HttpRequest.httpRequestFromUrl(url);
    assertNotNull(request);
}
```

**验收**: 字符编码测试通过

---

### 2.2 集成测试 (2 天)

#### Task 2.2.1: Montoya API 集成测试
- [ ] 测试 HTTP 请求发送
- [ ] 测试消息编辑器创建
- [ ] 测试代理监听器注册
- [ ] 测试日志输出

**验收**: Montoya API 集成测试通过

---

#### Task 2.2.2: 配置兼容性测试
- [ ] 测试加载 v2.2.0 配置文件
- [ ] 测试配置自动升级
- [ ] 测试配置备份
- [ ] 测试降级场景

**验收**: 配置兼容性测试通过

---

### 2.3 回归测试 (2 天)

#### Task 2.3.1: 准备回归测试环境
- [ ] 构建 v2.2.0 JAR
- [ ] 构建 v2.3.0 JAR
- [ ] 准备测试数据
- [ ] 配置测试环境

**验收**: 回归测试环境就绪

---

#### Task 2.3.2: 执行回归测试
- [ ] 运行 compatibility-test.sh
- [ ] 对比扫描结果
- [ ] 对比指纹识别结果
- [ ] 对比性能数据

**验收**: 回归测试通过，行为等价

---

### 2.4 手工测试 (2 天)

#### Task 2.4.1: 核心功能测试
- [ ] 加载插件到 Burp Suite
- [ ] 执行递归目录扫描
- [ ] 测试指纹识别功能
- [ ] 测试数据收集功能
- [ ] 测试配置管理

**验收**: 所有核心功能正常工作

---

#### Task 2.4.2: UI 交互测试
- [ ] 测试 OneScan Tab 显示
- [ ] 测试消息编辑器交互
- [ ] 测试右键菜单功能
- [ ] 测试配置界面

**验收**: UI 交互与 v2.2.0 一致

---

#### Task 2.4.3: 错误场景测试
- [ ] 测试网络超时处理
- [ ] 测试无效 URL 处理
- [ ] 测试服务器错误响应
- [ ] 测试配置文件损坏

**验收**: 错误处理行为与 v2.2.0 一致

---

### 2.5 性能测试 (1 天)

#### Task 2.5.1: 响应时间测试
- [ ] 执行性能基准测试
- [ ] 对比 v2.2.0 和 v2.3.0 响应时间
- [ ] 分析性能差异

**验收**: 响应时间不回退（目标：提升或持平）

---

#### Task 2.5.2: 内存使用测试
- [ ] 执行内存使用测试
- [ ] 对比 v2.2.0 和 v2.3.0 内存使用
- [ ] 分析内存差异

**验收**: 内存使用不回退（目标：减少）

---

### 2.6 问题修复 (机动时间)

#### Task 2.6.1: 修复测试发现的问题
- [ ] 记录所有测试失败
- [ ] 分析根本原因
- [ ] 修复问题
- [ ] 重新测试验证

**验收**: 所有测试问题已修复

---

## 阶段 3: 发布准备 (第 3 周末)

### 3.1 代码审查和清理 (1 天)

#### Task 3.1.1: 自我审查
- [ ] 检查是否有遗留的传统 API import
- [ ] 确认所有 TODO 已完成
- [ ] 验证代码风格一致性
- [ ] 清理无用代码

```bash
# 搜索遗留代码
grep -r "IBurp" src/
grep -r "IHttp" src/
```

**验收**: 代码干净，无遗留传统 API

---

#### Task 3.1.2: 更新文档
- [ ] 更新 CLAUDE.md 中的 API 说明
- [ ] 更新 README.md（如有需要）
- [ ] 创建 CHANGELOG.md 条目
- [ ] 编写升级指南

**验收**: 文档更新完成

---

### 3.2 版本发布 (1 天)

#### Task 3.2.1: 合并代码
- [ ] 创建 Pull Request
- [ ] 代码审查
- [ ] 合并到 master 分支

```bash
git checkout master
git merge --no-ff feat/migrate-to-montoya-api
```

**验收**: 代码合并成功

---

#### Task 3.2.2: 打包发布
- [ ] 运行 `mvn clean package`
- [ ] 验证 JAR 文件
- [ ] 创建 Git tag
- [ ] 推送到远程仓库

```bash
mvn clean package
git tag -a v2.3.0 -m "迁移到 Montoya API"
git push origin v2.3.0
```

**验收**: v2.3.0 版本发布

---

#### Task 3.2.3: 发布说明
- [ ] 编写 Release Notes
- [ ] 说明迁移内容
- [ ] 提供下载链接
- [ ] 说明升级步骤

**验收**: Release Notes 发布

---

### 3.3 监控和支持 (持续)

#### Task 3.3.1: 监控用户反馈
- [ ] 关注 GitHub Issues
- [ ] 收集用户反馈
- [ ] 记录问题和建议

**验收**: 持续监控 3 天

---

#### Task 3.3.2: 快速响应问题
- [ ] 分析问题报告
- [ ] 快速修复严重 bug
- [ ] 发布 hotfix 版本（如需要）

**验收**: 问题得到及时响应

---

## 验收标准总览

### 需求 1: 功能行为等价性
- [ ] 递归目录扫描结果一致
- [ ] 指纹识别类型和数量一致
- [ ] 配置选项完全支持
- [ ] 扫描历史数据格式一致

### 需求 2: 开发过程简洁性
- [ ] 直接替换所有传统 API
- [ ] 编译器检查找出所有修改点
- [ ] Git 版本控制支持快速回滚
- [ ] 完全移除传统 API 依赖

### 需求 3: 性能和稳定性
- [ ] 消除双重数据拷贝
- [ ] 利用 Montoya API 现代特性
- [ ] 线程安全保证
- [ ] UTF-8 编码支持
- [ ] 清晰的异常信息

### 需求 4: 测试覆盖
- [ ] 单元测试通过
- [ ] 集成测试通过
- [ ] 回归测试通过
- [ ] 端到端测试通过
- [ ] 性能测试通过
- [ ] 字符编码测试通过
- [ ] 错误恢复测试通过

### 需求 5: 用户体验
- [ ] 界面功能和交互一致
- [ ] 响应和反馈一致
- [ ] 数据格式和显示一致
- [ ] 现有配置完全兼容
- [ ] 无缝升级无需额外操作

### 需求 6: 代码可维护性
- [ ] 完全移除传统 API 代码
- [ ] 直接使用 Montoya API
- [ ] 清晰简洁的代码结构
- [ ] 易于理解无复杂抽象
- [ ] 直接的 API 调用关系

### 需求 7: 数据向后兼容
- [ ] v2.2.0 配置文件成功加载
- [ ] v2.2.0 扫描结果正确显示
- [ ] v2.2.0 指纹规则匹配一致
- [ ] 持久化数据格式兼容
- [ ] 降级场景支持

### 需求 8: 错误恢复能力
- [ ] 网络超时标记主机并继续
- [ ] HTTP 请求失败跳过 Payload
- [ ] 正则匹配失败跳过规则
- [ ] 配置损坏使用默认配置
- [ ] 线程池异常优雅关闭

---

## 风险和应对

### 风险 1: 字符编码问题
**应对**: 专项测试中文字符处理，确保 UTF-8 正确支持

### 风险 2: 性能回退
**应对**: 性能基准测试，对比 v2.2.0，分析瓶颈

### 风险 3: 配置不兼容
**应对**: 配置版本管理，自动升级，备份恢复

### 风险 4: 用户体验变化
**应对**: 充分手工测试，确保 UI 交互一致

### 风险 5: 未发现的 API 调用
**应对**: 编译器驱动，搜索遗留代码，代码审查

---

## 进度跟踪

### 第 1 周
- [ ] 阶段 1.1: 准备工作
- [ ] 阶段 1.2: 插件入口重构
- [ ] 阶段 1.3: HTTP 请求处理重构
- [ ] 阶段 1.4: UI 组件重构
- [ ] 阶段 1.5: 代理监听器重构
- [ ] 阶段 1.6: 配置兼容性实现
- [ ] 阶段 1.7: 日志和错误处理

### 第 2 周
- [ ] 阶段 2.1: 单元测试
- [ ] 阶段 2.2: 集成测试
- [ ] 阶段 2.3: 回归测试
- [ ] 阶段 2.4: 手工测试
- [ ] 阶段 2.5: 性能测试

### 第 3 周
- [ ] 阶段 2.6: 问题修复
- [ ] 阶段 3.1: 代码审查和清理
- [ ] 阶段 3.2: 版本发布
- [ ] 阶段 3.3: 监控和支持

---

## 总结

**总任务数**: 50+ 个具体任务
**总工期**: 2-3 周
**关键里程碑**:
1. 第 1 周末: API 替换完成，代码编译通过
2. 第 2 周末: 所有测试通过，问题修复完成
3. 第 3 周末: 版本发布，开始监控

**成功标准**: 所有 8 个需求的验收标准通过

---

**文档版本**: v1.0
**创建日期**: 2025-01-06
**维护者**: OneScan Team
