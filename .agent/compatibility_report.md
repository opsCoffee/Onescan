# OneScan Burp API 迁移 - 兼容性测试报告

> **测试日期**: 2025-12-07
> **项目版本**: 2.2.0
> **任务编号**: MIGRATE-502
> **测试类型**: 兼容性分析与测试计划
> **测试环境**: 静态分析 (CI/CD 环境,无图形界面)

---

## 执行摘要

### 核心发现

**【Linus 的判断】: "This needs runtime testing. Static analysis can only tell you so much."**

1. **测试限制**: CI/CD 环境无法进行真实的 Burp Suite 运行时测试
2. **静态分析结果**: API 兼容性理论可行,但存在运行时阻塞问题 (详见 MIGRATE-501)
3. **API 混用风险**: 代码中仍存在 3 处传统 API 引用,需要在测试中特别关注
4. **建议**: 本报告提供人工测试计划和检查清单,需在真实 Burp Suite 环境中执行

### 兼容性评估摘要

| 维度 | 评估结果 | 说明 |
|------|---------|------|
| **Burp Suite 版本兼容性** | 🟡 待验证 | montoya-api 2025.5 理论支持 Burp 2025.1+ |
| **Java 版本兼容性** | ✅ 兼容 | Java 17 (项目配置) |
| **API 迁移完整性** | 🔴 不完整 | 66% 完成,存在 13 处 NPE 风险 |
| **其他插件兼容性** | ⚠️ 未知 | 需要人工测试验证 |
| **向后兼容性** | 🔴 破坏 | 传统 API 已部分移除 |

---

## 1. Burp Suite 版本兼容性分析

### 1.1 Montoya API 版本说明

**当前配置**:
- **montoya-api**: 2025.5
- **burp-extender-api**: 2.3 (已弃用,仅保留兼容)

**Montoya API 版本规则**:
- Montoya API 版本号与 Burp Suite 版本号对应
- 例如: montoya-api 2025.5 对应 Burp Suite 2025.5.x

### 1.2 支持的 Burp Suite 版本范围

| Burp Suite 版本 | montoya-api 2025.5 兼容性 | 测试优先级 | 测试状态 |
|-----------------|-------------------------|----------|---------|
| **2025.5+** | ✅ **原生支持** (推荐) | P0 | ⏭️ 需人工测试 |
| **2025.1 - 2025.4** | ✅ 向前兼容 (可能) | P1 | ⏭️ 需人工测试 |
| **2024.x** | ⚠️ **不保证兼容** | P2 | ⏭️ 需人工测试 |
| **2023.x** | ❌ **不兼容** | P3 | 不推荐测试 |

**Linus 的视角**:
> "Never break userspace" - 但这里的 "userspace" 是 Burp Suite 版本,我们无法控制。
> 实用主义的做法: 支持最新的 LTS 版本,而不是追求完美的向后兼容。

**建议的最低支持版本**: Burp Suite Professional/Community 2025.1

### 1.3 API 版本依赖分析

#### 当前项目使用的 Montoya API 模块

```
montoya-api 2025.5
├─ burp.api.montoya.BurpExtension (核心入口)
├─ burp.api.montoya.MontoyaApi (主 API 接口)
├─ burp.api.montoya.core.ByteArray (字节数组处理)
├─ burp.api.montoya.http.* (HTTP 请求/响应处理)
├─ burp.api.montoya.proxy.* (代理处理)
├─ burp.api.montoya.ui.* (用户界面)
├─ burp.api.montoya.logging.* (日志)
└─ burp.api.montoya.extension.* (扩展生命周期)
```

**风险评估**:
- ✅ 所有使用的 API 都是 Montoya API 的核心稳定 API
- ✅ 未使用实验性或不稳定的 API
- ⚠️ 部分功能仍依赖传统 API (见 1.4)

### 1.4 传统 API 残留分析

**问题**: 代码中仍存在传统 API 引用

| 文件 | 传统 API | 用途 | 迁移任务 | 兼容性风险 |
|------|---------|------|---------|----------|
| `RawEditorAdapter.java` | `IMessageEditor` | 消息编辑器适配器 | MIGRATE-303 | 🟡 中等 |
| `HttpReqRespAdapter.java` | `IHttpRequestResponse` | HTTP 请求/响应适配 | MIGRATE-401 | 🔴 高 |
| `HttpReqRespAdapter.java` | `IHttpService` | HTTP 服务适配 | MIGRATE-401 | 🔴 高 |

**影响**:
1. **运行时依赖**: 这些类在运行时需要传统 API,Burp Suite 需要同时支持两种 API
2. **未来风险**: Burp Suite 未来版本可能完全移除传统 API,导致插件失效
3. **内存开销**: 同时加载两套 API 增加内存使用

**Linus 的视角**:
> "Mixing two APIs is like mixing two data structures. It's a sign of incomplete migration."
> 数据结构混乱的根源: `mCallbacks` 被设为 null,但依赖它的代码路径未完全重构。

---

## 2. Java 版本兼容性

### 2.1 项目 Java 版本配置

```xml
<properties>
    <jdk.version>17</jdk.version>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
</properties>
```

### 2.2 Java 版本兼容性矩阵

| Java 版本 | 项目兼容性 | Burp Suite 支持 | 测试优先级 | 测试状态 |
|-----------|----------|---------------|----------|---------|
| **Java 17** | ✅ **原生支持** (项目配置) | ✅ Burp 2024.x+ | P0 | ⏭️ 需人工测试 |
| **Java 21** | ✅ 向前兼容 | ✅ Burp 2025.x+ | P1 | ⏭️ 需人工测试 |
| **Java 11** | ⚠️ 未测试 | ⚠️ Burp 2023.x | P3 | 不推荐 |
| **Java 8** | ❌ **不兼容** | ❌ 不支持 | - | 不支持 |

**测试建议**:
- **主要测试**: Java 17 (与项目配置一致)
- **次要测试**: Java 21 (验证向前兼容性)
- **不测试**: Java 11 及以下 (Montoya API 不支持)

### 2.3 Java 特性使用情况

**项目使用的 Java 17 特性** (静态分析):
- ✅ Lambda 表达式和方法引用
- ✅ Stream API
- ✅ try-with-resources
- ✅ Multi-catch 异常处理
- ❌ 未使用 Records (Java 14+)
- ❌ 未使用 Sealed Classes (Java 17)
- ❌ 未使用 Pattern Matching (Java 17+)

**结论**: 代码相对保守,未使用 Java 17 独有特性,理论上可以向下兼容到 Java 11,但不推荐。

---

## 3. 其他插件兼容性分析

### 3.1 潜在冲突点

#### 3.1.1 UI 组件冲突

**OneScan 注册的 UI 组件**:
- Suite Tab: "OneScan"
- Context Menu: "Send to OneScan Scan" / "Send to OneScan Repeater"
- Message Editor Tab: "OneScan Info" (如果 MIGRATE-303 完成)

**可能冲突的插件类型**:
1. **其他扫描器插件**: 可能注册相同名称的 Tab
2. **上下文菜单扩展**: 可能与 "Send to..." 菜单项冲突
3. **HTTP 监听器插件**: 可能干扰 Proxy Response 处理

**检测方法**:
- 在测试环境中同时加载多个插件
- 观察 Burp Suite UI 是否显示正确
- 检查控制台是否有冲突警告

#### 3.1.2 HTTP 处理冲突

**OneScan 的 HTTP 处理流程**:
1. `ProxyResponseHandler`: 监听代理响应
2. 被动扫描: 解析响应头和 body
3. 任务队列: 异步处理扫描任务

**可能冲突的场景**:
- **其他代理监听器**: 可能修改同一个响应,导致数据不一致
- **扫描器插件**: 可能触发相同的扫描逻辑,导致重复扫描
- **日志插件**: 可能同时记录相同的 HTTP 消息

**Linus 的视角**:
> "If multiple extensions are modifying the same HTTP message, you have a data ownership problem."
> 建议: OneScan 应该只读取数据,不修改 HTTP 消息,避免与其他插件冲突。

#### 3.1.3 线程和资源冲突

**OneScan 的并发模型**:
- 任务线程池: `ExecutorService` (具体配置需查看 `TaskExecutor` 类)
- 同步集合: `Collections.synchronizedSet(sRepeatFilter)`

**潜在问题**:
- **线程池饥饿**: 如果其他插件占用所有线程,OneScan 任务可能阻塞
- **内存竞争**: 多个插件同时处理大量 HTTP 消息,可能导致内存溢出

### 3.2 推荐的测试插件组合

#### 组合 1: 扫描器冲突测试 (P0)
- **OneScan** + **Burp Scanner** (内置)
- 目的: 验证被动扫描不冲突
- 预期: 两个扫描器各自独立工作

#### 组合 2: UI 冲突测试 (P1)
- **OneScan** + **Logger++** (流行的日志插件)
- 目的: 验证 UI 组件不冲突
- 预期: Tab 和菜单项正常显示

#### 组合 3: 代理监听器冲突测试 (P1)
- **OneScan** + **Auto Repeater** (自动发送到 Repeater 的插件)
- 目的: 验证代理监听器不冲突
- 预期: 两个插件都能正确拦截响应

#### 组合 4: 复杂环境测试 (P2)
- **OneScan** + **Logger++** + **Auto Repeater** + **Collaborator Everywhere**
- 目的: 模拟真实的多插件环境
- 预期: 所有插件正常工作,无崩溃或性能问题

---

## 4. API 迁移完整性评估

### 4.1 迁移状态概览

**当前迁移进度**: 12/18 任务完成 (66%)

| 阶段 | 完成度 | 阻塞问题 |
|------|--------|---------|
| 阶段 0: API 分析 | 100% | 无 |
| 阶段 1: 核心入口点 | 100% | 无 |
| 阶段 2: HTTP 处理 | 100% | 无 |
| 阶段 3: UI 组件 | 67% | MIGRATE-303 未完成 |
| 阶段 4: 工具类 | 33% | MIGRATE-401 未完成 |
| 阶段 5: 测试验证 | 33% | 依赖阶段 4 |

### 4.2 关键兼容性问题

#### 问题 1: `mCallbacks` 和 `mHelpers` 被设为 null

**代码位置**: `BurpExtender.java:233-234`

```java
this.mCallbacks = null; // ⚠️ 运行时会失败!
this.mHelpers = null;   // ⚠️ 运行时会失败!
```

**影响**: 13 处 `NullPointerException` 风险 (详见 test_report.md)

**兼容性风险**:
- 🔴 **运行时崩溃**: 核心功能无法使用
- 🔴 **部分功能失效**: HTTP 请求发送、响应解析等
- 🟡 **调试困难**: NPE 异常不明显,用户体验差

**Linus 的判断**:
> "This is a classic example of 'it compiles but doesn't run'. Useless."
> 设置为 null 是一种假装完成迁移的方式,但实际上只是把问题从编译时推迟到运行时。
> 正确的做法: 要么保留这些字段直到所有依赖迁移完成,要么立即完成所有依赖迁移。

#### 问题 2: 传统 API 与 Montoya API 混用

**位置**:
- `RawEditorAdapter.java`: `IMessageEditor` (传统) + `RawEditor` (Montoya)
- `HttpReqRespAdapter.java`: `IHttpRequestResponse` (传统) + Montoya 类型

**风险**:
- **类型转换问题**: 两种 API 的数据类型不兼容
- **版本耦合**: Burp Suite 需要同时支持两种 API
- **维护成本**: 未来需要完全迁移

#### 问题 3: 缺少的功能

**未迁移的功能**:
- ❌ 消息编辑器 Tab (MIGRATE-303)
- ❌ 辅助工具类 (MIGRATE-401)

**影响**:
- 用户无法在自定义 Tab 中查看 OneScan 扫描结果
- 核心功能 (请求解析、响应解析) 会崩溃

---

## 5. 兼容性测试计划

### 5.1 测试前提条件

**⚠️ 重要**: 在进行兼容性测试前,必须先完成以下任务:

1. ✅ **MIGRATE-401**: 辅助工具类迁移 (解决 13 处 NPE)
   - **预计工时**: 6 小时
   - **优先级**: P0 (阻塞所有测试)

2. 🔧 **MIGRATE-202 补充**: 完成 `makeHttpRequest()` 迁移
   - **预计工时**: 2 小时
   - **优先级**: P0 (阻塞核心功能测试)

3. ⏭️ **MIGRATE-303**: 消息编辑器迁移 (可选)
   - **预计工时**: 8 小时
   - **优先级**: P2 (不阻塞核心功能)

**当前状态**: 🔴 **代码不可测试** (存在 13 处 NPE 风险)

### 5.2 测试环境准备

#### 5.2.1 测试环境配置

**硬件要求**:
- CPU: 4 核以上
- 内存: 8GB 以上 (推荐 16GB)
- 存储: 10GB 可用空间

**软件要求**:
- **操作系统**: Windows 10/11, macOS 12+, Ubuntu 20.04+
- **Java**: JDK 17 (优先) 或 JDK 21
- **Burp Suite**: Professional 或 Community 2025.5+

#### 5.2.2 测试环境清单

| 环境 ID | 操作系统 | Java 版本 | Burp Suite 版本 | 测试优先级 |
|---------|---------|-----------|----------------|----------|
| **ENV-1** | Windows 11 | Java 17 | Burp 2025.5+ | P0 |
| **ENV-2** | macOS 14+ | Java 17 | Burp 2025.5+ | P1 |
| **ENV-3** | Ubuntu 22.04 | Java 17 | Burp 2025.5+ | P1 |
| **ENV-4** | Windows 11 | Java 21 | Burp 2025.11+ | P2 |
| **ENV-5** | Windows 11 | Java 17 | Burp 2025.1 | P2 |

### 5.3 功能兼容性测试

#### 测试用例 TC-001: 插件加载测试

**目的**: 验证插件能否在不同 Burp Suite 版本中正常加载

**步骤**:
1. 启动 Burp Suite
2. 导航到 Extender → Extensions
3. 点击 "Add" 加载 OneScan JAR 文件
4. 观察插件加载状态

**预期结果**:
- ✅ 插件显示在扩展列表中
- ✅ 状态为 "Loaded"
- ✅ 无错误信息输出到控制台

**测试环境**: ENV-1, ENV-2, ENV-3, ENV-4, ENV-5

---

#### 测试用例 TC-002: UI 组件显示测试

**目的**: 验证 OneScan Tab 是否正确显示

**步骤**:
1. 加载 OneScan 插件
2. 检查 Burp Suite 顶部 Tab 栏
3. 点击 "OneScan" Tab

**预期结果**:
- ✅ "OneScan" Tab 出现在顶部 Tab 栏
- ✅ 点击后显示 OneScan 主界面
- ✅ 界面布局正常,无显示错误

**测试环境**: ENV-1, ENV-2, ENV-3

---

#### 测试用例 TC-003: 上下文菜单测试

**目的**: 验证右键上下文菜单是否正常工作

**步骤**:
1. 加载 OneScan 插件
2. 在 Proxy → HTTP history 中选择一个请求
3. 右键点击请求
4. 查找 "Send to OneScan Scan" 菜单项

**预期结果**:
- ✅ 上下文菜单中出现 OneScan 菜单项
- ✅ 点击菜单项后触发扫描 (需验证日志输出)
- ✅ 无异常或错误

**测试环境**: ENV-1, ENV-2, ENV-3

---

#### 测试用例 TC-004: 代理响应拦截测试

**目的**: 验证代理监听器能否正确拦截响应

**步骤**:
1. 加载 OneScan 插件
2. 配置浏览器使用 Burp 代理
3. 访问测试网站 (例如: http://testphp.vulnweb.com/)
4. 观察 Burp Suite 的 Extender → Output 控制台

**预期结果**:
- ✅ 控制台输出显示 OneScan 正在处理响应
- ✅ 无 NullPointerException 或其他异常
- ✅ 响应被正确解析

**前提条件**: 必须先完成 MIGRATE-401 (否则会 NPE)

**测试环境**: ENV-1, ENV-2, ENV-3

---

#### 测试用例 TC-005: 日志输出测试

**目的**: 验证日志是否正确输出到 Burp 控制台

**步骤**:
1. 加载 OneScan 插件
2. 触发扫描 (通过上下文菜单或代理拦截)
3. 检查 Extender → Output 控制台

**预期结果**:
- ✅ 日志信息正确输出
- ✅ 格式清晰,包含时间戳和日志级别
- ✅ 错误信息 (如果有) 输出到 Error 控制台

**测试环境**: ENV-1, ENV-2, ENV-3

---

#### 测试用例 TC-006: 插件卸载测试

**目的**: 验证插件能否正确卸载并清理资源

**步骤**:
1. 加载 OneScan 插件
2. 触发一些扫描任务
3. 在 Extender → Extensions 中选择 OneScan
4. 点击 "Remove" 卸载插件
5. 检查控制台和任务线程

**预期结果**:
- ✅ 插件从列表中移除
- ✅ 所有线程正确关闭 (无僵尸线程)
- ✅ UI 组件被清理 (Tab、菜单项消失)
- ✅ 无资源泄漏警告

**测试环境**: ENV-1, ENV-2, ENV-3

---

### 5.4 性能兼容性测试

#### 测试用例 TC-007: 插件加载性能

**目的**: 验证插件加载时间在可接受范围内

**步骤**:
1. 关闭 Burp Suite
2. 重新启动并加载 OneScan
3. 记录从点击 "Add" 到状态变为 "Loaded" 的时间

**预期结果**:
- ✅ 加载时间 < 5 秒 (优秀)
- ⚠️ 加载时间 5-10 秒 (可接受)
- ❌ 加载时间 > 10 秒 (需优化)

**测试环境**: ENV-1, ENV-2, ENV-3

---

#### 测试用例 TC-008: 代理处理性能

**目的**: 验证代理监听器不会显著降低 Burp 性能

**步骤**:
1. 配置浏览器使用 Burp 代理
2. 访问一个包含大量请求的网站 (例如: https://example.com)
3. 记录处理 100 个响应的总时间
4. 卸载 OneScan 后重复测试,对比性能

**预期结果**:
- ✅ 性能下降 < 10% (优秀)
- ⚠️ 性能下降 10-20% (可接受)
- ❌ 性能下降 > 20% (需优化)

**测试环境**: ENV-1

---

#### 测试用例 TC-009: 内存使用测试

**目的**: 验证插件不会导致内存泄漏

**步骤**:
1. 启动 Burp Suite 并记录初始内存使用 (通过 Task Manager 或 `jconsole`)
2. 加载 OneScan 插件
3. 运行 1000 次扫描任务
4. 记录内存使用情况
5. 卸载插件,触发 GC,观察内存是否回收

**预期结果**:
- ✅ 内存稳定,无持续增长
- ✅ 卸载后内存回收 > 90%
- ❌ 内存持续增长或无法回收 (内存泄漏)

**测试环境**: ENV-1

---

### 5.5 多插件兼容性测试

#### 测试用例 TC-010: 与 Logger++ 兼容性

**目的**: 验证 OneScan 与流行日志插件 Logger++ 的兼容性

**步骤**:
1. 同时加载 OneScan 和 Logger++
2. 触发一些 HTTP 请求
3. 检查两个插件是否正常工作

**预期结果**:
- ✅ 两个插件都正常加载
- ✅ UI 组件无冲突 (Tab 和菜单项都显示)
- ✅ HTTP 监听器互不干扰
- ✅ 无崩溃或异常

**测试环境**: ENV-1

---

#### 测试用例 TC-011: 与 Burp Scanner 兼容性

**目的**: 验证 OneScan 与 Burp 内置扫描器的兼容性

**步骤**:
1. 加载 OneScan 插件 (Burp Scanner 默认启用)
2. 对同一个目标同时触发两个扫描器
3. 观察扫描结果和性能

**预期结果**:
- ✅ 两个扫描器各自独立工作
- ✅ 扫描结果正确
- ⚠️ 性能下降在可接受范围内 (< 20%)
- ✅ 无重复扫描或冲突

**测试环境**: ENV-1

---

### 5.6 向后兼容性测试

#### 测试用例 TC-012: Burp Suite 2025.1 兼容性

**目的**: 验证插件能否在 Burp 2025.1 中运行 (低于 montoya-api 2025.5)

**步骤**:
1. 安装 Burp Suite 2025.1
2. 加载 OneScan 插件
3. 执行 TC-001 到 TC-006 的所有测试

**预期结果**:
- ✅ 插件能够加载
- ⚠️ 部分功能可能不可用 (取决于 API 版本差异)
- ✅ 核心功能正常

**测试环境**: ENV-5

---

## 6. 测试检查清单

### 6.1 测试前检查

- [ ] **代码状态**: 确认 MIGRATE-401 已完成 (必需)
- [ ] **编译状态**: 确认 `mvn clean package` 成功
- [ ] **JAR 包生成**: 确认 `target/OneScan-v2.2.0.jar` 存在
- [ ] **测试环境**: 准备至少一个测试环境 (ENV-1)
- [ ] **测试工具**: 安装 Burp Suite Professional/Community 2025.5+

### 6.2 功能测试检查清单

- [ ] **TC-001**: 插件加载测试 (ENV-1, ENV-2, ENV-3, ENV-4, ENV-5)
- [ ] **TC-002**: UI 组件显示测试 (ENV-1, ENV-2, ENV-3)
- [ ] **TC-003**: 上下文菜单测试 (ENV-1, ENV-2, ENV-3)
- [ ] **TC-004**: 代理响应拦截测试 (ENV-1, ENV-2, ENV-3)
- [ ] **TC-005**: 日志输出测试 (ENV-1, ENV-2, ENV-3)
- [ ] **TC-006**: 插件卸载测试 (ENV-1, ENV-2, ENV-3)

### 6.3 性能测试检查清单

- [ ] **TC-007**: 插件加载性能 (ENV-1, ENV-2, ENV-3)
- [ ] **TC-008**: 代理处理性能 (ENV-1)
- [ ] **TC-009**: 内存使用测试 (ENV-1)

### 6.4 兼容性测试检查清单

- [ ] **TC-010**: 与 Logger++ 兼容性 (ENV-1)
- [ ] **TC-011**: 与 Burp Scanner 兼容性 (ENV-1)
- [ ] **TC-012**: Burp Suite 2025.1 兼容性 (ENV-5)

### 6.5 测试后检查

- [ ] **测试报告**: 记录所有测试结果 (通过/失败/阻塞)
- [ ] **问题记录**: 创建 issue 跟踪失败的测试用例
- [ ] **性能数据**: 汇总性能测试数据 (加载时间、内存使用)
- [ ] **兼容性矩阵**: 更新兼容性矩阵 (哪些环境通过测试)

---

## 7. 已知问题和限制

### 7.1 阻塞问题

| 问题 ID | 描述 | 严重性 | 阻塞测试 | 修复任务 |
|---------|------|-------|---------|---------|
| **ISSUE-001** | `mCallbacks` 和 `mHelpers` 为 null,导致 13 处 NPE | 🔴 致命 | 所有功能测试 | MIGRATE-401 |
| **ISSUE-002** | `mCallbacks.makeHttpRequest()` NPE | 🔴 致命 | TC-004 | MIGRATE-202 补充 |
| **ISSUE-003** | 消息编辑器 Tab 未迁移 | 🟡 中等 | 无 (可选功能) | MIGRATE-303 |

### 7.2 已知限制

1. **无自动化测试**: 项目缺少单元测试和集成测试
2. **无 CI/CD 集成**: 无法在 CI 环境中进行自动化兼容性测试
3. **依赖 GUI**: 所有测试需要在图形界面环境中手动执行
4. **版本覆盖有限**: 无法测试所有 Burp Suite 版本组合

### 7.3 风险评估

| 风险 | 可能性 | 影响 | 缓解措施 |
|------|-------|------|---------|
| Burp Suite API 变更 | 中 | 高 | 定期更新 montoya-api 版本 |
| 其他插件冲突 | 低 | 中 | 在 README 中列出已知兼容插件 |
| 内存泄漏 | 中 | 高 | 实现完整的资源清理逻辑 (TC-006) |
| 性能下降 | 低 | 中 | 优化代理监听器性能 (TC-008) |

---

## 8. Linus 的视角总结

### 8.1 核心问题分析

**"Bad programmers worry about the code. Good programmers worry about data structures."**

当前兼容性问题的根源不是代码行数,而是**数据所有权和生命周期管理**:

1. **数据结构问题**:
   - `mCallbacks` 和 `mHelpers` 被设为 null,但依赖它们的数据流向未重构
   - 这不是迁移,而是"假装迁移" (设置为 null 来通过编译)

2. **特殊情况问题**:
   - 13 处 NPE 风险点,每一处都是一个"特殊情况"
   - 好的设计应该消除这些特殊情况,而不是用 try-catch 包裹

3. **复杂度问题**:
   - MIGRATE-401 被跳过,导致 13 处依赖未解决
   - 这不是"简化",而是制造技术债务

### 8.2 实用主义建议

**"Theory and practice sometimes clash. Theory loses. Every single time."**

理论上,我们应该支持所有 Burp Suite 版本 (2023.x, 2024.x, 2025.x),但实际上:

1. **支持最新的 LTS 版本** (Burp Suite 2025.5+)
   - 用户应该升级到最新版本
   - Montoya API 是未来的方向,传统 API 已弃用

2. **不要为了向后兼容而牺牲代码质量**
   - 保留传统 API 引用只会让代码更复杂
   - "Never break userspace" 的前提是 userspace 是你能控制的

3. **解决真实问题,而不是假想的威胁**
   - 真实问题: 13 处 NPE,代码无法运行
   - 假想威胁: Burp Suite 2023.x 兼容性 (用户早该升级了)

### 8.3 立即行动建议

**优先级 P0 (立即执行)**:
1. ✅ 完成 MIGRATE-401 (6-8 小时)
2. ✅ 完成 MIGRATE-202 补充 (2 小时)
3. ✅ 重新运行功能测试 (MIGRATE-501)

**优先级 P1 (下一步)**:
4. 🧪 执行 TC-001 到 TC-006 (功能测试)
5. 🧪 执行 TC-007 到 TC-009 (性能测试)
6. 📊 生成测试结果报告

**优先级 P2 (可选)**:
7. 🧪 执行 TC-010 到 TC-012 (兼容性测试)
8. ⚙️ 完成 MIGRATE-303 (消息编辑器迁移,8 小时)

**"It's not shipping until it works."**

当前代码状态: 🔴 **不可部署** (存在 13 处 NPE)
修复后预期: ✅ **可测试** → ✅ **可部署**

---

## 9. 测试报告模板

### 9.1 测试结果记录

**测试用例**: TC-XXX
**测试环境**: ENV-X
**测试日期**: YYYY-MM-DD
**测试人员**: [姓名]

**测试结果**: ✅ 通过 / ❌ 失败 / ⏭️ 跳过 / ⚠️ 部分通过

**实际结果**:
[描述实际观察到的结果]

**问题记录** (如果失败):
- **问题描述**: [详细描述]
- **重现步骤**: [1, 2, 3...]
- **错误信息**: [截图或日志]
- **严重性**: 🔴 致命 / 🟡 中等 / 🟢 低

**备注**:
[其他备注]

### 9.2 最终测试报告结构

完成所有测试后,生成最终报告:

```
.agent/
├── compatibility_report.md (本报告)
└── compatibility_test_results.md (测试结果汇总)
    ├── 1. 测试环境总结
    ├── 2. 测试覆盖率统计
    ├── 3. 测试结果汇总 (通过率)
    ├── 4. 问题列表
    ├── 5. 性能数据汇总
    ├── 6. 兼容性矩阵
    └── 7. 结论和建议
```

---

## 10. 附录

### 10.1 参考文档

- [Montoya API 官方文档](https://portswigger.github.io/burp-extensions-montoya-api/)
- [Burp Suite 发布历史](https://portswigger.net/burp/releases)
- [功能测试报告](.agent/test_report.md)
- [迁移计划](.agent/migration_plan.md)
- [API 映射表](.agent/api_mapping.md)

### 10.2 相关工具

- **Burp Suite**: https://portswigger.net/burp
- **Logger++**: https://github.com/nccgroup/BurpSuiteLoggerPlusPlus
- **Auto Repeater**: https://github.com/nccgroup/AutoRepeater
- **jconsole**: Java 自带的监控工具 (用于内存测试)

### 10.3 测试环境信息

```
CI/CD 环境 (本报告生成):
- OS: Linux 6.11.0-1018-azure
- Java: 17
- Maven: 3.x
- Build: GitHub Actions
- 限制: 无图形界面,无法运行 Burp Suite

推荐人工测试环境:
- OS: Windows 11 / macOS 14+ / Ubuntu 22.04
- Java: 17 或 21
- Burp Suite: Professional/Community 2025.5+
- RAM: 16GB+ (推荐)
```

---

**报告生成时间**: 2025-12-07T08:00:00Z
**报告版本**: 1.0
**下一步行动**: 完成 MIGRATE-401 后重新执行兼容性测试
**负责人**: AI Agent (Claude Code)
**审阅状态**: 待人工审阅

---

**重要提醒**:
🔴 **当前代码不可测试** - 必须先完成 MIGRATE-401 修复 13 处 NPE
🟡 **本报告提供测试计划** - 实际测试需在真实 Burp Suite 环境中执行
✅ **测试检查清单已准备** - 可直接用于人工测试
