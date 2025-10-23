# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

OneScan 是一款专业的 BurpSuite 插件，用于递归目录扫描和漏洞发现。插件采用 Java 17 开发，使用 Maven 多模块架构构建。

## 项目文件说明

### 重要配置文件
- **prompt.md**：项目需求和任务文档（非临时文件，请勿删除）
- **CLAUDE.md**：本文档，为 Claude Code 提供项目指导
- **README.md**：项目说明文档
- **CHANGELOG.md**：版本变更记录

## 构建与开发命令

### 构建项目
```bash
# 完整构建（包含所有模块和依赖）
mvn clean package

# 仅构建插件（快速构建，生成 OneScan-vX.X.X.jar）
cd extender && mvn clean package

# 跳过测试构建
mvn clean package -DskipTests

# 运行单个测试
mvn test -Dtest=类名#方法名
```

### 开发调试
```bash
# 查看依赖树
mvn dependency:tree

# 检查编译警告
mvn compile -Dmaven.compiler.showWarnings=true

# 运行所有测试
mvn test

# 生成测试报告
mvn surefire-report:report
```

## 核心架构

### Maven 模块结构
```
onescan/
├── burp-extender-api/  # Burp 扩展 API 接口 (v2.3)
├── montoya-api/        # Montoya API 接口 (v2023.12.1)
└── extender/           # 主插件实现 (v2.1.9)
```

### 插件架构设计

#### 1. 入口与生命周期管理
**核心类**: `burp.BurpExtender`
- 实现接口：IBurpExtender, IProxyListener, ITab, IContextMenuFactory 等
- 线程池管理：
  - 任务线程池：50 个线程处理扫描任务
  - 低频任务线程池：25 个线程处理 Proxy/Send/Redirect 任务
  - 指纹识别线程池：10 个线程异步识别指纹
- QPS 限制器：使用令牌桶算法，支持 1-9999 QPS
- 去重机制：ConcurrentHashMap 管理已扫描 URL 集合

#### 2. 扫描引擎架构
**核心设计**：
- **递归扫描策略**：从 URL 路径提取各级目录，对每级应用 Payload 字典
- **扫描方向控制**：支持从左到右/从右到左，可配置扫描层级 (1-99)
- **动态变量系统**：30+ 种变量，包括 {{host}}, {{domain}}, {{timestamp}} 等
- **Payload Processing**：基于规则引擎的请求处理流水线

**关键组件**：
- `TaskRunnable`：异步任务执行基类
- `PayloadRule`：处理规则实现（URL/Header/Body/Request）
- `ProcessingItem`：处理项配置管理

#### 3. 指纹识别系统 (FpManager)
**设计特点**：
- 双向识别：支持请求/响应包识别
- 12 种匹配方法：equals, contains, regex 及其变体
- 缓存机制：避免重复识别，提升性能
- UI 集成：颜色标记和实时展示

**数据流**：
```
HTTP请求/响应 -> 异步识别线程 -> 规则匹配 -> 缓存结果 -> UI更新
```

#### 4. 数据收集模块 (CollectManager)
- JSON 字段自动提取和分类
- WebName 智能收集（从 URL 路径分析）
- 异步处理，不阻塞主扫描流程

#### 5. UI 组件体系
**主要组件**：
- `DataBoardTab`：主控制面板，任务管理和开关控制
- `ConfigPanel`：配置管理面板
  - `PayloadTab`：字典和处理规则配置
  - `RequestTab`：请求参数配置（QPS, 延迟, 请求头等）
  - `HostTab`：黑白名单管理
  - `RedirectTab`：重定向策略配置
  - `OtherTab`：其他配置项
- `FingerprintTab`：指纹规则管理
- `CollectTab`：数据收集展示
- `TaskTable`：任务列表组件（支持排序、过滤、颜色标记）

### 关键设计模式与最佳实践

#### 线程安全设计
- 使用 `ConcurrentHashMap` 管理并发集合
- `AtomicInteger` 进行计数器操作
- 正确的线程池生命周期管理（shutdown 和资源释放）

#### 性能优化策略
- QPS 限制防止目标过载
- URL 去重减少无效扫描
- 超时主机自动拦截
- 批量处理和异步执行

#### 配置管理架构
- 配置路径优先级：插件目录 > 用户配置目录
- `Config` 类统一管理所有配置项
- 支持 YAML/JSON 双格式（优先 YAML）

## 代码规范

### 命名约定
- 成员变量：`m` 前缀（如 `mCallbacks`）
- 静态变量：`s` 前缀（如 `sRepeatFilter`）
- 常量：全大写下划线分隔（如 `TASK_THREAD_COUNT`）
- 包结构：`burp.vaycore.onescan.*`

### 异常处理原则
- 网络请求必须处理超时
- 线程中断需正确响应
- 资源释放使用 finally 或 try-with-resources
- 避免吞没异常，至少记录日志

### 日志规范
- 使用 `Logger` 类统一输出
- DEBUG 模式通过 `Constants.DEBUG` 控制
- 重要操作记录 INFO 级别

## 功能实现要点

### 递归扫描核心算法
1. 解析请求 URL，提取路径层级
2. 根据配置的扫描方向和层级限制生成目标列表
3. 对每个目标应用 Payload 字典
4. 处理动态变量替换
5. 应用 Payload Processing 规则
6. 提交异步扫描任务

### 动态变量处理流程
1. 正则匹配 `{{variable}}` 格式
2. 解析变量类型和参数
3. 获取变量值（失败则跳过当前 Payload）
4. 支持嵌套变量如 `{{subdomains.0}}`

### 指纹识别工作流
1. HTTP 请求/响应进入识别队列
2. 异步线程池处理识别任务
3. 遍历指纹规则进行匹配
4. 缓存识别结果（避免重复）
5. 更新 UI 显示和颜色标记

### 重定向处理机制
1. 检测 30x 响应码
2. 解析 Location 头
3. 可选 Cookie 跟随
4. 黑白名单过滤
5. 递归扫描重定向目标

## 测试与调试

### 单元测试
```bash
# 运行特定测试类
mvn test -Dtest=RegexUtilsTest

# 运行特定测试方法
mvn test -Dtest=RegexUtilsTest#testPattern

# 查看测试覆盖率（需要配置 jacoco 插件）
mvn clean test jacoco:report
```

### 调试技巧
- 启用 `Constants.DEBUG = true` 查看详细日志
- 使用 Burp 的 Extender 标签查看输出
- 监控线程池状态：`getActiveCount()`, `getQueueSize()`
- 内存分析：关注去重集合大小

### 常见问题排查
- **扫描无响应**：检查 QPS 限制、请求延迟配置
- **内存占用高**：检查去重集合、任务队列积压
- **插件卸载失败**：确保线程池正确关闭
- **指纹不生效**：清除指纹缓存，检查规则配置

## 版本管理

更新版本时修改 `extender/pom.xml` 中的 `<version>` 标签，当前版本为 2.1.9。

## 插件特性深度解析

### Payload Processing 规则引擎
支持四种处理类型：
- **URL**: 添加前缀/后缀，正则替换
- **Header**: 请求头操作（添加/修改/删除）
- **Body**: 请求体内容处理
- **Request**: 整个请求包处理

### 任务调度机制
- 高优先级任务：扫描任务（FROM_SCAN）
- 低优先级任务：代理/发送/重定向任务
- 任务状态：pending → in_progress → completed
- 失败重试：支持 0-9 次重试，可配置间隔

### 黑白名单系统
- 支持通配符匹配
- 白名单优先级高于黑名单
- 支持超时主机自动拦截
- 实时生效，无需重启

## 依赖管理

### 核心依赖
- Burp Extender API: 官方扩展接口
- Montoya API: 新版 Burp API
- Gson: JSON 处理
- SnakeYAML: YAML 配置文件支持

### Shade 插件配置
- 重定位 Gson 避免冲突：`burp.vaycore.shaded.gson`
- 重定位 SnakeYAML：`burp.vaycore.shaded.yaml`
- 排除签名文件和 META-INF

## Burp 插件开发规范

### 核心开发原则
- **字符编码处理**：必须正确处理中文字符，避免数据包中出现乱码
- **UI 设计原则**：布局样式统一、自适应、稳定
- **API 使用规范**：必须全部使用 Montoya 接口，绝对禁止使用传统 Burp API
- **性能优化**：正则表达式必须预编译后使用
- **开发哲学**：遵循"Linus式"开发原则——简洁、实用、无破坏性改动

### 代码元信息规范
所有类文件必须包含统一的作者信息：
```java
/**
 * @author kenyon
 * @mail kenyon <kenyon@noreply.localhost>
 */
```

### Maven 构建规范
**强制要求**：必须保持纯粹、规范的 Maven 构建，不允许使用 Gradle

#### POM 配置规范
1. **Java 版本**：Java 17 作为默认与强制编译版本
2. **编译器配置**：
   - 开启 `-parameters` 参数保留方法参数名
   - 显示编译警告：`-Xlint:all`
   - 收敛警告到可接受范围
3. **资源处理**：启用 resources 过滤
4. **Shade 插件**：
   - 仅产出一个最终 jar
   - 进行常见依赖 relocation
   - 过滤无关文件（META-INF/*.SF, *.DSA, *.RSA 等）
5. **插件管理**：
   - pluginManagement 明确版本号
   - enforcer 插件校验运行环境

#### 示例 POM 配置
```xml
<properties>
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
    <maven.compiler.parameters>true</maven.compiler.parameters>
    <maven.compiler.showWarnings>true</maven.compiler.showWarnings>
    <maven.compiler.showDeprecation>true</maven.compiler.showDeprecation>
</properties>

<build>
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-compiler-plugin</artifactId>
            <configuration>
                <release>17</release>
                <parameters>true</parameters>
                <compilerArgs>
                    <arg>-Xlint:all</arg>
                    <arg>-Xlint:-processing</arg>
                </compilerArgs>
            </configuration>
        </plugin>
    </plugins>
</build>
```

### 字符编码最佳实践
1. **统一编码**：所有文件使用 UTF-8 编码
2. **请求处理**：使用 `StandardCharsets.UTF_8` 处理字符串
3. **URL 编码**：正确处理 URL 中的中文字符
4. **响应解析**：根据响应头 charset 正确解码

### UI 开发规范
1. **布局管理**：使用自定义的 Layout 管理器（VLayout, HLayout）
2. **组件初始化**：避免在构造函数中引起 `this` 逃逸
3. **事件处理**：在 `addNotify()` 中注册监听器
4. **自适应设计**：组件宽度按比例分配，支持窗口缩放

### 性能优化规范
1. **正则预编译**：
```java
private static final Pattern PATTERN = Pattern.compile("regex");
```
2. **线程池复用**：使用固定大小的线程池
3. **缓存机制**：重复计算结果缓存
4. **懒加载**：延迟初始化重量级组件

### Montoya API 使用规范
1. **禁用传统 API**：不使用 `IBurpExtenderCallbacks`
2. **使用新接口**：优先使用 `MontoyaApi` 及其子接口
3. **消息处理**：使用 `HttpRequestResponse` 替代旧版本接口
4. **扩展点**：通过 `Registration` 接口注册各类处理器