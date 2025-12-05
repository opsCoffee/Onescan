---
name: onescan-code-review
description: OneScan 项目代码评审规范和标准，包含针对 BurpSuite 插件的特定评审维度、工具链、质量标准和最佳实践
license: MIT
metadata:
  version: "1.0.0"
  project: OneScan
  language: zh-CN
---

# OneScan 代码评审规范

本 Skill 提供 OneScan 项目（BurpSuite 安全扫描插件）的代码评审标准和最佳实践。

## 评审维度

### 1. 安全性检查

作为安全工具，OneScan 自身的安全性至关重要：

- **输入验证**
  - URL、Payload、配置文件的输入验证
  - 防止注入攻击（SQL、命令注入、路径遍历）
  - 用户输入的边界检查和长度限制

- **敏感数据处理**
  - 凭证、Token、Cookie 的安全存储
  - 避免在日志中记录敏感信息
  - 内存中敏感数据的及时清理

- **依赖库安全**
  - 使用 OWASP Dependency-Check 扫描已知漏洞
  - 及时更新存在安全问题的依赖
  - 避免使用废弃或不维护的库

### 2. 并发性和线程安全

扫描工具涉及大量并发请求：

- **线程池管理**
  - 合理配置线程池大小
  - 避免线程泄漏
  - 正确处理线程中断

- **共享资源同步**
  - 识别共享可变状态
  - 使用适当的同步机制（synchronized、Lock、Atomic）
  - 避免死锁和竞态条件

- **并发集合使用**
  - 优先使用 java.util.concurrent 包的并发集合
  - 避免在迭代时修改集合
  - 正确使用 CopyOnWriteArrayList、ConcurrentHashMap 等

### 3. 性能和资源管理

- **内存管理**
  - 检测内存泄漏（长时间运行场景）
  - 大数据量处理优化（指纹缓存、历史记录）
  - 及时释放不再使用的对象引用

- **资源释放**
  - 使用 try-with-resources 管理资源
  - 确保连接、文件句柄、线程正确关闭
  - 避免资源泄漏

- **性能优化**
  - QPS 限制和请求队列实现
  - 避免不必要的对象创建
  - 使用合适的数据结构

### 4. 可靠性

- **异常处理**
  - 不要捕获通用 Exception，使用具体异常类型
  - 异常必须记录日志（包含上下文信息）
  - 不要吞掉异常（空 catch 块）
  - 在适当的层级处理异常

- **重试机制**
  - 验证重试逻辑的正确性
  - 避免无限重试
  - 实现指数退避策略

- **超时处理**
  - 所有网络操作必须设置超时
  - 正确处理超时异常
  - 支持任务取消

### 5. UI 响应性

- **异步处理**
  - 长时间操作必须在后台线程执行
  - 避免阻塞 UI 线程
  - 使用 SwingUtilities.invokeLater 更新 UI

- **进度反馈**
  - 提供操作进度指示
  - 支持任务取消
  - 显示有意义的状态信息

## 静态分析工具链

### Java 代码分析

- **SpotBugs**：检测常见 Bug 和安全问题
- **PMD**：代码规范和最佳实践检查
- **Checkstyle**：代码风格一致性
- **SonarLint**：综合代码质量分析

### 依赖安全检查

- **OWASP Dependency-Check**：检测依赖库的已知漏洞
- **Maven 依赖分析**：识别冗余和冲突依赖

### 代码度量

- 圈复杂度分析（识别过于复杂的方法）
- 代码重复度检测
- 类和方法的大小统计

## 代码质量标准

### 编码规范

- 遵循 Google Java Style Guide
- 类名使用 PascalCase
- 方法和变量使用 camelCase
- 常量使用 UPPER_SNAKE_CASE
- 包名全小写，使用域名反转规则

### 注释要求

- 所有 public 类和方法必须有 JavaDoc
- 复杂逻辑必须有行内注释说明
- 注释使用中文，保持与项目一致
- 注释应解释"为什么"而不是"是什么"

### 方法和类的大小

- 方法不超过 50 行（复杂逻辑除外）
- 类不超过 500 行
- 圈复杂度不超过 10
- 方法参数不超过 5 个

### 命名规范

- 使用有意义的名称，避免缩写
- 布尔变量使用 is/has/can 前缀
- 集合变量使用复数形式
- 避免使用魔法数字，定义为常量

## 最佳实践

### 异常处理原则

```java
// ❌ 错误：捕获通用异常
try {
    // ...
} catch (Exception e) {
    // ...
}

// ✅ 正确：捕获具体异常
try {
    // ...
} catch (IOException e) {
    logger.error("文件读取失败: {}", filePath, e);
    throw new ConfigLoadException("配置文件加载失败", e);
}
```

### 资源管理

```java
// ❌ 错误：手动关闭资源
BufferedReader reader = null;
try {
    reader = new BufferedReader(new FileReader(file));
    // ...
} finally {
    if (reader != null) {
        reader.close();
    }
}

// ✅ 正确：使用 try-with-resources
try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
    // ...
}
```

### 线程安全

```java
// ❌ 错误：不安全的共享状态
private List<String> results = new ArrayList<>();

public void addResult(String result) {
    results.add(result);  // 线程不安全
}

// ✅ 正确：使用并发集合
private final List<String> results = new CopyOnWriteArrayList<>();

public void addResult(String result) {
    results.add(result);  // 线程安全
}
```

### 空值处理

```java
// ❌ 错误：可能返回 null
public String getConfig(String key) {
    return configMap.get(key);  // 可能返回 null
}

// ✅ 正确：使用 Optional
public Optional<String> getConfig(String key) {
    return Optional.ofNullable(configMap.get(key));
}
```

## 性能基准

- 单次扫描任务启动延迟 < 100ms
- UI 操作响应时间 < 50ms
- 内存占用增长率 < 10MB/小时（长时间运行）
- 支持至少 10000 条历史记录不卡顿
- QPS 限制功能正常工作

## 评审流程

### 1. 评审前准备

- 确保项目可以正常编译（`mvn clean compile`）
- 运行现有测试（如果有）
- 在 Burp Suite 中加载插件并验证基本功能
- 备份当前代码（创建评审分支）

### 2. 分层评审策略

**架构层面**（30 分钟）
- 模块划分合理性
- 依赖关系清晰度
- 扩展点设计

**模块层面**（每个核心模块 20 分钟）
- 职责单一性
- 接口设计
- 模块间耦合度

**代码层面**（使用工具辅助）
- 运行静态分析工具
- 人工审查关键代码路径
- 识别代码坏味道

### 3. 风险评估

对每个发现的问题评估：
- **影响范围**：局部/模块级/全局
- **风险等级**：低/中/高/严重
- **修复难度**：简单/中等/复杂
- **回归风险**：低/中/高

### 4. 优先级判断标准

- **P0（严重）**：安全漏洞、数据丢失、崩溃问题
- **P1（高）**：性能严重下降、功能不可用、内存泄漏
- **P2（中）**：代码质量问题、可维护性问题、小的性能问题
- **P3（低）**：代码风格、注释完善、重构优化

## 参考资源

详细的设计模式和工作流程请参考：
- `references/workflows.md` - 多步骤流程和条件逻辑
- `references/output-patterns.md` - 输出格式和质量标准
- `references/burp-api-guide.md` - Burp Suite API 使用指南
