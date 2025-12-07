# MIGRATE-101-B 深度思考分析

## 任务理解

**目标**: 迁移 UI 相关 API 从传统 Burp Extender API 到 Montoya API

**前置条件**: MIGRATE-101-A 已完成(核心接口已从 IBurpExtender → BurpExtension)

## Linus 的五层思考

### 1. 数据结构分析
"Bad programmers worry about code. Good programmers worry about data structures."

**核心数据流**:
- 旧: `IBurpExtenderCallbacks callbacks` → 提供所有服务的单一接口
- 新: `MontoyaApi api` → 按功能域分离的服务模块
- UI 服务: `api.userInterface()` 提供所有 UI 相关功能

**架构改进**:
旧设计把所有东西塞一个接口(God Object 反模式)
新设计按功能域分离(符合单一职责原则)
这是好的架构演进!

### 2. 特殊情况识别
"好代码没有特殊情况"

**典型 API 映射**:
```java
// 旧
callbacks.customizeUiComponent(component);
callbacks.addSuiteTab(tab);
callbacks.registerContextMenuFactory(factory);

// 新
api.userInterface().customizeUiComponent(component);
api.userInterface().registerSuiteTab(tabName, component);
api.userInterface().registerContextMenuItemsProvider(provider);
```

**关键差异**:
- `addSuiteTab()` → `registerSuiteTab()`: 方法名变化,参数可能不同
- `registerContextMenuFactory()` → `registerContextMenuItemsProvider()`: 接口类型变化

### 3. 复杂度审查
"如果实现需要超过3层缩进,重新设计它"

**任务本质**(一句话):
把所有 UI 相关的 API 调用从 `callbacks.xxx()` 改为 `api.userInterface().xxx()`,并调整方法签名

**执行步骤**:
1. 找到所有 UI 相关调用点
2. 查阅新 API 的对应方法
3. 逐个替换
4. 编译验证

**简化原则**:
不要过度设计,不要引入不必要的抽象层
Just replace the fucking API calls, period.

### 4. 破坏性分析
"Never break userspace!"

**可能被破坏的功能**:
1. UI 标签页 → 用户看不到插件界面
2. 右键菜单 → 用户无法使用上下文菜单功能
3. UI 组件样式 → UI 可能显示异常

**零破坏性保证**:
- 不修改任何业务逻辑,只替换 API 调用
- 编译失败=立即回退
- 每改一点,立即编译验证
- 不引入新依赖,不改变数据流

### 5. 实用性验证
"Theory and practice sometimes clash. Theory loses."

**问题真实性**: ✅ Burp Suite 2023.x 已弃用旧 API,插件无法加载
**影响范围**: 所有使用新版 Burp Suite 的 OneScan 用户
**解决方案复杂度**: MEDIUM (API 替换,需要仔细但不复杂)
**问题严重性**: HIGH (插件完全无法使用)

**结论**: 值得做,必须做!

## 执行策略

### 并行 vs 串行

**可以并行吗?** NO!

**原因**:
所有 UI API 调用都在同一个 `BurpExtender.java` 文件的 `initialize()` 方法中。
并行修改同一个方法会产生冲突。

**正确做法**:
串行执行,每改一个调用点就编译一次,确保不破坏。
"Slow is smooth, smooth is fast" - 一次只改一个东西,反而最快。

## 执行计划

1. **读取当前代码**
   - 读取 `BurpExtender.java`
   - 找到所有 UI 相关 API 调用

2. **查阅 API 映射**
   - 读取 `.agent/api_mapping.md`
   - 确认新 API 映射关系

3. **逐个替换**
   - `customizeUiComponent()` → `api.userInterface().customizeUiComponent()`
   - `addSuiteTab()` → `api.userInterface().registerSuiteTab()`
   - `registerContextMenuFactory()` → 可能需要实现新接口

4. **编译验证**
   - 每替换一个,立即编译
   - 编译失败立即回退

5. **更新进度**
   - 更新 `task_status.json`
   - 标记 MIGRATE-101-B 完成
   - 提交 Git commit

## 风险控制

- **风险等级**: MEDIUM
- **回退策略**: Git revert
- **验证方式**: 编译 + 手动测试(如果可能)
- **不破坏原则**: 如果编译通过但运行时 UI 功能失效,视为 BUG 必须回退

## 预期产出

- ✅ UI 相关 API 全部迁移到 Montoya API
- ✅ 编译通过
- ✅ Git commit with detailed message
- ✅ task_status.json updated
