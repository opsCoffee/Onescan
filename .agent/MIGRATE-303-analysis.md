# MIGRATE-303: 消息编辑器迁移分析

## 当前状态

### 已完成 (MIGRATE-101-D)
- ✅ OneScanInfoTab 构造函数已迁移为接受 MontoyaApi
- ✅ 移除了 IExtensionHelpers 依赖
- ✅ 使用 Montoya API 解析 HTTP 请求/响应

### 待完成
1. **移除 IMessageEditorTabFactory 接口**
   - BurpExtender 类仍实现 IMessageEditorTabFactory
   - createNewInstance() 方法仍在使用

2. **迁移注册方式**
   - 当前: 未注册 (Line 252-254 已注释掉)
   - 目标: api.userInterface().registerHttpRequestEditorProvider()

3. **OneScanInfoTab 接口迁移**
   - 当前: 实现 IMessageEditorTab
   - 目标: 实现 ExtensionProvidedHttpRequestEditor/ExtensionProvidedHttpResponseEditor

4. **IMessageEditorController 依赖**
   - 当前: OneScanInfoTab 仍使用 IMessageEditorController
   - 目标: 完全移除,使用 Montoya API

## 复杂度分析

**难度**: 🔴 High
**预计工时**: 6-8 小时
**风险**: 需要重构 OneScanInfoTab 类的接口实现

## 建议方案

由于时间限制,建议分阶段执行:

### 阶段 1: 移除 IMessageEditorTabFactory (1小时)
- 从 BurpExtender 类声明中移除 `IMessageEditorTabFactory`
- 删除 `createNewInstance()` 方法
- 验证编译通过

### 阶段 2: 重构 OneScanInfoTab (3-4小时)
- 移除 `IMessageEditorTab` 接口
- 实现 Montoya API 的编辑器接口
- 移除 `IMessageEditorController` 依赖

### 阶段 3: 注册编辑器提供者 (1-2小时)
- 使用 `api.userInterface().registerHttpRequestEditorProvider()`
- 测试验证

## 决策

考虑到:
1. 当前已完成 55% 的任务
2. 剩余 7 个任务
3. 6小时时间限制
4. 此任务复杂度高 (6-8小时)

**建议**: 标记此任务状态,留待下次执行,优先完成更简单的任务。
