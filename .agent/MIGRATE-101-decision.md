# MIGRATE-101 执行决策报告

**任务**: BurpExtender 类迁移
**决策时间**: 2025-12-06
**决策者**: Linus Torvalds 视角审查

## 问题发现

原计划将 MIGRATE-101 和 MIGRATE-102 分为两个独立任务:
- MIGRATE-101: 修改入口点接口
- MIGRATE-102: 迁移扩展上下文

## 深度分析

### 数据结构分析
- **核心数据**: `IBurpExtenderCallbacks mCallbacks` (Line 177)
- **数据流**: 在 `initData()` 接收 → 存储为成员变量 → 全局使用(2246行代码,约150+处引用)
- **问题**: `MontoyaApi` 和 `IBurpExtenderCallbacks` 是**完全不兼容**的类型

### 特殊情况识别
1. **类型不兼容**: 无法通过强制转换或适配器模式
2. **全局依赖**: `mCallbacks` 和 `mHelpers` 被整个类的所有方法使用
3. **服务获取方式变化**:
   - 旧: `callbacks.getHelpers()`
   - 新: `api.utilities()` / `api.http()` / `api.proxy()` 等多个服务

### 复杂度审查
- **如果分开执行**:
  - MIGRATE-101 改完后代码**无法编译**(类型不匹配)
  - 必须添加临时的适配层或桥接代码
  - 违反"简洁执念"原则

- **如果合并执行**:
  - 一次性完成接口切换
  - 无需临时代码
  - 符合"用最笨但最清晰的方式实现"原则

### 破坏性分析
**影响范围统计**:
- `mCallbacks` 引用: 约 50+ 处
- `mHelpers` 引用: 约 100+ 处
- 受影响接口: 9 个实现的接口
- 受影响文件: 仅 `BurpExtender.java` (2246 行)

## 实用性验证
**问题真实性**: ✅ 阻塞性
**解决方案复杂度**: 🟡 中等(但无法简化)
**理论vs实践冲突**: **实践赢**

## 最终决策

### ✅ 值得做: 合并 MIGRATE-101 和 MIGRATE-102

**理由**:
1. "Theory and practice sometimes clash. Theory loses. Every single time."
2. 分开执行会引入不必要的复杂性(临时适配代码)
3. 两个任务操作同一文件,无并行优势
4. 合并后工时: 4+4=8小时,在可接受范围

### Linus 式方案

**第一步: 修改接口声明和成员变量**
```java
// 旧
public class BurpExtender implements IBurpExtender { ... }
private IBurpExtenderCallbacks mCallbacks;

// 新
public class BurpExtender implements BurpExtension { ... }
private MontoyaApi api;
```

**第二步: 修改初始化方法**
```java
// 旧
public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) { ... }

// 新
public void initialize(MontoyaApi api) { ... }
```

**第三步: 逐个替换 API 调用**(参照 `.agent/api_mapping.md`)

**第四步: 删除旧成员变量 `mCallbacks` 和 `mHelpers`**

**第五步: 编译验证**
```bash
mvn compile -DskipTests
```

## 风险评估

**高风险点**:
1. ❌ **无法通过增量验证**(必须一次性改完才能编译)
2. ⚠️ **API 映射可能不完整**(部分旧 API 无对应)
3. ⚠️ **运行时行为可能变化**(需要实际测试)

**缓解策略**:
1. 使用 Git 分支隔离改动
2. 参考 `.agent/api_mapping.md` 确保映射正确
3. 编译通过后立即提交,记录哈希

## 执行计划

**预计工时**: 8小时 (合并 MIGRATE-101 + MIGRATE-102)

**子任务分解**:
1. ✅ 深度思考和决策 (1h)
2. ⏳ 修改类声明和成员变量 (0.5h)
3. ⏳ 迁移 `initData()` 中的 API 调用 (1h)
4. ⏳ 迁移 `initView()` 中的 API 调用 (1h)
5. ⏳ 迁移 `initEvent()` 中的 API 调用 (1h)
6. ⏳ 迁移其余方法中的 API 调用 (3h)
7. ⏳ 编译修复和验证 (0.5h)

**如果超时**:
- 提交已完成的部分
- 在 `.agent/task_status.json` 中记录进度
- 创建子任务追踪未完成项

## 参考文档

- `.agent/api_mapping.md` - API 映射表
- `.agent/migration_plan.md` - 完整迁移计划
- `https://portswigger.github.io/burp-extensions-montoya-api/` - Montoya API 官方文档

---

**决策结论**: **实用主义胜过教条主义。直接硬切换,不搞花里胡哨的临时方案。**
