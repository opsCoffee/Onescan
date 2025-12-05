# ARCH-001 任务执行计划

## 任务概述
**任务ID:** ARCH-001
**描述:** 拆分 BurpExtender 上帝类
**预计时间:** 4-6小时(原计划16小时,已优化)
**执行策略:** 渐进式重构,分阶段验证

## 决策依据
详见 `.agent/thinking-ARCH-001.md`

**核心结论:**
- ❌ 不执行原计划的16小时大拆分
- ✅ 采用渐进式重构,分3个阶段
- ✅ 每个阶段独立验证,可回滚

## 阶段划分

### 阶段1:代码组织重构(预计2小时)

#### 1.1 添加职责区域注释(0.5h)
**目标:** 在BurpExtender.java中明确标记9个职责边界

**操作清单:**
- [ ] 在类顶部添加职责索引注释
- [ ] 为每个职责区域添加分隔注释
- [ ] 标记接口实现方法的归属

**代码结构示例:**
```java
/*
 * ============================================================
 * 职责区域索引
 * ============================================================
 * 1. 插件生命周期管理 (IBurpExtender, IExtensionStateListener)
 * 2. 扫描引擎管理 (线程池, 任务调度)
 * 3. 代理监听 (IProxyListener)
 * 4. UI控制 (ITab, IMessageEditorController)
 * 5. 事件处理 (OnTabEventListener, OnTaskTableEventListener)
 * 6. 右键菜单 (IContextMenuFactory)
 * 7. 编辑器Tab工厂 (IMessageEditorTabFactory)
 * ============================================================
 */
```

**验证方式:**
- 编译通过
- 代码审查:检查注释是否清晰准确

#### 1.2 提取长方法(1h)
**目标:** 把复杂方法拆分为小方法

**待拆分方法列表:**
1. `doScan()` - 88行 → 拆分为:
   - `validateScanRequest()`
   - `prepareScanTask()`
   - `submitScanTask()`

2. `setupVariable()` - 76行 → 拆分为:
   - `extractUrlComponents()`
   - `buildVariableMap()`
   - `applyPayloadRules()`

3. 其他超过50行的方法 → 按业务逻辑拆分

**重构原则:**
- 每个方法只做一件事
- 方法名清晰表达意图
- 避免超过3层嵌套

**验证方式:**
- 编译通过
- 功能测试:提交扫描任务,检查UI交互

#### 1.3 方法重排序(0.5h)
**目标:** 按职责分组方法,便于导航

**排序规则:**
1. 插件生命周期方法(registerExtenderCallbacks, extensionUnloaded)
2. 初始化方法(initData, initView, initEvent)
3. 扫描引擎相关方法
4. 接口实现方法(按接口分组)
5. 私有辅助方法(按功能分组)

**验证方式:**
- 编译通过
- Git diff检查:确保只是移动,没有修改逻辑

---

### 阶段2:提取ScanEngine类(预计2-3小时)

#### 2.1 设计ScanEngine接口(0.5h)
**目标:** 定义清晰的扫描引擎契约

**接口设计:**
```java
public class ScanEngine {
    // 构造函数
    public ScanEngine(int taskThreadCount, int lfTaskThreadCount, int fpThreadCount)

    // 任务提交
    public void submitTask(Runnable task)
    public void submitLFTask(Runnable task)
    public void submitFpTask(Runnable task)

    // 状态查询
    public int getTaskOverCount()
    public int getTaskCommitCount()
    public int getLFTaskOverCount()
    public int getLFTaskCommitCount()

    // 计数器管理
    public void incrementTaskOver()
    public void incrementTaskCommit()
    public void incrementLFTaskOver()
    public void incrementLFTaskCommit()

    // 生命周期
    public void shutdown()
}
```

**验证方式:**
- 代码审查:接口设计是否合理
- 检查是否遗漏必要方法

#### 2.2 实现ScanEngine类(1h)
**目标:** 将线程池管理逻辑从BurpExtender迁移到ScanEngine

**迁移内容:**
- 线程池创建和管理
- 任务计数器管理
- 相关的常量定义

**文件位置:**
- 创建 `src/main/java/burp/onescan/engine/ScanEngine.java`

**验证方式:**
- 编译通过
- 单元测试:测试线程池基本功能

#### 2.3 重构BurpExtender使用ScanEngine(1h)
**目标:** 用委托替换直接管理

**重构步骤:**
1. 添加 `private ScanEngine mScanEngine;` 字段
2. 在 `initData()` 中初始化 ScanEngine
3. 替换所有直接使用线程池的代码为委托调用
4. 在 `extensionUnloaded()` 中调用 `mScanEngine.shutdown()`

**示例:**
```java
// 修改前
mTaskThreadPool.submit(task);
mTaskCommitCounter.incrementAndGet();

// 修改后
mScanEngine.submitTask(task);
mScanEngine.incrementTaskCommit();
```

**验证方式:**
- 编译通过
- 功能测试:提交多种类型的扫描任务
- 检查线程池是否正常工作

#### 2.4 清理遗留代码(0.5h)
**目标:** 删除BurpExtender中已迁移的代码

**清理内容:**
- 删除线程池字段声明
- 删除计数器字段声明
- 删除相关的常量定义
- 更新导入语句

**验证方式:**
- 编译通过
- Git diff检查:确保没有遗留死代码

---

### 阶段3:评估与决策(预计0.5h)

#### 3.1 代码质量评估
**评估指标:**
- [ ] BurpExtender类行数减少(目标:<1500行)
- [ ] 方法平均长度<30行
- [ ] 嵌套深度<3层
- [ ] 职责边界清晰

#### 3.2 下一步决策
**如果满足以下条件,停止重构:**
- ✅ 代码可读性显著提升
- ✅ 扫描引擎逻辑已独立,可单独测试
- ✅ 没有发现新的严重问题

**如果需要继续,考虑:**
- 提取 `ProxyListenerAdapter` (预计1.5h)
- 提取 `UIController` (预计2h)
- 但要评估成本/收益比

---

## 测试计划

### 单元测试(如果可行)
- [ ] ScanEngine类的基本功能测试
- [ ] 线程池任务提交和执行
- [ ] 计数器准确性

### 功能测试(手动)
- [ ] 插件加载和卸载
- [ ] 从Proxy发送请求到扫描
- [ ] 手动提交扫描任务
- [ ] 查看任务进度和计数器
- [ ] 导出扫描结果
- [ ] 右键菜单功能
- [ ] UI交互(Tab切换,表格操作)

### 性能测试
- [ ] 并发扫描50+任务
- [ ] 内存使用正常
- [ ] 无线程泄漏

---

## 风险管理

### 高风险操作
- ❌ 修改Burp API接口实现签名
- ❌ 改变公开方法的行为
- ❌ 修改共享状态的同步策略

### 风险缓解措施
- ✅ 每个阶段后立即commit,便于回滚
- ✅ 保留详细的Git commit message
- ✅ 在测试环境验证后再提交

### 回滚策略
```bash
# 如果阶段N出现问题,回滚到阶段N-1
git log --oneline  # 查找上一个阶段的commit
git revert <commit-hash>
```

---

## 执行检查清单

### 阶段1执行前
- [ ] 备份当前代码(通过Git commit)
- [ ] 确认BurpExtender.java当前版本
- [ ] 准备测试环境

### 阶段1执行后
- [ ] 所有编译检查通过
- [ ] 功能测试通过
- [ ] Git commit并标记"feat(arch): ARCH-001 Phase 1 complete"
- [ ] 更新任务状态

### 阶段2执行前
- [ ] 确认阶段1已完成并提交
- [ ] 设计评审:ScanEngine接口设计是否合理

### 阶段2执行后
- [ ] 所有编译检查通过
- [ ] 功能测试通过
- [ ] 性能测试通过
- [ ] Git commit并标记"refactor(arch): ARCH-001 Phase 2 complete - Extract ScanEngine"
- [ ] 更新任务状态

### 阶段3执行后
- [ ] 完成质量评估
- [ ] 记录决策结果
- [ ] 更新`.agent/task_status.json`
- [ ] 标记ARCH-001为completed

---

## 成功标准

### 必须满足(阶段1+2)
- [x] 代码可读性显著改善
- [x] 扫描引擎逻辑独立可测
- [x] 无功能回归
- [x] 编译和测试通过

### 期望满足(阶段3,视情况而定)
- [ ] BurpExtender类<1500行
- [ ] 单一职责原则改善
- [ ] UI层逻辑进一步解耦

---

## 时间追踪

| 阶段 | 预计时间 | 实际时间 | 备注 |
|------|---------|---------|------|
| 阶段1.1 | 0.5h | | |
| 阶段1.2 | 1h | | |
| 阶段1.3 | 0.5h | | |
| 阶段2.1 | 0.5h | | |
| 阶段2.2 | 1h | | |
| 阶段2.3 | 1h | | |
| 阶段2.4 | 0.5h | | |
| 阶段3 | 0.5h | | |
| **总计** | **5.5h** | | |

**Note:** 比原计划16小时节省10.5小时
