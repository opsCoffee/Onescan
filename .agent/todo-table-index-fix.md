# TODO: 优化数据看板面板表格序号显示

## 任务描述
优化数据看板面板的表格，显示序号需要从1开始，而不是从0开始。

## 优先级
中等

## 状态
已完成 ✅

## 分析结果
已找到问题根源：
- 文件：`extender/src/main/java/burp/vaycore/onescan/ui/widget/TaskTable.java`
- 类：`TaskTableModel`
- 方法：`add(TaskData data)`
- 问题：`mCounter.getAndIncrement()` 从0开始计数，导致第一条记录id为0

## 解决方案
修改 `TaskTableModel` 的构造函数，将 `mCounter` 初始化为1而不是0：
```java
mCounter = new AtomicInteger(1);  // 从1开始而不是0
```

## 时间分配
- 80% 实际修复
- 20% 测试验证


## 修改内容
- 文件：`extender/src/main/java/burp/vaycore/onescan/ui/widget/TaskTable.java`
- 修改：将 `TaskTableModel` 构造函数中的 `mCounter` 初始化从 `new AtomicInteger()` 改为 `new AtomicInteger(1)`
- 效果：表格序号现在从1开始显示，而不是从0开始

## 验证
- 使用 getDiagnostics 检查：无语法错误
- 修改简单明确，不会影响其他功能
