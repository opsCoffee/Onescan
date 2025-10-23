# OneScan 维护工作区

这是 OneScan 项目的维护工作暂存区，用于追踪任务进度和存储分析文档。

## 📁 文件说明

### `todo-analysis.md`
详细的 TODO 项目分析报告，包含：
- 每个 TODO 项的当前实现分析
- 问题诊断
- 解决方案设计
- 实施步骤
- 影响范围评估
- 风险分析

### `tasks.md`
任务清单和进度追踪，包含：
- 4 个主要任务的详细子任务分解
- 任务优先级和时间估算
- 测试计划
- 完成标准

## 🎯 任务概览

| 任务 | 优先级 | 预计时间 | 状态 |
|------|--------|----------|------|
| 1. 移除数据收集功能 | 高 | 1-2h | 待开始 |
| 2. 表格宽度自适应 | 高 | 2-3h | 待开始 |
| 3. JSON 转 YAML | 中 | 2-3h | 待开始 |
| 4. 深色主题适配 | 中 | 3-4h | 待开始 |

**总工作量**: 8-12 小时（不含测试）

## 🚀 快速开始

### 推荐执行顺序

1. **任务 1: 移除数据收集** (最简单，风险最低)
   - 删除相关文件和代码引用
   - 清理 UI 组件
   - 提交代码

2. **任务 2: 表格宽度自适应** (用户体验改进)
   - 修改列宽计算逻辑
   - 添加响应式支持
   - 多分辨率测试

3. **任务 4: 深色主题适配** (UI 改进)
   - 审计硬编码颜色
   - 使用 Montoya API
   - 主题测试

4. **任务 3: JSON 转 YAML** (配置优化)
   - 添加依赖
   - 转换配置文件
   - 保持向后兼容

## 📋 关键技术点

### 1. 表格宽度自适应
```java
// 使用百分比而非固定像素
private static final double[] COLUMN_WIDTH_RATIOS = {
    0.05, 0.06, 0.06, 0.15, 0.20, 0.18, 0.10, 0.06, 0.08, 0.06
};

// 动态计算列宽
int columnWidth = (int) (tableWidth * ratio);
```

### 2. YAML 配置
```xml
<!-- 添加依赖 -->
<dependency>
    <groupId>org.yaml</groupId>
    <artifactId>snakeyaml</artifactId>
    <version>2.0</version>
</dependency>
```

### 3. 深色主题
```java
// 使用 Montoya API 获取主题
Theme theme = montoyaApi.userInterface().currentTheme();
if (theme == Theme.DARK) {
    // 深色主题配色
}
```

## ⚠️ 注意事项

1. **编译环境**
   - JDK 1.8
   - Maven 3.9.9
   - 编译命令: `mvn clean package`

2. **测试要求**
   - 每个任务完成后进行编译测试
   - 在 Burp Suite 中加载插件验证
   - 测试核心功能是否正常

3. **代码提交**
   - 每完成一个任务提交一次
   - 使用清晰的 commit message
   - 建议使用子代理调用 `/commit` 命令

4. **向后兼容**
   - JSON 转 YAML 时保持对旧格式的支持
   - 确保现有用户配置不受影响

## 🔍 代码位置参考

### 核心文件
- 主入口: `extender/src/main/java/burp/vaycore/onescan/OneScan.java`
- 表格组件: `extender/src/main/java/burp/vaycore/onescan/ui/widget/TaskTable.java`
- 指纹管理: `extender/src/main/java/burp/vaycore/onescan/manager/FpManager.java`
- 数据收集: `extender/src/main/java/burp/vaycore/onescan/manager/CollectManager.java`

### UI 组件
- 主面板: `extender/src/main/java/burp/vaycore/onescan/ui/tab/DataBoardTab.java`
- 配置面板: `extender/src/main/java/burp/vaycore/onescan/ui/tab/ConfigPanel.java`
- 指纹面板: `extender/src/main/java/burp/vaycore/onescan/ui/tab/FingerprintTab.java`

### 配置文件
- 指纹配置: `extender/src/main/resources/fp_config.json`
- Maven 配置: `pom.xml`, `extender/pom.xml`

## 📊 进度追踪

在 `tasks.md` 中更新任务状态：
- `[ ]` - 待开始
- `[~]` - 进行中
- `[x]` - 已完成

## 🐛 问题记录

遇到问题时，在此记录：

### 问题模板
```markdown
**日期**: YYYY-MM-DD
**任务**: 任务名称
**问题描述**: 
**解决方案**: 
**状态**: 已解决/待解决
```

---

## 📞 需要帮助？

- 查看 `todo-analysis.md` 了解详细的技术分析
- 查看 `tasks.md` 了解具体的实施步骤
- 使用 MCP 工具和深度思考来分析复杂问题
- 优先使用子代理来执行重复性任务

---

**最后更新**: 2025-10-20
**维护者**: AI Assistant
