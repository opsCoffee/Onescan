# ERR-001 执行计划

**任务**: 替换 printStackTrace() 防止信息泄露

**执行日期**: 2025-12-05

---

## 任务背景

printStackTrace() 会将完整的异常堆栈信息输出到标准错误流,可能暴露:
- 内部文件路径结构
- 类名和方法名
- 代码行号
- 服务器环境信息

这在生产环境中构成信息泄露风险,违反安全最佳实践。

## 执行策略

### 第一步:勘察现状
✅ 完成 - 发现 14 处 printStackTrace() 调用:
- FileUtils.java: 5 处
- GsonUtils.java: 4 处
- IOUtils.java: 2 处
- ClassUtils.java: 3 处

✅ 完成 - 确认项目使用 `burp.common.log.Logger` 日志系统

### 第二步:替换方案
统一替换为: `Logger.error(message, args)`

格式:
- 文件操作失败: "Failed to write/read file: %s - %s", path, e.getMessage()
- JSON 解析失败: "Failed to parse JSON to object: %s", e.getMessage()
- IO 操作失败: "Failed to close IO resource: %s", e.getMessage()
- 反射操作失败: "Failed to load class: %s - %s", className, e.getMessage()

### 第三步:逐文件替换
✅ FileUtils.java - 5 处替换完成
✅ GsonUtils.java - 4 处替换完成
✅ IOUtils.java - 2 处替换完成
✅ ClassUtils.java - 3 处替换完成

### 第四步:验证
✅ 编译通过: mvn clean compile
✅ 确认无残留: grep 未发现 printStackTrace()

## 修改汇总

| 文件 | 修改行数 | 说明 |
|------|----------|------|
| FileUtils.java | 5 | 添加 Logger import, 替换 5 处异常处理 |
| GsonUtils.java | 4 | 添加 Logger import, 替换 4 处异常处理 |
| IOUtils.java | 2 | 添加 Logger import, 替换 2 处异常处理 |
| ClassUtils.java | 3 | 添加 Logger import, 替换 3 处异常处理 |

总计: 4 个文件, 14 处替换

## 安全改进

**修复前**:
```java
} catch (Exception e) {
    e.printStackTrace();  // 泄露堆栈到 stderr
    return false;
}
```

**修复后**:
```java
} catch (Exception e) {
    Logger.error("Failed to write file: %s - %s", file.getPath(), e.getMessage());
    return false;
}
```

**改进点**:
1. 不再输出完整堆栈信息
2. 只记录必要的错误消息
3. 日志系统可以统一配置输出级别
4. 生产环境可以关闭详细日志

## 向后兼容性

✅ 零破坏性 - 纯内部实现优化
- 不影响方法签名
- 不影响返回值
- 不影响异常处理逻辑
- 不影响插件功能

## 预期效果

1. **安全性提升**: 消除信息泄露风险
2. **日志规范**: 统一使用 Logger 系统
3. **可维护性**: 结构化日志便于追踪
4. **可配置性**: 日志级别可运行时调整

---

## 执行时间

预估: 2 小时
实际: 约 1 小时

效率原因: 机械替换,无复杂逻辑
