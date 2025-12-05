# ERR-001 任务深度思考

**任务**: 替换 printStackTrace() 防止信息泄露

**评审日期**: 2025-12-05

---

## 任务理解
替换 14 处 printStackTrace() 调用,防止信息泄露
- 受影响文件: FileUtils, GsonUtils, WordlistManager, FpManager, Config
- 核心问题: printStackTrace() 会暴露内部路径和堆栈信息

## Linus 五层思考

### 第一层:数据结构分析
当前数据流: 异常对象 → printStackTrace() → System.err → 日志/控制台

问题:
- 无法控制输出格式和内容
- 没有日志级别控制
- 无法过滤敏感信息

改进后: 异常对象 → 格式化消息 → Logger.error() → 日志系统(可控)

### 第二层:特殊情况识别
统一策略:使用 Logger.error(message, exception)
- 不需要区分调试模式/生产模式
- 让日志系统配置决定输出详细程度
- 消除代码中的条件判断

### 第三层:复杂度审查
任务本质: 将 printStackTrace() 替换为结构化日志调用

简化方案:
- 直接使用现有 Logger
- 不需要新增抽象层
- 机械替换,保持语义一致

预估: 每处 5 分钟 × 14 处 = 70 分钟

### 第四层:破坏性分析
**零破坏性** - 纯内部实现优化
- 不影响插件外部行为
- 不影响扫描结果和 UI
- printStackTrace() 本来就是调试手段,不是 API

### 第五层:实用性验证
问题真实性: ✅ 生产环境会泄露路径信息
严重性: P0 级别(安全问题)
解决复杂度: 低(简单替换)
匹配度: ✅ 完美匹配,值得做

## 执行策略

### 第一步:勘察现状
- 搜索所有 printStackTrace() 调用点
- 确认项目中 Logger 的使用方式
- 检查是否有统一的日志工具类

### 第二步:最简方案设计
- 如果有 Logger:直接替换为 Logger.error(message, exception)
- 如果用 BurpSuite stderr:替换为 mStderr.println() + 格式化消息
- 格式统一: "操作失败: 描述" + exception.getMessage()

### 第三步:批量替换
按文件分组,每个文件完成后立即编译验证

### 第四步:验证
- 编译通过
- 确认不再有 printStackTrace() 调用
- 触发异常场景验证日志输出

## 最终决策

✅ **值得做** - 真实安全问题,低成本高收益

Linus式方案:
1. 找到现有日志方式
2. 用最简单方式替换
3. 不做过度设计
4. 保持异常处理逻辑不变
