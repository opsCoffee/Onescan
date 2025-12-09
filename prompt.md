# OneScan 项目任务列表

## ✅ 已完成任务

### 代码审查任务

#### 任务：完整全面Review最近20个Commit变更 ✅

**完成时间**：2025-12-09
**负责人**：Claude (Linus-style Review)
**状态**：✅ 已完成

**审查摘要**：
- 审查了最近20个commits (d42ad3a ~ 0f7a77e)
- 总体评分：🟡 **B+ (83/100)**
- 发现：1个优秀bug修复、3个需改进项、无P0安全问题

**关键发现**：
1. ✅ BufferedReader修复展现"好品味" (教科书级案例)
2. ⚠️ HTTP/2回退逻辑有误,需修复或删除
3. ⚠️ 指纹管理连续7个补丁,说明数据结构设计不够前置
4. 🔴 Git历史混乱(6个auto commit,临时文件混入)

**输出文档**：
- 📄 完整报告：`.agent/code_review_report_20_commits.md` (7000+字)
- 📄 执行摘要：`.agent/review_summary.md`

**立即行动项**：
1. ~~删除HTTP/2假回退代码 (BurpExtender.java:603)~~ ✅ 已完成
2. ~~规范Git流程 (添加.gitignore规则)~~ ✅ 已完成
3. ~~统一HTTP请求构建逻辑 (创建HttpRequestBuilder工具类)~~ ✅ 已完成

**技术债务**：约9小时修复时间 → 已修复约6小时

---

## ✅ 代码审查改进任务（2025-12-09）

### 任务：根据代码审查报告进行改进 ✅

**完成时间**：2025-12-09
**状态**：✅ 已完成

**改进内容**：

1. **删除 HTTP/2 假回退逻辑**
   - 文件：`BurpExtender.java`
   - 移除了 `buildHttpRequestWithVersionFallback` 中创建 testRequest 但从未真正测试的假逻辑
   - 简化为直接使用 HTTP/1.1（协议协商由 TLS ALPN 层自动处理）

2. **更新 .gitignore 规则**
   - 添加 `Test*.java` 和 `**/Test*.java` 规则
   - 防止临时测试文件混入版本控制

3. **统一 HTTP 请求构建逻辑**
   - 新建：`HttpRequestBuilder.java` 工具类
   - 重构：`BurpExtender.java` 中的请求构建方法
   - 重构：`HttpReqRespAdapter.java` 中的请求构建方法
   - 重构：`MontoyaHttpRequestBuilder.java` 中的请求构建方法
   - 消除了三处重复代码，提升了可维护性

---

## 📋 待处理任务

**当前无待处理任务**

---

## 📝 任务说明

此文件用于记录和跟踪OneScan项目的各项任务。请在完成任务后更新状态，并添加相关的执行结果和文档链接。

