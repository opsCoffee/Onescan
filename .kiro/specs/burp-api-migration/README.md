# Burp API 迁移规范

## 文档结构

- **requirements.md**: 需求文档，定义迁移的功能需求和验收标准
- **design.md**: 设计文档，描述技术实现方案和架构设计
- **compatibility-test.sh**: 兼容性测试脚本（Bash）
- **compare_results.py**: 扫描结果对比工具（Python）

## 核心改进点

相比初始版本，优化后的规范解决了以下关键问题：

### 1. 数据兼容性保障
- ✅ 新增"需求 7"：数据向后兼容性
- ✅ 配置文件版本管理和自动升级
- ✅ 支持降级场景的兼容加载
- ✅ 扫描历史格式验证

### 2. 错误处理修复
- ✅ 删除有问题的 `OneScanErrorHandler` 类
- ✅ 区分可恢复错误和致命错误
- ✅ 保持现有的容错能力（网络超时继续处理）
- ✅ 新增"需求 8"：错误恢复能力保障

### 3. 测试策略加强
- ✅ 删除"最多 2 次验证"的错误限制
- ✅ 增加回归测试、兼容性测试、性能测试
- ✅ 提供完整的测试代码示例
- ✅ 包含自动化测试脚本

### 4. 回滚机制完善
- ✅ 多层回���：代码 + 配置 + 数据
- ✅ 配置文件自动备份
- ✅ 用户通知机制（CHANGELOG）
- ✅ 降级回退支持

## 使用指南

### 准备工作

1. 确保已构建两个版本的 JAR 文件：
   ```bash
   # 构建 v2.2.0 (传统 API)
   git checkout v2.2.0
   mvn clean package
   cp target/OneScan-v2.2.0.jar ../jars/

   # 构建 v2.3.0 (Montoya API)
   git checkout v2.3.0
   mvn clean package
   cp target/OneScan-v2.3.0.jar ../jars/
   ```

2. 安装测试依赖：
   ```bash
   # Python 依赖（用于结果对比）
   pip3 install -r requirements.txt  # 如果需要
   ```

### 运行兼容性测试

#### 自动化测试脚本

```bash
# 运行完整的兼容性测试套件
cd .kiro/specs/burp-api-migration
chmod +x compatibility-test.sh
./compatibility-test.sh
```

测试脚本会自动执行以下检查：
1. 配置文件兼容性
2. 指纹规则兼容性
3. 扫描行为等价性
4. 错误恢复行为
5. 字符编码处理

#### 手动对比扫描结果

```bash
# 使用 v2.2.0 执行扫描
burp --load-extension=OneScan-v2.2.0.jar \
     --scan-url="http://testsite.com/app/" \
     --payloads="admin,backup,test" \
     --output=scan-old.json

# 使用 v2.3.0 执行扫描
burp --load-extension=OneScan-v2.3.0.jar \
     --scan-url="http://testsite.com/app/" \
     --payloads="admin,backup,test" \
     --output=scan-new.json

# 对比结果
python3 compare_results.py scan-old.json scan-new.json
```

### 实施迁移

遵循 design.md 中的迁移策略：

#### 阶段 1: API 直接替换 (1周)
- [ ] 修改 BurpExtender 入口类
- [ ] 替换 HTTP 请求调用
- [ ] 更新 UI 组件
- [ ] 修改代理监听器
- [ ] 实现配置兼容加载

#### 阶段 2: 测试和修复 (1-2周)
- [ ] 运行单元测试
- [ ] 执行回归测试
- [ ] 手工测试核心功能
- [ ] 专项测试（编码、错误、性能）
- [ ] 验证配置和数据兼容性

### 验收标准

所有 8 个需求的验收标准必须通过：

1. ✅ **需求 1**: 功能行为等价性
2. ✅ **需求 2**: 开发过程简洁性
3. ✅ **需求 3**: 性能和稳定性提升
4. ✅ **需求 4**: 充分的测试覆盖
5. ✅ **需求 5**: 用户体验无影响
6. ✅ **需求 6**: 代码简洁易维护
7. ✅ **需求 7**: 数据向后兼容
8. ✅ **需求 8**: 错误恢复能力保持

## 技术亮点

### 遵循 "Never break userspace" 原则

1. **配置自动升级**
   ```java
   // 检测旧版本配置，自动升级并备份
   if (version == null || version.startsWith("2.2.")) {
       Files.copy(configPath, backupPath);
       config = upgradeFromV2_2(data);
   }
   ```

2. **错误恢复保持一致**
   ```java
   // 网络超时不崩溃，继续处理其他 URL
   catch (SocketTimeoutException e) {
       montoya.logging().logToError("请求超时，跳过: " + url);
       markTimeoutHost(url);
       continue;  // 继续处理下一个
   }
   ```

3. **降级场景支持**
   ```java
   // 新版本配置可以降级加载（宽容模式）
   else if (fileVersion > CURRENT_VERSION) {
       return parseConfigLenient(data);
   }
   ```

### 简单但不简陋

- ✅ 拒绝过度工程（适配器层、转换器）
- ✅ 但不牺牲必要保障（测试、兼容性、回滚）
- ✅ 代码简洁，测试充分
- ✅ 快速迁移，质量优先

## 风险控制

### 多层回滚机制

1. **代码回滚**
   ```bash
   git revert <commit-hash>
   mvn clean package
   ```

2. **配置回滚**
   ```bash
   mv config.yaml.v2.2.0.backup ~/.onescan/config.yaml
   ```

3. **数据兼容**
   - 配置文件版本标记
   - 自动备份和恢复
   - 宽容模式解析

### 测试覆盖矩阵

| 测试类型 | 覆盖范围 | 自动化 | 状态 |
|---------|---------|--------|------|
| 单元测试 | 核心业务逻辑 | ✅ | 待实施 |
| 集成测试 | Montoya API 调用 | ✅ | 待实施 |
| 回归测试 | 行为等价性 | ✅ | 有脚本 |
| 兼容性测试 | 配置和数据 | ✅ | 有脚本 |
| 性能测试 | 响应时间和内存 | ✅ | 待实施 |
| 手工测试 | UI 和用户体验 | ❌ | 必需 |

## 常见问题

### Q: 为什么工期从 2 周增加到 2-3 周？
A: 增加的 1 周用于充分的测试和验证，确保迁移质量。这是值得的投入。

### Q: 如果发现兼容性问题怎么办？
A: 使用多层回滚机制：
1. 小问题：快速修复并重新测试
2. 大问题：回滚代码，分析根因，重新设计
3. 致命问题：提供 v2.2.0 下载链接，给用户选择

### Q: 用户需要手动迁移配置吗？
A: 不需要。配置文件会自动检测版本并升级，用户无感知。

### Q: 性能会不会下降？
A: 不会。Montoya API 的零拷贝设计理论上性能更好。我们会通过性能测试验证。

## 参考资料

- [Burp Suite Montoya API 文档](https://portswigger.net/burp/documentation/desktop/extensions/montoya)
- [OneScan 项目 README](../../../README.md)
- [OneScan 架构说明](../../../CLAUDE.md)

## 维护

此规范文档应在以下情况更新：
- 发现新的兼容性问题
- 测试策略调整
- 迁移过程中的经验总结
- 用户反馈的问题

---

**文档版本**: v1.1
**最后更新**: 2025-01-06
**维护者**: OneScan Team
