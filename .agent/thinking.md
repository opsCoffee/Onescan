# LGC-001 深度思考

**任务**: 统一文件编码为 UTF-8

**评审日期**: 2025-12-05

---

## Linus 三问分析

### 1. 这是真问题还是臆想？

**真问题！**

配置文件（YAML 指纹库、JSON 配置）如果包含中文，在不同平台会因编码不一致导致解析失败。

- Windows 默认 GBK
- Linux/macOS 默认 UTF-8
- 同一个配置文件在不同平台表现不同 → 生产环境 bug

### 2. 有更简单的方法吗？

**数据流**：磁盘文件 → byte[] → String → YAML/JSON 解析器

**问题点**：byte[] → String 转换时使用平台默认 Charset

**最简方案**：
- 在所有 String 构造处显式指定 `StandardCharsets.UTF_8`
- 不需要改变 API 签名
- 不需要新增配置项
- 只需在 3-4 个位置添加参数

### 3. 会破坏什么吗？

**向后兼容性分析**：

✅ **不会破坏**：
- YAML/JSON 规范本身就要求 UTF-8
- 现有的正确文件（UTF-8 编码）不受影响
- FileUtils 是内部工具类，非公开 API

⚠️ **边缘情况**：
- 如果有人用 GBK 保存了配置文件，会读取失败
- 但这本身就是错误用法，应该修正

**结论**：符合 "Never break userspace" 原则 - 修复 bug 不算破坏

---

## 执行计划

### 第一步：定位所有编码问题

需要检查的文件：
1. `FileUtils.java` - readFileToString(), readFile()
2. `GsonUtils.java` - 可能使用了 FileUtils
3. 搜索全局：PrintWriter, FileWriter, OutputStreamWriter 的使用

### 第二步：修复策略

**读取**：
```java
// Before
new String(bytes)  // 平台默认

// After
new String(bytes, StandardCharsets.UTF_8)
```

**写入**：
```java
// Before
new FileWriter(file)  // 平台默认

// After
new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8)
```

### 第三步：验证测试

创建测试用例：
1. 创建包含中文的临时文件（UTF-8）
2. 用修复后的方法读取
3. 断言内容一致
4. 写入后再读取，确保读写一致

### 第四步：回归测试

- 运行 `mvn clean compile`
- 运行 `mvn test`（如果有）
- 检查是否引入编译错误

---

## 潜在风险

1. **读写不一致**：必须同时修复读取和写入
2. **遗漏的文件 I/O**：需要全局搜索确认
3. **已有数据**：文档中说明从此版本起强制 UTF-8

---

## Linus 式总结

**核心判断**：✅ 值得做

**关键洞察**：
- 数据结构：byte[] → String 的转换点是唯一需要修复的地方
- 复杂度：消除 "平台依赖" 这个特殊情况
- 风险点：需要同时修复读取和写入

**执行方案**：
1. 找出所有 String 构造和文件 I/O
2. 统一加上 StandardCharsets.UTF_8
3. 搜索 PrintWriter/FileWriter
4. 写简单测试
5. 提交说明：修复平台编码依赖

**预估时间**：1 小时（非常直接的改动）
