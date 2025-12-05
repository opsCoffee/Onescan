# LGC-001 任务执行计划

**任务**: 统一文件编码为 UTF-8

**执行时间**: 2025-12-05

---

## 问题定位结果

### 需要修复的文件

#### 1. FileUtils.java - 4 处编码问题

**读取问题**：
- **Line 118**: `readFileToString()` - `new String(result, 0, result.length)` 无编码参数
- **Line 123**: `readStreamToString()` - `new String(result, 0, result.length)` 无编码参数
- **Line 152**: `readStreamToList()` - `new InputStreamReader(is)` 无编码参数

**写入问题**：
- **Line 87**: `writeFile()` - `new FileWriter(file, append)` 使用平台默认编码

### 不需要修改的文件

- **GsonUtils.java**: 只操作 String，不直接读写文件 ✅
- **Logger.java**: PrintWriter 包装 OutputStream（Burp API），用于控制台输出 ✅

---

## 修复方案

### 1. 修复读取操作（3 处）

```java
// Line 118: readFileToString()
// Before
return new String(result, 0, result.length);

// After
return new String(result, 0, result.length, StandardCharsets.UTF_8);
```

```java
// Line 123: readStreamToString()
// Before
return new String(result, 0, result.length);

// After
return new String(result, 0, result.length, StandardCharsets.UTF_8);
```

```java
// Line 152: readStreamToList()
// Before
br = new BufferedReader(new InputStreamReader(is));

// After
br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
```

### 2. 修复写入操作（1 处）

```java
// Line 84-87: writeFile()
// Before
public static boolean writeFile(File file, String content, boolean append) {
    FileWriter writer = null;
    try {
        writer = new FileWriter(file, append);

// After
public static boolean writeFile(File file, String content, boolean append) {
    Writer writer = null;
    try {
        writer = new OutputStreamWriter(new FileOutputStream(file, append), StandardCharsets.UTF_8);
```

**注意**：需要添加 import：
```java
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
```

---

## 测试策略

### 单元测试用例

创建 `FileUtilsEncodingTest.java`：

1. **测试读取 UTF-8 文件**：
   - 创建包含中文的临时文件（UTF-8）
   - 使用 `readFileToString()` 读取
   - 断言内容正确

2. **测试写入并读取**：
   - 使用 `writeFile()` 写入中文内容
   - 使用 `readFileToString()` 读取
   - 断言内容一致

3. **测试 readStreamToList()**：
   - 创建包含多行中文的文件
   - 使用 `readFileToList()` 读取
   - 断言每行内容正确

---

## 执行步骤

1. ✅ 定位所有编码问题
2. ⏳ 修复 FileUtils.java 的 4 处编码问题
3. ⏳ 添加必要的 import 语句
4. ⏳ 创建单元测试验证修复
5. ⏳ 运行 `mvn clean compile` 验证编译
6. ⏳ 提交代码并更新任务状态

---

## 预期影响

### 正面影响

- 中文配置文件在所有平台统一表现 ✅
- 符合 YAML/JSON 的 UTF-8 编码规范 ✅
- 消除平台依赖，提高可移植性 ✅

### 潜在风险

- **极低**：现有正确的 UTF-8 文件不受影响
- **边缘情况**：如果有人用 GBK 保存了配置（违反规范），会读取失败
  - 这本身就是错误用法，应该修正

---

## 完成标准

- [ ] 所有 4 处编码问题修复完成
- [ ] 添加单元测试且全部通过
- [ ] `mvn clean compile` 成功
- [ ] 代码提交并推送
- [ ] 更新 task_status.json
