---
name: coding-style
description: Java 8 代码风格规范，包括命名约定（成员变量 m 前缀、静态变量 s 前缀、常量 UPPER_SNAKE_CASE）、格式化标准（4 空格缩进、K&R 大括号风格）、Lambda 表达式和 Stream API 使用指南、异常处理、资源管理。适用于编写或审查 Java 代码、讨论代码规范、进行代码格式化、使用 Java 8 特性时使用。
---

# 代码风格指南

## 命名规范

### 类和接口
```java
// ✅ 正确：使用 PascalCase
public class FpManager { }
public interface OnFpColumnModifyListener { }

// ❌ 错误
public class fpManager { }
public class fp_manager { }
```

### 方法
```java
// ✅ 正确：使用 camelCase，动词开头
public void loadConfig() { }
public boolean isModified() { }
public String getColumnName() { }

// ❌ 错误
public void LoadConfig() { }
public void load_config() { }
```

### 变量

**成员变量**：使用 `m` 前缀
```java
public class FpTestWindow {
    // ✅ 正确
    private MontoyaApi mMontoyaApi;
    private HttpRequestEditor mReqEditor;
    private JButton mTestBtn;
    
    // ❌ 错误
    private MontoyaApi montoyaApi;
    private HttpRequestEditor reqEditor;
}
```

**静态变量**：使用 `s` 前缀
```java
public class FpManager {
    // ✅ 正确
    private static FpConfig sConfig;
    private static String sFilePath;
    
    // ❌ 错误
    private static FpConfig config;
    private static String filePath;
}
```

**常量**：使用 UPPER_SNAKE_CASE
```java
// ✅ 正确
public static final int TASK_THREAD_COUNT = 50;
public static final String FROM_PROXY = "Proxy";

// ❌ 错误
public static final int taskThreadCount = 50;
public static final String fromProxy = "Proxy";
```

**局部变量**：使用 camelCase
```java
// ✅ 正确
String columnName = "Notes";
int rowIndex = 0;
List<FpData> dataList = new ArrayList<>();

// ❌ 错误
String ColumnName = "Notes";
int row_index = 0;
```

### 包名
```java
// ✅ 正确：全小写，使用点分隔
package burp.onescan.manager;
package burp.onescan.ui.tab;

// ❌ 错误
package burp.onescan.oneScan.Manager;
package burp.onescan.onescan.UI.Tab;
```

## 代码格式

### 缩进和空格
```java
// ✅ 正确：4空格缩进
public void doTest() {
    if (condition) {
        doSomething();
    }
}

// 运算符两侧加空格
int result = a + b;
boolean flag = (x > 0) && (y < 10);

// 逗号后加空格
method(arg1, arg2, arg3);
```

### 大括号
```java
// ✅ 正确：K&R 风格（左大括号不换行）
public void method() {
    if (condition) {
        doSomething();
    } else {
        doOtherThing();
    }
}

// ❌ 错误：Allman 风格
public void method()
{
    if (condition)
    {
        doSomething();
    }
}
```

### 行长度
```java
// ✅ 正确：每行不超过 120 字符，适当换行
String message = String.format(
    "Failed to load fingerprint config: %s",
    e.getMessage()
);

// 链式调用换行
List<String> result = list.stream()
    .filter(s -> s.startsWith("test"))
    .map(String::toUpperCase)
    .collect(Collectors.toList());
```

## 注释规范

### 类注释
```java
/**
 * 指纹管理器
 * <p>
 * 负责指纹规则的加载、匹配和缓存管理
 * <p>
 * Created by vaycore on 2023-04-21.
 */
public class FpManager {
}
```

### 方法注释
```java
/**
 * 指纹识别
 *
 * @param reqBytes  HTTP 请求数据包
 * @param respBytes HTTP 响应数据包
 * @param useCache  是否使用缓存
 * @return 失败返回空列表
 */
public static List<FpData> check(byte[] reqBytes, byte[] respBytes, boolean useCache) {
    // 实现
}
```

### 行内注释
```java
// ✅ 正确：简洁说明意图
// 检查是否初始化
checkInit();

// 将指纹识别结果存放在缓存
addResultToCache(hashKey, result);

// ❌ 错误：重复代码内容
// 调用 checkInit 方法
checkInit();
```

### TODO 注释
```java
// TODO: 优化大规模规则集的匹配性能
// FIXME: 修复并发访问缓存的线程安全问题
// NOTE: 此处使用反射可能影响性能
```

## Java 8 特性使用

### Lambda 表达式
```java
// ✅ 正确：简洁的 lambda
list.forEach(item -> System.out.println(item));
list.sort((a, b) -> a.compareTo(b));

// ✅ 正确：多行 lambda 使用大括号
list.forEach(item -> {
    String processed = process(item);
    System.out.println(processed);
});

// ❌ 避免：过于复杂的 lambda
list.forEach(item -> {
    // 10+ 行代码
    // 应该提取为独立方法
});
```

### Stream API
```java
// ✅ 正确：清晰的流式处理
List<String> filtered = list.stream()
    .filter(s -> s.startsWith("test"))
    .map(String::toUpperCase)
    .collect(Collectors.toList());

// ✅ 正确：使用方法引用
list.forEach(System.out::println);
names.stream().map(String::toLowerCase);
```

### Optional
```java
// ✅ 正确：使用 Optional 避免 null
public Optional<String> findValue(String key) {
    return Optional.ofNullable(map.get(key));
}

// 使用 Optional
String value = findValue("key").orElse("default");

// ❌ 避免：过度使用 Optional
// 不要在方法参数中使用 Optional
public void method(Optional<String> param) { } // 不推荐
```

## 异常处理

### 异常捕获
```java
// ✅ 正确：具体的异常类型
try {
    loadConfig();
} catch (IOException e) {
    Logger.error("Failed to load config: %s", e.getMessage());
    throw new IllegalStateException("Config load failed", e);
}

// ❌ 避免：捕获过于宽泛的异常
try {
    loadConfig();
} catch (Exception e) { // 太宽泛
    // ...
}
```

### 异常抛出
```java
// ✅ 正确：提供有意义的错误信息
if (StringUtils.isEmpty(path)) {
    throw new IllegalArgumentException("Config path cannot be empty");
}

// ✅ 正确：保留原始异常
try {
    parseJson(content);
} catch (JsonSyntaxException e) {
    throw new IllegalArgumentException("Invalid JSON format", e);
}
```

## 资源管理

### Try-with-resources
```java
// ✅ 正确：使用 try-with-resources（Java 7+）
try (FileInputStream fis = new FileInputStream(file);
     BufferedReader reader = new BufferedReader(new InputStreamReader(fis))) {
    return reader.readLine();
}

// ❌ 避免：手动关闭资源
FileInputStream fis = null;
try {
    fis = new FileInputStream(file);
    // ...
} finally {
    if (fis != null) {
        fis.close();
    }
}
```

## 集合使用

### 初始化
```java
// ✅ 正确：指定初始容量（如果已知大小）
List<String> list = new ArrayList<>(100);
Map<String, String> map = new HashMap<>(16);

// ✅ 正确：使用接口类型声明
List<String> list = new ArrayList<>();  // 不是 ArrayList<String> list
Map<String, String> map = new HashMap<>();  // 不是 HashMap<String, String> map
```

### 空集合
```java
// ✅ 正确：返回空集合而不是 null
public List<FpData> getList() {
    if (sConfig == null) {
        return Collections.emptyList();  // 或 new ArrayList<>()
    }
    return sConfig.getList();
}

// ❌ 避免：返回 null
public List<FpData> getList() {
    if (sConfig == null) {
        return null;  // 调用者需要 null 检查
    }
    return sConfig.getList();
}
```

## 字符串处理

### 字符串拼接
```java
// ✅ 正确：少量拼接使用 +
String message = "Error: " + errorCode + " - " + errorMessage;

// ✅ 正确：大量拼接使用 StringBuilder
StringBuilder sb = new StringBuilder();
for (String item : items) {
    sb.append(item).append(", ");
}
String result = sb.toString();

// ✅ 正确：格式化使用 String.format
String message = String.format("User %s logged in at %s", username, timestamp);
```

### 字符串比较
```java
// ✅ 正确：常量在前避免 NPE
if ("SUCCESS".equals(status)) { }

// ✅ 正确：使用工具类
if (StringUtils.isEmpty(value)) { }
if (StringUtils.isNotEmpty(value)) { }

// ❌ 避免：可能的 NPE
if (status.equals("SUCCESS")) { }  // status 可能为 null
```

## 代码组织

### 类成员顺序
```java
public class Example {
    // 1. 常量
    public static final int MAX_SIZE = 100;
    
    // 2. 静态变量
    private static String sInstance;
    
    // 3. 成员变量
    private MontoyaApi mMontoyaApi;
    private String mName;
    
    // 4. 构造方法
    public Example() { }
    
    // 5. 公共方法
    public void publicMethod() { }
    
    // 6. 私有方法
    private void privateMethod() { }
    
    // 7. 内部类
    private static class InnerClass { }
}
```

### 方法长度
```java
// ✅ 正确：方法保持简短（建议不超过 50 行）
public void processData() {
    validateInput();
    transformData();
    saveResult();
}

// ❌ 避免：过长的方法（应该拆分）
public void processData() {
    // 100+ 行代码
    // 应该拆分为多个小方法
}
```

## 最佳实践

1. **保持一致性**：遵循项目现有的代码风格
2. **可读性优先**：代码是写给人看的，其次才是机器
3. **避免魔法数字**：使用常量代替硬编码的数字
4. **单一职责**：每个类、方法只做一件事
5. **DRY 原则**：不要重复自己（Don't Repeat Yourself）
6. **KISS 原则**：保持简单（Keep It Simple, Stupid）
7. **及时重构**：发现代码异味及时重构，不要拖延
