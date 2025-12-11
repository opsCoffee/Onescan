---
name: coding-style
description: Java 17 代码风格规范，包括命名约定（成员变量 m 前缀、静态变量 s 前缀、常量 UPPER_SNAKE_CASE）、格式化标准（4 空格缩进、K&R 大括号风格）、现代 Java 特性使用指南（var、Records、Text Blocks、Pattern Matching、Stream API）、异常处理、资源管理。适用于编写或审查 Java 代码、讨论代码规范、进行代码格式化时使用。
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
    .toList();
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

## 现代 Java 特性使用

### var 关键字（Java 10+）
```java
// ✅ 正确：类型明显时使用 var
var list = new ArrayList<String>();
var map = new HashMap<String, Integer>();
var result = service.fetchData();

// ✅ 正确：循环中使用
for (var entry : map.entrySet()) {
    System.out.println(entry.getKey() + ": " + entry.getValue());
}

// ❌ 避免：类型不明显时不要用 var
var data = getData();  // 返回类型不清晰
var x = calculate();   // 无法推断类型
```

### Records 记录类（Java 16+）
```java
// ✅ 正确：简单数据载体使用 record
public record FingerprintResult(String name, String value, boolean matched) {}
public record HttpPair(String request, String response) {}

// 使用 record
var result = new FingerprintResult("Apache", "2.4.51", true);
String name = result.name();

// ❌ 避免：需要可变状态时不要用 record
// record 的字段是 final 的，不可修改
```

### Text Blocks 文本块（Java 15+）
```java
// ✅ 正确：多行字符串使用文本块
String json = """
    {
        "name": "OneScan",
        "version": "2.2.0"
    }
    """;

String sql = """
    SELECT id, name, status
    FROM fingerprints
    WHERE enabled = true
    ORDER BY name
    """;

// ✅ 正确：HTML 模板
String html = """
    <html>
        <body>
            <h1>%s</h1>
        </body>
    </html>
    """.formatted(title);

// ❌ 避免：单行字符串不需要文本块
String name = """
    OneScan""";  // 过度使用
```

### Pattern Matching（Java 16+）
```java
// ✅ 正确：instanceof 模式匹配
if (obj instanceof String s) {
    System.out.println(s.toUpperCase());
}

if (obj instanceof List<?> list && !list.isEmpty()) {
    process(list.get(0));
}

// ❌ 旧写法：需要额外的类型转换
if (obj instanceof String) {
    String s = (String) obj;  // 冗余
    System.out.println(s.toUpperCase());
}
```

### Switch Expressions（Java 14+）
```java
// ✅ 正确：switch 表达式
String result = switch (status) {
    case "SUCCESS" -> "操作成功";
    case "FAILED" -> "操作失败";
    case "PENDING" -> "处理中";
    default -> "未知状态";
};

// ✅ 正确：多值匹配
int numDays = switch (month) {
    case 1, 3, 5, 7, 8, 10, 12 -> 31;
    case 4, 6, 9, 11 -> 30;
    case 2 -> 28;
    default -> throw new IllegalArgumentException("Invalid month");
};

// ✅ 正确：需要多行逻辑时使用 yield
String desc = switch (code) {
    case 200 -> "OK";
    case 404 -> "Not Found";
    default -> {
        Logger.warn("Unknown code: " + code);
        yield "Unknown";
    }
};
```

### Lambda 表达式
```java
// ✅ 正确：简洁的 lambda
list.forEach(item -> System.out.println(item));
list.sort((a, b) -> a.compareTo(b));

// ✅ 正确：多行 lambda 使用大括号
list.forEach(item -> {
    var processed = process(item);
    System.out.println(processed);
});

// ✅ 正确：使用方法引用
list.forEach(System.out::println);
names.stream().map(String::toLowerCase);

// ❌ 避免：过于复杂的 lambda（应提取为方法）
list.forEach(item -> {
    // 10+ 行代码应该提取为独立方法
});
```

### Stream API
```java
// ✅ 正确：使用 toList()（Java 16+）
List<String> filtered = list.stream()
    .filter(s -> s.startsWith("test"))
    .map(String::toUpperCase)
    .toList();

// ✅ 正确：takeWhile/dropWhile（Java 9+）
List<Integer> taken = numbers.stream()
    .takeWhile(n -> n < 10)
    .toList();

// ✅ 正确：链式调用格式化
var result = list.stream()
    .filter(Objects::nonNull)
    .map(String::trim)
    .filter(s -> !s.isEmpty())
    .distinct()
    .sorted()
    .toList();
```

### Optional
```java
// ✅ 正确：使用 Optional 避免 null
public Optional<String> findValue(String key) {
    return Optional.ofNullable(map.get(key));
}

// ✅ 正确：orElseThrow 无参版本（Java 10+）
String value = findValue("key").orElseThrow();

// ✅ 正确：ifPresentOrElse（Java 9+）
findValue("key").ifPresentOrElse(
    v -> System.out.println("Found: " + v),
    () -> System.out.println("Not found")
);

// ✅ 正确：or 方法链（Java 9+）
Optional<String> result = findInCache(key)
    .or(() -> findInDatabase(key))
    .or(() -> findInRemote(key));

// ❌ 避免：方法参数中使用 Optional
public void method(Optional<String> param) { }  // 不推荐
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
// ✅ 正确：使用 try-with-resources
try (var fis = new FileInputStream(file);
     var reader = new BufferedReader(new InputStreamReader(fis))) {
    return reader.readLine();
}

// ✅ 正确：Java 9+ 可以使用外部声明的 effectively final 变量
FileInputStream fis = new FileInputStream(file);
try (fis) {
    return fis.read();
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

### 不可变集合工厂方法（Java 9+）
```java
// ✅ 正确：使用工厂方法创建不可变集合
List<String> list = List.of("a", "b", "c");
Set<String> set = Set.of("x", "y", "z");
Map<String, Integer> map = Map.of("one", 1, "two", 2);

// ✅ 正确：多个键值对使用 Map.ofEntries
var map = Map.ofEntries(
    Map.entry("key1", "value1"),
    Map.entry("key2", "value2"),
    Map.entry("key3", "value3")
);
```

### 可变集合初始化
```java
// ✅ 正确：指定初始容量（如果已知大小）
List<String> list = new ArrayList<>(100);
Map<String, String> map = new HashMap<>(16);

// ✅ 正确：使用接口类型声明
List<String> list = new ArrayList<>();
Map<String, String> map = new HashMap<>();
```

### 空集合
```java
// ✅ 正确：返回空集合而不是 null
public List<FpData> getList() {
    if (sConfig == null) {
        return List.of();  // 不可变空集合
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
var sb = new StringBuilder();
for (var item : items) {
    sb.append(item).append(", ");
}
String result = sb.toString();

// ✅ 正确：格式化使用 String.format 或 formatted
String message = String.format("User %s logged in at %s", username, timestamp);
String message2 = "User %s logged in at %s".formatted(username, timestamp);
```

### 字符串方法（Java 11+）
```java
// ✅ 正确：使用新的字符串方法
String stripped = str.strip();           // 去除首尾空白（支持 Unicode）
String repeated = str.repeat(3);         // 重复字符串
boolean blank = str.isBlank();           // 检查空白
List<String> lines = str.lines().toList(); // 按行分割
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
    
    // 7. 内部类/内部 record
    private record InnerRecord(String name) { }
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
    // 100+ 行代码应该拆分为多个小方法
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
8. **善用现代特性**：优先使用 Java 17 的新特性简化代码
