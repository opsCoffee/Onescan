---
name: error-handling
description: Java 异常处理最佳实践，包括检查型/非检查型异常分类、参数验证、配置加载、try-with-resources 资源管理、正则表达式和反射操作错误处理、UI 错误显示、日志记录级别、错误恢复策略（默认值、降级、重试）、空指针检查、集合操作安全。适用于处理异常、编写错误处理代码、调试错误、设计容错机制时使用。
---

# 错误处理规范

## 错误处理原则

1. **快速失败**：尽早发现和报告错误
2. **明确信息**：提供清晰的错误描述
3. **保留上下文**：保留原始异常信息
4. **适当恢复**：在可能的情况下优雅降级
5. **记录日志**：记录错误以便调试

## 异常分类

### 1. 检查型异常（Checked Exception）

用于可预期的、可恢复的错误：

```java
// ✅ 正确：文件操作使用检查型异常
public String readFile(String path) throws IOException {
    return FileUtils.readFileToString(new File(path), StandardCharsets.UTF_8);
}

// 调用者必须处理
try {
    String content = readFile(configPath);
} catch (IOException e) {
    Logger.error("Failed to read file: %s", e.getMessage());
    // 处理或重新抛出
}
```

### 2. 非检查型异常（Unchecked Exception）

用于编程错误或不可恢复的错误：

```java
// ✅ 正确：参数验证使用非检查型异常
public void init(String path) {
    if (StringUtils.isEmpty(path)) {
        throw new IllegalArgumentException("Config path cannot be empty");
    }
    if (!FileUtils.isFile(path)) {
        throw new IllegalArgumentException("Config file not found: " + path);
    }
    // 继续处理
}
```

## 异常处理模式

### 1. 参数验证

```java
public class FpManager {
    
    /**
     * 初始化指纹管理器
     *
     * @param path 配置文件路径
     * @throws IllegalArgumentException 如果路径无效
     */
    public static void init(String path) {
        // ✅ 正确：验证参数并提供清晰的错误信息
        if (StringUtils.isEmpty(path)) {
            throw new IllegalArgumentException("Fingerprint config path cannot be empty");
        }
        
        if (!FileUtils.isFile(path)) {
            throw new IllegalArgumentException(
                String.format("Fingerprint config file not found: %s", path)
            );
        }
        
        // 继续处理
        loadConfig(path);
    }
}
```

### 2. 配置加载

```java
private static void loadConfig() {
    String content = FileUtils.readFileToString(sFilePath);
    
    // ✅ 正确：验证内容
    if (StringUtils.isEmpty(content)) {
        throw new IllegalArgumentException("Fingerprint config is empty");
    }
    
    try {
        // 尝试解析 JSON
        sConfig = GsonUtils.toObject(content, FpConfig.class);
    } catch (JsonSyntaxException e) {
        // ✅ 正确：提供详细错误信息并保留原始异常
        throw new IllegalArgumentException(
            "Failed to parse fingerprint config: " + e.getMessage(),
            e
        );
    }
    
    // ✅ 正确：验证解析结果
    if (sConfig == null) {
        throw new IllegalArgumentException("Fingerprint config parsing failed");
    }
    
    // 验证配置完整性
    validateConfig(sConfig);
}

private static void validateConfig(FpConfig config) {
    if (config.getColumns() == null || config.getColumns().isEmpty()) {
        throw new IllegalArgumentException(
            "Fingerprint config must have at least one column"
        );
    }
    
    if (config.getList() == null) {
        throw new IllegalArgumentException(
            "Fingerprint config list cannot be null"
        );
    }
}
```

### 3. 资源操作

```java
// ✅ 正确：使用 try-with-resources 自动关闭资源
public String readConfig(String path) throws IOException {
    try (FileInputStream fis = new FileInputStream(path);
         InputStreamReader isr = new InputStreamReader(fis, StandardCharsets.UTF_8);
         BufferedReader reader = new BufferedReader(isr)) {
        
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }
        return content.toString();
        
    } catch (FileNotFoundException e) {
        throw new IOException("Config file not found: " + path, e);
    } catch (IOException e) {
        throw new IOException("Failed to read config file: " + e.getMessage(), e);
    }
}
```

### 4. 正则表达式

```java
public static boolean regex(String data, String pattern) {
    try {
        Pattern p = Pattern.compile(pattern);
        return p.matcher(data).find();
    } catch (PatternSyntaxException e) {
        // ✅ 正确：记录错误但不中断程序
        Logger.error("Invalid regex pattern '%s': %s", pattern, e.getMessage());
        return false;
    }
}
```

### 5. 反射操作

```java
private static boolean invokeFpMethod(String methodName, String data, String content) {
    try {
        Method method = FpMethodHandler.class.getDeclaredMethod(
            methodName, 
            String.class, 
            String.class
        );
        return (Boolean) method.invoke(null, data, content);
        
    } catch (NoSuchMethodException e) {
        Logger.error("Fingerprint method not found: %s", methodName);
        return false;
        
    } catch (IllegalAccessException e) {
        Logger.error("Cannot access fingerprint method: %s", methodName);
        return false;
        
    } catch (InvocationTargetException e) {
        Logger.error("Fingerprint method execution failed: %s", 
            e.getCause().getMessage());
        return false;
        
    } catch (Exception e) {
        Logger.error("Unexpected error invoking fingerprint method: %s", 
            e.getMessage());
        return false;
    }
}
```

## 用户界面错误处理

### 1. 显示错误对话框

```java
public class FingerprintTab extends BaseTab {
    
    private void doReload() {
        try {
            // 尝试重新加载配置
            FpManager.init(FpManager.getPath());
            mFpTable.reloadData();
            refreshCount();
            
            // ✅ 正确：成功时显示提示
            UIHelper.showTipsDialog(L.get("reload_success"));
            
        } catch (IllegalArgumentException e) {
            // ✅ 正确：失败时显示错误对话框
            Logger.error("Failed to reload fingerprint config: %s", e.getMessage());
            UIHelper.showErrorDialog(
                L.get("reload_failed") + ": " + e.getMessage()
            );
        }
    }
}
```

### 2. 在面板中显示错误

```java
public class FpTestResultPanel extends JScrollPane {
    
    /**
     * 显示提示信息（包括错误信息）
     */
    public void showTips(String tips) {
        clearResult();
        if (mPanel != null) {
            // ✅ 正确：在 UI 中显示错误信息
            JLabel label = new JLabel(tips);
            label.setForeground(Color.RED);  // 错误信息用红色
            mPanel.add(label);
            UIHelper.refreshUI(this);
        }
    }
}
```

### 3. 测试窗口错误处理

```java
public class FpTestWindow extends JPanel {
    
    private void doTest() {
        try {
            // 获取输入
            HttpRequest request = mReqEditor.getRequest();
            HttpResponse response = mRespEditor.getResponse();
            
            // ✅ 正确：验证输入
            if (request == null && response == null) {
                mTestResultPanel.showTips(L.get("input_is_empty"));
                return;
            }
            
            // 执行测试
            byte[] reqBytes = request != null ? 
                request.toByteArray().getBytes() : new byte[0];
            byte[] respBytes = response != null ? 
                response.toByteArray().getBytes() : new byte[0];
            
            List<FpData> results = FpManager.check(reqBytes, respBytes, false);
            
            // ✅ 正确：处理空结果
            if (results.isEmpty()) {
                mTestResultPanel.showTips(L.get("no_test_result_hint"));
                return;
            }
            
            // 显示结果
            mTestResultPanel.setData(results);
            
        } catch (Exception e) {
            // ✅ 正确：捕获并显示错误
            Logger.error("Fingerprint test failed: %s", e.getMessage());
            mTestResultPanel.showTips(
                L.get("test_failed") + ": " + e.getMessage()
            );
        }
    }
}
```

## 日志记录

### 日志级别

```java
// ERROR - 错误，需要关注
Logger.error("Failed to load config: %s", e.getMessage());

// WARN - 警告，可能有问题但不影响运行
Logger.warn("Fingerprint data at index %d has no rules", i);

// INFO - 信息，重要的业务流程
Logger.info("Fingerprint config loaded: %d rules", count);

// DEBUG - 调试信息
Logger.debug("Cache hit for key: %s", cacheKey);
```

### 日志最佳实践

```java
// ✅ 正确：提供上下文信息
Logger.error("Failed to parse JSON config at line %d: %s", 
    lineNumber, e.getMessage());

// ✅ 正确：使用格式化字符串
Logger.info("Loaded %d fingerprint rules from %s", count, path);

// ❌ 避免：字符串拼接（性能问题）
Logger.debug("Processing item: " + item.toString());  // 即使不输出也会拼接

// ✅ 正确：使用格式化
Logger.debug("Processing item: %s", item);
```

## 错误恢复策略

### 1. 提供默认值

```java
public String getColumnName(int index) {
    try {
        return sConfig.getColumns().get(index).getName();
    } catch (IndexOutOfBoundsException e) {
        Logger.warn("Column index out of bounds: %d", index);
        return "Unknown";  // ✅ 返回默认值
    }
}
```

### 2. 降级处理

```java
public List<FpData> check(byte[] reqBytes, byte[] respBytes, boolean useCache) {
    try {
        // 尝试使用缓存
        if (useCache) {
            String cacheKey = calculateCacheKey(reqBytes, respBytes);
            List<FpData> cached = findCacheByKey(cacheKey);
            if (cached != null) {
                return cached;
            }
        }
    } catch (Exception e) {
        // ✅ 正确：缓存失败时降级到不使用缓存
        Logger.warn("Cache lookup failed, proceeding without cache: %s", 
            e.getMessage());
    }
    
    // 继续正常处理
    return performCheck(reqBytes, respBytes);
}
```

### 3. 重试机制

```java
public void saveConfig(int maxRetries) {
    int attempts = 0;
    Exception lastException = null;
    
    while (attempts < maxRetries) {
        try {
            // 尝试保存
            doSaveConfig();
            return;  // 成功则返回
            
        } catch (IOException e) {
            lastException = e;
            attempts++;
            Logger.warn("Save config failed (attempt %d/%d): %s", 
                attempts, maxRetries, e.getMessage());
            
            if (attempts < maxRetries) {
                // 等待后重试
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }
    
    // 所有重试都失败
    throw new IllegalStateException(
        "Failed to save config after " + maxRetries + " attempts",
        lastException
    );
}
```

## 常见错误处理场景

### 1. 空指针检查

```java
// ✅ 正确：提前检查
public void processData(FpData data) {
    if (data == null) {
        Logger.warn("Received null FpData, skipping processing");
        return;
    }
    
    if (data.getRules() == null || data.getRules().isEmpty()) {
        Logger.warn("FpData has no rules, skipping processing");
        return;
    }
    
    // 继续处理
}

// ✅ 正确：使用工具类
if (StringUtils.isEmpty(value)) {
    return defaultValue;
}
```

### 2. 集合操作

```java
// ✅ 正确：检查集合状态
public String getFirstItem(List<String> list) {
    if (list == null || list.isEmpty()) {
        return null;
    }
    return list.get(0);
}

// ✅ 正确：使用 Stream API 的安全方法
public Optional<String> findFirst(List<String> list) {
    return list.stream()
        .filter(s -> s.startsWith("test"))
        .findFirst();
}
```

### 3. 类型转换

```java
// ✅ 正确：安全的类型转换
public Integer parseInteger(String value) {
    try {
        return Integer.parseInt(value);
    } catch (NumberFormatException e) {
        Logger.warn("Invalid integer value: %s", value);
        return null;
    }
}

// ✅ 正确：使用 instanceof 检查
public void processObject(Object obj) {
    if (obj instanceof String) {
        String str = (String) obj;
        // 处理字符串
    } else if (obj instanceof Integer) {
        Integer num = (Integer) obj;
        // 处理整数
    } else {
        Logger.warn("Unsupported object type: %s", 
            obj.getClass().getName());
    }
}
```

## 错误信息国际化

```java
// ✅ 正确：使用国际化资源
UIHelper.showErrorDialog(L.get("config_load_failed", errorMessage));

// 在 i18n 资源文件中定义：
// config_load_failed=配置加载失败：{0}
// config_load_failed=Failed to load config: {0}
```

## 总结

1. **快速失败**：尽早发现和报告错误
2. **清晰信息**：提供有意义的错误描述
3. **保留上下文**：使用异常链保留原始错误
4. **记录日志**：记录错误以便调试和监控
5. **优雅降级**：在可能的情况下提供降级方案
6. **用户友好**：向用户显示易懂的错误信息
7. **避免吞没异常**：不要捕获异常后什么都不做
8. **资源清理**：使用 try-with-resources 确保资源释放
