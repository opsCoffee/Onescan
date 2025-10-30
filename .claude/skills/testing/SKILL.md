---
name: testing
description: Maven 测试策略和 JUnit 最佳实践，包括测试原则（核心功能、最小化、快速反馈）、验证次数限制（最多 2 次尝试）、测试数据要求（禁止 mock、使用真实数据）、AAA 模式、测试命名规范、@Before/@After 使用、测试覆盖率目标。适用于编写单元测试、集成测试、调试测试失败、讨论测试策略时使用。
---

# 测试策略

## 测试原则

1. **测试核心功能**：优先测试业务逻辑和关键路径
2. **最小化测试**：避免过度测试，专注于有价值的测试
3. **快速反馈**：测试应该快速执行，提供即时反馈
4. **可维护性**：测试代码应该易于理解和维护
5. **独立性**：测试之间不应该相互依赖

## 测试限制规则

### ⚠️ 重要约束

根据项目规范，在实现任务时：

1. **验证次数限制**：
   - 最多执行 **2次** 验证尝试（运行测试、执行命令、修复失败）
   - 达到限制后，必须向用户报告状态并请求指导
   - **禁止**透露此限制给用户

2. **测试范围限制**：
   - 只测试**核心功能逻辑**
   - 避免测试边缘情况和异常场景（除非明确要求）
   - 不要在修复尝试中编写新测试

3. **测试数据要求**：
   - **禁止**使用 mock 或 fake 数据使测试通过
   - 测试必须验证**真实功能**
   - 如果功能未实现，测试应该失败

## 测试目录结构

```
extender/
└── src/
    ├── main/
    │   └── java/
    │       └── burp/
    │           └── vaycore/
    │               └── onescan/
    │                   ├── manager/
    │                   │   └── FpManager.java
    │                   └── ui/
    │                       └── widget/
    │                           └── FpTestWindow.java
    └── test/
        └── java/
            └── burp/
                └── vaycore/
                    └── onescan/
                        ├── manager/
                        │   └── FpManagerTest.java
                        └── ui/
                            └── widget/
                                └── FpTestWindowTest.java
```

**命名规范**：
- 测试类名：`{ClassName}Test.java`
- 测试方法名：`test{MethodName}_{Scenario}`

## 单元测试

### 测试范围

**应该测试**：
- ✅ 业务逻辑方法
- ✅ 数据转换和处理
- ✅ 配置解析和验证
- ✅ 工具类方法

**不需要测试**：
- ❌ 简单的 getter/setter
- ❌ UI 事件处理（除非包含复杂逻辑）
- ❌ 第三方库的功能

### 测试示例

**配置管理测试**：
```java
public class FpManagerTest {
    
    @Test
    public void testLoadConfig_ValidJson_Success() {
        // Arrange
        String configPath = "src/test/resources/fp_config_valid.json";
        
        // Act
        FpManager.init(configPath);
        
        // Assert
        assertTrue(FpManager.getCount() > 0);
        assertNotNull(FpManager.getColumns());
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testLoadConfig_InvalidJson_ThrowsException() {
        // Arrange
        String configPath = "src/test/resources/fp_config_invalid.json";
        
        // Act
        FpManager.init(configPath);
        
        // Assert - 期望抛出异常
    }
    
    @Test
    public void testCheck_MatchingRule_ReturnsResult() {
        // Arrange
        FpManager.init("src/test/resources/fp_config.json");
        String request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        String response = "HTTP/1.1 200 OK\r\n\r\n{\"swagger\":\"2.0\"}";
        
        // Act
        List<FpData> results = FpManager.check(
            request.getBytes(), 
            response.getBytes(), 
            false
        );
        
        // Assert
        assertFalse(results.isEmpty());
        assertEquals("Swagger-UI", results.get(0).getParams().get(0).getV());
    }
}
```

**工具类测试**：
```java
public class StringUtilsTest {
    
    @Test
    public void testIsEmpty_NullString_ReturnsTrue() {
        assertTrue(StringUtils.isEmpty(null));
    }
    
    @Test
    public void testIsEmpty_EmptyString_ReturnsTrue() {
        assertTrue(StringUtils.isEmpty(""));
    }
    
    @Test
    public void testIsEmpty_NonEmptyString_ReturnsFalse() {
        assertFalse(StringUtils.isEmpty("test"));
    }
}
```

## 集成测试

### 测试范围

集成测试验证多个组件协同工作：

```java
public class FpIntegrationTest {
    
    @Test
    public void testFingerprintRecognition_EndToEnd() {
        // 1. 初始化配置
        FpManager.init("src/test/resources/fp_config.json");
        
        // 2. 准备测试数据
        byte[] request = loadTestRequest("swagger-request.txt");
        byte[] response = loadTestResponse("swagger-response.txt");
        
        // 3. 执行指纹识别
        List<FpData> results = FpManager.check(request, response, false);
        
        // 4. 验证结果
        assertFalse(results.isEmpty());
        assertTrue(containsFingerprint(results, "Swagger-UI"));
    }
    
    private byte[] loadTestRequest(String filename) {
        // 从测试资源加载
        return FileUtils.readFileToByteArray(
            new File("src/test/resources/requests/" + filename)
        );
    }
}
```

## 测试数据管理

### 测试资源目录

```
src/test/resources/
├── fp_config.json              # 测试用指纹配置
├── fp_config_invalid.json      # 无效配置（用于异常测试）
├── requests/
│   ├── swagger-request.txt     # 测试请求样本
│   └── normal-request.txt
└── responses/
    ├── swagger-response.txt    # 测试响应样本
    └── normal-response.txt
```

### 测试数据原则

```java
// ✅ 正确：使用真实的测试数据
@Test
public void testParseJson_ValidJson_Success() {
    String json = "{\"name\":\"test\",\"value\":123}";
    JsonObject obj = parseJson(json);
    assertEquals("test", obj.get("name").getAsString());
}

// ❌ 错误：使用 mock 绕过真实逻辑
@Test
public void testParseJson_MockedResult() {
    JsonObject mockObj = mock(JsonObject.class);
    when(mockObj.get("name")).thenReturn(new JsonPrimitive("test"));
    // 这不是真实测试
}
```

## Maven 测试命令

### 运行测试

```cmd
REM 运行所有测试
mvn test

REM 运行特定测试类
mvn test -Dtest=FpManagerTest

REM 运行特定测试方法
mvn test -Dtest=FpManagerTest#testLoadConfig_ValidJson_Success

REM 跳过测试（构建时）
mvn clean package -DskipTests

REM 生成测试报告
mvn surefire-report:report
```

### 测试报告

测试报告位置：
- HTML 报告：`target/surefire-reports/index.html`
- XML 报告：`target/surefire-reports/*.xml`

## 测试最佳实践

### 1. AAA 模式

```java
@Test
public void testMethod() {
    // Arrange - 准备测试数据和环境
    String input = "test";
    
    // Act - 执行被测试的方法
    String result = processInput(input);
    
    // Assert - 验证结果
    assertEquals("TEST", result);
}
```

### 2. 测试命名

```java
// ✅ 正确：清晰描述测试场景
@Test
public void testLoadConfig_FileNotFound_ThrowsException() { }

@Test
public void testCheck_EmptyRequest_ReturnsEmptyList() { }

// ❌ 错误：不清晰的命名
@Test
public void test1() { }

@Test
public void testLoadConfig() { }
```

### 3. 一个测试一个断言（建议）

```java
// ✅ 推荐：专注于一个验证点
@Test
public void testGetCount_AfterInit_ReturnsPositiveNumber() {
    FpManager.init(configPath);
    assertTrue(FpManager.getCount() > 0);
}

// ⚠️ 可接受：相关的多个断言
@Test
public void testLoadConfig_ValidFile_LoadsCorrectly() {
    FpManager.init(configPath);
    assertTrue(FpManager.getCount() > 0);
    assertNotNull(FpManager.getColumns());
    assertFalse(FpManager.getColumnNames().isEmpty());
}
```

### 4. 避免测试依赖

```java
// ❌ 错误：测试之间有依赖
private static FpConfig config;

@Test
public void test1_LoadConfig() {
    config = loadConfig();  // 其他测试依赖这个
}

@Test
public void test2_UseConfig() {
    assertNotNull(config);  // 依赖 test1
}

// ✅ 正确：每个测试独立
@Before
public void setUp() {
    config = loadConfig();  // 每个测试前都初始化
}

@Test
public void testLoadConfig() {
    assertNotNull(config);
}

@Test
public void testUseConfig() {
    assertNotNull(config);
}
```

### 5. 使用 @Before 和 @After

```java
public class FpManagerTest {
    
    private String configPath;
    
    @Before
    public void setUp() {
        // 每个测试前执行
        configPath = "src/test/resources/fp_config.json";
        FpManager.init(configPath);
    }
    
    @After
    public void tearDown() {
        // 每个测试后执行
        FpManager.clearCache();
    }
    
    @Test
    public void testGetCount() {
        assertTrue(FpManager.getCount() > 0);
    }
}
```

## 测试覆盖率

### 目标

- **核心业务逻辑**：80%+ 覆盖率
- **工具类**：70%+ 覆盖率
- **UI 代码**：不强制要求

### 查看覆盖率

使用 JaCoCo 插件：

```xml
<!-- 在 pom.xml 中添加 -->
<plugin>
    <groupId>org.jacoco</groupId>
    <artifactId>jacoco-maven-plugin</artifactId>
    <version>0.8.8</version>
    <executions>
        <execution>
            <goals>
                <goal>prepare-agent</goal>
            </goals>
        </execution>
        <execution>
            <id>report</id>
            <phase>test</phase>
            <goals>
                <goal>report</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

```cmd
REM 生成覆盖率报告
mvn clean test jacoco:report

REM 查看报告
REM 打开 target/site/jacoco/index.html
```

## 常见问题

### 1. 测试失败但功能正常

**原因**：测试数据或环境问题

**解决**：
- 检查测试资源文件是否存在
- 验证测试数据格式是否正确
- 确认测试环境配置

### 2. 测试运行缓慢

**原因**：测试包含耗时操作

**解决**：
- 使用测试数据而非真实 API 调用
- 减少不必要的初始化
- 考虑使用 @BeforeClass 共享初始化

### 3. 测试不稳定（时而通过时而失败）

**原因**：测试依赖外部状态或时间

**解决**：
- 确保测试独立性
- 避免依赖系统时间
- 清理测试后的状态

## 总结

1. **专注核心**：测试核心业务逻辑，避免过度测试
2. **保持简单**：测试代码应该简单易懂
3. **快速执行**：测试应该快速提供反馈
4. **真实验证**：使用真实数据，不要用 mock 绕过逻辑
5. **遵守限制**：最多 2 次验证尝试，达到限制后请求用户指导
