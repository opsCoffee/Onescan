# Montoya API 版本更新说明

## 版本信息

- **当前版本**: v2023.12.1
- **最新版本**: v2025.5（截至2025年10月的最新稳定版本）
- **建议操作**: 升级到最新版本

## 版本差异

根据PortSwigger官方GitHub仓库，Montoya API从2023.12.1到2025.5经历了多次更新，主要改进包括：

1. **API稳定性提升** - 更成熟的接口设计
2. **性能优化** - 编辑器组件性能改进
3. **Bug修复** - 修复了已知问题
4. **新功能** - 可能包含新的API方法和功能

## Maven依赖配置

### 当前配置 (v2023.12.1)

```xml
<dependency>
    <groupId>net.portswigger.burp.extensions</groupId>
    <artifactId>montoya-api</artifactId>
    <version>2023.12.1</version>
</dependency>
```

### 推荐配置 (v2025.5)

```xml
<dependency>
    <groupId>net.portswigger.burp.extensions</groupId>
    <artifactId>montoya-api</artifactId>
    <version>2025.5</version>
</dependency>
```

### Gradle配置 (v2025.5)

```gradle
implementation 'net.portswigger.burp.extensions:montoya-api:2025.5'
```

## 升级步骤

1. **更新POM文件**
   ```bash
   # 编辑 montoya-api/pom.xml
   # 将 <version>2023.12.1</version> 改为 <version>2025.5</version>
   ```

2. **清理并重新构建**
   ```bash
   mvn clean install
   ```

3. **测试兼容性**
   - 运行现有测试用例
   - 验证插件功能正常
   - 检查是否有API变更影响

4. **更新文档**
   - 更新README.md中的版本信息
   - 更新开发者文档

## API兼容性

根据Montoya API的设计原则，版本更新通常保持向后兼容。我们使用的核心API方法在v2025.5中仍然可用：

### 确认可用的API方法

✅ **HttpRequestEditor**
- `HttpRequest getRequest()`
- `void setRequest(HttpRequest request)`
- `Component uiComponent()`
- `boolean isModified()`

✅ **HttpResponseEditor**
- `HttpResponse getResponse()`
- `void setResponse(HttpResponse response)`
- `Component uiComponent()`
- `boolean isModified()`

✅ **UserInterface**
- `HttpRequestEditor createHttpRequestEditor(EditorOptions... options)`
- `HttpResponseEditor createHttpResponseEditor(EditorOptions... options)`

## 注意事项

1. **测试环境**: 建议先在测试环境中升级并验证
2. **Burp Suite版本**: 确保Burp Suite版本与Montoya API版本匹配
3. **依赖冲突**: 检查是否有其他依赖与新版本冲突
4. **功能验证**: 重点测试HTTP编辑器相关功能

## 参考资源

- [Montoya API GitHub仓库](https://github.com/portswigger/burp-extensions-montoya-api)
- [Montoya API文档](https://portswigger.github.io/burp-extensions-montoya-api/)
- [Maven Central仓库](https://central.sonatype.com/artifact/net.portswigger.burp.extensions/montoya-api)
