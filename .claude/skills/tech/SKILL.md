---
name: tech
description: Technology stack and build system constraints. Java 17 compilation target, Maven only (no Gradle), Montoya API exclusively (no legacy Burp Extender API), Windows platform (cmd-compatible commands). Single-module Maven structure, core dependencies (Montoya API v2025.5, Gson, SnakeYAML), build commands, assembly plugin configuration. Java 17 feature usage guidelines. Use when setting up build, managing dependencies, or ensuring Java 17 compatibility.
---

# Technology Stack & Build System

## Critical Constraints

- **Java 17 (JDK 17)** - Current compilation target
- **Maven only** - Gradle is prohibited
- **Montoya API exclusively** - Never use legacy Burp Extender API in new code
- **Windows platform** - Use cmd-compatible commands (& not &&, dir not ls)

## Maven Single-Module Structure

```
onescan/                    # Single module project (v2.2.0)
├── src/                    # Source code
│   ├── main/
│   └── test/
├── target/                 # Build output
└── pom.xml                 # Maven POM
```

## Core Dependencies

### Burp Suite API

- **Montoya API** v2025.5 - Current version in project
  - Use for all Burp integration
  - Key interfaces: `MontoyaApi`, `HttpRequestEditor`, `HttpResponseEditor`
  - Documentation: https://portswigger.github.io/burp-extensions-montoya-api/

**Version Update Strategy**:
- Check for updates: https://github.com/portswigger/burp-extensions-montoya-api/releases
- Before updating: Review breaking changes in release notes
- Test compatibility: Verify all Montoya API usage after update
- Update path: Modify `pom.xml` version tag

### Other Dependencies

- **Gson** v2.10.1 - JSON processing
- **SnakeYAML** v2.2 - YAML config

## Build Commands (Windows cmd)

```cmd
REM Full build
mvn clean package

REM Skip tests
mvn clean package -DskipTests

REM Run tests
mvn test

REM Specific test
mvn test -Dtest=ClassName#methodName
```

## Build Output

- **Artifact**: `OneScan-v{version}.jar` in `target/`
- **Type**: Uber JAR with all dependencies
- **Assembly**: Uses maven-assembly-plugin with jar-with-dependencies descriptor

## Java 17 Feature Usage Guidelines

Java 17 is an LTS release with many modern features that **should be used** to improve code quality:

### ✅ Recommended Java 17 Features

**Lambda Expressions & Stream API** (Java 8+):
```java
// ✅ Good: Use lambda for cleaner code
list.forEach(item -> System.out.println(item));

// ✅ Good: Use streams for collection processing
List<String> filtered = list.stream()
    .filter(s -> s.startsWith("test"))
    .collect(Collectors.toList());
```

**Optional** (Java 8+):
```java
// ✅ Good: Use Optional to avoid null checks
Optional<String> result = findValue();
return result.orElse("default");
```

**var keyword** (Java 10+):
```java
// ✅ Good: Use var for local variables with obvious types
var list = new ArrayList<String>();
var result = calculateSomething();
```

**Text Blocks** (Java 13+):
```java
// ✅ Good: Use text blocks for multi-line strings
String json = """
    {
        "name": "OneScan",
        "version": "2.2.0"
    }
    """;
```

**Records** (Java 14+):
```java
// ✅ Good: Use records for simple data carriers
public record FingerprintResult(String name, String value, boolean matched) {}
```

**Pattern Matching for instanceof** (Java 16+):
```java
// ✅ Good: Use pattern matching
if (obj instanceof String s) {
    System.out.println(s.toUpperCase());
}
```

**Sealed Classes** (Java 17):
```java
// ✅ Good: Use sealed classes for controlled inheritance
public sealed interface Result permits Success, Failure {}
```

### 📝 Best Practices

1. **Use modern Java features** to write cleaner, more maintainable code
2. **Leverage records** for DTOs and simple data structures
3. **Use text blocks** for JSON, SQL, and multi-line strings
4. **Apply pattern matching** to reduce boilerplate code
5. **Keep it readable** - don't over-complicate with functional programming
