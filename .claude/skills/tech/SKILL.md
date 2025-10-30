---
name: tech
description: Technology stack and build system constraints. Strict Java 8 (JDK 1.8) compilation target, Maven only (no Gradle), Montoya API exclusively (no legacy Burp Extender API), Windows platform (cmd-compatible commands). Maven multi-module structure, core dependencies (Montoya API v2023.12.1, Gson, SnakeYAML), build commands, dependency shading. Java 8 feature usage guidelines (lambdas, streams, Optional recommended; avoid Java 9+ features). Use when setting up build, managing dependencies, or ensuring Java 8 compatibility.
---

# Technology Stack & Build System

## Critical Constraints

- **Java 8 (JDK 1.8)** - Strict compilation target, do not use Java 9+ features
- **Maven only** - Gradle is prohibited
- **Montoya API exclusively** - Never use legacy Burp Extender API in new code
- **Windows platform** - Use cmd-compatible commands (& not &&, dir not ls)

## Maven Multi-Module Structure

```
onescan/                    # Parent POM (v2.1.9)
├── burp-extender-api/     # v2.3 (legacy, do not modify)
├── montoya-api/           # v2023.12.1 (current in project)
└── extender/              # Main plugin implementation
```

## Core Dependencies

### Burp Suite API

- **Montoya API** v2023.12.1 - Current version in project
  - Use for all Burp integration
  - Key interfaces: `MontoyaApi`, `HttpRequestEditor`, `HttpResponseEditor`
  - Documentation: https://portswigger.github.io/burp-extensions-montoya-api/

**Version Update Strategy**:
- Check for updates: https://github.com/portswigger/burp-extensions-montoya-api/releases
- Before updating: Review breaking changes in release notes
- Test compatibility: Verify all Montoya API usage after update
- Update path: Modify `montoya-api/pom.xml` version tag

**Latest Known Versions** (as of 2024):
- v2024.x.x series available
- Check GitHub releases for latest stable version
- Consider updating to benefit from new features and bug fixes

### Other Dependencies

- **Gson** v2.10.1 - JSON processing (shaded as `burp.vaycore.shaded.gson`)
- **SnakeYAML** v2.2 - YAML config (shaded as `burp.vaycore.shaded.yaml`)

## Build Commands (Windows cmd)

```cmd
REM Full build
mvn clean package

REM Plugin only (faster)
cd extender & mvn clean package

REM Skip tests
mvn clean package -DskipTests

REM Run tests
mvn test

REM Specific test
mvn test -Dtest=ClassName#methodName
```

## Build Output

- **Artifact**: `OneScan-v{version}.jar` in `extender/target/`
- **Type**: Uber JAR with shaded dependencies
- **Exclusions**: Signature files (*.SF, *.DSA, *.RSA)

## Dependency Shading

When adding dependencies that might conflict with Burp:
- Relocate packages using maven-shade-plugin
- Pattern: `burp.vaycore.shaded.{library}`
- Exclude signature files from META-INF

## Java 8 Feature Usage Guidelines

Java 8 introduced many modern features that **should be used** to improve code quality:

### ✅ Recommended Java 8 Features

**Lambda Expressions**:
```java
// ✅ Good: Use lambda for cleaner code
list.forEach(item -> System.out.println(item));

// ❌ Avoid: Verbose anonymous class
list.forEach(new Consumer<String>() {
    public void accept(String item) {
        System.out.println(item);
    }
});
```

**Stream API**:
```java
// ✅ Good: Use streams for collection processing
List<String> filtered = list.stream()
    .filter(s -> s.startsWith("test"))
    .collect(Collectors.toList());
```

**Optional**:
```java
// ✅ Good: Use Optional to avoid null checks
Optional<String> result = findValue();
return result.orElse("default");
```

**Method References**:
```java
// ✅ Good: Use method references when appropriate
list.forEach(System.out::println);
```

### ⚠️ Features to Avoid (Not in Java 8)

- `var` keyword (Java 10+)
- Text blocks `"""` (Java 13+)
- Records (Java 14+)
- Pattern matching (Java 14+)
- Sealed classes (Java 17+)

### 📝 Best Practices

1. **Use Java 8 features** to write cleaner, more maintainable code
2. **Avoid Java 9+ features** to maintain compatibility
3. **Test thoroughly** when using streams and lambdas for performance-critical code
4. **Keep it readable** - don't over-complicate with functional programming
