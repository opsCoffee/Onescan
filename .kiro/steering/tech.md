---
inclusion: always
---

# Technology Stack

## Build System

**Maven** (multi-module project) - Pure Maven builds required, Gradle is not permitted.

## Language & Runtime

- **Java 8** (JDK 1.8) - Current compilation target
- **Note**: CLAUDE.md mentions Java 17 as a future standard, but current POMs use Java 8

## Project Modules

```
onescan/                    # Parent POM
├── burp-extender-api/     # Burp Extender API v2.3 (legacy)
├── montoya-api/           # Montoya API v2023.12.1 (current standard)
└── extender/              # Main plugin implementation v2.1.9
```

## Core Dependencies

- **Burp Extender API** v2.3 - Legacy Burp extension interface
- **Montoya API** v2023.12.1 - Modern Burp extension API (must use exclusively)
- **Gson** v2.10.1 - JSON processing (shaded to avoid conflicts)
- **SnakeYAML** v2.2 - YAML configuration support (shaded)

## Common Commands

### Build Commands

```bash
# Full build (all modules)
mvn clean package

# Quick build (plugin only)
cd extender && mvn clean package

# Skip tests
mvn clean package -DskipTests

# Show compiler warnings
mvn compile -Dmaven.compiler.showWarnings=true
```

### Testing Commands

```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=ClassName

# Run specific test method
mvn test -Dtest=ClassName#methodName

# Generate test report
mvn surefire-report:report
```

### Development Commands

```bash
# View dependency tree
mvn dependency:tree

# Check for dependency updates
mvn versions:display-dependency-updates

# Validate project structure
mvn validate
```

## Build Output

- **Artifact**: `OneScan-v{version}.jar`
- **Location**: `extender/target/`
- **Type**: Uber JAR (includes all dependencies via maven-assembly-plugin)

## Shading Configuration

Dependencies are relocated to avoid conflicts:
- `com.google.gson` → `burp.vaycore.shaded.gson`
- `org.yaml.snakeyaml` → `burp.vaycore.shaded.yaml`

Excluded from final JAR: signature files (*.SF, *.DSA, *.RSA), META-INF manifests
