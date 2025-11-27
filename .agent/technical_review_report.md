# OneScan Technical Review Report

## 1. Executive Summary
The OneScan codebase is a functional Burp Suite extension but suffers from significant technical debt, particularly in error handling, code organization, and test coverage. The most critical issues are the widespread swallowing of exceptions and the lack of automated tests. `BurpExtender` acts as a "God Class," making maintenance difficult.

## 2. Logic Errors (High Priority)

### 2.1 Swallowed Exceptions
**Description**: Multiple utility classes catch `Exception` or `IOException` and simply print the stack trace or log an error without propagating the failure or handling it gracefully. This leads to silent failures and null pointer exceptions downstream.
**Locations**:
- `src/main/java/burp/common/utils/Utils.java`: `getSysClipboardText`, `md5`
- `src/main/java/burp/common/utils/FileUtils.java`: `writeFile`, `readFile`, `readStreamToList`
- `src/main/java/burp/common/utils/IOUtils.java`: `closeIO`, `readStream`
- `src/main/java/burp/common/utils/GsonUtils.java`: `toJson`, `toObject`, `toMap`, `toList`
**Impact**: Debugging is difficult; application state may become inconsistent.
**Fix**: Use specific exceptions, propagate them where appropriate, or return `Optional<T>`.

### 2.2 Hardcoded Ports
**Description**: `Utils.isIgnorePort` hardcodes ports 80 and 443.
**Location**: `src/main/java/burp/common/utils/Utils.java`
**Impact**: Inflexible if protocols change or non-standard ports are used.
**Fix**: Move to configuration or constants.

## 3. Redundant Code (Medium Priority)

### 3.1 Duplicate I/O Logic
**Description**: `FileUtils` implements `readStreamToString` and `readFile` logic that partially overlaps with `IOUtils`.
**Location**: `src/main/java/burp/common/utils/FileUtils.java` vs `src/main/java/burp/common/utils/IOUtils.java`
**Fix**: Refactor `FileUtils` to strictly use `IOUtils` for stream operations.

### 3.2 Manual Hash Implementation
**Description**: `IconHash.java` contains a manual implementation of Murmur3 hash, copied from Google Guava.
**Location**: `src/main/java/burp/common/helper/IconHash.java`
**Fix**: Replace with a dependency on Google Guava or Apache Commons Codec to reduce maintenance burden.

## 4. Technical Debt (Medium Priority)

### 4.1 God Class (`BurpExtender`)
**Description**: `BurpExtender.java` is ~1900 lines long and handles UI, Business Logic, and Burp integration.
**Location**: `src/main/java/burp/BurpExtender.java`
**Impact**: Hard to read, test, and maintain. High risk of regression during changes.
**Fix**: Extract logic into `ScanManager`, `UIManager`, `ConfigManager`.

### 4.2 Zero Test Coverage
**Description**: `mvn test` reports "No tests to run".
**Impact**: No safety net for refactoring.
**Fix**: Add JUnit tests, starting with utility classes (`Utils`, `FileUtils`, `GsonUtils`).

### 4.3 Manual Hex/Base64 Implementation
**Description**: `Utils.bytesToHex` is manually implemented.
**Location**: `src/main/java/burp/common/utils/Utils.java`
**Fix**: Use `java.util.HexFormat` (Java 17+) or Apache Commons Codec.

## 5. Fix Proposals & Prioritization

| Priority | Issue | Estimated Effort | Proposal |
| :--- | :--- | :--- | :--- |
| **High** | Swallowed Exceptions | Medium | Refactor `Utils` classes to throw checked exceptions or use `Optional`. Add proper logging. |
| **High** | Zero Test Coverage | High | Add JUnit 5 and Mockito. Write tests for Utils first, then core logic. |
| **Medium** | God Class (`BurpExtender`) | High | Extract `ScanController` and `PayloadProcessor` from `BurpExtender`. |
| **Medium** | Redundant I/O | Low | Simplify `FileUtils` to delegate to `IOUtils`. |
| **Low** | Manual Hash/Hex | Low | Replace with library calls. |

## 6. Example Fix (Swallowed Exception)

**Current (`GsonUtils.java`):**
```java
public static <T> T toObject(String json, Class<T> clz) {
    try {
        return sGson.fromJson(json, clz);
    } catch (Exception e) {
        e.printStackTrace();
        return null;
    }
}
```

**Proposed:**
```java
public static <T> Optional<T> toObject(String json, Class<T> clz) {
    if (StringUtils.isEmpty(json)) {
        return Optional.empty();
    }
    try {
        return Optional.ofNullable(sGson.fromJson(json, clz));
    } catch (JsonSyntaxException e) {
        Logger.error("JSON Parse Error: " + e.getMessage());
        return Optional.empty();
    }
}
```
