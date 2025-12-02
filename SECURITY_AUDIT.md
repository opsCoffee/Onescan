# OneScan Security Audit Report

## Executive Summary

The OneScan BurpSuite plugin is a reconnaissance and directory scanning tool written in Java 17. This comprehensive security audit identified **7 security vulnerabilities** spanning multiple OWASP categories, ranging from **Medium to Critical severity**. Most issues relate to insecure string handling in regex operations, weak cryptography, unsafe deserialization, and insufficient input validation.

**Overall Risk Level: MEDIUM-HIGH**

---

## Detailed Findings

### 1. OWASP A3:2021 - Injection (ReDoS - Regular Expression Denial of Service)

**Severity: HIGH**

**Location:**
- `/home/runner/work/Onescan/Onescan/src/main/java/burp/onescan/ui/widget/payloadlist/rule/MatchReplace.java:59`
- `/home/runner/work/Onescan/Onescan/src/main/java/burp/onescan/common/FpMethodHandler.java:134-170`

**Issue Description:**

The plugin compiles and uses user-supplied regex patterns directly without validation, creating ReDoS (Regular Expression Denial of Service) vulnerabilities:

```java
// Line 59 - MatchReplace.java
public String handleProcess(String content) {
    String[] values = getParamValues();
    String regex = values[0];  // User-controlled!
    String value = values[1];
    return content.replaceAll(regex, value);  // VULNERABLE
}
```

```java
// Line 136 - FpMethodHandler.java
public static boolean regex(String data, String content) {
    try {
        Pattern pattern = Pattern.compile(content);  // User input!
        return pattern.matcher(data).find();
    } catch (Exception var3) {
        Logger.error("Regex compile error: %s", var3.getMessage());
        return false;
    }
}
```

**Impact:**
- Malicious regex patterns can cause exponential backtracking
- Attacker can craft payloads that consume 100% CPU, hanging the Burp Suite interface
- Fingerprint matching rules loaded from config files are vulnerable

**Example Attack:**
```
Regex: (a+)+b
Input: aaaaaaaaaaaaaaaaaaaaaaaac
Result: ~2^20 backtracking attempts, complete hang
```

**Recommendation:**
1. Implement regex timeout using `Pattern.compile()` with timeout mechanism
2. Add regex validation to detect catastrophic backtracking patterns
3. Use Apache Commons Lang `RegexUtils` or implement pattern complexity scoring
4. Enforce strict regex patterns from config files with validation

**Fix Example:**
```java
private static final Pattern REGEX_TIMEOUT_PATTERN = Pattern.compile("...");

public static boolean regex(String data, String content, long timeoutMs) {
    try {
        Pattern pattern = Pattern.compile(content);
        Matcher matcher = pattern.matcher(data);
        
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<Boolean> future = executor.submit(() -> matcher.find());
        
        return future.get(timeoutMs, TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
        return false; // Regex took too long
    }
}
```

---

### 2. OWASP A5:2021 - Cryptographic Failures (Weak Hash Algorithm)

**Severity: MEDIUM**

**Location:**
- `/home/runner/work/Onescan/Onescan/src/main/java/burp/common/utils/Utils.java:129-138`
- `/home/runner/work/Onescan/Onescan/src/main/java/burp/onescan/bean/FpHttpReqDS.java`
- `/home/runner/work/Onescan/Onescan/src/main/java/burp/onescan/bean/FpHttpDS.java`

**Issue Description:**

The application uses MD5 hashing for caching and duplicate detection, which is cryptographically broken:

```java
// Utils.java - Line 129-138
public static String md5(byte[] bytes) {
    try {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(bytes);
        byte[] digest = md.digest();
        return bytesToHex(digest);
    } catch (Exception e) {
        Logger.error(e.getMessage());
    }
    return "";
}
```

**Usage Examples:**
```java
// FpHttpDS.java - Response body hashing for caching
this.bodyMd5 = Utils.md5(bodyBytes);

// FpHttpReqDS.java - Request hashing for caching
return Utils.md5(dataBytes);
```

**Impact:**
- MD5 is vulnerable to collision attacks (practical attacks demonstrated in 2004)
- Cache poisoning: attacker can craft two different responses with same MD5
- Configuration integrity: headers are verified using MD5 (line 195 in Config.java)
- Fingerprint identification can be bypassed

**Severity Justification:**
- MD5 is no longer considered secure for cryptographic purposes
- NIST deprecated MD5 in 2019
- While cache collisions are unlikely in practice, it violates security standards

**Recommendation:**
1. Replace MD5 with SHA-256 for all hashing operations
2. Use SHA-256 for fingerprint caching and duplicate detection
3. Audit all existing cached data for poisoning

**Fix:**
```java
public static String sha256(byte[] bytes) {
    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(bytes);
        byte[] digest = md.digest();
        return bytesToHex(digest);
    } catch (Exception e) {
        Logger.error(e.getMessage());
    }
    return "";
}
```

---

### 3. OWASP A8:2021 - Software & Data Integrity Failures (Unsafe Deserialization)

**Severity: HIGH**

**Location:**
- `/home/runner/work/Onescan/Onescan/src/main/java/burp/common/utils/ClassUtils.java:152-176`

**Issue Description:**

The `deepCopy` method uses Java serialization/deserialization without validation:

```java
// ClassUtils.java - Line 152-176
public static <T extends Serializable> T deepCopy(T obj) {
    if (obj == null) {
        return null;
    }
    ByteArrayOutputStream bos = null;
    ObjectOutputStream oos = null;
    ByteArrayInputStream bis = null;
    ObjectInputStream ois = null;
    try {
        bos = new ByteArrayOutputStream();
        oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        bis = new ByteArrayInputStream(bos.toByteArray());
        ois = new ObjectInputStream(bis);
        return (T) ois.readObject();  // VULNERABLE!
    } catch (Exception e) {
        e.printStackTrace();
        return null;
    }
}
```

**Impact:**
- Arbitrary code execution if attacker can control serialized objects
- ClassUtils reflection utilities (lines 22-33) allow field access modification
- Combined with malicious gadgets, could lead to RCE
- Objects copied internally may contain untrusted data

**Attack Scenario:**
```
1. Attacker crafts malicious serialized payload
2. If plugin copies untrusted config objects, gadget chain executes
3. Result: RCE in Burp Suite context
```

**Recommendation:**
1. Avoid Java serialization for untrusted data
2. Implement `ObjectInputFilter` (Java 9+) to restrict deserialization
3. Replace deep copy with explicit field-by-field copying
4. If serialization must be used, disable for external/config data

**Fix:**
```java
public static <T extends Serializable> T deepCopy(T obj) {
    // Use explicit copying instead of serialization
    if (obj instanceof ProcessingItem) {
        ProcessingItem original = (ProcessingItem) obj;
        ProcessingItem copy = new ProcessingItem();
        // Manually copy fields...
        return (T) copy;
    }
    // Or use reflection with whitelisted fields only
}
```

---

### 4. OWASP A4:2021 - Insecure Design (Missing Input Validation in Regex)

**Severity: HIGH**

**Location:**
- `/home/runner/work/Onescan/Onescan/src/main/java/burp/onescan/manager/FpManager.java:89-102`
- `/home/runner/work/Onescan/Onescan/src/main/java/burp/onescan/manager/FpManager.java:330-346`

**Issue Description:**

YAML fingerprint configuration files are loaded with `Yaml.load()` using limited protections. While `LoaderOptions` are configured, the patterns themselves are compiled without validation:

```java
// FpManager.java - Line 88-94
LoaderOptions options = new LoaderOptions();
options.setMaxAliasesForCollections(50);
options.setAllowDuplicateKeys(false);
options.setCodePointLimit(2_000_000);
options.setNestingDepthLimit(50);
Yaml yaml = new Yaml(options);
Object obj = yaml.load(content);  // Loads untrusted YAML
```

```java
// FpManager.java - Line 340-346
rule.setCompiled(java.util.regex.Pattern.compile(content));
```

**Issues:**
1. No validation of regex complexity before compilation
2. Config file path traversal not protected (if editable by attacker)
3. No signature verification for fingerprint configs

**Recommendation:**
1. Validate regex patterns before compilation
2. Implement pattern complexity limits
3. Sign/verify fingerprint configuration files
4. Restrict fingerprint directory permissions

---

### 5. OWASP A7:2021 - Cross-Site Scripting (XSS) Risk in String Handling

**Severity: MEDIUM**

**Location:**
- `/home/runner/work/Onescan/Onescan/src/main/java/burp/onescan/ui/widget/payloadlist/rule/MatchReplace.java:44-51`

**Issue Description:**

The replacement value in `MatchReplace` is used without escaping in `replaceAll()`. While not directly XSS (since it's not rendered to web), the replacement can inject special characters:

```java
public String handleProcess(String content) {
    String[] values = getParamValues();
    String regex = values[0];
    String value = values[1];  // User-controlled replacement!
    return content.replaceAll(regex, value);  // Special chars not escaped
}
```

**Issue:** The replacement string can contain backreferences like `$1`, `$2` that will be interpreted by `replaceAll()`:

```java
// If user sets:
regex = "(.+)"
replacement = "$1\n$1"  // Will repeat matched group with newline

// Results in unintended data modification
```

**Impact:**
- Unintended payload modification
- Log injection: injected newlines/special chars in logs
- Potential confusion of scanning results

**Recommendation:**
1. Use `Matcher.quoteReplacement()` to escape replacement string
2. Add warning about special regex replacement characters
3. Validate user input patterns

**Fix:**
```java
public String handleProcess(String content) {
    String[] values = getParamValues();
    String regex = values[0];
    String value = values[1];
    return content.replaceAll(regex, Matcher.quoteReplacement(value));
}
```

---

### 6. OWASP A1:2021 - Broken Access Control (Missing Path Traversal Protection)

**Severity: MEDIUM**

**Location:**
- `/home/runner/work/Onescan/Onescan/src/main/java/burp/onescan/manager/WordlistManager.java`
- `/home/runner/work/Onescan/Onescan/src/main/java/burp/BurpExtender.java:165-171`

**Issue Description:**

File paths are constructed using string concatenation without canonicalization:

```java
// WordlistManager.java - Dynamic path construction
String path = sWordlistDir + File.separator + key + File.separator + item + ".txt";
```

```java
// BurpExtender.java - Line 165-171
private String getWorkDir() {
    String workDir = Paths.get(mCallbacks.getExtensionFilename())
            .getParent().toString() + File.separator + "OneScan" + File.separator;
    if (FileUtils.isDir(workDir)) {
        return workDir;
    }
    return null;  // Falls back to user config directory
}
```

**Potential Paths:**
```
Normal: ~/.config/OneScan/wordlist/payload/default.txt
Attack: ~/.config/OneScan/wordlist/../../etc/passwd
Attack: ~/.config/OneScan/wordlist/payload/../../../../bin/sh
```

**Impact:**
- If user input is not validated in word list renaming operations
- Attacker could read/overwrite arbitrary files in plugin directory
- Limited impact since plugin runs in BurpSuite context

**Recommendation:**
1. Validate all file paths using `File.getCanonicalPath()`
2. Ensure resolved path is within expected directory
3. Use `Files.getCanonicalPath()` for validation

**Fix:**
```java
private String sanitizePath(String basePath, String userInput) {
    File baseFile = new File(basePath).getCanonicalFile();
    File resolvedFile = new File(basePath, userInput).getCanonicalFile();
    
    if (!resolvedFile.getPath().startsWith(baseFile.getPath())) {
        throw new IllegalArgumentException("Path traversal detected");
    }
    return resolvedFile.getAbsolutePath();
}
```

---

### 7. OWASP A5:2021 - Broken Logging (Sensitive Data Exposure in Logs)

**Severity: LOW-MEDIUM**

**Location:**
- `/home/runner/work/Onescan/Onescan/src/main/java/burp/common/log/Logger.java`
- Multiple locations logging request/response data

**Issue Description:**

The logger outputs to stdout/stderr with debug mode enabled:

```java
// Logger.java - Line 39-46
public static void debug(String format, Object... args) {
    if (!isDebug) {
        return;
    }
    if (StringUtils.isEmpty(format)) {
        return;
    }
    stdout.format(format + System.lineSeparator(), args);  // Direct output
}
```

**Examples of Sensitive Logs:**
- BurpExtender.java:343 - `Logger.debug("doScan receive: %s", url.toString());`
- BurpExtender.java:759 - `Logger.debug("Do Send Request id: %s", reqId);`

**When DEBUG=true:**
- Full URLs logged including query parameters
- Request IDs logged (could reveal patterns)
- Dynamic variables logged (IPs, domains, timestamps)

**Impact:**
- Sensitive URLs exposed in Burp logs
- Attack patterns visible in logs
- Information disclosure if logs are captured

**Recommendation:**
1. Never log sensitive data (URLs, credentials, tokens)
2. Implement log masking for sensitive fields
3. Use `Constants.DEBUG` sparingly
4. Document what's logged when DEBUG is enabled

---

## Summary Table

| # | Vulnerability | Severity | Category | File | CWE |
|---|---|---|---|---|---|
| 1 | ReDoS in Regex | HIGH | Injection | MatchReplace.java, FpMethodHandler.java | CWE-1333 |
| 2 | MD5 Hashing | MEDIUM | Cryptography | Utils.java, FpHttpDS.java | CWE-327 |
| 3 | Unsafe Deserialization | HIGH | Integrity | ClassUtils.java | CWE-502 |
| 4 | Missing Pattern Validation | HIGH | Insecure Design | FpManager.java | CWE-434 |
| 5 | Regex Replacement Injection | MEDIUM | Injection | MatchReplace.java | CWE-95 |
| 6 | Path Traversal | MEDIUM | Access Control | WordlistManager.java | CWE-22 |
| 7 | Sensitive Data Logging | LOW-MEDIUM | Logging | Logger.java | CWE-532 |

---

## Remediation Priority

### Immediate (Critical)
1. **ReDoS Protection** - Implement regex timeout mechanism
2. **Deserialization Safety** - Add ObjectInputFilter or replace serialization

### High Priority
3. **Pattern Validation** - Validate regex complexity before compilation
4. **Path Traversal** - Canonicalize all file paths

### Medium Priority
5. **Cryptography** - Replace MD5 with SHA-256
6. **Replacement Escaping** - Use `Matcher.quoteReplacement()`

### Low Priority
7. **Logging** - Mask sensitive data in logs

---

## Testing Recommendations

### ReDoS Testing
```java
// Test cases for ReDoS vulnerability
@Test
public void testReDoSDetection() {
    String maliciousRegex = "(a+)+b";
    String data = "aaaaaaaaaaaaaaaaaaaaaaaac";
    
    // Should timeout, not hang
    assertTimeoutPreemptively(Duration.ofSeconds(2), () -> {
        FpMethodHandler.regex(data, maliciousRegex);
    });
}
```

### Deserialization Testing
```java
// Verify ObjectInputFilter is applied
@Test
public void testDeserializationSafety() {
    // Attempt gadget chain deserialization
    // Should be blocked by filter
}
```

### Path Traversal Testing
```java
@Test
public void testPathTraversalPrevention() {
    String attack = "../../etc/passwd";
    assertThrows(IllegalArgumentException.class, () -> {
        WordlistManager.validatePath(baseDir, attack);
    });
}
```

---

## References

1. **CWE-1333** - Inefficient Regular Expression Complexity
   - https://cwe.mitre.org/data/definitions/1333.html

2. **CWE-327** - Use of Broken/Risky Cryptographic Algorithm
   - https://cwe.mitre.org/data/definitions/327.html

3. **CWE-502** - Deserialization of Untrusted Data
   - https://cwe.mitre.org/data/definitions/502.html

4. **OWASP Top 10 2021**
   - https://owasp.org/Top10/

5. **Java Regular Expression DoS**
   - https://www.regular-expressions.info/catastrophic.html

6. **SnakeYAML Security**
   - https://github.com/snakeyaml/snakeyaml/wiki/Documentation

---

## Conclusion

The OneScan plugin demonstrates generally good code structure and design practices. However, the identified vulnerabilities, particularly around regex handling and unsafe deserialization, require immediate attention. The high risk of ReDoS attacks is the most critical issue, as it could render BurpSuite unresponsive.

**Recommended Action:** Address vulnerabilities #1-3 within the next release cycle. Implement the suggested fixes and add security-focused unit tests to prevent regression.

