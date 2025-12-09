# 导入URL扫描功能Bug分析

## 问题描述

- **现象**：导入多个URL（如 URL1, URL2, URL3）进行扫描时，只有第一个URL被扫描，后续URL没有被扫描
- **触发条件**：使用特定字典文件 `dd.txt` 时出现问题
- **临时解决方案**：切换到其他字典（如 `default.txt`）后重新扫描，问题消失

## 字典文件对比

| 属性 | dd.txt (有问题) | default.txt (正常) |
|------|----------------|-------------------|
| 文件大小 | 9940 字节 | 1752 字节 |
| 行数 | 348 行 | 92 行 |
| 编码 | UTF-8 (无BOM) | UTF-8 (无BOM) |
| 换行符 | LF (0x0A) | LF (0x0A) |
| 超过8KB缓冲区 | ✅ 是 | ❌ 否 |

## 已排除的可能原因

1. **编码问题** - 两个文件都是 UTF-8 编码，无 BOM
2. **换行符问题** - 两个文件都使用 LF 换行符
3. **空行问题** - 两个文件都没有空行
4. **文件内容格式** - 第一行内容相同，格式一致

## 高度怀疑的问题点

### `BufferedReader.ready()` 的错误使用

**问题代码位置**：`src/main/java/burp/common/utils/FileUtils.java` 第 138-152 行

```java
public static ArrayList<String> readStreamToList(InputStream is) {
    try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
        ArrayList<String> lines = new ArrayList<>();
        while (br.ready()) {  // <-- 问题在这里！
            String line = br.readLine();
            if (StringUtils.isNotEmpty(line)) {
                lines.add(line);
            }
        }
        return lines;
    }
}
```

**问题分析**：

`BufferedReader.ready()` 方法返回 `true` 仅当缓冲区中有数据可以**立即**读取，而不是表示"文件还有更多内容"。

- `BufferedReader` 默认缓冲区大小：**8192 字节 (8KB)**
- `dd.txt` 文件大小：**9940 字节**，超过缓冲区
- `default.txt` 文件大小：**1752 字节**，未超过缓冲区

当文件大小超过缓冲区时，`ready()` 可能在缓冲区数据读完后返回 `false`，导致：
- 文件读取不完整
- 或者在某些并发/时序条件下返回异常结果

**正确的写法应该是**：

```java
public static ArrayList<String> readStreamToList(InputStream is) {
    try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
        ArrayList<String> lines = new ArrayList<>();
        String line;
        while ((line = br.readLine()) != null) {  // 正确：使用 readLine() != null
            if (StringUtils.isNotEmpty(line)) {
                lines.add(line);
            }
        }
        return lines;
    }
}
```

## 待验证

1. 修复 `readStreamToList` 方法后，使用 `dd.txt` 字典导入多个URL是否能正常扫描
2. 确认问题是否与文件大小超过 8KB 缓冲区直接相关

## 相关代码调用链

```
importUrl() 
  → doScan(httpReqResp, FROM_IMPORT)
    → WordlistManager.getItem(KEY_PAYLOAD)  // 获取字典名
    → doScan(httpReqResp, from, payloadItem)
      → performRecursiveScan()
        → WordlistManager.getPayload(payloadItem)
          → getList(KEY_PAYLOAD, item)
            → FileUtils.readFileToList(path)
              → readStreamToList(fis)  // <-- 问题方法
```
