# OneScan 项目 TODO 分析报告

## 项目概况

OneScan 是一款用于递归目录扫描的 BurpSuite 插件，基于 Java 1.8 开发，使用 Maven 构建。项目包含三个模块：
- `burp-extender-api`: Burp 扩展 API (v2.3)
- `montoya-api`: Burp Montoya API (v2023.12.1)
- `extender`: 主要实现模块 (v2.1.9)

## TODO 项目分析

### 1. 修改结果表格宽度为自适应

**当前实现分析：**

文件位置：`extender/src/main/java/burp/vaycore/onescan/ui/widget/TaskTable.java`

```java
// 当前硬编码的列宽（像素）
private static final int[] PRE_COLUMN_WIDTH = {
    70,  // #
    65,  // From
    70,  // Method
    200, // Host
    200, // Url
    200, // Title
    125, // IP
    70,  // Status
    100, // Length
    70,  // Color
};

// 当前设置为不自动调整
setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
```

**问题：**
- 使用固定像素宽度，不适应不同分辨率
- AUTO_RESIZE_OFF 模式导致右侧有空白区域
- 所有列宽度之和未达到 100%

**解决方案：**

方案 A：使用百分比宽度（推荐）
- 将固定像素宽度转换为百分比
- 根据表格总宽度动态计算每列宽度
- 监听表格大小变化事件，动态调整列宽

方案 B：使用 JTable 内置自动调整模式
- 改用 `AUTO_RESIZE_ALL_COLUMNS` 或 `AUTO_RESIZE_SUBSEQUENT_COLUMNS`
- 为重要列设置最小/最大宽度
- 让 JTable 自动分配剩余空间

**推荐实现步骤：**

1. 定义列宽度比例数组（替代固定像素）
```java
private static final double[] COLUMN_WIDTH_RATIOS = {
    0.05,  // # (5%)
    0.06,  // From (6%)
    0.06,  // Method (6%)
    0.15,  // Host (15%)
    0.20,  // Url (20%)
    0.18,  // Title (18%)
    0.10,  // IP (10%)
    0.06,  // Status (6%)
    0.08,  // Length (8%)
    0.06,  // Color (6%)
};
// 总和 = 100%
```

2. 修改 `initColumnWidth()` 方法
```java
private void initColumnWidth() {
    int tableWidth = getParent() != null ? getParent().getWidth() : 1000;
    int columnCount = getColumnModel().getColumnCount();
    
    for (int columnIndex = 0; columnIndex < columnCount; columnIndex++) {
        double ratio = 0.1; // 默认 10%
        if (columnIndex < COLUMN_WIDTH_RATIOS.length) {
            ratio = COLUMN_WIDTH_RATIOS[columnIndex];
        }
        int columnWidth = (int) (tableWidth * ratio);
        getColumnModel().getColumn(columnIndex).setPreferredWidth(columnWidth);
    }
}
```

3. 添加组件监听器，响应大小变化
```java
addComponentListener(new ComponentAdapter() {
    @Override
    public void componentResized(ComponentEvent e) {
        initColumnWidth();
    }
});
```

4. 改用自动调整模式
```java
setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
```

**影响范围：**
- 文件：`TaskTable.java`
- 方法：`initColumnWidth()`, 构造函数
- 测试：需要在不同分辨率下测试表格显示效果

---

### 2. 将指纹配置文件格式从 JSON 修改为 YAML

**当前实现分析：**

配置文件：`extender/src/main/resources/fp_config.json`
解析类：`extender/src/main/java/burp/vaycore/onescan/manager/FpManager.java`

当前 JSON 结构：
```json
{
  "columns": [{"id": "yPv", "name": "Notes"}],
  "list": [
    {
      "params": [{"k": "yPv", "v": "Swagger-UI"}],
      "color": "red",
      "rules": [[...]]
    }
  ]
}
```

**解决方案：**

1. 添加 YAML 解析依赖
在 `pom.xml` 中添加：
```xml
<dependency>
    <groupId>org.yaml</groupId>
    <artifactId>snakeyaml</artifactId>
    <version>2.0</version>
</dependency>
```

2. 转换配置文件格式
创建 `fp_config.yaml`：
```yaml
columns:
  - id: yPv
    name: Notes

list:
  - params:
      - k: yPv
        v: Swagger-UI
    color: red
    rules:
      - - ds: response
          f: body
          m: iContains
          c: '"swagger":'
```

3. 修改 FpManager 解析逻辑
```java
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

private static void loadConfig() {
    String content = FileUtils.readFileToString(sFilePath);
    if (StringUtils.isEmpty(content)) {
        throw new IllegalArgumentException("fingerprint config is empty.");
    }
    
    // 判断文件类型
    if (sFilePath.endsWith(".yaml") || sFilePath.endsWith(".yml")) {
        Yaml yaml = new Yaml(new Constructor(FpConfig.class));
        sConfig = yaml.load(content);
    } else {
        // 兼容旧的 JSON 格式
        sConfig = GsonUtils.toObject(content, FpConfig.class);
    }
    
    if (sConfig == null) {
        throw new IllegalArgumentException("fingerprint config parsing failed.");
    }
}
```

4. 转换工具脚本（可选）
创建 JSON 到 YAML 的转换工具，方便用户迁移现有配置

**影响范围：**
- 文件：`FpManager.java`, `pom.xml`, `fp_config.yaml`
- 依赖：新增 snakeyaml
- 兼容性：建议保持对 JSON 格式的向后兼容

**优势：**
- YAML 更易读、易编辑
- 支持注释
- 更适合人工维护配置

---

### 3. 基于 Burp Montoya 原生接口使用，深色主题适配

**当前实现分析：**

项目已经使用 Montoya API (v2023.12.1)，并且在 `TaskTable.java` 中已经使用 `UIManager` 获取主题颜色：

```java
Color result = UIManager.getColor("Table.background");
Color result = UIManager.getColor("Table.alternateRowColor");
Color result = UIManager.getColor("Table.selectionBackground");
Color fontColor = UIManager.getColor("Table.foreground");
```

**问题分析：**
- 部分 UI 组件可能硬编码了颜色
- 自定义颜色（指纹高亮色）在深色主题下可能不协调
- 需要全面检查所有 UI 组件的颜色使用

**解决方案：**

1. 审计所有硬编码颜色
搜索代码中的 `new Color(`, `Color.WHITE`, `Color.BLACK` 等

2. 使用 Montoya API 的主题支持
```java
import burp.api.montoya.ui.Theme;
import burp.api.montoya.MontoyaApi;

// 获取当前主题
Theme theme = montoyaApi.userInterface().currentTheme();

// 根据主题调整颜色
if (theme == Theme.DARK) {
    // 深色主题配色
} else {
    // 浅色主题配色
}
```

3. 调整指纹高亮颜色
修改 `FpManager.sColorHex` 数组，为深色主题提供更合适的颜色：
```java
// 深色主题下的颜色调整
private static String[] getColorHexForTheme(Theme theme) {
    if (theme == Theme.DARK) {
        return new String[] {
            "#CC4444", // red - 降低亮度
            "#CC9944", // orange
            "#CCCC44", // yellow
            "#44CC44", // green
            // ...
        };
    }
    return sColorHex; // 默认浅色主题颜色
}
```

4. 全局 UI 组件适配
- 所有 JPanel, JButton, JLabel 等使用 UIManager 颜色
- 移除硬编码的背景色和前景色
- 使用系统默认字体和大小

**需要检查的文件：**
- `extender/src/main/java/burp/vaycore/onescan/ui/` 下所有文件
- `TaskTable.java`
- `DataBoardTab.java`
- 所有自定义 Widget 组件

**测试方法：**
1. 在 Burp Suite 中切换到深色主题
2. 加载插件，检查所有 UI 面板
3. 确保文字可读、对比度足够
4. 检查高亮颜色是否协调

---

### 4. 移除数据收集功能

**当前实现分析：**

数据收集相关文件：
- `extender/src/main/java/burp/vaycore/onescan/manager/CollectManager.java`
- `extender/src/main/java/burp/vaycore/onescan/collect/JsonFieldCollect.java`
- `extender/src/main/java/burp/vaycore/onescan/collect/WebNameCollect.java`
- `extender/src/main/java/burp/vaycore/onescan/bean/CollectData.java`
- `extender/src/main/java/burp/vaycore/onescan/bean/CollectNode.java`
- `extender/src/main/java/burp/vaycore/onescan/bean/CollectReqResp.java`
- `extender/src/main/java/burp/vaycore/onescan/ui/tab/CollectPanel.java`
- `extender/src/main/java/burp/vaycore/onescan/ui/tab/collect/` 目录

**解决方案：**

1. 删除数据收集相关类
```bash
# Bean 类
rm extender/src/main/java/burp/vaycore/onescan/bean/CollectData.java
rm extender/src/main/java/burp/vaycore/onescan/bean/CollectNode.java
rm extender/src/main/java/burp/vaycore/onescan/bean/CollectReqResp.java

# Manager 类
rm extender/src/main/java/burp/vaycore/onescan/manager/CollectManager.java

# Collect 模块
rm -r extender/src/main/java/burp/vaycore/onescan/collect/

# UI 组件
rm extender/src/main/java/burp/vaycore/onescan/ui/tab/CollectPanel.java
rm -r extender/src/main/java/burp/vaycore/onescan/ui/tab/collect/
```

2. 移除对 CollectManager 的引用
搜索并删除所有调用 CollectManager 的代码：
```bash
grep -r "CollectManager" extender/src/main/java/
grep -r "CollectPanel" extender/src/main/java/
grep -r "import.*collect" extender/src/main/java/
```

3. 更新主入口类
在 `OneScan.java` 或主面板中移除数据收集标签页

4. 清理配置项
移除与数据收集相关的配置键（如果有）

5. 更新 UI
从主界面移除"数据收集"相关的按钮、菜单项、标签页

**影响范围：**
- 删除文件：约 10+ 个文件
- 修改文件：主入口、配置类、UI 面板类
- 功能影响：完全移除数据收集功能

**注意事项：**
- 确保没有其他功能依赖数据收集模块
- 更新用户文档，说明该功能已移除
- 考虑是否需要数据迁移或导出功能

---

## 实施优先级建议

1. **高优先级 - 移除数据收集** (1-2 小时)
   - 影响范围明确，风险较低
   - 可以减少代码复杂度
   - 为后续工作腾出空间

2. **高优先级 - 表格宽度自适应** (2-3 小时)
   - 直接影响用户体验
   - 实现相对简单
   - 测试工作量适中

3. **中优先级 - 深色主题适配** (3-4 小时)
   - 需要全面审计 UI 代码
   - 测试工作量较大
   - 可能需要多次迭代

4. **中优先级 - JSON 转 YAML** (2-3 小时)
   - 需要添加新依赖
   - 需要转换现有配置
   - 建议保持向后兼容

## 总工作量估算

- 总计：8-12 小时
- 测试时间：20% (2-3 小时)
- 文档更新：1 小时

## 风险评估

1. **表格宽度调整**
   - 风险：低
   - 可能问题：某些列内容显示不全
   - 缓解措施：设置最小列宽

2. **YAML 转换**
   - 风险：中
   - 可能问题：解析错误、兼容性问题
   - 缓解措施：保持 JSON 格式支持

3. **深色主题**
   - 风险：中
   - 可能问题：颜色对比度不足、可读性差
   - 缓解措施：充分测试，提供配置选项

4. **移除数据收集**
   - 风险：低
   - 可能问题：遗漏清理某些引用
   - 缓解措施：全局搜索，编译检查

## 下一步行动

1. 创建功能分支
2. 按优先级逐个实现
3. 每完成一项提交代码
4. 编写单元测试（如需要）
5. 进行集成测试
6. 更新文档
7. 合并到主分支
