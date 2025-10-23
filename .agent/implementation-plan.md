# OneScan 项目实施计划

## 执行顺序建议

基于深度技术分析，建议按以下顺序执行任务：

### 第一阶段：快速见效（Day 1）

#### 任务 1：移除数据收集功能 ⏱️ 1-2小时
**理由：**
- 最简单，风险最低
- 代码独立性强
- 为后续工作清理代码库

**执行步骤：**
1. 移除 BurpExtender.java 中的 5 处调用
2. 移除 OneScan.java 中的 UI 集成
3. 清理 Config.java 和 BaseConfigTab.java
4. 删除 13 个相关文件
5. 编译测试
6. 提交代码

---

### 第二阶段：用户体验改进（Day 1-2）

#### 任务 2：表格宽度自适应 ⏱️ 2-3小时
**理由：**
- 直接改善用户体验
- 实现方案明确
- 测试简单

**执行步骤：**
1. 定义列宽度比例数组（总和 100%）
```java
private static final double[] COLUMN_WIDTH_RATIOS = {
    0.05, 0.06, 0.06, 0.15, 0.20, 0.18, 0.10, 0.06, 0.08, 0.06
};
```

2. 修改 initColumnWidth() 方法
```java
private void initColumnWidth() {
    int tableWidth = getParent() != null ? getParent().getWidth() : 1000;
    for (int columnIndex = 0; columnIndex < getColumnModel().getColumnCount(); columnIndex++) {
        double ratio = columnIndex < COLUMN_WIDTH_RATIOS.length ?
            COLUMN_WIDTH_RATIOS[columnIndex] : 0.1;
        int columnWidth = (int) (tableWidth * ratio);
        getColumnModel().getColumn(columnIndex).setPreferredWidth(columnWidth);
    }
}
```

3. 添加 ComponentListener
```java
addComponentListener(new ComponentAdapter() {
    @Override
    public void componentResized(ComponentEvent e) {
        SwingUtilities.invokeLater(() -> initColumnWidth());
    }
});
```

4. 修改自动调整模式
```java
setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
```

5. 多分辨率测试（1366x768, 1920x1080, 2560x1440）
6. 提交代码

---

### 第三阶段：主题优化（Day 2）

#### 任务 4：深色主题适配 ⏱️ 3-4小时
**理由：**
- 改善深色主题体验
- 大部分代码已经兼容
- Montoya API 已就位

**执行步骤：**

1. 获取并使用 Montoya API 主题
```java
import burp.api.montoya.ui.Theme;
private Theme getCurrentTheme() {
    return montoyaApi.userInterface().currentTheme();
}
```

2. 修改 FpManager 高亮颜色
```java
public static String[] getColorHexForTheme(Theme theme) {
    if (theme == Theme.DARK) {
        return new String[] {
            "#CC4444", "#CC9944", "#CCCC44", "#44CC44",
            "#4444CC", "#CC44CC", "#44CCCC", "#888888"
        };
    }
    return DEFAULT_COLOR_HEX; // 浅色主题默认值
}
```

3. 修改 TaskTable 的硬编码颜色
```java
// line 101: 替换 Color.BLACK
fontColor = theme == Theme.DARK ? Color.WHITE : Color.BLACK;
```

4. 审计并修改其他硬编码颜色
   - FpTestResultPanel.java
   - DividerLine.java
   - UIHelper.java

5. 测试深色/浅色主题切换
6. 提交代码

---

### 第四阶段：配置优化（Day 3）

#### 任务 3：JSON 转 YAML ⏱️ 2-3小时
**理由：**
- 优化配置可读性
- 需要保持兼容性
- 最后执行减少风险

**执行步骤：**

1. 添加 Maven 依赖
```xml
<dependency>
    <groupId>org.yaml</groupId>
    <artifactId>snakeyaml</artifactId>
    <version>2.0</version>
</dependency>
```

2. 创建 YAML 配置文件
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

3. 修改 FpManager 支持双格式
```java
private static void loadConfig() {
    String content = FileUtils.readFileToString(sFilePath);
    if (sFilePath.endsWith(".yaml") || sFilePath.endsWith(".yml")) {
        Yaml yaml = new Yaml(new Constructor(FpConfig.class));
        sConfig = yaml.load(content);
    } else {
        sConfig = GsonUtils.toObject(content, FpConfig.class);
    }
}
```

4. 提供 JSON 到 YAML 转换工具（可选）
5. 测试两种格式的加载
6. 更新文档
7. 提交代码

---

## 测试计划

### 每个任务完成后的测试清单

#### 通用测试项
- [ ] mvn clean compile 无错误
- [ ] mvn package 生成 JAR 文件
- [ ] Burp Suite 加载插件成功
- [ ] 代理监听功能正常
- [ ] 递归扫描功能正常
- [ ] 指纹识别功能正常

#### 任务 1 特定测试
- [ ] 确认数据收集菜单/面板已消失
- [ ] 确认核心扫描功能不受影响

#### 任务 2 特定测试
- [ ] 不同分辨率下表格显示正常
- [ ] 窗口缩放时列宽自动调整
- [ ] 没有水平滚动条出现

#### 任务 3 特定测试
- [ ] YAML 配置文件加载成功
- [ ] 旧 JSON 配置仍可使用
- [ ] 指纹规则正确解析

#### 任务 4 特定测试
- [ ] 深色主题下所有文字可读
- [ ] 颜色对比度合适
- [ ] 高亮颜色协调
- [ ] 主题切换无异常

---

## 风险管理

### 风险矩阵

| 任务 | 风险等级 | 主要风险 | 缓解措施 |
|------|---------|----------|----------|
| 任务1 | 低 | 遗漏引用 | 全局搜索+编译检查 |
| 任务2 | 低 | 列内容显示不全 | 设置最小列宽 |
| 任务3 | 中 | 解析错误 | 保持JSON兼容 |
| 任务4 | 中 | 颜色不协调 | 充分测试+可配置 |

---

## Git 提交计划

每个任务完成后独立提交：

```bash
# 任务 1
git commit -m "feat: 移除数据收集功能模块

- 删除 CollectManager 及相关类
- 清理 UI 集成代码
- 移除配置项引用"

# 任务 2
git commit -m "feat: 实现表格列宽自适应

- 使用百分比替代固定像素宽度
- 添加窗口大小变化监听
- 改用 AUTO_RESIZE_ALL_COLUMNS 模式"

# 任务 3
git commit -m "feat: 支持 YAML 格式指纹配置

- 添加 snakeyaml 依赖
- 实现 YAML 解析逻辑
- 保持 JSON 向后兼容"

# 任务 4
git commit -m "feat: 添加深色主题支持

- 使用 Montoya API 获取主题
- 动态调整高亮颜色
- 替换硬编码颜色值"
```

---

## 时间线

**总预计时间：** 8-12 小时

### 建议的执行计划

**Day 1（4小时）**
- 上午：任务 1（1-2小时）
- 下午：任务 2 开始（2小时）

**Day 2（4小时）**
- 上午：任务 2 完成+测试（1小时）
- 下午：任务 4（3小时）

**Day 3（4小时）**
- 上午：任务 3（2-3小时）
- 下午：整体测试+文档更新（1-2小时）

---

## 成功标准

所有任务完成后，应满足：

✅ 代码编译无错误无警告
✅ 插件在 Burp Suite 中正常加载
✅ 核心扫描功能完全正常
✅ 表格自适应不同分辨率
✅ 深色/浅色主题切换流畅
✅ YAML 配置文件正确解析
✅ 数据收集功能完全移除
✅ 用户文档已更新

---

## Linus 式总结

> "这四个任务都很直接。没有过度工程，没有理论完美主义。都是实际问题的务实解决方案。
>
> 移除数据收集？不用就删，干净利落。
> 表格宽度？百分比替代像素，小学数学。
> 深色主题？UIManager 已经帮你做了 80%。
> JSON 转 YAML？只是换个解析器。
>
> 记住：好的代码改动应该让代码变简单，而不是更复杂。"

---

*文档生成时间：2025-10-20*
*基于 OneScan v2.1.9 代码分析*