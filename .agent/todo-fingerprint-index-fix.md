# 指纹管理面板表格序号优化

## 问题描述
指纹管理面板的表格显示序号从 0 开始，用户期望从 1 开始显示，更符合人类阅读习惯。

## 问题定位
文件：`extender/src/main/java/burp/vaycore/onescan/ui/widget/FpTable.java`
位置：第 287 行，`FpTableModel.getValueAt()` 方法

当前代码：
```java
if (columnIndex == 0) {
    return rowIndex;
}
```

## 解决方案
将序号显示逻辑修改为 `rowIndex + 1`，使序号从 1 开始显示。

修改后代码：
```java
if (columnIndex == 0) {
    return rowIndex + 1;
}
```

## 影响范围
- 仅影响指纹表格的 ID 列显示
- 不影响内部数据索引逻辑
- 不影响其他功能（添加、编辑、删除等操作仍使用原始索引）

## 测试要点
1. 验证表格第一行显示序号为 1
2. 验证序号连续递增
3. 验证添加、编辑、删除功能正常
4. 验证排序功能正常
5. 验证过滤功能正常

## 状态
- [x] 问题分析完成
- [x] 代码修改
- [x] 测试验证（无语法错误）
- [ ] 提交代码

## 实施记录
- 修改时间：2025-10-29
- 修改文件：`extender/src/main/java/burp/vaycore/onescan/ui/widget/FpTable.java`
- 修改内容：将 `return rowIndex;` 改为 `return rowIndex + 1;`
- 验证结果：代码编译通过，无语法错误
