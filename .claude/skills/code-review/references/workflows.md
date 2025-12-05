# 代码评审工作流程

## 评审阶段工作流

### 阶段 0：项目评审与分析

#### 0.1 评审前准备

```bash
# 1. 确保项目可以正常编译
mvn clean compile

# 2. 运行现有测试
mvn test

# 3. 创建评审分支
git checkout -b review/code-quality-$(date +%Y%m%d)

# 4. 备份当前状态
git tag backup-before-review
```

#### 0.2 运行静态分析工具

```bash
# SpotBugs 分析
mvn spotbugs:check

# PMD 分析
mvn pmd:check

# Checkstyle 检查
mvn checkstyle:check

# 依赖安全检查
mvn org.owasp:dependency-check-maven:check
```

#### 0.3 代码度量收集

- 统计代码行数
- 计算圈复杂度
- 识别重复代码
- 分析依赖关系

#### 0.4 生成评审报告

创建 `.agent/analysis_report.md`，包含：
- 执行摘要
- 项目健康度评分
- 问题清单（按严重程度分类）
- 代码度量数据
- 改进建议优先级矩阵

#### 0.5 初始化任务跟踪

创建 `.agent/task_status.json`，包含：
- 所有待执行任务
- 任务优先级和依赖关系
- 任务状态跟踪字段

### 阶段 1+：执行优化任务

#### 任务执行流程

```
1. 选择任务
   ↓
2. 创建功能分支
   ↓
3. 代码修改
   ↓
4. 本地测试
   ↓
5. 提交代码
   ↓
6. 更新任务状态
   ↓
7. 合并到主分支（可选）
```

#### 1. 任务选择

```python
# 使用任务管理器获取下一个任务
python .agent/task_status_manager.py next
```

选择标准：
- 按优先级从高到低
- 检查任务依赖关系
- 评估当前是否适合执行

#### 2. 创建功能分支

```bash
# 分支命名规范：<type>/<task-id>-<description>
git checkout -b fix/P1-T001-sql-injection
```

#### 3. 代码修改

- 遵循代码质量标准
- 保持修改最小化
- 添加必要的注释
- 更新相关文档

#### 4. 本地测试

```bash
# 编译检查
mvn clean compile

# 运行测试
mvn test

# 在 Burp Suite 中手动测试
# 1. 加载插件
# 2. 验证修复效果
# 3. 检查是否引入新问题
```

#### 5. 提交代码

```bash
# 标记任务为进行中
python .agent/task_status_manager.py start P1-T001

# 提交代码（使用 -F 避免 Windows 兼容性问题）
git add .
git commit -F - << 'EOF'
fix(security): 修复 XXX 注入漏洞

- 添加输入验证
- 使用参数化查询
- 更新相关测试

关联任务: P1-T001
EOF

# 标记任务为完成
python .agent/task_status_manager.py complete P1-T001 $(git rev-parse HEAD)
```

提交信息格式：
```
<type>(<scope>): <subject>

<body>

关联任务: <task-id>
```

类型（type）：
- `fix`: 修复 Bug
- `feat`: 新功能
- `refactor`: 重构
- `perf`: 性能优化
- `docs`: 文档更新
- `style`: 代码格式
- `test`: 测试相关

#### 6. 更新任务状态

任务状态会自动同步到：
- `.agent/task_status.json`
- `prompt.md`

#### 7. 合并到主分支

```bash
# 切换到主分支
git checkout master

# 合并功能分支
git merge --no-ff fix/P1-T001-sql-injection

# 删除功能分支
git branch -d fix/P1-T001-sql-injection
```

## 条件逻辑

### 根据问题严重程度决定处理方式

```
if 严重程度 == P0:
    立即修复，优先级最高
    创建独立分支
    完成后立即合并
    
elif 严重程度 == P1:
    本周内修复
    可以批量处理相关问题
    
elif 严重程度 == P2:
    本月内修复
    可以与其他优化一起处理
    
else:  # P3
    后续迭代处理
    可以延后或跳过
```

### 根据修复难度决定策略

```
if 修复难度 == 简单 and 影响范围 == 局部:
    直接修复
    
elif 修复难度 == 中等:
    先写测试
    再进行修复
    
else:  # 复杂
    先设计方案
    评审方案
    分步实施
    每步都测试
```

### 根据回归风险决定测试策略

```
if 回归风险 == 高:
    全面回归测试
    手动测试所有核心功能
    考虑延迟发布
    
elif 回归风险 == 中:
    相关模块测试
    自动化测试覆盖
    
else:  # 低
    基本功能测试
    快速验证
```

## 回滚计划

### 创建检查点

```bash
# 每个阶段完成后打 tag
git tag phase-1.1-completed
git tag phase-1.2-completed
```

### 回滚操作

```bash
# 如果发现严重问题，回滚到上一个稳定版本
git reset --hard phase-1.1-completed

# 或者创建回滚提交
git revert <commit-hash>
```

## 进度跟踪

### 查看当前状态

```bash
python .agent/task_status_manager.py status
```

输出示例：
```
============================================================
📊 任务执行状态
============================================================
当前阶段: 1.2
当前任务: SECURITY-001
总进度: 8/35 (23%)
已完成: 8
进行中: 1
待处理: 26
最后更新: 2025-12-05T16:30:00+08:00
============================================================
```

### 检查是否全部完成

```bash
python .agent/task_status_manager.py check-completion
```

## 文档同步

### 需要同步的文档

- `README.md` - 如果功能有变化
- `CHANGELOG.md` - 记录重要变更
- `prompt.md` - 任务完成状态
- `.agent/analysis_report.md` - 评审报告更新

### 同步时机

- 完成一个阶段后
- 修复重要问题后
- 重构核心模块后
