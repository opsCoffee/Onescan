---
name: git-standards
description: Git 命令规范和最佳实践。强调 --no-pager 参数必须放在 git 命令后面（git --no-pager <子命令>），而非子命令选项后。包括 Windows 环境下使用 -F 参数提交（通过 fsWrite 创建 commit.log）、Conventional Commits 格式（必须中文、禁止 AI 标识）、分支管理（--no-ff 合并）、Git 别名使用。适用于执行 Git 命令、提交代码、合并分支、查看历史、处理 Git 操作时使用。
---

# Git 命令规范

## 核心规则

### 1. 查看类命令必须使用 --no-pager

**原因**：避免进入交互式分页模式，导致工作流程卡顿

**⚠️ 重要：--no-pager 参数的位置**

`--no-pager` 是 git 命令本身的选项，**必须紧跟在 git 后面**，不能放在子命令的选项后面：

```cmd
REM ✅ 正确位置：git --no-pager <子命令> [选项]
git --no-pager log --oneline
git --no-pager diff HEAD~1 HEAD
git --no-pager show abc123

REM ❌ 错误位置：git <子命令> --no-pager [选项]
git log --no-pager --oneline     # 虽然某些版本可能工作，但不规范
git diff --no-pager HEAD~1       # 不规范的写法
```

**适用命令**：
- `git --no-pager diff` - 查看文件差异
- `git --no-pager show` - 查看提交详情
- `git --no-pager log` - 查看提交历史，推荐使用 `--oneline` 获得简洁输出
- `git --no-pager blame` - 查看文件修改历史
- `git --no-pager branch` - 列出分支（带 `-v` 或 `-vv` 时）
- `git status` - 推荐使用 `--short` 获得简洁输出（status 不需要 --no-pager）

**示例**：

```cmd
REM ❌ 错误：可能进入交互模式
git log
git diff

REM ✅ 正确：直接输出所有内容（注意 --no-pager 的位置）
git --no-pager log --oneline
git --no-pager diff

REM 查看状态（简洁输出，不需要 --no-pager）
git status --short

REM 查看最近5次提交
git --no-pager log --oneline -5

REM 查看文件差异
git --no-pager diff HEAD~1 HEAD

REM 查看特定提交
git --no-pager show abc123

REM 查看文件修改历史
git --no-pager blame src/main/java/burp/BurpExtender.java

REM 查看分支详情
git --no-pager branch -vv
```

### 2. Windows 环境下提交必须使用 -F 参数

**原因**：避免空格、换行、引号等特殊字符在 cmd 终端下的兼容性问题

**错误方式**：
```cmd
REM ❌ 错误：引号和换行符可能导致问题
git commit -m "Fix bug: 修复指纹识别问题"

REM ❌ 错误：多行消息在 cmd 中难以处理
git commit -m "Feature: 添加新功能

- 支持 Montoya API
- 优化性能"
```

**正确方式**：

**方式1：使用 fsWrite 工具创建文件（推荐）**

Agent 应该使用 `fsWrite` 工具创建 commit.log 文件：

```javascript
// 使用 fsWrite 工具创建 commit.log
fsWrite({
  path: "commit.log",
  text: `Feature: 实现指纹测试功能

- 添加 FpTestWindow 使用 Montoya API
- 实现 HTTP 消息编辑器
- 优化配置文件处理`
});

// 然后执行提交
executePwsh({ command: "git commit -F commit.log" });

// 提交后删除文件
deleteFile({ targetFile: "commit.log" });
```

**方式2：使用 PowerShell 命令（最后备选）**
```powershell
# 使用 PowerShell 创建 UTF-8 编码的提交消息
$commitMessage = @"
Feature: 实现指纹测试功能

- 添加 FpTestWindow 使用 Montoya API
- 实现 HTTP 消息编辑器
- 优化配置文件处理
"@

# 写入文件，指定 UTF-8 编码（无 BOM）
[System.IO.File]::WriteAllText("commit.log", $commitMessage, [System.Text.UTF8Encoding]::new($false))

# 使用 -F 参数提交
git commit -F commit.log

# 提交后删除临时文件
Remove-Item commit.log
```

**重要注意事项**：
1. ⚠️ **不要将 commit.log 添加到 Git**：
   ```cmd
   REM ❌ 错误：不要添加 commit.log
   git add commit.log
   
   REM ✅ 正确：只添加实际修改的文件
   git add src/main/java/burp/onescan/manager/FpManager.java
   ```

2. ⚠️ **提交后必须删除 commit.log**：
   ```cmd
   REM 提交完成后立即删除
   git commit -F commit.log
   del commit.log
   ```

3. 💡 **建议添加到 .gitignore**：
   ```
   # 在项目根目录的 .gitignore 中添加
   commit.log
   ```

## 常用命令模板

### 查看状态和历史

```cmd
REM 查看工作区状态（简洁输出）
git status --short

REM 查看工作区状态（详细输出）
git status

REM 查看最近提交（简洁格式）
git --no-pager log --oneline -10

REM 查看分支图
git --no-pager log --graph --oneline --all -20

REM 查看文件修改
git --no-pager diff

REM 查看暂存区修改
git --no-pager diff --cached
```

### 提交代码

**Agent 操作流程**：
```javascript
// 1. 添加文件
executePwsh({ 
  command: "git add src/main/java/burp/onescan/manager/FpManager.java" 
});

// 2. 使用 fsWrite 创建提交消息
fsWrite({
  path: "commit.log",
  text: "Feature: 实现指纹测试功能\n\n- 添加缓存验证\n- 优化性能"
});

// 3. 提交
executePwsh({ command: "git commit -F commit.log" });

// 4. 删除临时文件
deleteFile({ targetFile: "commit.log" });
```

**用户手动操作**：
```cmd
REM 添加文件
git add src/main/java/burp/onescan/manager/FpManager.java

REM 使用编辑器创建 commit.log，然后提交
git commit -F commit.log
del commit.log
```

### 分支操作

```cmd
REM 查看分支
git --no-pager branch

REM 创建并切换分支
git checkout -b feature/fingerprint-test

REM 切换分支
git checkout main

REM 合并分支（保留分支历史）
git merge feature/fingerprint-test --no-ff --no-edit

REM 删除已合并的分支
git branch -d feature/fingerprint-test

REM 强制删除分支（未合并）
git branch -D feature/fingerprint-test
```

### 远程操作

```cmd
REM 拉取更新
git pull origin main

REM 推送代码
git push origin main

REM 查看远程仓库
git remote -v
```

## 提交信息规范

### Conventional Commits 格式

**必须使用中文**，遵循以下格式：

```
<类型>: <简短描述>

<详细描述>（可选）

<关联信息>（可选）
```

### 提交类型

- **Feature**: 新功能
- **Fix**: 修复 bug
- **Refactor**: 重构代码（不改变功能）
- **Style**: 代码格式调整（不影响功能）
- **Docs**: 文档更新
- **Test**: 测试相关
- **Chore**: 构建、配置等杂项

### 提交示例

```
Feature: 实现指纹测试功能

- 添加 FpTestWindow 使用 Montoya API
- 实现 HTTP 消息编辑器
- 优化配置文件处理
```

```
Fix: 修复指纹识别缓存问题

修正了并发访问缓存时的线程安全问题，添加了缓存键验证逻辑。
```

```
Refactor: 重构 FpManager 配置加载逻辑

- 提取配置验证方法
- 改进错误处理
- 添加详细日志
```

### ⚠️ 禁止事项

```
❌ 错误：包含 AI 协作标识
Feature: 实现指纹测试功能

Co-authored-by: AI Assistant
Generated with AI assistance

❌ 错误：使用英文
Feature: Implement fingerprint test function

✅ 正确：使用中文，无 AI 标识
Feature: 实现指纹测试功能

- 添加 FpTestWindow 使用 Montoya API
- 实现 HTTP 消息编辑器
```

## 代码合并规范

### 合并策略

```cmd
REM ✅ 正确：使用 --no-ff 保留分支历史
git merge feature/fingerprint-test --no-ff --no-edit

REM ❌ 避免：快进合并（丢失分支历史）
git merge feature/fingerprint-test
```

### 合并前检查

1. **运行所有测试**：
   ```cmd
   mvn test
   ```

2. **检查代码风格**：
   ```cmd
   mvn compile -Dmaven.compiler.showWarnings=true
   ```

3. **确认无冲突**：
   ```cmd
   git status --short
   ```

### 合并后清理

```cmd
REM 合并完成后删除功能分支
git branch -d feature/fingerprint-test

REM 推送删除到远程
git push origin --delete feature/fingerprint-test
```

## 最佳实践

1. **提交前检查**：
   - 使用 `git status --short` 查看修改
   - 使用 `git diff --no-pager` 确认变更内容

2. **提交消息规范**：
   - **必须**使用 Conventional Commits 格式
   - **必须**使用中文描述
   - **禁止**添加 AI 协作标识或署名
   - 支持多行详细描述

3. **提交消息创建（优先级顺序）**：
   - **优先**：Agent 使用 `fsWrite` 工具创建 commit.log
   - **备选**：用户手动使用文本编辑器创建 commit.log
   - **最后**：使用 PowerShell 命令指定 UTF-8 编码

4. **commit.log 管理**：
   - ⚠️ **不要** `git add commit.log` 到暂存区
   - ⚠️ 执行 `git commit -F commit.log` 后**立即删除**
   - 💡 建议将 commit.log 添加到 .gitignore

5. **小步提交**：每个提交只包含一个逻辑变更

6. **避免交互模式**：所有查看命令都加 `--no-pager`

7. **分支管理**：
   - 使用 `--no-ff` 合并保留分支历史
   - 合并前确保通过所有测试
   - 合并后删除已合并的功能分支

## Git 别名配置

### 可用的别名

用户系统中已配置以下 Git 别名，可以简化命令操作：

```gitconfig
[alias]
co = checkout                    # 切换分支
a = add -p                       # 交互式添加
b = branch                       # 分支操作
cp = cherry-pick                 # 挑选提交
d = diff                         # 查看差异
l = log                          # 查看日志
m = merge                        # 合并分支
p = push                         # 推送
pwl = push --force-with-lease    # 安全的强制推送
lg = log --color --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit  # 美化日志
```

### 别名使用说明

**✅ 推荐使用的别名**：

```cmd
REM 切换分支
git co main
git co -b feature/new-feature

REM 查看分支
git b

REM 查看美化的提交历史（仍需在 git 后添加 --no-pager）
git --no-pager lg -10

REM 查看差异（仍需在 git 后添加 --no-pager）
git --no-pager d

REM 合并分支
git m feature/branch --no-ff --no-edit

REM 推送
git p origin main
```

### Agent 使用别名的规则

Agent 在执行 Git 命令时：

1. **可以使用的别名**：
   - `git co` 替代 `git checkout`
   - `git b` 替代 `git branch`
   - `git m` 替代 `git merge`
   - `git p` 替代 `git push`
   - `git lg` 替代复杂的 log 命令

2. **需要补充参数的别名**：
   - `git --no-pager d` - diff 别名仍需在 git 后添加 --no-pager
   - `git --no-pager l --oneline` - log 别名仍需在 git 后添加 --no-pager 和其他参数

### 别名使用示例

```cmd
REM 使用别名的完整工作流程

REM 1. 创建并切换分支
git co -b feature/fingerprint-test

REM 2. 查看状态
git status --short

REM 3. 添加文件
git add src/main/java/burp/onescan/manager/FpManager.java

REM 4. 提交（使用标准流程，不使用别名）
REM 创建 commit.log
git commit -F commit.log
del commit.log

REM 5. 切换回主分支
git co main

REM 6. 合并（保留分支历史）
git m feature/fingerprint-test --no-ff --no-edit

REM 7. 查看美化的提交历史
git lg -5

REM 8. 推送
git p origin main

REM 9. 删除分支
git b -d feature/fingerprint-test
```

## Agent 工具使用说明

Agent 在处理 Git 提交时应该：
- ✅ 使用 `fsWrite` 创建 commit.log（UTF-8 编码，自动处理）
- ✅ 使用 `executePwsh` 执行 git 命令
- ✅ 使用 `deleteFile` 删除 commit.log
- ✅ 可以使用 Git 别名简化命令（如 `git co`、`git b`、`git m`、`git p`）
- ❌ 不要使用 `echo` 或其他可能导致编码问题的命令

## 完整工作流程示例

### Agent 完整流程

```javascript
// 1. 查看修改（使用简洁输出）
executePwsh({ command: "git status --short" });
executePwsh({ command: "git --no-pager diff" });

// 2. 添加文件
executePwsh({
  command: "git add src/main/java/burp/onescan/manager/FpManager.java"
});

// 3. 使用 fsWrite 创建提交消息（Conventional Commits 格式，中文）
fsWrite({
  path: "commit.log",
  text: `Fix: 修复指纹识别缓存问题

- 添加缓存键验证
- 优化内存使用
- 修复并发访问问题`
});

// 4. 提交（不要添加 AI 标识）
executePwsh({ command: "git commit -F commit.log" });

// 5. 删除临时文件
deleteFile({ targetFile: "commit.log" });

// 6. 推送（如需要）
executePwsh({ command: "git push origin main" });
```

### 用户手动流程

```cmd
REM 1. 查看修改
git status --short
git --no-pager diff

REM 2. 添加文件
git add src/main/java/burp/onescan/manager/FpManager.java

REM 3. 使用文本编辑器创建 commit.log 文件
REM    格式：<类型>: <描述>（必须使用中文）

REM 4. 提交
git commit -F commit.log

REM 5. 清理临时文件
del commit.log

REM 6. 推送（如需要）
git push origin main
```

### 功能分支完整流程

```cmd
REM 1. 创建功能分支
git checkout -b feature/fingerprint-test

REM 2. 开发和提交
git add .
REM 创建 commit.log（Conventional Commits 格式）
git commit -F commit.log
del commit.log

REM 3. 切换回主分支
git checkout main

REM 4. 合并（保留分支历史）
git merge feature/fingerprint-test --no-ff --no-edit

REM 5. 运行测试确认
mvn test

REM 6. 删除功能分支
git branch -d feature/fingerprint-test

REM 7. 推送
git push origin main
```
