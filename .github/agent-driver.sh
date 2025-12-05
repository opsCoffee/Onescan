#!/usr/bin/env bash
set -euo pipefail

cd "$GITHUB_WORKSPACE"

# 1. 确保状态系统就绪（你已经有这个逻辑）
if [ ! -f .agent/task_status.json ]; then
  echo "首次运行，初始化状态系统..."
  python .agent/task_status_manager.py init || echo "初始化完成"
fi

# 2. 清理旧的完成标记（允许继续）
rm -f .agent/completed

# 3. 让 Claude 严格按你的状态系统执行当前任务（关键！）
echo "交给 Claude 执行当前待处理任务..."
claude -p --dangerously-skip-permissions << 'EOF'
$(cat prompt.md)

---

请严格遵守以下执行流程（这是最高优先级指令）：

1. 立即运行：python .agent/task_status_manager.py status
   显示当前应该执行哪个任务

2. 如果有 in_progress_tasks，直接继续该任务
   如果没有，自动调用：python .agent/task_status_manager.py next
   获取下一个待执行任务并标记为 in_progress

3. 专注于当前这一个任务（或可安全并行的几个子任务）
   - 深度思考 → 拆分子任务 → 执行修复 → 写测试 → 验证
   - 所有操作必须符合 .claude/skills/ 目录下的所有 SKILL.md 规范

4. 任务完成后，必须执行：
   python .agent/task_status_manager.py complete <TASK-ID> $(git rev-parse HEAD)

5. 如果本次任务导致了新问题或测试失败，主动创建新的子任务加入队列

6. 不要一次性做太多！只做当前进度允许的任务
   做完后让系统自动触发下一轮

7. 绝不在本次运行中进入无限循环
EOF

# 4. 检查是否全部完成
if [ -f .agent/completed ]; then
  echo "所有任务已完成，停止触发"
  exit 0
fi

# 5. 【自驱动核心】完成本轮后，自动触发下一轮
echo "本轮完成，触发下一轮优化..."
gh workflow run "Claude 代码处理" --ref $(git rev-parse --abbrev-ref HEAD)
