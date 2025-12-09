#!/usr/bin/env python3
"""
任务状态管理器 - 用于管理和追踪项目任务进度
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


class TaskStatusManager:
    def __init__(self, status_file=".agent/task_status.json"):
        self.status_file = Path(status_file)
        self.data = self._load()

    def _load(self):
        """加载任务状态"""
        if not self.status_file.exists():
            return self._create_default()
        with open(self.status_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    def _create_default(self):
        """创建默认状态文件"""
        return {
            "version": "2.0",
            "lastUpdate": datetime.now(timezone.utc).isoformat(),
            "current_phase": None,
            "current_task": None,
            "completed_tasks": [],
            "in_progress_tasks": [],
            "skipped_tasks": [],
            "failed_tasks": [],
            "task_details": {},
            "summary": {
                "totalTasks": 0,
                "completedTasks": 0,
                "inProgressTasks": 0,
                "pendingTasks": 0,
                "progressPercentage": 0
            }
        }

    def _save(self):
        """保存任务状态"""
        self.data["lastUpdate"] = datetime.now(timezone.utc).isoformat()
        self._update_summary()
        with open(self.status_file, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)

    def _update_summary(self):
        """更新统计信息"""
        total = len(self.data.get("tasks", []))
        completed = len(self.data.get("completed_tasks", []))
        in_progress = len(self.data.get("in_progress_tasks", []))
        pending = total - completed - in_progress - len(self.data.get("skipped_tasks", []))

        self.data["summary"].update({
            "totalTasks": total,
            "completedTasks": completed,
            "inProgressTasks": in_progress,
            "pendingTasks": pending,
            "progressPercentage": int((completed / total * 100) if total > 0 else 0)
        })

    def status(self):
        """显示当前状态"""
        summary = self.data.get("summary", {})
        current_task = self.data.get("current_task")
        in_progress = self.data.get("in_progress_tasks", [])

        print(f"📊 任务状态概览")
        print(f"总任务数: {summary.get('totalTasks', 0)}")
        print(f"已完成: {summary.get('completedTasks', 0)}")
        print(f"进行中: {summary.get('inProgressTasks', 0)}")
        print(f"待处理: {summary.get('pendingTasks', 0)}")
        print(f"进度: {summary.get('progressPercentage', 0)}%")
        print()

        if in_progress:
            print(f"🔄 当前任务: {in_progress[0]}")
            task_detail = self.data.get("task_details", {}).get(in_progress[0], {})
            if "sub_tasks" in task_detail:
                print(f"   子任务:")
                for sub in task_detail["sub_tasks"]:
                    status_icon = "✅" if sub["status"] == "completed" else "⏳" if sub["status"] == "in_progress" else "⬜"
                    print(f"   {status_icon} {sub['id']}: {sub['title']}")
        else:
            print(f"⏸️  无正在进行的任务")

        return 0

    def next_task(self):
        """获取下一个待执行任务"""
        # 检查是否有进行中的任务
        in_progress = self.data.get("in_progress_tasks", [])
        if in_progress:
            print(f"⚠️  任务 {in_progress[0]} 仍在进行中")
            print(f"请先完成或跳过该任务")
            return 1

        # 查找下一个待处理任务
        tasks = self.data.get("tasks", [])
        completed = set(self.data.get("completed_tasks", []))
        skipped = set(self.data.get("skipped_tasks", []))

        for task in tasks:
            task_id = task["taskId"]
            if task_id not in completed and task_id not in skipped:
                # 检查依赖是否满足
                deps = task.get("dependencies", [])
                if all(dep in completed or dep in skipped for dep in deps):
                    # 标记为进行中
                    self.data["in_progress_tasks"] = [task_id]
                    self.data["current_task"] = task_id
                    self.data["current_phase"] = task["phaseId"]

                    # 更新任务详情
                    if task_id not in self.data["task_details"]:
                        self.data["task_details"][task_id] = {}
                    self.data["task_details"][task_id]["status"] = "in_progress"
                    self.data["task_details"][task_id]["started_at"] = datetime.now(timezone.utc).isoformat()

                    self._save()

                    print(f"✅ 开始任务: {task_id}")
                    print(f"标题: {task['title']}")
                    print(f"描述: {task['description']}")
                    return 0

        print("✅ 所有任务已完成!")
        return 0

    def complete(self, task_id, commit_hash=""):
        """标记任务完成"""
        if task_id not in self.data.get("in_progress_tasks", []):
            print(f"⚠️  任务 {task_id} 不在进行中")
            return 1

        # 移除进行中标记
        self.data["in_progress_tasks"].remove(task_id)

        # 添加到已完成列表
        if task_id not in self.data["completed_tasks"]:
            self.data["completed_tasks"].append(task_id)

        # 更新任务详情
        if task_id not in self.data["task_details"]:
            self.data["task_details"][task_id] = {}

        self.data["task_details"][task_id].update({
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "commit": commit_hash
        })

        self._save()

        print(f"✅ 任务 {task_id} 已完成")
        if commit_hash:
            print(f"Commit: {commit_hash}")
        return 0

    def skip(self, task_id, reason=""):
        """跳过任务"""
        if task_id in self.data.get("in_progress_tasks", []):
            self.data["in_progress_tasks"].remove(task_id)

        if task_id not in self.data["skipped_tasks"]:
            self.data["skipped_tasks"].append(task_id)

        if task_id not in self.data["task_details"]:
            self.data["task_details"][task_id] = {}

        self.data["task_details"][task_id].update({
            "status": "skipped",
            "notes": [reason] if reason else []
        })

        self._save()

        print(f"⏭️  任务 {task_id} 已跳过")
        if reason:
            print(f"原因: {reason}")
        return 0


def main():
    if len(sys.argv) < 2:
        print("用法: python task_status_manager.py <command> [args]")
        print("命令:")
        print("  status              - 显示当前状态")
        print("  next                - 获取并开始下一个任务")
        print("  complete <task_id> [commit] - 标记任务完成")
        print("  skip <task_id> [reason]     - 跳过任务")
        return 1

    manager = TaskStatusManager()
    command = sys.argv[1]

    if command == "status":
        return manager.status()
    elif command == "next":
        return manager.next_task()
    elif command == "complete":
        if len(sys.argv) < 3:
            print("错误: 需要提供 task_id")
            return 1
        task_id = sys.argv[2]
        commit = sys.argv[3] if len(sys.argv) > 3 else ""
        return manager.complete(task_id, commit)
    elif command == "skip":
        if len(sys.argv) < 3:
            print("错误: 需要提供 task_id")
            return 1
        task_id = sys.argv[2]
        reason = sys.argv[3] if len(sys.argv) > 3 else ""
        return manager.skip(task_id, reason)
    else:
        print(f"未知命令: {command}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
