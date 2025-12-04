#!/usr/bin/env python3
"""
任务状态同步工具
用于在完成任务后同步更新 task_status.json 和 prompt.md
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

class TaskStatusManager:
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.status_file = self.project_root / ".agent" / "task_status.json"
        self.prompt_file = self.project_root / "prompt.md"
        
    def load_status(self) -> Dict:
        """加载任务状态"""
        if not self.status_file.exists():
            return self._create_initial_status()
        
        with open(self.status_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def save_status(self, status: Dict):
        """保存任务状态"""
        status['last_update'] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00")
        
        with open(self.status_file, 'w', encoding='utf-8') as f:
            json.dump(status, f, ensure_ascii=False, indent=2)
    
    def mark_task_completed(self, task_id: str, commit_hash: Optional[str] = None):
        """标记任务为已完成"""
        status = self.load_status()
        
        # 更新任务状态
        if task_id in status.get('in_progress_tasks', []):
            status['in_progress_tasks'].remove(task_id)
        
        if task_id not in status.get('completed_tasks', []):
            status['completed_tasks'].append(task_id)
        
        # 更新任务详情
        if 'task_details' not in status:
            status['task_details'] = {}
        
        status['task_details'][task_id] = {
            'status': 'completed',
            'completed_at': datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00"),
            'commit': commit_hash or 'N/A',
            'description': status['task_details'].get(task_id, {}).get('description', '')
        }
        
        # 更新计数
        status['completed_count'] = len(status['completed_tasks'])
        status['pending_count'] = status['total_tasks'] - status['completed_count'] - len(status.get('in_progress_tasks', []))
        status['progress_percentage'] = int((status['completed_count'] / status['total_tasks']) * 100)
        
        # 保存状态
        self.save_status(status)
        
        # 同步到 prompt.md
        self._sync_to_prompt(task_id, 'completed')
        
        print(f"✅ 任务 {task_id} 已标记为完成")
        print(f"📊 总进度: {status['completed_count']}/{status['total_tasks']} ({status['progress_percentage']}%)")
    
    def mark_task_in_progress(self, task_id: str):
        """标记任务为进行中"""
        status = self.load_status()
        
        if task_id not in status.get('in_progress_tasks', []):
            status['in_progress_tasks'].append(task_id)
        
        # 更新当前任务
        status['current_task'] = task_id
        
        # 更新任务详情
        if 'task_details' not in status:
            status['task_details'] = {}
        
        if task_id not in status['task_details']:
            status['task_details'][task_id] = {}
        
        status['task_details'][task_id]['status'] = 'in_progress'
        status['task_details'][task_id]['started_at'] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00")
        
        # 更新计数
        status['in_progress_count'] = len(status['in_progress_tasks'])
        
        # 保存状态
        self.save_status(status)
        
        # 同步到 prompt.md
        self._sync_to_prompt(task_id, 'in_progress')
        
        print(f"🔄 任务 {task_id} 已标记为进行中")
    
    def get_next_task(self) -> Optional[str]:
        """获取下一个待执行的任务"""
        status = self.load_status()
        
        # 定义任务顺序
        all_tasks = [
            # Phase 1.1
            "CLIPPY-1", "CLIPPY-2", "CLIPPY-3", "CLIPPY-4", "CLIPPY-5", "CLIPPY-6", "CLIPPY-7",
            # Phase 1.2
            "SECURITY-001", "LOGIC-001", "LOGIC-002", "CONCURRENCY-001", 
            "DATAFLOW-001", "ERRORS-001", "PERFORMANCE-001", "MEMORY-001",
            # Phase 2.1
            "SECURITY-002", "CONCURRENCY-002", "LOGIC-003", "PERFORMANCE-002",
            "DATAFLOW-002", "SECURITY-003", "DATAFLOW-003", "LOGIC-004",
            "PERFORMANCE-003", "PERFORMANCE-004", "CONCURRENCY-003", "SECURITY-004",
            # Phase 3.1
            "ARCH-001", "ARCH-002", "ARCH-003",
        ]
        
        completed = set(status.get('completed_tasks', []))
        in_progress = set(status.get('in_progress_tasks', []))
        
        for task_id in all_tasks:
            if task_id not in completed and task_id not in in_progress:
                return task_id
        
        return None
    
    def _sync_to_prompt(self, task_id: str, status: str):
        """同步状态到 prompt.md"""
        if not self.prompt_file.exists():
            print(f"⚠️  警告: {self.prompt_file} 不存在")
            return
        
        with open(self.prompt_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 根据状态更新复选框
        if status == 'completed':
            # 查找并替换 [ ] 为 [x]，并添加 ✅ 标记
            pattern = rf'(- \[ \] \*\*\[{task_id}\]\*\*.*?)(?=\n|$)'
            replacement = rf'- [x] **[{task_id}]** \1 ✅'
            content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
        
        elif status == 'in_progress':
            # 添加 🔄 标记
            pattern = rf'(- \[ \] \*\*\[{task_id}\]\*\*.*?)(?=\n|$)'
            replacement = rf'\1 🔄 **← 当前任务**'
            content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
        
        with open(self.prompt_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"📝 已同步状态到 prompt.md")
    
    def _create_initial_status(self) -> Dict:
        """创建初始状态"""
        return {
            "version": "1.0",
            "last_update": datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00"),
            "current_phase": "1.1",
            "current_task": "CLIPPY-1",
            "completed_phases": [],
            "completed_tasks": [],
            "in_progress_tasks": [],
            "skipped_tasks": [],
            "failed_tasks": [],
            "task_details": {},
            "total_tasks": 35,
            "completed_count": 0,
            "in_progress_count": 0,
            "pending_count": 35,
            "progress_percentage": 0,
            "phases": {
                "1.1": {"name": "Clippy 错误修复", "status": "pending", "total_tasks": 7, "completed_tasks": 0},
                "1.2": {"name": "高风险问题修复", "status": "pending", "total_tasks": 8, "completed_tasks": 0},
                "2.1": {"name": "中风险问题修复", "status": "pending", "total_tasks": 12, "completed_tasks": 0},
                "3.1": {"name": "超大文件拆分", "status": "pending", "total_tasks": 3, "completed_tasks": 0},
                "4.1": {"name": "低风险问题优化", "status": "pending", "total_tasks": 5, "completed_tasks": 0}
            }
        }
    
    def show_status(self):
        """显示当前状态"""
        status = self.load_status()
        
        print("\n" + "="*60)
        print("📊 任务执行状态")
        print("="*60)
        print(f"当前阶段: {status.get('current_phase', 'N/A')}")
        print(f"当前任务: {status.get('current_task', 'N/A')}")
        print(f"总进度: {status.get('completed_count', 0)}/{status.get('total_tasks', 0)} ({status.get('progress_percentage', 0)}%)")
        print(f"已完成: {len(status.get('completed_tasks', []))}")
        print(f"进行中: {len(status.get('in_progress_tasks', []))}")
        print(f"待处理: {status.get('pending_count', 0)}")
        print(f"最后更新: {status.get('last_update', 'N/A')}")
        print("="*60 + "\n")


def main():
    import sys
    
    manager = TaskStatusManager()
    
    if len(sys.argv) < 2:
        print("用法:")
        print("  python task_status_manager.py status              # 显示当前状态")
        print("  python task_status_manager.py next                # 获取下一个任务")
        print("  python task_status_manager.py start <TASK_ID>     # 开始任务")
        print("  python task_status_manager.py complete <TASK_ID> [COMMIT_HASH]  # 完成任务")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "status":
        manager.show_status()
    
    elif command == "next":
        next_task = manager.get_next_task()
        if next_task:
            print(f"下一个任务: {next_task}")
        else:
            print("✅ 所有任务已完成!")
    
    elif command == "start":
        if len(sys.argv) < 3:
            print("错误: 请提供任务ID")
            sys.exit(1)
        task_id = sys.argv[2]
        manager.mark_task_in_progress(task_id)
    
    elif command == "complete":
        if len(sys.argv) < 3:
            print("错误: 请提供任务ID")
            sys.exit(1)
        task_id = sys.argv[2]
        commit_hash = sys.argv[3] if len(sys.argv) > 3 else None
        manager.mark_task_completed(task_id, commit_hash)
    
    else:
        print(f"未知命令: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
