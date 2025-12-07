#!/usr/bin/env python3
"""
添加阶段 6 任务到 task_status.json
"""

import json
from datetime import datetime, timezone

# 读取现有的 task_status.json
with open('.agent/task_status.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# 定义阶段 6 的任务
phase6_tasks = [
    {
        "taskId": "MIGRATE-601",
        "title": "迁移完整性检查",
        "description": "扫描所有源代码文件,确认无残留的传统 API 引用,检查所有 burp.* 包的导入语句是否已清理,验证所有已迁移的类是否正确使用 Montoya API,生成迁移完整性报告",
        "estimatedHours": 2.5,
        "priority": "P1",
        "severity": "高",
        "category": "验证"
    },
    {
        "taskId": "MIGRATE-602",
        "title": "代码质量评审",
        "description": "评审已迁移代码的质量和规范性,检查异常处理是否完善,验证日志输出是否统一使用 Montoya Logging API,检查资源管理和内存泄漏风险,评估代码可维护性和可读性",
        "estimatedHours": 3.5,
        "priority": "P1",
        "severity": "高",
        "category": "评审"
    },
    {
        "taskId": "MIGRATE-603",
        "title": "API 使用规范性检查",
        "description": "验证 Montoya API 的使用是否符合最佳实践,检查是否有不推荐的 API 使用方式,确认线程安全性和并发处理,验证 UI 组件的注册和注销是否正确",
        "estimatedHours": 2.5,
        "priority": "P1",
        "severity": "中",
        "category": "验证"
    },
    {
        "taskId": "MIGRATE-604",
        "title": "技术债务评估",
        "description": "整理跳过的迁移任务(MIGRATE-303, MIGRATE-401),评估技术债务的影响和优先级,制定后续优化计划,更新 .agent/TECHNICAL_DEBT.md",
        "estimatedHours": 1.5,
        "priority": "P2",
        "severity": "中",
        "category": "评估"
    },
    {
        "taskId": "MIGRATE-605",
        "title": "文档完整性检查",
        "description": "检查代码注释是否完整和准确,验证 README.md 是否需要更新,确认迁移相关文档的完整性,生成最终迁移总结报告",
        "estimatedHours": 1.5,
        "priority": "P2",
        "severity": "中",
        "category": "文档"
    }
]

# 添加阶段 6 到 phases (如果不存在)
if "phases" not in data:
    data["phases"] = {}

data["phases"]["6"] = {
    "name": "迁移验证与评审",
    "description": "全面检查迁移完成情况,评审代码质量,确保无遗漏",
    "priority": "P1",
    "status": "pending",
    "total_tasks": 5,
    "completed_tasks": 0,
    "estimatedHours": 11.5,
    "actualHours": 0
}

# 添加任务详情到 task_details
for task in phase6_tasks:
    data["task_details"][task["taskId"]] = {
        "status": "pending",
        "description": task["description"]
    }

# 添加任务到 tasks 数组
if "tasks" not in data:
    data["tasks"] = []

for task in phase6_tasks:
    data["tasks"].append({
        "taskId": task["taskId"],
        "phaseId": "6",
        "title": task["title"],
        "description": task["description"],
        "priority": task["priority"],
        "severity": task["severity"],
        "category": task["category"],
        "impact": "全局",
        "estimatedHours": task["estimatedHours"],
        "actualHours": 0,
        "affectedFiles": [],
        "deliverables": [],
        "dependencies": ["MIGRATE-503"] if task["taskId"] == "MIGRATE-601" else [f"MIGRATE-{int(task['taskId'][-3:])-1}"],
        "status": "pending",
        "testRequired": task["taskId"] in ["MIGRATE-601", "MIGRATE-602", "MIGRATE-603"],
        "documentationRequired": True
    })

# 更新 summary
data["summary"]["totalTasks"] = 23
data["summary"]["pendingTasks"] = 5
data["summary"]["progressPercentage"] = int((14 / 23) * 100)
data["summary"]["estimatedTotalHours"] = 80 + 11.5

# 更新时间戳
data["lastUpdate"] = datetime.now(timezone.utc).isoformat()

# 保存更新后的文件
with open('.agent/task_status.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print("✅ 成功添加阶段 6 的 5 个任务到 task_status.json")
print(f"📊 总任务数: {data['summary']['totalTasks']}")
print(f"📈 进度: {data['summary']['progressPercentage']}%")
