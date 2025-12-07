#!/usr/bin/env python3
"""
初始化阶段 7 任务到 task_status.json
"""

import json
from datetime import datetime, timezone

# 读取现有的 task_status.json
with open('.agent/task_status.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# 定义阶段 7.1 的任务 (消息编辑器迁移)
phase71_tasks = [
    {
        "taskId": "MIGRATE-303-A",
        "phaseId": "7.1",
        "title": "分析现有消息编辑器使用情况",
        "description": "分析 RawEditorAdapter.java 的实现和使用场景,识别所有依赖 IMessageEditor 的组件,分析 OneScanInfoTab 的 UI 结构和数据流,制定详细的重构方案",
        "estimatedHours": 1.5,
        "priority": "P1",
        "severity": "中",
        "category": "分析",
        "dependencies": ["MIGRATE-605"]
    },
    {
        "taskId": "MIGRATE-303-B",
        "phaseId": "7.1",
        "title": "重构 OneScanInfoTab 使用 Montoya RawEditor",
        "description": "移除 IMessageEditorTab 接口实现,直接使用 Montoya RawEditor API,更新 UI 组件的数据绑定逻辑,测试 UI 交互功能",
        "estimatedHours": 3,
        "priority": "P1",
        "severity": "中",
        "category": "重构",
        "dependencies": ["MIGRATE-303-A"]
    },
    {
        "taskId": "MIGRATE-303-C",
        "phaseId": "7.1",
        "title": "更新 BurpExtender 中的编辑器引用",
        "description": "将 mRequestTextEditor 和 mResponseTextEditor 类型改为 RawEditor,移除 RawEditorAdapter 的使用,更新所有相关的方法调用",
        "estimatedHours": 2,
        "priority": "P1",
        "severity": "中",
        "category": "重构",
        "dependencies": ["MIGRATE-303-B"]
    },
    {
        "taskId": "MIGRATE-303-D",
        "phaseId": "7.1",
        "title": "清理和测试",
        "description": "删除 RawEditorAdapter.java 文件,移除 IMessageEditor 相关导入,完整测试消息编辑器功能,更新相关文档和注释",
        "estimatedHours": 1.5,
        "priority": "P1",
        "severity": "中",
        "category": "清理",
        "dependencies": ["MIGRATE-303-C"]
    }
]

# 定义阶段 7.2 的任务 (辅助工具类迁移)
phase72_tasks = [
    {
        "taskId": "MIGRATE-401-A",
        "phaseId": "7.2",
        "title": "IHttpService 迁移分析和规划",
        "description": "统计 IHttpService 的所有使用位置(27处),分析每个使用场景的迁移策略,确定迁移到 HttpService 的具体方案,识别需要重构的复杂场景",
        "estimatedHours": 2,
        "priority": "P2",
        "severity": "中",
        "category": "分析",
        "dependencies": ["MIGRATE-303-D"]
    },
    {
        "taskId": "MIGRATE-401-B",
        "phaseId": "7.2",
        "title": "重构 HttpReqRespAdapter",
        "description": "将 IHttpRequestResponse 接口改为内部接口或移除,将 IHttpService 替换为 Montoya HttpService,更新适配器的构造方法和工厂方法,保持与现有代码的兼容性",
        "estimatedHours": 3,
        "priority": "P2",
        "severity": "中",
        "category": "重构",
        "dependencies": ["MIGRATE-401-A"]
    },
    {
        "taskId": "MIGRATE-401-C",
        "phaseId": "7.2",
        "title": "更新 BurpExtender 中的 IHttpService 使用",
        "description": "批量替换 IHttpService 为 HttpService,更新所有工具方法的参数和返回值类型,修复类型转换和方法调用,分批测试每个修改的方法",
        "estimatedHours": 4,
        "priority": "P2",
        "severity": "中",
        "category": "重构",
        "dependencies": ["MIGRATE-401-B"]
    },
    {
        "taskId": "MIGRATE-401-D",
        "phaseId": "7.2",
        "title": "更新核心数据结构",
        "description": "重构 TaskData 类,移除 IHttpRequestResponse 依赖,更新 TaskPool 和相关扫描引擎代码,使用 Montoya 原生类型或自定义数据类,确保扫描功能完整性",
        "estimatedHours": 5,
        "priority": "P3",
        "severity": "高",
        "category": "重构",
        "dependencies": ["MIGRATE-401-C"]
    },
    {
        "taskId": "MIGRATE-401-E",
        "phaseId": "7.2",
        "title": "清理和验证",
        "description": "删除 HttpReqRespAdapter.java(如果不再需要),移除所有 IHttpRequestResponse 和 IHttpService 导入,从 pom.xml 移除 burp-extender-api 依赖,完整回归测试所有功能",
        "estimatedHours": 2,
        "priority": "P2",
        "severity": "中",
        "category": "清理",
        "dependencies": ["MIGRATE-401-D"]
    }
]

# 定义阶段 7.3 的任务 (最终验证和文档)
phase73_tasks = [
    {
        "taskId": "MIGRATE-701",
        "phaseId": "7.3",
        "title": "完整性最终验证",
        "description": "重新扫描所有源代码,确认零传统 API 引用,验证 pom.xml 已移除 burp-extender-api,确认所有代码使用 Montoya API,生成最终迁移报告",
        "estimatedHours": 1,
        "priority": "P1",
        "severity": "高",
        "category": "验证",
        "dependencies": ["MIGRATE-303-D", "MIGRATE-401-E"]
    },
    {
        "taskId": "MIGRATE-702",
        "phaseId": "7.3",
        "title": "性能和稳定性测试",
        "description": "压力测试扫描引擎,内存泄漏检测,并发场景测试,长时间运行稳定性测试",
        "estimatedHours": 2,
        "priority": "P1",
        "severity": "高",
        "category": "测试",
        "dependencies": ["MIGRATE-701"]
    },
    {
        "taskId": "MIGRATE-703",
        "phaseId": "7.3",
        "title": "文档更新和发布准备",
        "description": "更新 README.md(API版本、兼容性说明),更新代码注释和 JavaDoc,编写迁移完成总结报告,准备发布说明(Release Notes)",
        "estimatedHours": 2,
        "priority": "P2",
        "severity": "中",
        "category": "文档",
        "dependencies": ["MIGRATE-702"]
    }
]

# 合并所有阶段 7 任务
all_phase7_tasks = phase71_tasks + phase72_tasks + phase73_tasks

# 添加阶段 7 到 phases (如果不存在)
if "phases" not in data:
    data["phases"] = {}

data["phases"]["7.1"] = {
    "name": "消息编辑器迁移",
    "description": "完成 MIGRATE-303 的所有子任务",
    "priority": "P1",
    "status": "pending",
    "total_tasks": 4,
    "completed_tasks": 0,
    "estimatedHours": 8,
    "actualHours": 0
}

data["phases"]["7.2"] = {
    "name": "辅助工具类迁移",
    "description": "完成 MIGRATE-401 的所有子任务",
    "priority": "P2",
    "status": "pending",
    "total_tasks": 5,
    "completed_tasks": 0,
    "estimatedHours": 16,
    "actualHours": 0
}

data["phases"]["7.3"] = {
    "name": "最终验证和文档",
    "description": "最终验证、性能测试和文档更新",
    "priority": "P1",
    "status": "pending",
    "total_tasks": 3,
    "completed_tasks": 0,
    "estimatedHours": 5,
    "actualHours": 0
}

# 添加任务详情到 task_details
for task in all_phase7_tasks:
    data["task_details"][task["taskId"]] = {
        "status": "pending",
        "description": task["description"]
    }

# 添加任务到 tasks 数组
if "tasks" not in data:
    data["tasks"] = []

for task in all_phase7_tasks:
    data["tasks"].append({
        "taskId": task["taskId"],
        "phaseId": task["phaseId"],
        "title": task["title"],
        "description": task["description"],
        "priority": task["priority"],
        "severity": task["severity"],
        "category": task["category"],
        "impact": "全局" if task["severity"] == "高" else "局部",
        "estimatedHours": task["estimatedHours"],
        "actualHours": 0,
        "affectedFiles": [],
        "deliverables": [],
        "dependencies": task["dependencies"],
        "status": "pending",
        "testRequired": task["category"] in ["验证", "测试"],
        "documentationRequired": task["category"] in ["文档", "清理"]
    })

# 更新 summary
total_tasks = len(data["tasks"])
completed_tasks = len(data["completed_tasks"])
data["summary"]["totalTasks"] = total_tasks
data["summary"]["pendingTasks"] = total_tasks - completed_tasks - len(data.get("skipped_tasks", []))
data["summary"]["progressPercentage"] = int((completed_tasks / total_tasks) * 100) if total_tasks > 0 else 0
data["summary"]["estimatedTotalHours"] = data["summary"].get("estimatedTotalHours", 0) + 29

# 更新时间戳
data["lastUpdate"] = datetime.now(timezone.utc).isoformat()

# 保存更新后的文件
with open('.agent/task_status.json', 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print("✅ 成功添加阶段 7 的 12 个任务到 task_status.json")
print(f"📊 总任务数: {data['summary']['totalTasks']}")
print(f"✅ 已完成: {data['summary']['completedTasks']}")
print(f"⏳ 待处理: {data['summary']['pendingTasks']}")
print(f"📈 进度: {data['summary']['progressPercentage']}%")
