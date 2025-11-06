你的任务是帮我搞定 OneScan 项目，优先使用 MCP、深度思考、子代理来分析、设计和完善下列 TODO：

TODO list:

1. 请帮我深度思考分析，能否修改指纹配置文件，从如下原始格式保存成我希望的格式？
- 指纹逻辑说明：
  - 始终合并相同 dataSource + field + method 下不同 content
  - 相同 dataSource + field + method 下不同 content 间的逻辑关系为 逻辑与
  - 但是，逻辑或需要写入在一条 content 中，使用正则表达式实现（同时推荐用户也如此实现）
- 不要过度设计
原始格式
```yaml
- name: Swagger-UI
  enabled: true
  color: red
  matchers-condition: and
  matchers:
  - dataSource: response
    field: body
    method: iContains
    content: '"swagger":'
  - dataSource: response
    field: title
    method: contains
    content: Swagger UI
- name: Swagger-UI
  enabled: true
  color: red
  matchers-condition: and
  matchers:
  - dataSource: response
    field: body
    method: iContains
    content: '"swaggerVersion":'
  - dataSource: response
    field: title
    method: contains
    content: Swagger UI
```
我希望的格式
```yaml
- name: Swagger-UI
  enabled: true
  color: red
  matchers-condition: and
  matchers:
  - dataSource: response
    field: body
    method: iContains
    content:
      - '"swagger":'
      - '"swaggerVersion":'
  - dataSource: response
    field: title
    method: contains
    content: Swagger UI
```

rules:

你可以访问当前的 onescan 代码库。

开始修复：

- 使用 .agent/ 目录作为工作暂存区，在此存储长期计划和待办事项列表。
- 创建 TodoWrite 来追踪任务
- 优先使用 mcp、深度思考和子代理
- 按优先级处理问题
- 每次编辑文件后都需要使用子代理调用 `/commit` 斜杠命令提交并推送更改

你需要为项目编写端到端测试和单元测试。但请确保将大部分时间用于实际工作而非测试，建议的时间分配比例是：80% 用于实际移植，20% 用于测试。
