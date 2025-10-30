# 实现计划

- [ ] 1. 配置Montoya API依赖和项目结构
  - 验证项目使用Maven中央仓库的montoya-api依赖（本地模块已移除）
  - 将Montoya API版本从v2023.12.1升级到v2025.5（当前最新稳定版本）
  - 更新根pom.xml中的montoya-api.version属性为2025.5
  - 执行mvn clean compile验证依赖下载和编译成功
  - 检查Montoya API的HttpRequestEditor和HttpResponseEditor接口可用性
  - 检查Gson依赖是否支持pretty printing功能
  - _需求: 2.1, 2.2, 2.3_

- [ ] 2. 改进FpManager配置文件处理
- [ ] 2.1 添加配置文件格式校验方法
  - 实现validateConfig()方法，校验columns和list字段
  - 添加对每个FpData规则完整性的验证
  - 记录警告日志但不阻止加载
  - _需求: 1.1, 1.2, 1.5_

- [ ] 2.2 优化配置文件加载逻辑
  - 改进loadConfig()方法的异常处理
  - 为JSON和YAML解析失败提供详细错误信息
  - 在加载完成后调用validateConfig()
  - _需求: 1.1, 1.2, 7.1_

- [ ] 2.3 实现配置文件保存功能
  - 创建saveConfig()方法
  - 使用GsonBuilder配置pretty printing和HTML转义
  - 确保保存的JSON文件格式化且可读
  - 添加保存失败的异常处理
  - _需求: 1.3, 1.4_

- [ ]* 2.4 编写FpManager配置处理单元测试
  - 测试JSON格式解析
  - 测试YAML格式解析
  - 测试格式校验逻辑
  - 测试错误处理和异常信息
  - _需求: 1.1, 1.2, 1.5_

- [ ] 3. 重构FpTestWindow使用Montoya API
- [ ] 3.1 更新FpTestWindow构造方法
  - 添加MontoyaApi参数到构造方法
  - 添加支持预填充数据的重载构造方法
  - 移除旧的String类型的request和response字段
  - _需求: 2.1, 2.2, 3.1, 3.2_

- [ ] 3.2 实现HTTP消息编辑器初始化
  - 使用montoyaApi.userInterface().createHttpRequestEditor()创建请求编辑器
  - 使用montoyaApi.userInterface().createHttpResponseEditor()创建响应编辑器
  - 不需要配置EditorOptions参数（默认即可编辑）
  - 通过uiComponent()方法获取编辑器的UI组件用于布局
  - _需求: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

- [ ] 3.3 重构UI布局使用分割面板
  - 创建JSplitPane实现水平分割
  - 将请求编辑器放置在左侧
  - 将响应编辑器放置在右侧
  - 设置分割比例为50:50，支持拖动调整
  - 调整窗口初始大小为1000x700
  - _需求: 4.1, 4.2, 4.5_

- [ ] 3.4 重构doTest()方法
  - 使用mReqEditor.getRequest()获取HttpRequest对象
  - 使用mRespEditor.getResponse()获取HttpResponse对象
  - 使用HttpRequest.toByteArray().getBytes()转换为字节数组
  - 使用HttpResponse.toByteArray().getBytes()转换为字节数组
  - 调用FpManager.check()执行指纹识别（禁用缓存）
  - 处理空数据情况（request或response为null）
  - _需求: 3.1, 3.2, 6.1, 6.4_

- [ ] 3.5 重构doReset()方法
  - 调用mReqEditor.setRequest(null)清空请求
  - 调用mRespEditor.setResponse(null)清空响应
  - 清空测试结果面板
  - _需求: 6.2_

- [ ] 3.6 添加setRequestResponse()辅助方法
  - 接受HttpRequest和HttpResponse参数
  - 设置到对应的编辑器中
  - 支持null值处理
  - _需求: 3.1, 3.2, 6.5_

- [ ]* 3.7 编写FpTestWindow UI集成测试
  - 测试HTTP编辑器初始化
  - 测试分割面板功能
  - 测试按钮交互
  - 测试数据设置和获取
  - _需求: 2.1, 2.2, 4.1, 4.2_

- [ ] 4. 更新FingerprintTab集成
- [ ] 4.1 添加MontoyaApi字段到FingerprintTab
  - 添加private MontoyaApi mMontoyaApi字段
  - 更新构造方法接受MontoyaApi参数
  - _需求: 2.1_

- [ ] 4.2 更新doTest()方法创建测试窗口
  - 传入mMontoyaApi实例到FpTestWindow构造方法
  - 保持窗口单例模式
  - _需求: 2.1, 6.1_

- [ ] 5. 更新BurpExtender主类集成
- [ ] 5.1 获取MontoyaApi实例
  - 在registerExtenderCallbacks()中获取MontoyaApi
  - 存储到成员变量mMontoyaApi
  - _需求: 2.1_

- [ ] 5.2 传递MontoyaApi到FingerprintTab
  - 创建FingerprintTab时传入mMontoyaApi
  - 确保所有依赖组件都能访问MontoyaApi
  - _需求: 2.1_

- [ ] 6. 错误处理和用户反馈改进
- [ ] 6.1 添加配置文件加载错误处理
  - 在FpManager.init()调用处添加try-catch
  - 使用UIHelper.showErrorDialog()显示友好错误信息
  - 记录详细错误日志
  - _需求: 7.1_

- [ ] 6.2 添加HTTP消息解析错误处理
  - 在doTest()方法中添加try-catch
  - 捕获HttpRequest/HttpResponse解析异常
  - 在FpTestResultPanel显示错误提示
  - _需求: 7.4_

- [ ] 6.3 添加指纹匹配错误处理
  - 在FpManager.check()调用处添加try-catch
  - 捕获匹配过程中的异常
  - 显示友好的错误提示信息
  - _需求: 7.2_

- [ ] 6.4 改进窗口资源释放
  - 在closeWindow()方法中释放Montoya编辑器资源
  - 确保窗口关闭时正确清理
  - _需求: 7.5_

- [ ] 7. 手动验证和测试
  - 在Burp Suite中加载插件，打开指纹测试窗口
  - 验证HTTP编辑器显示正常，支持多种视图模式
  - 测试编辑、重置、关闭按钮功能
  - 验证指纹匹配结果正确展示
  - 测试配置文件保存后格式是否可读
  - _需求: 所有需求_
