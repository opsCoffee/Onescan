# 实现计划

- [x] 1. 配置Montoya API依赖和项目结构
  - 验证项目使用Maven中央仓库的montoya-api依赖（本地模块已移除）
  - 将Montoya API版本从v2023.12.1升级到v2025.5（当前最新稳定版本）
  - 更新根pom.xml中的montoya-api.version属性为2025.5
  - 执行mvn clean compile验证依赖下载和编译成功
  - 检查Montoya API的HttpRequestEditor和HttpResponseEditor接口可用性
  - 检查Gson依赖是否支持pretty printing功能
  - _需求: 2.1, 2.2, 2.3_

- [x] 2. 改进FpManager配置文件处理

- [x] 2.1 添加配置文件格式校验方法
  - 在FpManager中实现validateConfig()方法，校验columns和list字段
  - 添加对每个FpData规则完整性的验证
  - 记录警告日志但不阻止加载
  - _需求: 1.1, 1.2, 1.5_

- [x] 2.2 优化配置文件加载逻辑
  - 改进loadConfig()方法的异常处理（方法已存在）
  - 为JSON和YAML解析失败提供详细错误信息
  - 在加载完成后调用validateConfig()
  - 添加文件路径到错误信息中
  - _需求: 1.1, 1.2, 7.1_

- [x] 2.3 改进配置文件保存功能（实现格式幂等性）
  - 修改FpConfig.writeToFile()方法（方法已存在）
  - 根据文件扩展名选择保存格式（.yaml/.yml → YAML，其他 → JSON）
  - 配置YAML输出：使用DumperOptions设置BLOCK风格、pretty flow、2空格缩进
  - 配置JSON输出：使用GsonBuilder设置setPrettyPrinting()和disableHtmlEscaping()
  - 确保YAML文件保存为YAML格式（完全幂等）
  - 确保JSON文件保存为格式化的JSON（可读性）
  - 不修改GsonUtils类，避免影响其他功能
  - _需求: 1.3, 1.4, 格式幂等性_

- [ ]* 2.4 编写FpManager配置处理单元测试
  - 测试JSON格式解析
  - 测试YAML格式解析
  - 测试格式校验逻辑
  - 测试错误处理和异常信息
  - _需求: 1.1, 1.2, 1.5_

- [ ] 3. 重构FpTestWindow使用Montoya API
- [ ] 3.1 更新FpTestWindow构造方法和字段
  - 添加MontoyaApi参数到构造方法
  - 添加支持预填充数据的重载构造方法（接受HttpRequest和HttpResponse）
  - 移除旧的String类型的request和response字段
  - 移除旧的JTextArea类型的mReqEditor和mRespEditor字段
  - 添加HttpRequestEditor和HttpResponseEditor类型的字段
  - _需求: 2.1, 2.2, 3.1, 3.2_

- [ ] 3.2 实现HTTP消息编辑器初始化
  - 使用montoyaApi.userInterface().createHttpRequestEditor()创建请求编辑器
  - 使用montoyaApi.userInterface().createHttpResponseEditor()创建响应编辑器
  - 不需要配置EditorOptions参数（默认即可编辑）
  - 通过uiComponent()方法获取编辑器的UI组件用于布局
  - _需求: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

- [ ] 3.3 重构UI布局使用分割面板
  - 创建JSplitPane实现水平分割
  - 将请求编辑器的uiComponent()放置在左侧
  - 将响应编辑器的uiComponent()放置在右侧
  - 设置分割比例为50:50，支持拖动调整
  - 移除旧的TitledBorder和JScrollPane布局
  - 调整窗口初始大小为1000x700
  - _需求: 4.1, 4.2, 4.5_

- [ ] 3.4 重构doTest()方法
  - 使用mReqEditor.getRequest()获取HttpRequest对象
  - 使用mRespEditor.getResponse()获取HttpResponse对象
  - 使用HttpRequest.toByteArray().getBytes()转换为字节数组
  - 使用HttpResponse.toByteArray().getBytes()转换为字节数组
  - 移除旧的字符串处理逻辑（getText()和replace("\n", "\r\n")）
  - 调用FpManager.check()执行指纹识别（禁用缓存）
  - 处理空数据情况（request或response为null）
  - _需求: 3.1, 3.2, 6.1, 6.4_

- [ ] 3.5 重构doReset()方法
  - 调用mReqEditor.setRequest(null)清空请求
  - 调用mRespEditor.setResponse(null)清空响应
  - 移除旧的setText("")调用
  - 清空测试结果面板
  - _需求: 6.2_

- [ ] 3.6 添加setRequestResponse()辅助方法
  - 接受HttpRequest和HttpResponse参数
  - 使用mReqEditor.setRequest()设置请求
  - 使用mRespEditor.setResponse()设置响应
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
  - 在initData()或构造方法中保存MontoyaApi实例
  - _需求: 2.1_

- [ ] 4.2 更新doTest()方法创建测试窗口
  - 修改FpTestWindow实例化，传入mMontoyaApi参数
  - 保持窗口单例模式（if (mFpTestWindow == null)检查）
  - _需求: 2.1, 6.1_

- [ ] 5. 更新BurpExtender主类集成
- [ ] 5.1 获取MontoyaApi实例
  - 在registerExtenderCallbacks()或initData()中调用callbacks.getMontoyaApi()
  - 存储到成员变量mMontoyaApi
  - 添加必要的import语句（burp.api.montoya.MontoyaApi）
  - _需求: 2.1_

- [ ] 5.2 传递MontoyaApi到FingerprintTab
  - 在initView()中创建FingerprintTab时传入mMontoyaApi
  - 查找mOneScan.getFingerprintTab()或类似方法获取FingerprintTab实例
  - 确保所有依赖组件都能访问MontoyaApi
  - _需求: 2.1_

- [ ] 6. 错误处理和用户反馈改进
- [ ] 6.1 添加配置文件加载错误处理
  - 在BurpExtender中FpManager.init()调用处添加try-catch
  - 使用UIHelper.showErrorDialog()显示友好错误信息
  - 使用Logger.error()记录详细错误日志
  - _需求: 7.1_

- [ ] 6.2 添加HTTP消息解析错误处理
  - 在FpTestWindow.doTest()方法中添加try-catch
  - 捕获getRequest()/getResponse()可能的异常
  - 捕获toByteArray()转换异常
  - 在FpTestResultPanel使用showTips()显示错误提示
  - _需求: 7.4_

- [ ] 6.3 添加指纹匹配错误处理
  - 在FpTestWindow.doTest()中FpManager.check()调用处添加try-catch
  - 捕获匹配过程中的异常
  - 使用mTestResultPanel.showTips()显示友好的错误提示信息
  - _需求: 7.2_

- [ ] 6.4 改进窗口资源释放
  - 在closeWindow()方法中检查编辑器是否需要显式释放
  - 确保窗口关闭时正确清理（Montoya API通常自动管理资源）
  - 测试窗口关闭后重新打开是否正常
  - _需求: 7.5_

- [ ] 7. 手动验证和测试
  - 编译项目：mvn clean package
  - 在Burp Suite中加载插件JAR文件
  - 打开OneScan插件的指纹测试窗口
  - 验证HTTP编辑器显示正常，支持Raw、Headers、Hex等视图模式
  - 输入测试数据，点击"测试"按钮验证指纹匹配功能
  - 测试"重置"按钮清空编辑器和结果
  - 测试"关闭"按钮关闭窗口
  - 验证指纹匹配结果正确展示在结果面板
  - 修改指纹配置，保存后检查文件格式是否可读（JSON或YAML）
  - _需求: 所有需求_
