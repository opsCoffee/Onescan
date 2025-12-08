package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.common.helper.DomainHelper;
import burp.common.helper.QpsLimiter;
import burp.common.helper.UIHelper;
import burp.common.log.Logger;
import burp.common.utils.*;
import burp.onescan.OneScan;
import burp.onescan.bean.FpData;
import burp.onescan.bean.TaskData;
import burp.onescan.common.*;
import burp.onescan.common.IHttpRequestResponse; // 显式导入,避免与 burp.IHttpRequestResponse 冲突
import burp.onescan.manager.FpManager;
import burp.onescan.manager.WordlistManager;
import burp.onescan.ui.tab.DataBoardTab;
import burp.onescan.ui.tab.FingerprintTab;
import burp.onescan.ui.tab.config.OtherTab;
import burp.onescan.ui.tab.config.RequestTab;
import burp.onescan.ui.widget.TaskTable;
import burp.onescan.ui.widget.payloadlist.PayloadItem;
import burp.onescan.ui.widget.payloadlist.PayloadRule;
import burp.onescan.ui.widget.payloadlist.ProcessingItem;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.io.File;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.stream.Collectors;

/**
 * 插件入口
 * <p>
 * Created by vaycore on 2022-08-07.
 * <p>
 * ============================================================
 * 职责区域索引 (7 大职责)
 * ============================================================
 * 1. 插件生命周期管理
 * - BurpExtension: 插件注册和初始化 (Montoya API)
 * - api.extension().registerUnloadingHandler(): 插件卸载监听
 *
 * 2. 扫描引擎管理
 * - 线程池管理 (mTaskThreadPool, mLFTaskThreadPool, mFpThreadPool)
 * - 任务调度和去重 (sRepeatFilter, sTimeoutReqHost)
 * - 任务计数器 (mTaskOverCounter, mTaskCommitCounter)
 *
 * 3. 代理监听 (Montoya API)
 * - ProxyResponseHandler: 代理响应拦截和处理
 *
 * 4. UI 控制 (Montoya API)
 * - api.userInterface().registerSuiteTab(): 插件 Tab 注册
 * - HttpRequestEditor/HttpResponseEditor: HTTP 消息编辑器
 *
 * 5. 任务表事件处理
 * - TaskTable.OnTaskTableEventListener: 任务表操作事件
 *
 * 6. Tab 事件处理
 * - OnTabEventListener: 配置 Tab 事件
 *
 * 7. 请求处理核心逻辑
 * - 请求过滤和验证
 * - Payload 处理和变量替换
 * - HTTP 请求发送和响应处理
 * ============================================================
 */
public class BurpExtender implements BurpExtension,
        TaskTable.OnTaskTableEventListener, OnTabEventListener {

    /**
     * 任务线程数量
     */
    private static final int TASK_THREAD_COUNT = 50;

    /**
     * 低频任务线程数量
     */
    private static final int LF_TASK_THREAD_COUNT = 25;

    /**
     * 指纹识别线程数量
     */
    private static final int FP_THREAD_COUNT = 10;

    /**
     * 空字节数组常量（防止频繁创建）
     */
    private static final byte[] EMPTY_BYTES = new byte[0];

    /**
     * 请求来源：代理
     */
    private static final String FROM_PROXY = "Proxy";

    /**
     * 请求来源：发送到 OneScan 扫描
     */
    private static final String FROM_SEND = "Send";

    /**
     * 请求来源：Payload Processing
     */
    private static final String FROM_PROCESS = "Process";

    /**
     * 请求来源：导入
     */
    private static final String FROM_IMPORT = "Import";

    /**
     * 请求来源：扫描
     */
    private static final String FROM_SCAN = "Scan";

    /**
     * 请求来源：重定向
     */
    private static final String FROM_REDIRECT = "Redirect";

    /**
     * 去重过滤集合最大容量，防止 OOM
     */
    private static final int MAX_REPEAT_FILTER_SIZE = 50_000;

    /**
     * HTTP 协议相关常量
     */
    private static final int HTTP_DEFAULT_PORT = 80;
    private static final int HTTPS_DEFAULT_PORT = 443;
    private static final int HTTP_STATUS_REDIRECT_START = 300;
    private static final int HTTP_STATUS_CLIENT_ERROR_START = 400;

    /**
     * 限制和阈值常量
     */
    private static final int MAX_TASK_LIMIT = 9999;
    private static final int MIN_LENGTH_FOR_TRUNCATION = 100_000;

    /**
     * 性能优化相关常量
     */
    private static final int HTTP_REQUEST_BUILDER_INITIAL_CAPACITY = 1024;
    private static final int STATUS_REFRESH_INTERVAL_MS = 1000;

    /**
     * 去重过滤集合
     */
    private final Set<String> sRepeatFilter = createLruSet(MAX_REPEAT_FILTER_SIZE);

    /**
     * 超时的请求主机集合
     */
    private final Set<String> sTimeoutReqHost = ConcurrentHashMap.newKeySet();

    private MontoyaApi api;
    private OneScan mOneScan;
    private DataBoardTab mDataBoardTab;
    private HttpRequestEditor mRequestTextEditor;
    private HttpResponseEditor mResponseTextEditor;
    private burp.onescan.engine.ScanEngine mScanEngine;
    private burp.onescan.common.IHttpRequestResponse mCurrentReqResp;
    private QpsLimiter mQpsLimit;
    private Timer mStatusRefresh;

    // ============================================================
    // 辅助方法 - 工具函数
    // ============================================================

    /**
     * 创建 LRU Set
     * <p>
     * 使用 LinkedHashMap 实现 LRU（最近最少使用）策略，当集合超过最大容量时，
     * 自动移除最老的元素。通过 Collections.synchronizedSet 包装以保证线程安全。
     *
     * @param maxSize 最大集合容量
     * @return 线程安全的 LRU Set
     */
    private static <E> Set<E> createLruSet(int maxSize) {
        return Collections.synchronizedSet(Collections.newSetFromMap(
                new java.util.LinkedHashMap<E, Boolean>(16, 0.75f, true) {
                    @Override
                    protected boolean removeEldestEntry(java.util.Map.Entry<E, Boolean> eldest) {
                        return size() > maxSize;
                    }
                }));
    }

    // ============================================================
    // 职责 1: 插件生命周期管理
    // 实现接口: BurpExtension (Montoya API)
    // ============================================================

    @Override
    public void initialize(MontoyaApi api) {
        initData(api);
        initView();
        initEvent();
        Logger.debug("register Extender ok! Log: %b", Constants.DEBUG);
    }

    private void initData(MontoyaApi api) {
        this.api = api;
        // 初始化扫描引擎
        this.mScanEngine = new burp.onescan.engine.ScanEngine(
                TASK_THREAD_COUNT,
                LF_TASK_THREAD_COUNT,
                FP_THREAD_COUNT);
        api.extension().setName(Constants.PLUGIN_NAME + " v" + Constants.PLUGIN_VERSION);
        // 初始化日志打印 (MIGRATE-403: 使用 Montoya API)
        Logger.init(Constants.DEBUG, api);
        // 初始化默认配置
        Config.init(getWorkDir());
        // 初始化域名辅助类
        DomainHelper.init("public_suffix_list.json");
        // 初始化QPS限制器
        initQpsLimiter();
        // 注册扩展卸载监听器 (Montoya API)
        api.extension().registerUnloadingHandler(this::extensionUnloaded);
    }

    /**
     * 获取工作目录路径（优先获取当前插件 jar 包所在目录配置文件，如果配置不存在，则使用默认工作目录）
     */
    private String getWorkDir() {
        String workDir = Paths.get(api.extension().filename())
                .getParent().toString() + File.separator + "OneScan" + File.separator;
        if (FileUtils.isDir(workDir)) {
            return workDir;
        }
        return null;
    }

    /**
     * 初始化 QPS 限制器
     */
    private void initQpsLimiter() {
        // 检测范围，如果不符合条件，不创建限制器
        int limit = Config.getInt(Config.KEY_QPS_LIMIT);
        int delay = Config.getInt(Config.KEY_REQUEST_DELAY);
        if (limit > 0 && limit <= MAX_TASK_LIMIT) {
            this.mQpsLimit = new QpsLimiter(limit, delay);
        }
    }

    private void initView() {
        mOneScan = new OneScan();
        mDataBoardTab = mOneScan.getDataBoardTab();
        // 注册事件
        mDataBoardTab.setOnTabEventListener(this);
        mOneScan.getConfigPanel().setOnTabEventListener(this);
        // 将页面添加到 BurpSuite (使用 Montoya API)
        api.userInterface().registerSuiteTab(Constants.PLUGIN_NAME, mOneScan);
        // 创建请求和响应编辑器 (使用 Montoya API - 带语法高亮和多视图)
        mRequestTextEditor = api.userInterface().createHttpRequestEditor();
        mResponseTextEditor = api.userInterface().createHttpResponseEditor();
        mDataBoardTab.init(mRequestTextEditor.uiComponent(), mResponseTextEditor.uiComponent());
        mDataBoardTab.getTaskTable().setOnTaskTableEventListener(this);
    }

    private void initEvent() {
        // 监听代理的响应 (Montoya API)
        api.proxy().registerResponseHandler(new OneScanProxyResponseHandler());
        // 注册上下文菜单 (Montoya API)
        api.userInterface()
                .registerContextMenuItemsProvider(new burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider() {
                    @Override
                    public List<Component> provideMenuItems(burp.api.montoya.ui.contextmenu.ContextMenuEvent event) {
                        return BurpExtender.this.provideMenuItems(event);
                    }
                });
        // 状态栏刷新定时器
        mStatusRefresh = new Timer(STATUS_REFRESH_INTERVAL_MS, e -> {
            if (mDataBoardTab == null) {
                return;
            }
            mDataBoardTab.refreshTaskStatus(mScanEngine.getTaskOverCount(), mScanEngine.getTaskCommitCount());
            mDataBoardTab.refreshLFTaskStatus(mScanEngine.getLFTaskOverCount(), mScanEngine.getLFTaskCommitCount());
            mDataBoardTab.refreshTaskHistoryStatus();
            mDataBoardTab.refreshFpCacheStatus();
        });
        mStatusRefresh.start();
    }

    // ============================================================
    // 职责 7: 右键菜单
    // 实现接口: ContextMenuItemsProvider (Montoya API)
    // ============================================================

    private List<Component> provideMenuItems(burp.api.montoya.ui.contextmenu.ContextMenuEvent event) {
        ArrayList<Component> items = new ArrayList<>();
        // 扫描选定目标
        JMenuItem sendToOneScanItem = new JMenuItem(L.get("send_to_plugin"));
        items.add(sendToOneScanItem);
        sendToOneScanItem.addActionListener((actionEvent) -> new Thread(() -> {
            // Montoya API: 获取选中的消息 (处理不同的事件类型)
            List<burp.api.montoya.http.message.HttpRequestResponse> messages = new ArrayList<>();

            // 从消息编辑器获取
            if (event.messageEditorRequestResponse().isPresent()) {
                burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse editorReqResp = event
                        .messageEditorRequestResponse().get();
                // 构建 HttpRequestResponse
                messages.add(createHttpRequestResponse(editorReqResp));
            }
            // 从选中的请求中获取
            else if (!event.selectedRequestResponses().isEmpty()) {
                messages.addAll(event.selectedRequestResponses());
            }

            for (burp.api.montoya.http.message.HttpRequestResponse httpReqResp : messages) {
                doScan(httpReqResp, FROM_SEND);
                if (isTaskThreadPoolShutdown()) {
                    return;
                }
            }
        }).start());
        // 选择 Payload 扫描
        List<String> payloadList = WordlistManager.getItemList(WordlistManager.KEY_PAYLOAD);
        if (!payloadList.isEmpty() && payloadList.size() > 1) {
            JMenu menu = new JMenu(L.get("use_payload_scan"));
            items.add(menu);
            ActionListener listener = createDynamicPayloadScanListener(event);
            for (String itemName : payloadList) {
                JMenuItem item = new JMenuItem(itemName);
                item.setActionCommand(itemName);
                item.addActionListener(listener);
                menu.add(item);
            }
        }
        return items;
    }

    /**
     * 从消息编辑器的 RequestResponse 创建 HttpRequestResponse
     */
    private burp.api.montoya.http.message.HttpRequestResponse createHttpRequestResponse(
            burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse editorReqResp) {
        return burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(
                editorReqResp.requestResponse().request(),
                editorReqResp.requestResponse().response());
    }

    /**
     * 创建使用动态 Payload 的批量扫描 ActionListener
     * Payload 从 ActionEvent.getActionCommand() 获取
     *
     * @param event 上下文菜单事件 (Montoya API)
     * @return ActionListener
     */
    private ActionListener createDynamicPayloadScanListener(burp.api.montoya.ui.contextmenu.ContextMenuEvent event) {
        return (actionEvent) -> new Thread(() -> {
            String payloadItem = actionEvent.getActionCommand();
            // Montoya API: 获取选中的消息 (处理不同的事件类型)
            List<burp.api.montoya.http.message.HttpRequestResponse> messages = new ArrayList<>();

            // 从消息编辑器获取
            if (event.messageEditorRequestResponse().isPresent()) {
                burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse editorReqResp = event
                        .messageEditorRequestResponse().get();
                // 构建 HttpRequestResponse
                messages.add(createHttpRequestResponse(editorReqResp));
            }
            // 从选中的请求中获取
            else if (!event.selectedRequestResponses().isEmpty()) {
                messages.addAll(event.selectedRequestResponses());
            }

            for (burp.api.montoya.http.message.HttpRequestResponse httpReqResp : messages) {
                doScan(httpReqResp, FROM_SEND, payloadItem);
                if (isTaskThreadPoolShutdown()) {
                    return;
                }
            }
        }).start();
    }

    // ============================================================
    // 职责 3: 代理监听 (已迁移到 Montoya API)
    // 实现接口: ProxyResponseHandler
    // ============================================================

    /**
     * 代理响应处理器 (Montoya API)
     * <p>
     * 替代传统的 IProxyListener.processProxyMessage() 方法
     * 优势: 不需要 boolean 判断,直接处理响应阶段
     */
    private class OneScanProxyResponseHandler implements burp.api.montoya.proxy.http.ProxyResponseHandler {

        @Override
        public burp.api.montoya.proxy.http.ProxyResponseReceivedAction handleResponseReceived(
                burp.api.montoya.proxy.http.InterceptedResponse interceptedResponse) {
            // 检测开关状态
            if (!mDataBoardTab.hasListenProxyMessage()) {
                return burp.api.montoya.proxy.http.ProxyResponseReceivedAction.continueWith(interceptedResponse);
            }

            // 获取请求响应对象 (Montoya API)
            // InterceptedResponse 本身实现了 HttpResponse,而 initiatingRequest() 返回 HttpRequest
            burp.api.montoya.http.message.HttpRequestResponse montoyaReqResp = burp.api.montoya.http.message.HttpRequestResponse
                    .httpRequestResponse(
                            interceptedResponse.initiatingRequest(),
                            interceptedResponse // InterceptedResponse 就是 HttpResponse
                    );

            // 扫描任务
            doScan(montoyaReqResp, FROM_PROXY);

            // 继续传递响应 (不修改)
            return burp.api.montoya.proxy.http.ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        @Override
        public burp.api.montoya.proxy.http.ProxyResponseToBeSentAction handleResponseToBeSent(
                burp.api.montoya.proxy.http.InterceptedResponse interceptedResponse) {
            // 不需要在发送前阶段进行处理
            return burp.api.montoya.proxy.http.ProxyResponseToBeSentAction.continueWith(interceptedResponse);
        }
    }

    // ============================================================
    // 辅助方法: Montoya API 请求构建
    // ============================================================

    /**
     * 从 URL 字符串构建 Montoya API 的 HttpRequestResponse
     * MIGRATE-202: HTTP 消息处理迁移的一部分
     *
     * @param url URL 字符串
     * @return HttpRequestResponse 实例
     * @throws IllegalArgumentException 如果 URL 格式错误
     */
    private burp.api.montoya.http.message.HttpRequestResponse buildMontoyaRequestFromUrl(String url)
            throws IllegalArgumentException {
        if (StringUtils.isEmpty(url)) {
            throw new IllegalArgumentException("url is null");
        }
        if (!UrlUtils.isHTTP(url)) {
            throw new IllegalArgumentException(url + " does not include the protocol.");
        }
        try {
            URL u = new URL(url);
            String host = UrlUtils.getHostByURL(u);
            String pqf = UrlUtils.toPQF(u);
            byte[] requestBytes = buildSimpleGetRequest(host, pqf);

            burp.api.montoya.http.HttpService service = burp.api.montoya.http.HttpService.httpService(
                    u.getHost(),
                    u.getPort() == -1 ? (u.getProtocol().equals("https") ? 443 : 80) : u.getPort(),
                    u.getProtocol().equals("https"));

            burp.api.montoya.http.message.requests.HttpRequest request = burp.api.montoya.http.message.requests.HttpRequest
                    .httpRequest(service,
                            burp.api.montoya.core.ByteArray.byteArray(requestBytes));

            return burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(
                    request,
                    null // 导入URL时没有响应
            );
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Url: " + url + " format error.");
        }
    }

    /**
     * 从重定向信息构建 Montoya API 的 HttpRequestResponse
     * MIGRATE-202: 用于处理重定向场景
     *
     * @param service  旧API的HttpService
     * @param urlOrPqf 完整URL或路径
     * @param headers  请求头列表
     * @param cookies  Cookie列表
     * @return HttpRequestResponse 实例
     * @throws IllegalArgumentException 如果参数错误
     */
    private burp.api.montoya.http.message.HttpRequestResponse buildMontoyaRequestFromRedirect(
            burp.api.montoya.http.HttpService service, String urlOrPqf, List<String> headers, List<String> cookies)
            throws IllegalArgumentException {

        // service 已经是 Montoya HttpService,直接使用
        // 构建请求字节数组
        byte[] requestBytes;
        if (UrlUtils.isHTTP(urlOrPqf)) {
            // 完整URL
            try {
                URL u = new URL(urlOrPqf);
                String pqf = UrlUtils.toPQF(u);
                requestBytes = buildRequestWithHeadersAndCookies(pqf, headers, cookies, service);
            } catch (MalformedURLException e) {
                throw new IllegalArgumentException("Invalid URL: " + urlOrPqf);
            }
        } else {
            // 只有路径
            requestBytes = buildRequestWithHeadersAndCookies(urlOrPqf, headers, cookies, service);
        }

        burp.api.montoya.http.message.requests.HttpRequest request = burp.api.montoya.http.message.requests.HttpRequest
                .httpRequest(service,
                        burp.api.montoya.core.ByteArray.byteArray(requestBytes));

        return burp.api.montoya.http.message.HttpRequestResponse.httpRequestResponse(
                request,
                null // 重定向请求时没有响应
        );
    }

    /**
     * 构建包含headers和cookies的请求字节数组
     */
    private byte[] buildRequestWithHeadersAndCookies(String reqPQF, List<String> headers,
            List<String> cookies,
            burp.api.montoya.http.HttpService service) {
        boolean existsCookie = headers != null && headers.stream()
                .anyMatch(h -> h.toLowerCase().startsWith("cookie: "));

        StringBuilder builder = new StringBuilder();
        String host = service.host() + (service.port() == 80 || service.port() == 443 ? "" : ":" + service.port());

        builder.append("GET ").append(reqPQF).append(" HTTP/1.1").append("\r\n");
        builder.append("Host: ").append(host).append("\r\n");

        if (headers != null && headers.size() > 1) {
            for (int i = 1; i < headers.size(); i++) {
                String item = headers.get(i);
                // 排除 Host 请求头
                if (item.toLowerCase().startsWith("host: ")) {
                    continue;
                }
                // 处理 Cookie
                if (!existsCookie && i == 2 && cookies != null && !cookies.isEmpty()) {
                    builder.append("Cookie: ").append(String.join("; ", cookies)).append("\r\n");
                } else if (item.toLowerCase().startsWith("cookie: ")) {
                    if (cookies != null && !cookies.isEmpty()) {
                        builder.append("Cookie: ").append(String.join("; ", cookies)).append("\r\n");
                    } else {
                        builder.append(item).append("\r\n");
                    }
                    continue;
                }
                builder.append(item).append("\r\n");
            }
        }
        builder.append("\r\n");
        return builder.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 构建简单的 GET 请求字节数组
     *
     * @param host   主机名
     * @param reqPQF 请求路径 (Path + Query + Fragment)
     * @return 请求字节数组
     */
    private static byte[] buildSimpleGetRequest(String host, String reqPQF) {
        return ("GET " + reqPQF + " HTTP/1.1\r\n" +
                "Host: " + host + "\r\n" +
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
                +
                "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n" +
                "Accept-Encoding: gzip, deflate\r\n" +
                "Cache-Control: max-age=0\r\n" +
                "\r\n").getBytes(StandardCharsets.UTF_8);
    }

    // ============================================================
    // 职责 9: 请求处理核心逻辑
    // 包含: 扫描任务调度、请求过滤、Payload处理、HTTP请求发送
    // ============================================================

    private void doScan(burp.api.montoya.http.message.HttpRequestResponse httpReqResp, String from) {
        String item = WordlistManager.getItem(WordlistManager.KEY_PAYLOAD);
        doScan(httpReqResp, from, item);
    }

    /**
     * 检查是否应该跳过 HTTP payload（用于递归扫描）
     *
     * @param path    当前扫描路径
     * @param payload payload 项
     * @return true 表示应该跳过
     */
    private boolean shouldSkipHttpPayload(String path, String payload) {
        // 对完整 Host 地址的字典取消递归扫描（直接替换请求路径扫描）
        return StringUtils.isNotEmpty(path) && UrlUtils.isHTTP(payload);
    }

    /**
     * 构建扫描用的 URL 路径
     *
     * @param path    当前路径
     * @param payload payload 项
     * @param reqPath 请求路径
     * @param reqHost 请求主机地址
     * @return 构建后的 URL 路径
     */
    private String buildScanUrlPath(String path, String payload, String reqPath, String reqHost) {
        String urlPath = path + payload;

        // 如果配置的字典不含 '/' 前缀，在根目录下扫描时，自动添加 '/' 符号
        if (StringUtils.isEmpty(path) && !payload.startsWith("/") && !UrlUtils.isHTTP(payload)) {
            urlPath = "/" + payload;
        }

        // 检测一下是否携带完整的 Host 地址（兼容一下携带了完整的 Host 地址的情况）
        // 但有个前提：如果字典存在完整的 Host 地址，直接不做处理
        if (UrlUtils.isHTTP(reqPath) && !UrlUtils.isHTTP(payload)) {
            urlPath = reqHost + urlPath;
        }

        return urlPath;
    }

    private void doScan(burp.api.montoya.http.message.HttpRequestResponse httpReqResp, String from,
            String payloadItem) {
        if (httpReqResp == null || httpReqResp.httpService() == null) {
            return;
        }

        byte[] requestBytes = httpReqResp.request().toByteArray().getBytes();
        byte[] responseBytes = httpReqResp.response() != null
                ? httpReqResp.response().toByteArray().getBytes()
                : new byte[0];

        HttpRequest request = httpReqResp.request();
        String host = httpReqResp.httpService().host();

        // 应用过滤规则
        if (shouldFilterRequest(from, host, request.method())) {
            return;
        }

        // 提交指纹识别任务
        submitFingerprintTask(requestBytes, responseBytes);

        // 处理原始请求
        try {
            URL url = new URL(request.url());
            processOriginalRequest(httpReqResp, request, url, from);

            // 递归目录扫描
            if (mDataBoardTab.hasDirScan()) {
                performRecursiveScan(httpReqResp, request, url, payloadItem);
            }
        } catch (java.net.MalformedURLException e) {
            Logger.debug("Invalid URL from request: %s", request.url());
        }
    }

    /**
     * 检查请求是否应该被过滤
     */
    private boolean shouldFilterRequest(String from, String host, String method) {
        // 对来自代理的包进行检测
        if (from.equals(FROM_PROXY)) {
            if (includeMethodFilter(method)) {
                Logger.debug("doScan filter request method: %s, host: %s", method, host);
                return true;
            }
            if (hostAllowlistFilter(host) || hostBlocklistFilter(host)) {
                Logger.debug("doScan allowlist and blocklist filter host: %s", host);
                return true;
            }
        }

        // 对来自重定向的包进行检测
        if (from.startsWith(FROM_REDIRECT) && Config.getBoolean(Config.KEY_REDIRECT_TARGET_HOST_LIMIT)) {
            if (hostAllowlistFilter(host) || hostBlocklistFilter(host)) {
                Logger.debug("doScan allowlist and blocklist filter host: %s", host);
                return true;
            }
        }

        return false;
    }

    /**
     * 提交指纹识别任务
     */
    private void submitFingerprintTask(byte[] request, byte[] response) {
        if (!mScanEngine.isFpThreadPoolShutdown()) {
            mScanEngine.submitFpTask(() -> FpManager.check(request, response));
        }
    }

    /**
     * 处理原始请求（非递归扫描）
     */
    private void processOriginalRequest(burp.api.montoya.http.message.HttpRequestResponse httpReqResp,
            HttpRequest request, URL url, String from) {
        if (!proxyExcludeSuffixFilter(url.getPath())) {
            runScanTask(httpReqResp, request, null, from);
        } else {
            Logger.debug("proxyExcludeSuffixFilter filter request path: %s", url.getPath());
        }
    }

    /**
     * 执行递归目录扫描
     */
    private void performRecursiveScan(burp.api.montoya.http.message.HttpRequestResponse httpReqResp,
            HttpRequest request, URL url, String payloadItem) {
        String reqPath = getReqPathByRequestInfo(request);
        String reqHost = getReqHostByReqPath(reqPath);
        Logger.debug("doScan receive: %s", url.toString());

        ArrayList<String> pathDict = getUrlPathDict(url.getPath());
        List<String> payloads = WordlistManager.getPayload(payloadItem);

        // 一级目录一级目录递减访问
        for (int i = pathDict.size() - 1; i >= 0; i--) {
            String path = pathDict.get(i);
            // 去除结尾的 '/' 符号
            if (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }

            // 对每个 payload 生成扫描任务
            for (String item : payloads) {
                if (isTaskThreadPoolShutdown()) {
                    return;
                }
                if (shouldSkipHttpPayload(path, item)) {
                    continue;
                }

                String urlPath = buildScanUrlPath(path, item, reqPath, reqHost);
                runScanTask(httpReqResp, request, urlPath, FROM_SCAN);
            }
        }
    }

    /**
     * 从 HttpRequest 实例中读取请求行中的请求路径
     *
     * @param request HttpRequest 实例
     * @return 不存在返回空字符串
     */
    private String getReqPathByRequestInfo(HttpRequest request) {
        if (request == null) {
            return "";
        }
        // Montoya API 的 HttpRequest 已经提供了 path() 方法,直接使用
        return request.path();
    }

    /**
     * 从请求路径中（有些站点请求路径中包含完整的 Host 地址）获取请求的 Host 地址
     *
     * @param reqPath 请求路径
     * @return 不包含 Host 地址，返回空字符串
     */
    private String getReqHostByReqPath(String reqPath) {
        if (StringUtils.isEmpty(reqPath) || !UrlUtils.isHTTP(reqPath)) {
            return "";
        }
        try {
            URL url = new URL(reqPath);
            return UrlUtils.getReqHostByURL(url);
        } catch (MalformedURLException e) {
            return "";
        }
    }

    /**
     * 过滤请求方法
     *
     * @param method 请求方法
     * @return true=拦截；false=不拦截
     */
    private boolean includeMethodFilter(String method) {
        String includeMethod = Config.get(Config.KEY_INCLUDE_METHOD);
        // 如果配置为空，不拦截任何请求方法
        if (StringUtils.isNotEmpty(includeMethod)) {
            String[] split = includeMethod.split("\\|");
            boolean hasFilter = true;
            for (String item : split) {
                if (method.equals(item)) {
                    hasFilter = false;
                    break;
                }
            }
            return hasFilter;
        }
        return false;
    }

    /**
     * Host 白名单过滤
     *
     * @param host Host
     * @return true=拦截；false=不拦截
     */
    private boolean hostAllowlistFilter(String host) {
        List<String> list = WordlistManager.getHostAllowlist();
        // 白名单为空，不启用白名单
        if (list.isEmpty()) {
            return false;
        }
        for (String item : list) {
            if (matchHost(host, item)) {
                return false;
            }
        }
        Logger.debug("hostAllowlistFilter filter host: %s", host);
        return true;
    }

    /**
     * Host 黑名单过滤
     *
     * @param host Host
     * @return true=拦截；false=不拦截
     */
    private boolean hostBlocklistFilter(String host) {
        List<String> list = WordlistManager.getHostBlocklist();
        // 黑名单为空，不启用黑名单
        if (list.isEmpty()) {
            return false;
        }
        for (String item : list) {
            if (matchHost(host, item)) {
                Logger.debug("hostBlocklistFilter filter host: %s （rule: %s）", host, item);
                return true;
            }
        }
        return false;
    }

    /**
     * 检测 Host 是否匹配规则
     *
     * @param host Host（不包含协议、端口号）
     * @param rule 规则
     * @return true=匹配；false=不匹配
     */
    private static boolean matchHost(String host, String rule) {
        if (StringUtils.isEmpty(host)) {
            return StringUtils.isEmpty(rule);
        }
        // 规则就是*号，直接返回true
        if (rule.equals("*")) {
            return true;
        }
        // 不包含*号，检测 Host 与规则是否相等
        if (!rule.contains("*")) {
            return host.equals(rule);
        }
        // 根据*号位置，进行匹配
        String ruleValue = rule.replace("*", "");
        if (rule.startsWith("*") && rule.endsWith("*")) {
            return host.contains(ruleValue);
        } else if (rule.startsWith("*")) {
            return host.endsWith(ruleValue);
        } else if (rule.endsWith("*")) {
            return host.startsWith(ruleValue);
        } else {
            String[] split = rule.split("\\*");
            return host.startsWith(split[0]) && host.endsWith(split[1]);
        }
    }

    /**
     * 代理请求的后缀过滤
     *
     * @param reqPath 请求路径（不包含 Query 参数）
     * @return true=拦截；false=不拦截
     */
    private boolean proxyExcludeSuffixFilter(String reqPath) {
        if (StringUtils.isEmpty(reqPath) || "/".equals(reqPath)) {
            return false;
        }
        // 统一转换为小写
        String suffix = Config.get(Config.KEY_EXCLUDE_SUFFIX).toLowerCase();
        String path = reqPath.toLowerCase();
        if (StringUtils.isEmpty(suffix)) {
            return false;
        }
        // 配置中不存在多个过滤的后缀名，直接检测
        if (!suffix.contains("|") && path.endsWith("." + suffix)) {
            return true;
        }
        String[] split = suffix.split("\\|");
        for (String item : split) {
            if (path.endsWith("." + item)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 使用 '/' 分割 URL 实例的 path 数据，通过组合第一层级目录，生成字典列表
     *
     * @param urlPath URL 实例的 path 数据
     * @return 失败返回空列表
     */
    private ArrayList<String> getUrlPathDict(String urlPath) {
        String direct = Config.get(Config.KEY_SCAN_LEVEL_DIRECT);
        int scanLevel = Config.getInt(Config.KEY_SCAN_LEVEL);
        ArrayList<String> result = new ArrayList<>();
        result.add("/");
        if (StringUtils.isEmpty(urlPath) || "/".equals(urlPath)) {
            return result;
        }
        // 限制方向从左往右，并且扫描层级为1
        if (Config.DIRECT_LEFT.equals(direct) && scanLevel <= 1) {
            return result;
        }
        // 结尾如果不是'/'符号，去掉访问的文件
        if (!urlPath.endsWith("/")) {
            urlPath = urlPath.substring(0, urlPath.lastIndexOf("/") + 1);
        }
        String[] splitDirname = urlPath.split("/");
        if (splitDirname.length == 0) {
            return result;
        }
        // 限制方向从右往左，默认不扫描根目录
        if (Config.DIRECT_RIGHT.equals(direct) && scanLevel < splitDirname.length) {
            result.remove("/");
        }
        StringBuilder sb = new StringBuilder("/");
        for (String dirname : splitDirname) {
            if (StringUtils.isNotEmpty(dirname)) {
                sb.append(dirname).append("/");
                int level = StringUtils.countMatches(sb.toString(), "/");
                // 根据不同方向，限制目录层级
                if (Config.DIRECT_LEFT.equals(direct) && level > scanLevel) {
                    continue;
                } else if (Config.DIRECT_RIGHT.equals(direct)) {
                    level = splitDirname.length - level;
                    if (level >= scanLevel) {
                        continue;
                    }
                }
                result.add(sb.toString());
            }
        }
        return result;
    }

    /**
     * 运行扫描任务
     *
     * @param httpReqResp   请求响应实例
     * @param info          IRequestInfo 实例
     * @param pathWithQuery 路径+query参数
     * @param from          请求来源
     */
    private void runScanTask(burp.api.montoya.http.message.HttpRequestResponse httpReqResp, HttpRequest originalRequest,
            String pathWithQuery, String from) {
        burp.api.montoya.http.HttpService service = httpReqResp.httpService();
        // 处理请求头
        byte[] request = handleHeader(httpReqResp, originalRequest, pathWithQuery, from);
        // 处理请求头失败时，丢弃该任务
        if (request == null) {
            return;
        }
        // 重新解析修改后的请求
        HttpRequest newRequest = HttpRequest.httpRequest(service, ByteArray.byteArray(request));
        String reqId = generateReqId(newRequest, from);
        // 如果当前 URL 已经扫描，中止任务
        if (checkRepeatFilterByReqId(reqId)) {
            return;
        }
        // 如果未启用“请求包处理”功能，直接对扫描的任务发起请求
        if (!mDataBoardTab.hasPayloadProcessing()) {
            doBurpRequest(service, reqId, request, from);
            return;
        }
        // 运行已经启用并且需要合并的任务
        runEnableAndMergeTask(service, reqId, request, from);
        // 运行已经启用并且不需要合并的任务
        runEnabledWithoutMergeProcessingTask(service, reqId, request);
    }

    /**
     * 生成请求 ID
     *
     * @param request HttpRequest 实例
     * @param from    请求来源
     * @return 失败返回 "null" 字符串
     */
    private String generateReqId(HttpRequest request, String from) {
        if (request == null || StringUtils.isEmpty(from)) {
            return "null";
        }
        String reqPath = getReqPathByRequestInfo(request);
        // 生成携带完整的 Host 地址请求的请求 ID 值
        if (UrlUtils.isHTTP(reqPath)) {
            try {
                URL originUrl = new URL(request.url());
                String originReqHost = UrlUtils.getReqHostByURL(originUrl);
                return originReqHost + "->" + reqPath;
            } catch (java.net.MalformedURLException e) {
                Logger.debug("Invalid URL in generateReqId: %s", request.url());
                return reqPath;
            }
        }
        URL url = getUrlByRequestInfo(request);
        String reqHost = UrlUtils.getReqHostByURL(url);
        // 生成重定向请求的请求 ID 值
        if (from.startsWith(FROM_REDIRECT)) {
            return reqHost + reqPath;
        }
        // 默认使用 http://x.x.x.x/path/to/index.html 格式作为请求 ID 值
        return reqHost + url.getPath();
    }

    /**
     * 根据 Url 检测是否重复扫描
     *
     * <p>
     * 线程安全说明: sRepeatFilter 使用 ConcurrentHashMap.newKeySet() 创建,
     * add() 方法本身是原子操作,返回 true 表示成功添加(首次出现),返回 false 表示已存在(重复)。
     * 无需额外的 synchronized 同步。
     * </p>
     *
     * @param reqId 请求 ID
     * @return true=重复；false=不重复
     */
    private boolean checkRepeatFilterByReqId(String reqId) {
        return !sRepeatFilter.add(reqId);
    }

    /**
     * 运行已经启用并且需要合并的任务
     *
     * @param service     请求目标服务实例
     * @param reqId       请求 ID
     * @param reqRawBytes 请求数据包
     * @param from        请求来源
     */
    private void runEnableAndMergeTask(burp.api.montoya.http.HttpService service, String reqId, byte[] reqRawBytes,
            String from) {
        // 获取已经启用并且需要合并的“请求包处理”规则
        List<ProcessingItem> processList = getPayloadProcess()
                .stream().filter(ProcessingItem::isEnabledAndMerge)
                .collect(Collectors.toList());
        // 如果规则为空，直接发起请求
        if (processList.isEmpty()) {
            doBurpRequest(service, reqId, reqRawBytes, from);
            return;
        }
        byte[] resultBytes = reqRawBytes;
        for (ProcessingItem item : processList) {
            ArrayList<PayloadItem> items = item.getItems();
            resultBytes = handlePayloadProcess(service, resultBytes, items);
        }
        if (resultBytes != null) {
            // 检测是否未进行任何处理
            boolean equals = Arrays.equals(reqRawBytes, resultBytes);
            // 未进行任何处理时，不变更 from 值
            String newFrom = equals ? from : from + "（" + FROM_PROCESS + "）";
            doBurpRequest(service, reqId, resultBytes, newFrom);
        } else {
            // 如果规则处理异常导致数据返回为空，则发送原来的请求
            doBurpRequest(service, reqId, reqRawBytes, from);
        }
    }

    /**
     * 运行已经启用并且不需要合并的任务
     *
     * @param service     请求目标服务实例
     * @param reqId       请求 ID
     * @param reqRawBytes 请求数据包
     */
    private void runEnabledWithoutMergeProcessingTask(burp.api.montoya.http.HttpService service, String reqId,
            byte[] reqRawBytes) {
        // 遍历规则列表，进行 Payload Processing 处理后，再次请求数据包
        getPayloadProcess().parallelStream().filter(ProcessingItem::isEnabledWithoutMerge)
                .forEach((item) -> {
                    ArrayList<PayloadItem> items = item.getItems();
                    byte[] requestBytes = handlePayloadProcess(service, reqRawBytes, items);
                    // 因为不需要合并的规则是将每条处理完成的数据包都发送请求，所以规则处理异常的请求包，不需要发送请求
                    if (requestBytes == null) {
                        return;
                    }
                    // 检测是否未进行任何处理（如上所述的原因，未进行任何处理的请求包，也不需要发送请求）
                    boolean equals = Arrays.equals(reqRawBytes, requestBytes);
                    if (equals) {
                        return;
                    }
                    doBurpRequest(service, reqId, requestBytes, FROM_PROCESS + "（" + item.getName() + "）");
                });
    }

    /**
     * 使用 Burp 自带的方式请求
     *
     * @param service     请求目标服务实例
     * @param reqId       请求 ID
     * @param reqRawBytes 请求数据包
     * @param from        请求来源
     */
    private void doBurpRequest(burp.api.montoya.http.HttpService service, String reqId, byte[] reqRawBytes,
            String from) {
        // 线程池关闭后，不接收任何任务
        if (isTaskThreadPoolShutdown()) {
            Logger.debug("doBurpRequest: thread pool is shutdown, intercept req id: %s", reqId);
            // 将未执行的任务从去重过滤集合中移除
            sRepeatFilter.remove(reqId);
            return;
        }
        // 创建任务运行实例
        TaskRunnable task = new TaskRunnable(reqId, from) {
            @Override
            public void run() {
                String reqId = getReqId();
                // 低频任务不进行 QPS 限制
                if (!isLowFrequencyTask(from) && checkQPSLimit()) {
                    // 拦截后，将未执行的任务从去重过滤集合中移除
                    sRepeatFilter.remove(reqId);
                    // 任务完成计数
                    incrementTaskOverCounter(from);
                    return;
                }
                Logger.debug("Do Send Request id: %s", reqId);
                // 获取配置的请求重试次数
                int retryCount = Config.getInt(Config.KEY_RETRY_COUNT);
                // 发起请求
                burp.onescan.common.IHttpRequestResponse newReqResp = doMakeHttpRequest(service, reqRawBytes,
                        retryCount);
                // 构建展示的数据包
                TaskData data = buildTaskData(newReqResp, from);
                mDataBoardTab.getTaskTable().addTaskData(data);
                // 处理重定向
                handleFollowRedirect(data);
                // 任务完成计数
                incrementTaskOverCounter(from);
            }
        };
        // 将任务添加线程池
        try {
            // 如果是低频任务，使用低频的任务线程池
            if (isLowFrequencyTask(from)) {
                mScanEngine.submitLFTask(task);
                // 低频任务提交计数
                mScanEngine.incrementLFTaskCommit();
            } else {
                // 否则使用常规的任务线程池
                mScanEngine.submitTask(task);
                // 任务提交计数
                mScanEngine.incrementTaskCommit();
            }
        } catch (Exception e) {
            Logger.error("doBurpRequest thread execute error: %s", e.getMessage());
        }
    }

    /**
     * 任务线程池是否关闭
     *
     * @return true=是；false=否
     */
    private boolean isTaskThreadPoolShutdown() {
        return mScanEngine.isTaskThreadPoolShutdown();
    }

    /**
     * 当前请求来源，是否为低频任务
     *
     * @param from 请求来源
     * @return true=是；false=否
     */
    private boolean isLowFrequencyTask(String from) {
        if (StringUtils.isEmpty(from)) {
            return false;
        }
        return from.startsWith(FROM_PROXY) || from.startsWith(FROM_SEND) || from.startsWith(FROM_REDIRECT);
    }

    /**
     * 增加任务完成计数
     *
     * @param from 请求来源
     */
    private void incrementTaskOverCounter(String from) {
        if (isLowFrequencyTask(from)) {
            // 低频任务完成计数
            mScanEngine.incrementLFTaskOver();
        } else {
            // 任务完成计数
            mScanEngine.incrementTaskOver();
        }
    }

    /**
     * 处理跟随重定向
     */
    private void handleFollowRedirect(TaskData data) {
        // 如果未启用"跟随重定向"功能，不继续执行
        if (!Config.getBoolean(Config.KEY_FOLLOW_REDIRECT)) {
            return;
        }
        int status = data.getStatus();
        // 检测 30x 状态码
        if (status < HTTP_STATUS_REDIRECT_START || status >= HTTP_STATUS_CLIENT_ERROR_START) {
            return;
        }
        // 如果线程中断，不继续往下执行
        if (Thread.currentThread().isInterrupted()) {
            Logger.debug("handleFollowRedirect: thread pool is shutdown, intercept data id: %s", data.getId());
            return;
        }
        // 解析响应头的 Location 值
        IHttpRequestResponse reqResp = data.getReqResp();
        HttpResponse httpResponse = HttpResponse.httpResponse(ByteArray.byteArray(reqResp.getResponse()));
        String location = getLocationByResponseInfo(httpResponse);
        if (location == null) {
            return;
        }
        // 如果启用了 Cookie 跟随，获取响应头中的 Cookie 值
        List<String> cookies = null;
        if (Config.getBoolean(Config.KEY_REDIRECT_COOKIES_FOLLOW)) {
            cookies = getCookieByResponseInfo(httpResponse);
        }
        String reqHost = data.getHost();
        String reqPath = data.getUrl();
        try {
            burp.api.montoya.http.message.HttpRequestResponse montoyaReqResp;
            // 使用 Montoya API 解析请求
            HttpRequest httpRequest = HttpRequest.httpRequest(reqResp.getHttpService(),
                    ByteArray.byteArray(reqResp.getRequest()));
            List<String> headers = httpRequest.headers().stream()
                    .map(h -> h.name() + ": " + h.value())
                    .collect(java.util.stream.Collectors.toList());
            // 兼容完整 Host 地址
            if (UrlUtils.isHTTP(reqPath)) {
                URL originUrl = UrlUtils.parseURL(reqPath);
                URL redirectUrl = UrlUtils.parseRedirectTargetURL(originUrl, location);
                burp.api.montoya.http.HttpService service = reqResp.getHttpService();
                montoyaReqResp = buildMontoyaRequestFromRedirect(service, redirectUrl.toString(), headers, cookies);
            } else {
                URL originUrl = UrlUtils.parseURL(reqHost + reqPath);
                URL redirectUrl = UrlUtils.parseRedirectTargetURL(originUrl, location);
                burp.api.montoya.http.HttpService service = buildHttpServiceByURL(redirectUrl);
                montoyaReqResp = buildMontoyaRequestFromRedirect(service, UrlUtils.toPQF(redirectUrl), headers,
                        cookies);
            }
            doScan(montoyaReqResp, FROM_REDIRECT + "（" + data.getId() + "）");
        } catch (IllegalArgumentException e) {
            Logger.error("Follow redirect error: " + e.getMessage());
        }
    }

    /**
     * 从 HttpResponse 实例获取响应头 Location 值
     *
     * @param response HttpResponse 实例
     * @return 失败返回null
     */
    private String getLocationByResponseInfo(HttpResponse response) {
        // Montoya API 通过 headers() 获取所有header,需要遍历查找
        for (burp.api.montoya.http.message.HttpHeader header : response.headers()) {
            if (header.name().equalsIgnoreCase("Location")) {
                return header.value();
            }
        }
        return null;
    }

    /**
     * 从 HttpResponse 实例获取响应头 Set-Cookie 值,并转换为请求头的 Cookie 值列表
     *
     * @param response HttpResponse 实例
     * @return 失败返回空列表
     */
    private List<String> getCookieByResponseInfo(HttpResponse response) {
        List<String> cookies = new ArrayList<>();
        // Montoya API 使用 cookies() 方法获取 Cookie 列表
        for (burp.api.montoya.http.message.Cookie cookie : response.cookies()) {
            String name = cookie.name();
            String value = cookie.value();
            // 拼接后,添加到列表
            cookies.add(String.format("%s=%s", name, value));
        }
        return cookies;
    }

    /**
     * 调用 BurpSuite 请求方式
     *
     * @param service     请求目标服务实例
     * @param reqRawBytes 请求数据包
     * @param retryCount  重试次数（为0表示不重试）
     * @return 请求响应数据
     */
    private burp.onescan.common.IHttpRequestResponse doMakeHttpRequest(burp.api.montoya.http.HttpService service,
            byte[] reqRawBytes, int retryCount) {
        burp.onescan.common.IHttpRequestResponse reqResp;
        String reqHost = getReqHostByHttpService(service);
        // 如果启用拦截超时主机，并检测到当前请求主机超时，直接拦截
        if (Config.getBoolean(Config.KEY_INTERCEPT_TIMEOUT_HOST) && checkTimeoutByReqHost(reqHost)) {
            return HttpReqRespAdapter.from(service, reqRawBytes);
        }
        try {
            // 使用 Montoya API 发送 HTTP 请求
            HttpRequest httpRequest = HttpRequest.httpRequest(service, ByteArray.byteArray(reqRawBytes));
            burp.api.montoya.http.message.HttpRequestResponse montoyaReqResp = api.http().sendRequest(httpRequest);

            if (montoyaReqResp.response() != null) {
                byte[] respRawBytes = montoyaReqResp.response().toByteArray().getBytes();
                // Convert Montoya response to our internal type
                reqResp = HttpReqRespAdapter.from(service, montoyaReqResp.request().toByteArray().getBytes());
                reqResp.setResponse(respRawBytes);
                // Note: Montoya API doesn't have comment/highlight,使用默认值
                return reqResp;
            }
            reqResp = HttpReqRespAdapter.from(service, reqRawBytes);
        } catch (Exception e) {
            Logger.debug("Do Request error, request host: %s", reqHost);
            reqResp = HttpReqRespAdapter.from(service, reqRawBytes);
        }
        // 如果线程中断，不继续往下执行
        if (Thread.currentThread().isInterrupted()) {
            Logger.debug("doMakeHttpRequest: thread pool is shutdown, intercept task");
            return reqResp;
        }
        Logger.debug("Check retry request host: %s, count: %d", reqHost, retryCount);
        // 检测是否需要重试
        if (retryCount <= 0) {
            // 超时的请求，直接添加到集合中
            sTimeoutReqHost.add(reqHost);
            return reqResp;
        }
        // 获取配置的请求重试间隔时间
        int retryInterval = Config.getInt(Config.KEY_RETRY_INTERVAL);
        if (retryInterval > 0) {
            try {
                Thread.sleep(retryInterval);
            } catch (InterruptedException e) {
                // 如果线程中断，返回目前的响应结果
                return reqResp;
            }
        }
        // 请求重试
        return doMakeHttpRequest(service, reqRawBytes, retryCount - 1);
    }

    /**
     * 检测当前请求主机是否超时
     *
     * @param reqHost Host（格式：http://x.x.x.x、http://x.x.x.x:8080）
     * @return true=存在；false=不存在
     */
    private boolean checkTimeoutByReqHost(String reqHost) {
        if (sTimeoutReqHost.isEmpty()) {
            return false;
        }
        return sTimeoutReqHost.contains(reqHost);
    }

    /**
     * 处理请求头
     *
     * @param httpReqResp   Burp 的 HTTP 请求响应接口
     * @param pathWithQuery 请求路径，或者请求路径+Query（示例：/xxx、/xxx/index?a=xxx&b=xxx）
     * @param from          数据来源
     * @return 处理完成的数据包，失败时返回null
     */
    private byte[] handleHeader(burp.api.montoya.http.message.HttpRequestResponse httpReqResp, HttpRequest request,
            String pathWithQuery, String from) {
        List<String> configHeaders = getHeader();
        List<String> removeHeaders = getRemoveHeaders();
        // Convert Montoya API headers to List<String>
        List<String> originalHeaders = request.headers().stream()
                .map(h -> h.name() + ": " + h.value())
                .collect(java.util.stream.Collectors.toList());
        // Add request line as the first element
        originalHeaders.add(0, request.method() + " " + request.path() + " " + request.httpVersion());

        // 构建请求
        StringBuilder requestRaw = new StringBuilder(HTTP_REQUEST_BUILDER_INITIAL_CAPACITY);
        buildRequestLine(requestRaw, originalHeaders, pathWithQuery, from);
        processHeaders(requestRaw, originalHeaders, configHeaders, removeHeaders, from);
        appendRemainingConfigHeaders(requestRaw, configHeaders, removeHeaders);
        requestRaw.append("\r\n");
        appendRequestBody(requestRaw, httpReqResp, request, from);

        // 填充动态变量并更新 Content-Length
        return finalizeRequest(httpReqResp, request, requestRaw.toString());
    }

    /**
     * 构建 HTTP 请求行
     */
    private void buildRequestLine(StringBuilder requestRaw, List<String> headers, String pathWithQuery, String from) {
        if (from.equals(FROM_SCAN)) {
            requestRaw.append("GET ").append(pathWithQuery).append(" HTTP/1.1").append("\r\n");
        } else {
            String reqLine = headers.get(0);
            if (reqLine.contains(" HTTP/")) {
                int start = reqLine.lastIndexOf(" HTTP/");
                reqLine = reqLine.substring(0, start) + " HTTP/1.1";
            }
            requestRaw.append(reqLine).append("\r\n");
        }
    }

    /**
     * 处理原始请求头（移除/替换/保留）
     */
    private void processHeaders(StringBuilder requestRaw, List<String> headers,
            List<String> configHeaders, List<String> removeHeaders, String from) {
        // 从索引 1 开始，跳过请求行
        for (int i = 1; i < headers.size(); i++) {
            String header = headers.get(i);
            String headerKey = extractHeaderKey(header);

            if (headerKey == null) {
                Logger.debug("Invalid header format (missing key): %s", header);
                continue;
            }

            // 跳过需要移除的请求头
            if (shouldRemoveHeader(headerKey, removeHeaders, from)) {
                continue;
            }

            // 查找配置中是否有相同 key 的请求头
            String matchedConfigHeader = findMatchingConfigHeader(headerKey, configHeaders, removeHeaders);
            if (matchedConfigHeader != null) {
                requestRaw.append(matchedConfigHeader).append("\r\n");
                configHeaders.remove(matchedConfigHeader);
            } else {
                requestRaw.append(header).append("\r\n");
            }
        }
    }

    /**
     * 提取请求头的 key
     */
    private String extractHeaderKey(String header) {
        String[] parts = header.split(": ");
        return parts.length >= 1 ? parts[0] : null;
    }

    /**
     * 判断是否应该移除请求头
     */
    private boolean shouldRemoveHeader(String key, List<String> removeHeaders, String from) {
        if (removeHeaders.contains(key)) {
            return true;
        }
        // 扫描请求（GET）移除 Content-Length
        if (from.equals(FROM_SCAN) && "Content-Length".equalsIgnoreCase(key)) {
            return true;
        }
        return false;
    }

    /**
     * 查找配置中匹配的请求头
     */
    private String findMatchingConfigHeader(String targetKey, List<String> configHeaders, List<String> removeHeaders) {
        return configHeaders.stream()
                .filter(configHeader -> {
                    if (StringUtils.isEmpty(configHeader) || !configHeader.contains(": ")) {
                        return false;
                    }
                    String configKey = configHeader.split(": ")[0];
                    return !removeHeaders.contains(configKey) && configKey.equals(targetKey);
                })
                .findFirst()
                .orElse(null);
    }

    /**
     * 添加配置中剩余的请求头
     */
    private void appendRemainingConfigHeaders(StringBuilder requestRaw, List<String> configHeaders,
            List<String> removeHeaders) {
        for (String header : configHeaders) {
            String headerKey = extractHeaderKey(header);
            if (headerKey == null) {
                Logger.debug("Invalid config header format (missing key): %s", header);
                continue;
            }
            if (!removeHeaders.contains(headerKey)) {
                requestRaw.append(header).append("\r\n");
            }
        }
    }

    /**
     * 添加请求 body（仅非扫描请求）
     */
    private void appendRequestBody(StringBuilder requestRaw,
            burp.api.montoya.http.message.HttpRequestResponse httpReqResp, HttpRequest request, String from) {
        if (from.equals(FROM_SCAN)) {
            return;
        }

        byte[] httpRequest = httpReqResp.request().toByteArray().getBytes();
        int bodyOffset = request.bodyOffset();
        int bodySize = httpRequest.length - bodyOffset;
        if (bodySize > 0) {
            requestRaw.append(new String(httpRequest, bodyOffset, bodySize));
        }
    }

    /**
     * 完成请求构建：填充变量并更新 Content-Length
     */
    private byte[] finalizeRequest(burp.api.montoya.http.message.HttpRequestResponse httpReqResp, HttpRequest request,
            String requestRaw) {
        burp.api.montoya.http.HttpService service = httpReqResp.httpService();
        URL url = getUrlByRequestInfo(request);
        String processedRequest = setupVariable(service, url, requestRaw);

        if (processedRequest == null) {
            return null;
        }

        return updateContentLength(processedRequest.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 获取请求头配置
     */
    private List<String> getHeader() {
        if (!mDataBoardTab.hasReplaceHeader()) {
            return new ArrayList<>();
        }
        return WordlistManager.getHeader();
    }

    /**
     * 获取移除请求头列表配置
     */
    private List<String> getRemoveHeaders() {
        if (!mDataBoardTab.hasRemoveHeader()) {
            return new ArrayList<>();
        }
        return WordlistManager.getRemoveHeaders();
    }

    /**
     * 获取配置的 Payload Processing 规则
     */
    private List<ProcessingItem> getPayloadProcess() {
        ArrayList<ProcessingItem> list = Config.getPayloadProcessList();
        if (list == null) {
            return new ArrayList<>();
        }
        return list.stream().filter(ProcessingItem::isEnabled).collect(Collectors.toList());
    }

    /**
     * 检测 QPS 限制
     *
     * @return true=拦截；false=不拦截
     */
    private boolean checkQPSLimit() {
        if (mQpsLimit != null) {
            try {
                mQpsLimit.limit();
            } catch (InterruptedException e) {
                // 线程强制停止时，拦截请求
                return true;
            }
        }
        return false;
    }

    /**
     * 给数据包填充动态变量
     *
     * @param service    请求目标实例
     * @param url        请求 URL 实例
     * @param requestRaw 请求数据包字符串
     * @return 处理失败返回null
     */
    private String setupVariable(burp.api.montoya.http.HttpService service, URL url, String requestRaw) {
        try {
            // 准备基础变量
            VariableContext context = prepareBasicVariables(service, url);

            // 填充所有变量
            requestRaw = fillBasicVariables(requestRaw, context);
            requestRaw = fillDomainVariables(requestRaw, context);
            requestRaw = fillSubdomainVariables(requestRaw, context);
            requestRaw = fillRandomVariables(requestRaw, context);
            requestRaw = fillDateTimeVariables(requestRaw);

            return requestRaw;
        } catch (IllegalArgumentException e) {
            Logger.debug(e.getMessage());
            return null;
        }
    }

    /**
     * 变量上下文，包含所有需要替换的变量值
     */
    private static class VariableContext {
        String protocol;
        String host;
        String domain;
        String webroot;
        String domainMain;
        String domainName;
        String subdomain;
        String subdomains;
        String randomIP;
        String randomLocalIP;
        String randomUA;
        String timestamp;
    }

    /**
     * 准备基础变量值
     */
    private VariableContext prepareBasicVariables(burp.api.montoya.http.HttpService service, URL url) {
        VariableContext context = new VariableContext();

        context.protocol = service.secure() ? "https" : "http";
        context.host = service.host() + ":" + service.port();
        if (service.port() == HTTP_DEFAULT_PORT || service.port() == HTTPS_DEFAULT_PORT) {
            context.host = service.host();
        }
        context.domain = service.host();
        context.timestamp = String.valueOf(DateUtils.getTimestamp());
        context.randomIP = IPUtils.randomIPv4();
        context.randomLocalIP = IPUtils.randomIPv4ForLocal();
        context.randomUA = Utils.getRandomItem(WordlistManager.getUserAgent());
        context.domainMain = DomainHelper.getDomain(context.domain, null);
        context.domainName = DomainHelper.getDomainName(context.domain, null);
        context.subdomain = getSubdomain(context.domain);
        context.subdomains = getSubdomains(context.domain);
        context.webroot = getWebrootByURL(url);

        return context;
    }

    /**
     * 填充基础变量（protocol, host, webroot, ip）
     */
    private String fillBasicVariables(String requestRaw, VariableContext context) {
        requestRaw = fillVariable(requestRaw, "protocol", context.protocol);
        requestRaw = fillVariable(requestRaw, "host", context.host);
        requestRaw = fillVariable(requestRaw, "webroot", context.webroot);

        // IP 需要按需填充（避免不必要的 DNS 查询）
        if (requestRaw.contains("{{ip}}")) {
            String ip = findIpByHost(context.domain);
            requestRaw = fillVariable(requestRaw, "ip", ip);
        }

        return requestRaw;
    }

    /**
     * 填充域名相关变量
     */
    private String fillDomainVariables(String requestRaw, VariableContext context) {
        requestRaw = fillVariable(requestRaw, "domain", context.domain);
        requestRaw = fillVariable(requestRaw, "domain.main", context.domainMain);
        requestRaw = fillVariable(requestRaw, "domain.name", context.domainName);
        return requestRaw;
    }

    /**
     * 填充子域名相关变量
     */
    private String fillSubdomainVariables(String requestRaw, VariableContext context) {
        requestRaw = fillVariable(requestRaw, "subdomain", context.subdomain);
        requestRaw = fillVariable(requestRaw, "subdomains", context.subdomains);

        // 处理 {{subdomains.N}} 格式的变量
        if (requestRaw.contains("{{subdomains.")) {
            if (StringUtils.isEmpty(context.subdomains)) {
                return null;
            }

            String[] subdomainsSplit = context.subdomains.split("\\.");
            for (int i = 0; i < subdomainsSplit.length; i++) {
                requestRaw = fillVariable(requestRaw, "subdomains." + i, subdomainsSplit[i]);
            }

            // 如果还存在未填充的 subdomains 变量，忽略当前 payload
            if (requestRaw.contains("{{subdomains.")) {
                return null;
            }
        }

        return requestRaw;
    }

    /**
     * 填充随机值相关变量
     */
    private String fillRandomVariables(String requestRaw, VariableContext context) {
        requestRaw = fillVariable(requestRaw, "random.ip", context.randomIP);
        requestRaw = fillVariable(requestRaw, "random.local-ip", context.randomLocalIP);
        requestRaw = fillVariable(requestRaw, "random.ua", context.randomUA);
        requestRaw = fillVariable(requestRaw, "timestamp", context.timestamp);
        return requestRaw;
    }

    /**
     * 填充日期时间相关变量
     */
    private String fillDateTimeVariables(String requestRaw) {
        if (!requestRaw.contains("{{date.") && !requestRaw.contains("{{time.")) {
            return requestRaw;
        }

        String currentDate = DateUtils.getCurrentDate("yyyy-MM-dd HH:mm:ss;yy-M-d H:m:s");
        String[] split = currentDate.split(";");
        String[] leftDateTime = parseDateTime(split[0]);
        String[] rightDateTime = parseDateTime(split[1]);

        // 填充完整格式日期时间
        requestRaw = fillVariable(requestRaw, "date.yyyy", leftDateTime[0]);
        requestRaw = fillVariable(requestRaw, "date.MM", leftDateTime[1]);
        requestRaw = fillVariable(requestRaw, "date.dd", leftDateTime[2]);
        requestRaw = fillVariable(requestRaw, "time.HH", leftDateTime[3]);
        requestRaw = fillVariable(requestRaw, "time.mm", leftDateTime[4]);
        requestRaw = fillVariable(requestRaw, "time.ss", leftDateTime[5]);

        // 填充简化格式日期时间
        requestRaw = fillVariable(requestRaw, "date.yy", rightDateTime[0]);
        requestRaw = fillVariable(requestRaw, "date.M", rightDateTime[1]);
        requestRaw = fillVariable(requestRaw, "date.d", rightDateTime[2]);
        requestRaw = fillVariable(requestRaw, "time.H", rightDateTime[3]);
        requestRaw = fillVariable(requestRaw, "time.m", rightDateTime[4]);
        requestRaw = fillVariable(requestRaw, "time.s", rightDateTime[5]);

        return requestRaw;
    }

    /**
     * 填充动态变量
     *
     * @param src   数据源
     * @param name  变量名
     * @param value 需要填充的变量值
     * @throws IllegalArgumentException 当填充的变量值为空时，抛出该异常
     */
    private String fillVariable(String src, String name, String value) throws IllegalArgumentException {
        if (StringUtils.isEmpty(src)) {
            return src;
        }
        String key = String.format("{{%s}}", name);
        if (!src.contains(key)) {
            return src;
        }
        // 值为空时，返回null值丢弃当前请求
        if (StringUtils.isEmpty(value)) {
            throw new IllegalArgumentException(key + " fill failed, value is empty.");
        }
        return src.replace(key, value);
    }

    /**
     * 解析日期时间,将每个字段的数据存入数组
     *
     * @param dateTime 日期时间字符串(格式:yyyy-MM-dd HH:mm:ss 或者 yy-M-d H:m:s)
     * @return [0]=年;[1]=月;[2]=日;[3]=时;[4]=分;[5]=秒;如果解析失败返回空数组
     */
    private String[] parseDateTime(String dateTime) {
        if (dateTime == null || dateTime.trim().isEmpty()) {
            Logger.debug("DateTime string is null or empty");
            return new String[6];
        }

        try {
            // 定义支持的日期时间格式
            java.time.format.DateTimeFormatter formatter;
            if (dateTime.contains("-") && dateTime.split("-")[0].length() == 4) {
                // yyyy-MM-dd HH:mm:ss 格式
                formatter = java.time.format.DateTimeFormatter.ofPattern("yyyy-M-d H:m:s");
            } else {
                // yy-M-d H:m:s 格式
                formatter = java.time.format.DateTimeFormatter.ofPattern("yy-M-d H:m:s");
            }

            java.time.LocalDateTime dateTimeObj = java.time.LocalDateTime.parse(dateTime, formatter);

            String[] result = new String[6];
            result[0] = String.valueOf(dateTimeObj.getYear());
            result[1] = String.valueOf(dateTimeObj.getMonthValue());
            result[2] = String.valueOf(dateTimeObj.getDayOfMonth());
            result[3] = String.valueOf(dateTimeObj.getHour());
            result[4] = String.valueOf(dateTimeObj.getMinute());
            result[5] = String.valueOf(dateTimeObj.getSecond());
            return result;
        } catch (java.time.format.DateTimeParseException e) {
            Logger.debug("Failed to parse datetime '%s': %s", dateTime, e.getMessage());
            return new String[6];
        }
    }

    /**
     * 获取子域名
     *
     * @param domain 域名（格式示例：www.xxx.com）
     * @return 格式：www；如果没有子域名，或者获取失败，返回null
     */
    private String getSubdomain(String domain) {
        String subdomains = getSubdomains(domain);
        if (StringUtils.isEmpty(subdomains)) {
            return null;
        }
        if (subdomains.contains(".")) {
            return subdomains.substring(0, subdomains.indexOf("."));
        }
        return subdomains;
    }

    /**
     * 获取完整子域名
     *
     * @param domain 域名（格式示例：api.xxx.com、api.admin.xxx.com）
     * @return 格式：api、api.admin；如果没有子域名，或者获取失败，返回null
     */
    private String getSubdomains(String domain) {
        if (IPUtils.hasIPv4(domain)) {
            return null;
        }
        if (!domain.contains(".")) {
            return null;
        }
        String parseDomain = DomainHelper.getDomain(domain, null);
        if (StringUtils.isEmpty(parseDomain)) {
            return null;
        }
        int endIndex = domain.lastIndexOf(parseDomain) - 1;
        if (endIndex < 0) {
            return null;
        }
        return domain.substring(0, endIndex);
    }

    /**
     * 从URL实例中获取Web根目录名（例如："http://xxx.com/abc/a.php" => "abc"）
     *
     * @param url URL实例
     * @return 失败返回null
     */
    private String getWebrootByURL(URL url) {
        if (url == null) {
            return null;
        }
        String path = url.getPath();
        // 没有根目录名，直接返回null
        if (StringUtils.isEmpty(path) || "/".equals(path)) {
            return null;
        }
        // 找第二个'/'斜杠
        int end = path.indexOf("/", 1);
        if (end < 0) {
            return null;
        }
        // 找到之后，取中间的值
        return path.substring(1, end);
    }

    /**
     * 根据 Payload Process 规则，处理数据包
     *
     * @param service      请求目标服务
     * @param requestBytes 请求数据包
     * @return 处理后的数据包
     */
    private byte[] handlePayloadProcess(burp.api.montoya.http.HttpService service, byte[] requestBytes,
            List<PayloadItem> list) {
        if (requestBytes == null || requestBytes.length == 0 || list == null || list.isEmpty()) {
            return null;
        }
        // 解析请求
        HttpRequest httpRequest = HttpRequest.httpRequest(service, ByteArray.byteArray(requestBytes));
        int bodyOffset = httpRequest.bodyOffset();
        int bodySize = requestBytes.length - bodyOffset;
        String url = getReqPathByRequestInfo(httpRequest);
        String header = new String(requestBytes, 0, bodyOffset - 4);
        String body = bodySize <= 0 ? "" : new String(requestBytes, bodyOffset, bodySize);
        String request = new String(requestBytes, StandardCharsets.UTF_8);
        for (PayloadItem item : list) {
            // 只调用启用的规则
            PayloadRule rule = item.getRule();
            try {
                switch (item.getScope()) {
                    case PayloadRule.SCOPE_URL:
                        String newUrl = rule.handleProcess(url);
                        // 截取请求头第一行，用于定位要处理的位置
                        String reqLine = header.substring(0, header.indexOf("\r\n"));
                        Matcher matcher = Constants.REGEX_REQ_LINE_URL.matcher(reqLine);
                        if (matcher.find()) {
                            int start = matcher.start(1);
                            int end = matcher.end(1);
                            // 分隔要插入数据的位置
                            String left = header.substring(0, start);
                            String right = header.substring(end);
                            // 拼接处理好的数据
                            header = left + newUrl + right;
                            request = header + "\r\n\r\n" + body;
                        }
                        url = newUrl;
                        break;
                    case PayloadRule.SCOPE_HEADER:
                        String newHeader = rule.handleProcess(header);
                        header = newHeader;
                        request = newHeader + "\r\n\r\n" + body;
                        break;
                    case PayloadRule.SCOPE_BODY:
                        String newBody = rule.handleProcess(body);
                        request = header + "\r\n\r\n" + newBody;
                        body = newBody;
                        break;
                    case PayloadRule.SCOPE_REQUEST:
                        request = rule.handleProcess(request);
                        break;
                }
            } catch (Exception e) {
                Logger.debug("handlePayloadProcess exception: " + e.getMessage());
                return null;
            }
        }
        // 动态变量赋值
        URL u = getUrlByRequestInfo(httpRequest);
        String newRequest = setupVariable(service, u, request);
        if (newRequest == null) {
            return null;
        }
        // 更新 Content-Length
        return updateContentLength(newRequest.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 更新 Content-Length 参数值
     *
     * @param rawBytes 请求数据包
     * @return 更新后的数据包
     */
    private byte[] updateContentLength(byte[] rawBytes) {
        String temp = new String(rawBytes, StandardCharsets.US_ASCII);
        int bodyOffset = temp.indexOf("\r\n\r\n");
        if (bodyOffset == -1) {
            Logger.error("Handle payload process error: bodyOffset is -1");
            return null;
        }
        bodyOffset += 4;
        int bodySize = rawBytes.length - bodyOffset;
        if (bodySize < 0) {
            Logger.error("Handle payload process error: bodySize < 0");
            return null;
        } else if (bodySize == 0) {
            return rawBytes;
        }
        String header = new String(rawBytes, 0, bodyOffset - 4);
        if (!header.contains("Content-Length")) {
            header += "\r\nContent-Length: " + bodySize;
        } else {
            header = header.replaceAll("Content-Length:.*", "Content-Length: " + bodySize);
        }
        String body = new String(rawBytes, bodyOffset, bodySize);
        String result = header + "\r\n\r\n" + body;
        return result.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 构建Item数据
     *
     * @param httpReqResp Burp的请求响应对象
     * @return 列表Item数据
     */
    private TaskData buildTaskData(burp.onescan.common.IHttpRequestResponse httpReqResp, String from) {
        // 使用 Montoya API 解析请求
        HttpRequest httpRequest = HttpRequest.httpRequest(httpReqResp.getHttpService(),
                ByteArray.byteArray(httpReqResp.getRequest()));
        byte[] respBytes = httpReqResp.getResponse();
        // 获取所需要的参数
        String method = httpRequest.method();
        burp.api.montoya.http.HttpService service = httpReqResp.getHttpService();
        String reqHost = getReqHostByHttpService(service);
        String reqUrl = getReqPathByRequestInfo(httpRequest);
        String title = HtmlUtils.findTitleByHtmlBody(respBytes);
        String ip = findIpByHost(service.host());
        int status = -1;
        int length = -1;
        // 存在响应对象，获取状态和响应包大小
        if (respBytes != null && respBytes.length > 0) {
            HttpResponse httpResponse = HttpResponse.httpResponse(ByteArray.byteArray(respBytes));
            status = httpResponse.statusCode();
            // 处理响应 body 的长度
            length = respBytes.length - httpResponse.bodyOffset();
            if (length < 0) {
                length = 0;
            }
        }
        // 检测指纹数据
        List<FpData> checkResult = FpManager.check(httpReqResp.getRequest(), httpReqResp.getResponse());
        // 构建表格对象
        TaskData data = new TaskData();
        data.setFrom(from);
        data.setMethod(method);
        data.setHost(reqHost);
        data.setUrl(reqUrl);
        data.setTitle(title);
        data.setIp(ip);
        data.setStatus(status);
        data.setLength(length);
        data.setFingerprint(checkResult);
        data.setReqResp(httpReqResp);
        return data;
    }

    /**
     * 通过 HttpService 实例,获取请求的 Host 地址 (http://x.x.x.x、http://x.x.x.x:8080)
     *
     * @param service HttpService 实例
     * @return 返回请求的 Host 地址
     */
    private String getReqHostByHttpService(burp.api.montoya.http.HttpService service) {
        String protocol = service.secure() ? "https" : "http";
        String host = service.host();
        int port = service.port();
        if (Utils.isIgnorePort(port)) {
            return protocol + "://" + host;
        }
        return protocol + "://" + host + ":" + port;
    }

    /**
     * 通过 HttpService 实例,获取请求的 Host 值 (示例格式: x.x.x.x、x.x.x.x:8080)
     *
     * @return 失败返回null
     */
    public static String getHostByHttpService(burp.api.montoya.http.HttpService service) {
        if (service == null) {
            return null;
        }
        String host = service.host();
        int port = service.port();
        if (Utils.isIgnorePort(port)) {
            return host;
        }
        return host + ":" + port;
    }

    /**
     * 通过 URL 实例,构建 HttpService 实例 (Montoya API)
     *
     * @return 失败返回null
     */
    public static burp.api.montoya.http.HttpService buildHttpServiceByURL(URL url) {
        if (url == null) {
            return null;
        }
        String protocol = url.getProtocol();
        int port = url.getPort();
        if (port == -1) {
            port = protocol.equals("https") ? HTTPS_DEFAULT_PORT : HTTP_DEFAULT_PORT;
        }
        boolean secure = protocol.equals("https");
        return burp.api.montoya.http.HttpService.httpService(url.getHost(), port, secure);
    }

    /**
     * 根据 Host 查询 IP 地址
     *
     * @param host Host 值
     * @return 失败返回空字符串
     */
    private String findIpByHost(String host) {
        if (IPUtils.hasIPv4(host)) {
            return host;
        }
        try {
            InetAddress ip = InetAddress.getByName(host);
            return ip.getHostAddress();
        } catch (UnknownHostException e) {
            return "";
        }
    }

    /**
     * 获取 IRequestInfo 实例的请求 URL 实例
     *
     * @param info IRequestInfo 实例
     * @return 返回请求的 URL 实例
     */
    private URL getUrlByRequestInfo(HttpRequest request) {
        try {
            URL url = new URL(request.url());
            // 分两种情况，一种是完整 Host 地址，还有一种是普通请求路径
            String reqPath = getReqPathByRequestInfo(request);
            if (UrlUtils.isHTTP(reqPath)) {
                return new URL(reqPath);
            }
            // 普通请求路径因为 Montoya API 的 request.url() 方法已经很准确，直接使用
            return url;
        } catch (Exception e) {
            Logger.error("getUrlByRequestInfo: convert url error: %s", e.getMessage());
            try {
                return new URL(request.url());
            } catch (Exception ex) {
                return null;
            }
        }
    }

    // ============================================================
    // 职责 5: 任务表事件处理
    // 实现接口: TaskTable.OnTaskTableEventListener
    // ============================================================

    @Override
    public void onChangeSelection(TaskData data) {
        // 如果 data 为空，表示执行了清空历史记录操作
        if (data == null) {
            onClearHistory();
            return;
        }
        mCurrentReqResp = data.getReqResp();
        // 加载请求、响应数据包
        byte[] hintBytes = L.get("message_editor_loading").getBytes(StandardCharsets.UTF_8);
        mRequestTextEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(hintBytes)));
        mResponseTextEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(hintBytes)));
        mScanEngine.submitRefreshTask(this::refreshReqRespMessage);
    }

    /**
     * 清空历史记录
     */
    private void onClearHistory() {
        mCurrentReqResp = null;
        // 清空去重过滤集合
        sRepeatFilter.clear();
        // 清空超时的请求主机集合
        sTimeoutReqHost.clear();
        // 清空显示的请求、响应数据包
        mRequestTextEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(EMPTY_BYTES)));
        mResponseTextEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(EMPTY_BYTES)));
        // 清除指纹识别历史记录
        FpManager.clearHistory();
    }

    /**
     * 刷新请求响应信息
     */
    private void refreshReqRespMessage() {
        byte[] request = (mCurrentReqResp != null) ? mCurrentReqResp.getRequest() : new byte[0];
        byte[] response = (mCurrentReqResp != null) ? mCurrentReqResp.getResponse() : new byte[0];
        if (request == null || request.length == 0) {
            request = EMPTY_BYTES;
        }
        if (response == null || response.length == 0) {
            response = EMPTY_BYTES;
        }
        // 检测是否超过配置的显示长度限制
        int maxLength = Config.getInt(Config.KEY_MAX_DISPLAY_LENGTH);
        if (maxLength >= MIN_LENGTH_FOR_TRUNCATION && request.length >= maxLength) {
            String hint = L.get("message_editor_request_length_limit_hint");
            request = hint.getBytes(StandardCharsets.UTF_8);
        }
        if (maxLength >= MIN_LENGTH_FOR_TRUNCATION && response.length >= maxLength) {
            String hint = L.get("message_editor_response_length_limit_hint");
            response = hint.getBytes(StandardCharsets.UTF_8);
        }
        mRequestTextEditor.setRequest(HttpRequest.httpRequest(ByteArray.byteArray(request)));
        mResponseTextEditor.setResponse(HttpResponse.httpResponse(ByteArray.byteArray(response)));
    }

    @Override
    public void onSendToRepeater(ArrayList<TaskData> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        for (TaskData data : list) {
            if (data.getReqResp() == null) {
                continue;
            }
            IHttpRequestResponse reqResp = data.getReqResp();
            byte[] reqBytes = reqResp.getRequest();
            burp.api.montoya.http.HttpService service = reqResp.getHttpService();
            try {
                HttpRequest httpRequest = HttpRequest.httpRequest(service, ByteArray.byteArray(reqBytes));
                api.repeater().sendToRepeater(httpRequest);
            } catch (Exception e) {
                Logger.debug(e.getMessage());
            }
        }
    }

    @Override
    public byte[] getBodyByTaskData(TaskData data) {
        if (data == null || data.getReqResp() == null) {
            return new byte[] {};
        }
        mCurrentReqResp = data.getReqResp();
        byte[] respBytes = mCurrentReqResp.getResponse();
        if (respBytes == null || respBytes.length == 0) {
            return new byte[] {};
        }
        HttpResponse httpResponse = HttpResponse.httpResponse(ByteArray.byteArray(respBytes));
        int offset = httpResponse.bodyOffset();
        return Arrays.copyOfRange(respBytes, offset, respBytes.length);
    }

    @Override
    public void addHostToBlocklist(ArrayList<String> hosts) {
        if (hosts == null || hosts.isEmpty()) {
            return;
        }
        List<String> list = WordlistManager.getList(WordlistManager.KEY_HOST_BLOCKLIST);
        for (String host : hosts) {
            if (!list.contains(host)) {
                list.add(host);
            }
        }
        WordlistManager.putList(WordlistManager.KEY_HOST_BLOCKLIST, list);
        mOneScan.getConfigPanel().refreshHostTab();
    }

    // ============================================================
    // 职责 6: Tab 事件处理
    // 实现接口: OnTabEventListener
    // ============================================================

    @Override
    public void onTabEventMethod(String action, Object... params) {
        switch (action) {
            case RequestTab.EVENT_QPS_LIMIT:
                changeQpsLimit(String.valueOf(params[0]));
                break;
            case RequestTab.EVENT_REQUEST_DELAY:
                changeRequestDelay(String.valueOf(params[0]));
                break;
            case OtherTab.EVENT_UNLOAD_PLUGIN:
                api.extension().unload();
                break;
            case DataBoardTab.EVENT_IMPORT_URL:
                importUrl((List<?>) params[0]);
                break;
            case DataBoardTab.EVENT_STOP_TASK:
                stopAllTask();
                break;
        }
    }

    /**
     * 修改 QPS 限制
     *
     * @param limit QPS 限制值（数字）
     */
    private void changeQpsLimit(String limit) {
        initQpsLimiter();
        Logger.debug("Event: change qps limit: %s", limit);
    }

    /**
     * 修改请求延迟
     *
     * @param delay 延迟的值（数字）
     */
    private void changeRequestDelay(String delay) {
        initQpsLimiter();
        Logger.debug("Event: change request delay: %s", delay);
    }

    /**
     * 导入 URL
     *
     * @param list URL 列表
     */
    private void importUrl(List<?> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        // 处理导入的 URL 数据
        new Thread(() -> {
            for (Object item : list) {
                try {
                    String url = String.valueOf(item);
                    // 使用 Montoya API 构建 HTTP 请求
                    burp.api.montoya.http.message.HttpRequestResponse montoyaReqResp = buildMontoyaRequestFromUrl(url);
                    doScan(montoyaReqResp, FROM_IMPORT);
                } catch (IllegalArgumentException e) {
                    Logger.error("Import error: " + e.getMessage());
                }
                // 线程池关闭后，停止导入 Url 数据
                if (isTaskThreadPoolShutdown()) {
                    Logger.debug("importUrl: thread pool is shutdown, stop import url");
                    return;
                }
            }
        }).start();
    }

    /**
     * 停止扫描中的所有任务
     */
    private void stopAllTask() {
        // 关闭线程池，处理未执行的任务
        List<Runnable>[] tasks = mScanEngine.shutdownNowAndGetTasks();
        handleStopTasks(tasks[0]); // 任务列表
        handleStopTasks(tasks[1]); // 低频任务列表
        // 提示信息
        UIHelper.showTipsDialog(L.get("stop_task_tips"));
        // 停止后，重新创建扫描引擎
        mScanEngine = new burp.onescan.engine.ScanEngine(
                TASK_THREAD_COUNT,
                LF_TASK_THREAD_COUNT,
                FP_THREAD_COUNT);
        // 重新初始化 QPS 限制器
        initQpsLimiter();
    }

    /**
     * 处理停止的任务列表
     *
     * @param list 任务列表
     */
    private void handleStopTasks(List<Runnable> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        for (Runnable run : list) {
            if (run instanceof TaskRunnable) {
                TaskRunnable task = (TaskRunnable) run;
                String reqId = task.getReqId();
                String from = task.getFrom();
                // 将未执行的任务从去重过滤集合中移除
                sRepeatFilter.remove(reqId);
                // 将未执行的任务计数
                if (isLowFrequencyTask(from)) {
                    mScanEngine.incrementLFTaskOver();
                } else {
                    mScanEngine.incrementTaskOver();
                }
            }
        }
    }

    // ============================================================
    // 职责 1: 插件生命周期管理 (续) - 扩展卸载处理
    // ============================================================

    /**
     * 扩展卸载时的清理操作
     * <p>
     * 通过 api.extension().registerUnloadingHandler() 注册
     */
    private void extensionUnloaded() {
        // 代理监听器通过 Montoya API 注册,自动清理,无需手动移除
        // 上下文菜单通过 Montoya API 注册,自动清理,无需手动移除
        // 停止状态栏刷新定时器
        mStatusRefresh.stop();
        // 关闭扫描引擎(包含所有线程池)
        mScanEngine.shutdown();
        Logger.info("Close: scan engine shutdown completed.");
        // 清除指纹识别缓存
        int count = FpManager.getCacheCount();
        FpManager.clearCache();
        Logger.info("Clear: fingerprint recognition cache completed. Total %d records.", count);
        // 清除指纹识别历史记录
        count = FpManager.getHistoryCount();
        FpManager.clearHistory();
        Logger.info("Clear: fingerprint recognition history completed. Total %d records.", count);
        // 清除指纹字段修改监听器
        FpManager.clearsFpColumnModifyListeners();
        // 清除去重过滤集合
        count = sRepeatFilter.size();
        sRepeatFilter.clear();
        Logger.info("Clear: repeat filter list completed. Total %d records.", count);
        // 清除超时的请求主机集合
        count = sTimeoutReqHost.size();
        sTimeoutReqHost.clear();
        Logger.info("Clear: timeout request host list completed. Total %d records.", count);
        // 清除任务列表
        count = 0;
        if (mDataBoardTab != null) {
            TaskTable taskTable = mDataBoardTab.getTaskTable();
            if (taskTable != null) {
                count = taskTable.getTaskCount();
                taskTable.clearAll();
            }
            // 关闭导入 URL 窗口
            mDataBoardTab.closeImportUrlWindow();
        }
        Logger.info("Clear: task list completed. Total %d records.", count);
        // 关闭指纹相关窗口
        if (mOneScan != null && mOneScan.getFingerprintTab() != null) {
            FingerprintTab tab = mOneScan.getFingerprintTab();
            // 指纹测试窗口
            tab.closeFpTestWindow();
            // 指纹字段管理窗口
            tab.closeFpColumnManagerWindow();
        }
        // 卸载完成
        Logger.info(Constants.UNLOAD_BANNER);
    }
}