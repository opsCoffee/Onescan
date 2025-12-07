package burp.onescan.info;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.common.helper.UIHelper;
import burp.common.layout.VLayout;
import burp.common.utils.JsonUtils;
import burp.common.utils.StringUtils;
import burp.onescan.bean.FpData;
import burp.onescan.manager.FpManager;
import burp.onescan.ui.widget.FpTestResultPanel;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

/**
 * OneScan 信息辅助面板
 * <p>
 * Created by vaycore on 2023-04-21.
 * <p>
 * MIGRATE-303-B: 重构移除 IMessageEditorTab 接口,直接使用 Montoya API
 */
public class OneScanInfoTab {

    private final MontoyaApi mApi;
    private final JTabbedPane mTabPanel;
    private HttpRequestResponse mCurrentReqResp;

    private JList<String> mJsonKeyList;

    public OneScanInfoTab(MontoyaApi api) {
        mApi = api;
        mTabPanel = new JTabbedPane();
    }

    // ============================================================
    // 公共接口 (用于 Montoya 编辑器提供者)
    // ============================================================

    public String getCaption() {
        return "OneScan";
    }

    public Component getUiComponent() {
        return mTabPanel;
    }

    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        if (requestResponse == null) {
            return false;
        }

        // 检查请求
        if (requestResponse.request() != null) {
            byte[] requestBytes = requestResponse.request().toByteArray().getBytes();
            if (checkReqEnabled(requestBytes, requestResponse)) {
                return true;
            }
        }

        // 检查响应
        if (requestResponse.response() != null) {
            byte[] responseBytes = requestResponse.response().toByteArray().getBytes();
            if (checkRespEnabled(responseBytes)) {
                return true;
            }
        }

        return false;
    }

    public void setRequestResponse(HttpRequestResponse requestResponse) {
        mCurrentReqResp = requestResponse;
        mTabPanel.removeAll();

        if (requestResponse == null) {
            return;
        }

        // 处理请求和响应
        if (requestResponse.request() != null) {
            byte[] requestBytes = requestResponse.request().toByteArray().getBytes();
            handleReqMessage(requestBytes, requestResponse);
        }

        if (requestResponse.response() != null) {
            byte[] responseBytes = requestResponse.response().toByteArray().getBytes();
            handleRespMessage(responseBytes);
        }
    }

    public byte[] getSelectedData() {
        int index = mTabPanel.getSelectedIndex();
        if (index < 0 || index >= mTabPanel.getTabCount()) {
            return new byte[0];
        }

        String title = mTabPanel.getTitleAt(index);
        if ("Json".equals(title)) {
            List<String> keys = mJsonKeyList.getSelectedValuesList();
            return StringUtils.join(keys, "\n").getBytes(StandardCharsets.UTF_8);
        }
        return new byte[0];
    }

    public boolean isModified() {
        return false;  // 只读编辑器,不支持修改
    }

    // ============================================================
    // 私有辅助方法
    // ============================================================

    /**
     * 检测当前请求是否需要启用信息辅助面板
     *
     * @param content        请求数据包
     * @param requestResponse 请求响应对象
     * @return true=启用；false=不启用
     */
    private boolean checkReqEnabled(byte[] content, HttpRequestResponse requestResponse) {
        boolean hasEnabled = false;
        // 解析请求包数据 (使用 Montoya API)
        HttpRequest info = HttpRequest.httpRequest(ByteArray.byteArray(content));
        // 是否存在指纹识别历史记录
        if (FpManager.getHistoryCount() > 0) {
            String host = getHostByRequestInfo(info, requestResponse);
            List<FpData> historyResults = FpManager.findHistoryByHost(host);
            hasEnabled = historyResults != null && !historyResults.isEmpty();
        }
        // 如果未启用，检测请求包是否存在指纹识别数据
        if (!hasEnabled) {
            byte[] response = requestResponse != null && requestResponse.response() != null
                    ? requestResponse.response().toByteArray().getBytes()
                    : null;
            List<FpData> results = FpManager.check(content, response);
            hasEnabled = results != null && !results.isEmpty();
        }
        // 如果未启用，检测请求包中是否包含 JSON 数据格式
        if (!hasEnabled) {
            String body = getReqBody(info, content);
            hasEnabled = JsonUtils.hasJson(body);
        }
        return hasEnabled;
    }

    /**
     * 检测当前响应是否需要启用信息辅助面板
     *
     * @param content 响应数据包
     * @return true=启用；false=不启用
     */
    private boolean checkRespEnabled(byte[] content) {
        boolean hasEnabled = false;
        // 解析响应包数据 (使用 Montoya API)
        HttpResponse info = HttpResponse.httpResponse(ByteArray.byteArray(content));
        // 检测响应包中是否包含 JSON 数据格式
        String body = getRespBody(info, content);
        hasEnabled = JsonUtils.hasJson(body);
        return hasEnabled;
    }

    /**
     * 处理请求信息
     *
     * @param content        数据包
     * @param requestResponse 请求响应对象
     */
    private void handleReqMessage(byte[] content, HttpRequestResponse requestResponse) {
        // 解析请求包数据 (使用 Montoya API)
        HttpRequest info = HttpRequest.httpRequest(ByteArray.byteArray(content));

        // 识别请求包的指纹
        byte[] response = requestResponse != null && requestResponse.response() != null
                ? requestResponse.response().toByteArray().getBytes()
                : null;
        List<FpData> results = FpManager.check(content, response);
        if (results != null && !results.isEmpty()) {
            mTabPanel.addTab("Fingerprint", new FpTestResultPanel(results));
        }

        // 指纹识别的历史记录
        if (FpManager.getHistoryCount() > 0) {
            String host = getHostByRequestInfo(info, requestResponse);
            List<FpData> historyResults = FpManager.findHistoryByHost(host);
            if (historyResults != null && !historyResults.isEmpty()) {
                mTabPanel.addTab("Fingerprint-History", new FpTestResultPanel(historyResults));
            }
        }

        // 提取请求包 Json 字段数据展示
        String body = getReqBody(info, content);
        if (JsonUtils.hasJson(body)) {
            ArrayList<String> keys = JsonUtils.findAllKeysByJson(body);
            if (!keys.isEmpty()) {
                mTabPanel.addTab("Json", newJsonInfoPanel(keys));
            }
        }
    }

    /**
     * 处理响应信息
     *
     * @param content 数据包
     */
    private void handleRespMessage(byte[] content) {
        // 解析响应包数据 (使用 Montoya API)
        HttpResponse info = HttpResponse.httpResponse(ByteArray.byteArray(content));
        // 提取响应包 Json 字段数据展示
        String body = getRespBody(info, content);
        if (JsonUtils.hasJson(body)) {
            ArrayList<String> keys = JsonUtils.findAllKeysByJson(body);
            if (!keys.isEmpty()) {
                mTabPanel.addTab("Json", newJsonInfoPanel(keys));
            }
        }
    }

    private JPanel newJsonInfoPanel(List<String> keys) {
        JPanel panel = new JPanel(new VLayout());
        mJsonKeyList = new JList<>(new Vector<>(keys));
        UIHelper.setListCellRenderer(mJsonKeyList);
        JScrollPane scrollPane = new JScrollPane(mJsonKeyList);
        panel.add(scrollPane, "1w");
        return panel;
    }

    private String getReqBody(HttpRequest info, byte[] content) {
        if (info == null || content == null || content.length == 0) {
            return null;
        }
        int bodyOffset = info.bodyOffset();
        int bodySize = content.length - bodyOffset;
        return new String(content, bodyOffset, bodySize, StandardCharsets.UTF_8);
    }

    private String getRespBody(HttpResponse info, byte[] content) {
        if (info == null) {
            return null;
        }
        int bodyOffset = info.bodyOffset();
        int bodySize = content.length - bodyOffset;
        return new String(content, bodyOffset, bodySize, StandardCharsets.UTF_8);
    }

    /**
     * 通过 HttpRequest 实例，获取请求头中的 Host 值（示例格式：x.x.x.x、x.x.x.x:8080）
     *
     * @param info            HTTP请求对象
     * @param requestResponse 请求响应对象
     * @return 失败返回null
     */
    private String getHostByRequestInfo(HttpRequest info, HttpRequestResponse requestResponse) {
        if (info == null) {
            return null;
        }
        // 优先使用从 HTTP 请求头中获取的 Host 值
        String hostHeader = info.headerValue("Host");
        if (hostHeader != null && !hostHeader.isEmpty()) {
            return hostHeader;
        }
        // 从 HttpService 获取的 Host 值
        if (requestResponse != null && requestResponse.httpService() != null) {
            String host = requestResponse.httpService().host();
            int port = requestResponse.httpService().port();
            boolean isDefaultPort = (requestResponse.httpService().secure() && port == 443)
                    || (!requestResponse.httpService().secure() && port == 80);
            if (StringUtils.isNotEmpty(host)) {
                return isDefaultPort ? host : host + ":" + port;
            }
        }
        return null;
    }
}
