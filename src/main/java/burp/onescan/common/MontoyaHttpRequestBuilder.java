package burp.onescan.common;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.common.utils.HttpRequestBuilder;
import burp.common.utils.StringUtils;
import burp.common.utils.UrlUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Montoya API HttpRequestResponse Builder
 * <p>
 * 用于构建 HTTP 请求,替代旧的 HttpReqRespAdapter
 * <p>
 * Created by vaycore on 2025-12-07.
 */
public class MontoyaHttpRequestBuilder {

    private final MontoyaApi api;

    public MontoyaHttpRequestBuilder(MontoyaApi api) {
        if (api == null) {
            throw new IllegalArgumentException("MontoyaApi is null");
        }
        this.api = api;
    }

    /**
     * 从 URL 字符串构建 HttpRequest
     *
     * @param url URL 字符串
     * @return HttpRequest 实例
     * @throws IllegalArgumentException 如果 URL 格式错误
     */
    public HttpRequest buildFromUrl(String url) throws IllegalArgumentException {
        if (StringUtils.isEmpty(url)) {
            throw new IllegalArgumentException("url is null");
        }
        if (!UrlUtils.isHTTP(url)) {
            throw new IllegalArgumentException(url + " does not include the protocol.");
        }
        try {
            URL u = new java.net.URI(url).toURL();
            String host = UrlUtils.getHostByURL(u);
            String pqf = UrlUtils.toPQF(u);
            byte[] requestBytes = buildRequestBytes(host, pqf);

            return HttpRequest.httpRequest(
                    HttpService.httpService(
                            u.getHost(),
                            u.getPort() == -1 ? (u.getProtocol().equals("https") ? 443 : 80) : u.getPort(),
                            u.getProtocol().equals("https")),
                    burp.api.montoya.core.ByteArray.byteArray(requestBytes));
        } catch (java.net.URISyntaxException | MalformedURLException e) {
            throw new IllegalArgumentException("Url: " + url + " format error.");
        }
    }

    /**
     * 从 HttpService、请求路径、headers 和 cookies 构建 HttpRequest
     *
     * @param service HttpService 实例
     * @param reqPQF  请求路径 (Path + Query + Fragment)
     * @param headers 请求头列表
     * @param cookies Cookie 列表
     * @return HttpRequest 实例
     */
    public HttpRequest buildFromComponents(HttpService service, String reqPQF,
            List<String> headers, List<String> cookies) {
        boolean existsCookie = existsCookieByHeader(headers);
        StringBuilder builder = new StringBuilder();
        String host = service.host() + (service.port() == 80 || service.port() == 443 ? "" : ":" + service.port());

        builder.append("GET ").append(reqPQF).append(" HTTP/1.1").append("\r\n");
        builder.append("Host: ").append(host).append("\r\n");

        for (int i = 1; i < headers.size(); i++) {
            String item = headers.get(i);
            // 排除 Host 请求头（需要特殊定制）
            if (item.toLowerCase().startsWith("host: ")) {
                continue;
            }
            // 合并请求的 Cookie 值（如果原请求中不存在 Cookie 值,将 Cookie 插入到 2 的位置）
            if (!existsCookie && i == 2) {
                String cookie = mergeCookie(null, cookies);
                if (StringUtils.isNotEmpty(cookie)) {
                    builder.append("Cookie: ").append(cookie).append("\r\n");
                }
            } else if (item.toLowerCase().startsWith("cookie: ")) {
                // 分割 Header 的 name 和 value 值
                String cookieValue = item.split(": ")[1];
                // 分割 Cookie 的 key 和 value 值
                String[] oldCookie = cookieValue.split(";\\s*");
                String cookie = mergeCookie(oldCookie, cookies);
                if (StringUtils.isNotEmpty(cookie)) {
                    builder.append("Cookie: ").append(cookie).append("\r\n");
                }
                continue;
            }
            builder.append(item).append("\r\n");
        }
        builder.append("\r\n");
        byte[] requestBytes = builder.toString().getBytes(StandardCharsets.UTF_8);

        return HttpRequest.httpRequest(service,
                burp.api.montoya.core.ByteArray.byteArray(requestBytes));
    }

    /**
     * 从 HttpService 和原始请求字节构建 HttpRequest
     *
     * @param service      HttpService 实例
     * @param requestBytes 请求字节数组
     * @return HttpRequest 实例
     */
    public HttpRequest buildFromBytes(HttpService service, byte[] requestBytes) {
        return HttpRequest.httpRequest(service,
                burp.api.montoya.core.ByteArray.byteArray(requestBytes));
    }

    /**
     * 检测 Header 列表是否存在 Cookie 字段
     *
     * @param headers Header 列表
     * @return true=存在；false=不存在
     */
    private static boolean existsCookieByHeader(List<String> headers) {
        for (String header : headers) {
            if (header.toLowerCase().startsWith("cookie: ")) {
                return true;
            }
        }
        return false;
    }

    /**
     * 合并 Cookie 列表
     *
     * @param oldCookies 原请求的 Cookie 列表
     * @param cookies    响应包中的 Cookie 列表
     * @return 返回请求包中的 Cookie 格式
     */
    private static String mergeCookie(String[] oldCookies, List<String> cookies) {
        List<String> result = new ArrayList<>();
        // 处理响应包中 Cookie 列表为空的情况
        if (cookies == null || cookies.isEmpty()) {
            return StringUtils.join(oldCookies, "; ");
        }
        // 合并 Cookie 值
        for (String cookie : cookies) {
            String[] split = cookie.split("=");
            if (split.length < 2) {
                continue;
            }
            String key = split[0];
            String value = split[1];
            int index = cookieKeyIndexOf(oldCookies, key);
            if (index >= 0) {
                oldCookies[index] = null;
            }
            // 兼容 Shiro 移除 Cookie 的操作
            if (value.equalsIgnoreCase("deleteMe")) {
                continue;
            }
            result.add(cookie);
        }
        // 剩下未移除的,全部添加到列表
        if (oldCookies != null) {
            for (String cookie : oldCookies) {
                if (cookie != null) {
                    result.add(cookie);
                }
            }
        }
        return StringUtils.join(result, "; ");
    }

    /**
     * 查询 CookieKey 在列表中的下标
     *
     * @param cookies   列表实例
     * @param cookieKey Cookie 的 key
     * @return 失败返回 -1
     */
    private static int cookieKeyIndexOf(String[] cookies, String cookieKey) {
        if (cookies == null || cookies.length == 0) {
            return -1;
        }
        for (int i = 0; i < cookies.length; i++) {
            String item = cookies[i];
            if (item != null && item.contains("=")) {
                String key = item.split("=")[0];
                if (key.equals(cookieKey)) {
                    return i;
                }
            }
        }
        return -1;
    }

    /**
     * 构建请求字节数组（委托给 HttpRequestBuilder 工具类）
     */
    private static byte[] buildRequestBytes(String host, String reqPQF) {
        return HttpRequestBuilder.buildGetRequest(host, reqPQF);
    }
}
