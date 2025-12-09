package burp.common.utils;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * HTTP 请求构建工具类
 * <p>
 * 统一的 HTTP 请求字节数组构建逻辑，避免代码重复。
 * 注意：HTTP/2 协议协商由 TLS ALPN 层自动处理，应用层无需手动判断。
 *
 * @author kenyon
 */
public final class HttpRequestBuilder {

    /**
     * 默认 HTTP 版本
     */
    private static final String DEFAULT_HTTP_VERSION = "HTTP/1.1";

    /**
     * 私有构造函数，防止实例化
     */
    private HttpRequestBuilder() {
        // 工具类不允许实例化
    }

    /**
     * 构建简单的 GET 请求字节数组（使用默认 HTTP/1.1）
     *
     * @param host   主机名（可包含端口，如 example.com:8080）
     * @param reqPQF 请求路径、查询参数和片段（Path + Query + Fragment）
     * @return 请求字节数组
     */
    public static byte[] buildGetRequest(String host, String reqPQF) {
        return buildGetRequest(host, reqPQF, DEFAULT_HTTP_VERSION);
    }

    /**
     * 构建简单的 GET 请求字节数组
     *
     * @param host        主机名（可包含端口）
     * @param reqPQF      请求路径、查询参数和片段
     * @param httpVersion HTTP 协议版本（如 HTTP/1.1）
     * @return 请求字节数组
     */
    public static byte[] buildGetRequest(String host, String reqPQF, String httpVersion) {
        StringBuilder builder = buildGetRequestBuilder(host, reqPQF, httpVersion);
        return builder.toString().getBytes(StandardCharsets.UTF_8);
    }


    /**
     * 构建 GET 请求的 StringBuilder（用于需要进一步处理的场景）
     *
     * @param host        主机名
     * @param reqPQF      请求路径、查询参数和片段
     * @param httpVersion HTTP 协议版本
     * @return StringBuilder 实例
     */
    public static StringBuilder buildGetRequestBuilder(String host, String reqPQF, String httpVersion) {
        return new StringBuilder()
                .append("GET ").append(reqPQF).append(" ").append(httpVersion).append("\r\n")
                .append("Host: ").append(host).append("\r\n")
                .append("\r\n");
    }

    /**
     * 构建包含自定义请求头和 Cookie 的 GET 请求字节数组
     *
     * @param host    主机名
     * @param reqPQF  请求路径、查询参数和片段
     * @param headers 请求头列表（第一个元素通常是请求行，会被跳过）
     * @param cookies Cookie 列表
     * @return 请求字节数组
     */
    public static byte[] buildGetRequestWithHeaders(String host, String reqPQF,
            List<String> headers, List<String> cookies) {
        return buildGetRequestWithHeaders(host, reqPQF, headers, cookies, DEFAULT_HTTP_VERSION);
    }

    /**
     * 构建包含自定义请求头和 Cookie 的 GET 请求字节数组
     *
     * @param host        主机名
     * @param reqPQF      请求路径、查询参数和片段
     * @param headers     请求头列表
     * @param cookies     Cookie 列表
     * @param httpVersion HTTP 协议版本
     * @return 请求字节数组
     */
    public static byte[] buildGetRequestWithHeaders(String host, String reqPQF,
            List<String> headers, List<String> cookies, String httpVersion) {
        // 检查原始请求头中是否已存在 Cookie
        boolean existsCookie = headers != null && headers.stream()
                .anyMatch(h -> h.toLowerCase().startsWith("cookie: "));

        StringBuilder builder = new StringBuilder();
        builder.append("GET ").append(reqPQF).append(" ").append(httpVersion).append("\r\n");
        builder.append("Host: ").append(host).append("\r\n");

        if (headers != null && headers.size() > 1) {
            for (int i = 1; i < headers.size(); i++) {
                String item = headers.get(i);
                // 排除 Host 请求头（已在上面添加）
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
}
